#! /usr/bin/env python3

import os.path

import configparser
from typing import Callable, Any

import CloudFlare
import requests
import argparse
import json
import sys
import re

config = None
gparser = None
gargs = None

DEFAULT_CONFIG_PATH = '/etc/cloudflare-dns-tool.config'

VERSION = '1.0'

TOKEN_ENV_VAR = 'CF_API_TOKEN'
HOST_ENV_VAR = 'AUTO_UPDATE_HOST'
DEFAULT_TTL = 360

IP_SERVICES = [
    ['Cloudflare', 'https://www.cloudflare.com/cdn-cgi/trace', 'regexp', r'ip=([.0-9]+)'],
    ['Ipify', 'https://api.ipify.org?format=json', 'json', 'ip'],
    ['IPEcho', 'https://ipecho.net/plain', 'text'],
    ['Track IP', 'https://www.trackip.net/ip', 'text'],
    ['I Can Haz IP', 'https://icanhazip.com/', 'text'],
]

DESCRIPTION = '''
Show, create or update DNS host records on Cloudflare's DNS servers
'''

ZONE_TABLE = {
    'fields': {
        'ID': 'id',
        'Name': 'name',
        'DNS': lambda r: f'{",".join(r["name_servers"])}'
    }
}

DNS_TABLE = {
    'fields': {
        'ID': 'id',
        'Name': 'name',
        'Type': 'type',
        'Content': 'content',
    }
}


def parse_args(argv):
    global config, gparser, gargs
    parser = argparse.ArgumentParser(description=DESCRIPTION.strip())
    gparser = parser
    parser.add_argument('--verbose', '-v', action='count', default=0)
    parser.add_argument('--config', '-C', action='store',
                        help=f'config file path, default {DEFAULT_CONFIG_PATH}',
                        default=DEFAULT_CONFIG_PATH)
    parser.add_argument('--token', '-T', action='store',
                        help='cloudflare API token, default to CF_TOOL_TOKEN env var')
    subparsers = parser.add_subparsers(help='sub-command help', dest='sub')

    zones_parser = subparsers.add_parser('zones')

    list_parser = subparsers.add_parser('list',)
    list_parser.add_argument('domain', help='host or domain name, default to CF_TOOL_DEFAULT_DOMAIN')

    dyn_parser = subparsers.add_parser('dyn-dns', aliases=['dyn'])
    dyn_parser.add_argument('host', help='host name to update with public ipv4 address or cf rec id')

    get_parser = subparsers.add_parser('get')
    get_parser.add_argument('host', help='target host name')
    get_parser.add_argument('types', nargs='?', help='comma delimited list of dns record types, e.g. A,AAA,CNAME')

    remove_parser = subparsers.add_parser('remove')
    remove_parser.add_argument('host', help='host name or dns_record id to remove')
    remove_parser.add_argument('types', nargs='?', help='comma delimited list of dns record types, e.g. A,AAA,CNAME')

    replace_parser = subparsers.add_parser('replace')
    replace_parser.add_argument('host', help='host name or dns_record id to remove')
    replace_parser.add_argument('type', help='dns record type, e.g. A, TXT or CNAME')
    replace_parser.add_argument('content', help='value to set as content')

    create_parser = subparsers.add_parser('create', aliases=['update'])
    create_parser.add_argument('host', help='host name')
    create_parser.add_argument('type', help='dns record type, e.g. A, TXT or CNAME')
    create_parser.add_argument('content', help='value to set as content')
    create_parser.add_argument('ttl', nargs='?', help='value to set as content', default=DEFAULT_TTL)

    gargs = parser.parse_args(argv)

    config_parser = configparser.ConfigParser()
    config_parser.read(gargs.config)
    sections = config_parser.sections()
    if sections and len(sections):
        config = config_parser[sections[0]]

    if gargs.token is None and 'token' in config:
        gargs.token = config['token']

    return gargs


def display_table(table, records):
    headers = table['fields'].items()
    widths = {header: len(header) for header, prop in headers}
    stringify: Callable[[dict, Any], str] = lambda rec, prop: f'{prop(rec)}' if callable(prop) else f'{rec[prop]}'
    for r in records:
        for header, prop in headers:
            widths[header] = max(widths[header], len(stringify(r, prop)))
    print('\n' + ' '.join([header.ljust(widths[header]) for header, prop in headers]))
    print(' '.join(['-' * widths[header] for header, prop in headers]))
    for r in records:
        print(' '.join([stringify(r, prop).ljust(widths[header]) for header, prop in headers]).rstrip())
    print('')


def dprint(*args, level=1, file=sys.stderr):
    if gargs.verbose >= level:
        print(*args, file=file)


def error(*args, file=sys.stderr, exit_rc=1):
    print('Error:', *args, file=file)
    if exit_rc is not None:
        sys.exit(exit_rc)


def get_public_ip(args):
    ip = None

    for service in IP_SERVICES:
        name, url, frmt, *props = service
        response = requests.get(url)
        if response:
            if frmt == 'text':
                ip = response.text
            elif frmt == 'json':
                ip = response.json()[props[0]]
            elif frmt == 'regexp':
                m = re.search(props[0], response.text)
                if m and m[1]:
                    ip = m[1]
            else:
                dprint(f'Warning: unknown ip parsing format "{frmt}" for the "{name}" api service', 1)
        dprint(f'{name} API response: {"<empty>" if ip is None else ip}', level=2)
        if ip is not None:
            return ip, name

    error('Unable to obtain public ip address')


def get_top_devel_domain(host):
    return '.'.join(host.split('.')[-2:]).lower()


def list_zones(args):
    zones = CloudFlare.CloudFlare(token=args.token).zones.get()
    display_table(ZONE_TABLE, zones)


def get_zone_id_by_host(args, host, err=None):
    domain = get_top_devel_domain(host)
    zones = CloudFlare.CloudFlare(token=args.token).zones.get()
    zone = None
    for zone_rec in zones:
        if zone_rec['name'] == domain:
            zone = zone_rec
            break
    if zone is None and err:
        error(f'Zone for host {host} not found' if err == True else err)
    return None if zone is None else zone['id']


def get_all_domain_dns_records(args, host):
    zone_id = get_zone_id_by_host(args, host, err=True)
    dns_records = CloudFlare.CloudFlare(token=args.token).zones.dns_records(zone_id)
    return dns_records


def get_all_host_dns_records(args, host, rec_type=None):
    dns_records = get_all_domain_dns_records(args, host)
    types = None if rec_type is None else rec_type if isinstance(rec_type, list) else rec_type.split('.')
    found = [rec for rec in dns_records if rec['name'] == host.lower() and (types is None or rec['type'] in types)]
    return found


def list_dns_records(args, host):
    dns_records = get_all_domain_dns_records(args, host)
    display_table(DNS_TABLE, dns_records)


def get_wildcard_host(host):
    return '*.' + '.'.join(host.split('.')[1:])


def get_host_value(args, host, rec_types):
    recs = get_all_host_dns_records(args, host, rec_types)
    for rec in recs:
        type_info = '' if rec_types else f'{rec["type"]} '
        print(f'{type_info}{rec["content"]}')


def update_dns_record_content(args, record, content, rec_type=None, proxied=None, ttl=None):
    data = {
        'name': record['name'],
        'type': record['type'] if rec_type is None else rec_type,
        'content': content,
        'proxied': False if proxied is None else proxied
    }
    if ttl is not None:
        data['ttl'] = ttl

    response = CloudFlare.CloudFlare(token=args.token).zones.dns_records.put(record["zone_id"], record['id'], data=data)
    return response


def update_dyn_dns(args, host):
    rec = None
    zone_id = None
    if '.' not in host and re.match(r'^[a-f0-9]{8,}$', host):
        dns_rec_id = host
        zone_id = get_zone_id_by_host(args, host, err=True)
        rec = CloudFlare.CloudFlare(token=args.token).zones.dns_records.get(zone_id, dns_rec_id)
        if not rec:
            error('DNS record with id {host} not found')
    else:
        recs = get_all_host_dns_records(args, host, 'A')
        if recs is not None and len(recs) == 1:
            rec = recs[0]
        elif recs is not None and len(recs) > 1:
            error(f'multiple dns records found for {host}, use record id')
    v4ip_source = get_public_ip(args)
    if not v4ip_source:
        error('Unable to obtain public IP address')
    if rec:
        update_dns_record_content(args, rec, v4ip_source[0])
    else:
        zone_id = get_zone_id_by_host(args, host, err=True) if zone_id is None else zone_id
        create_dns_ip_record(args, zone_id, host, v4ip_source[0])


def create_dns_ip_record(args, zone_id, host, ip, ttl=None, proxied=None):
    v4 = '.' in ip
    rec_type = 'A' if v4 else 'AAAA'
    return create_dns_record(args, zone_id, host, rec_type, ip, ttl, proxied)


def create_dns_record(args, zone_id, host, rec_type, content, ttl=None, proxied=None):
    data = {
        "type": rec_type,
        "name": host,
        "content": content,
        "proxied": False if proxied is None else bool(proxied),
        "ttl": DEFAULT_TTL if ttl is None else int(ttl),
    }
    return CloudFlare.CloudFlare(token=args.token).zones.dns_records.post(zone_id, data=data)


def remove_dns_records(args: argparse.Namespace, host: str, types_list: str):
    records: list = get_all_host_dns_records(args, host, types_list)
    types: list = None
    if types_list:
        types = types_list.upper().split(',')
        records = [rec for rec in records if rec['type'] in types]
    for rec in records:
        response = CloudFlare.CloudFlare(token=args.token).zones.dns_records.delete(rec['zone_id'], rec['id'])
    return


def create_record(args, host, rec_type, content, ttl=DEFAULT_TTL):
    zone_id = get_zone_id_by_host(args, host)
    if zone_id is not None:
        return create_dns_record(args, zone_id, host, rec_type, content, ttl)


def update_record(args, host, rec_type, content, ttl=DEFAULT_TTL, replace_only=False):
    zone_id = get_zone_id_by_host(args, host)
    if zone_id is None:
        error(f'Zone not found for host {host}')
    records = get_all_host_dns_records(args, host, rec_type)
    if len(records) == 0:
        if replace_only:
            error(f'Existing {rec_type} dns record for {host} not found')
        return create_dns_record(args, zone_id, host, rec_type, content, ttl)
    elif len(records) == 1:
        return update_dns_record_content(args, records[0], content)
    else:
        error(f'Ambiguous update, there are {len(records)} {rec_type} dns records for {host}')

def main():
    args = parse_args(sys.argv[1:])

    try:
        if args.sub == 'zones':
            return list_zones(args)
        elif args.sub == 'list':
            return list_dns_records(args, args.domain)
        elif args.sub == 'dyn' or args.sub == 'dyn-dns':
            return update_dyn_dns(args, args.host)
        elif args.sub == 'remove':
            return remove_dns_records(args, args.host, args.types)
        elif args.sub == 'create':
            return create_record(args, args.host, args.type, args.content, args.ttl)
        elif args.sub == 'update':
            return update_record(args, args.host, args.type, args.content, args.ttl, False)
        elif args.sub == 'replace':
            return update_record(args, args.host, args.type, args.content, None, True)
        elif args.sub == 'get':
            return get_host_value(args, args.host, args.types)
        else:
            gparser.print_help()

    except CloudFlare.exceptions.CloudFlareAPIError as e:

        if hasattr(e, 'error_chain') and len(e.error_chain) and hasattr(e.error_chain[0], 'code'):
            error(f'unexpected cloudflare API exception - [{e.error_chain[0].code}] {e.error_chain[0].message}')
        error(f'unexpected cloudflare exception - {e}')

    except CloudFlare.exceptions.CloudFlareError as e:

        if hasattr(e, 'error_chain') and len(e.error_chain) and hasattr(e.error_chain[0], 'code'):
            error(f'unexpected cloudflare API exception - [{e.error_chain[0].code}] {e.error_chain[0].message}')
        error(f'unexpected cloudflare exception - {e}')


if __name__ == "__main__":
    main()
