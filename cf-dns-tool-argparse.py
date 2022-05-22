#! /usr/bin/env python3

import os.path

import configparser
import CloudFlare
import requests
import argparse
import json
import sys
import re
import os

config = None

DEFAULT_CONFIG_PATH = '/etc/cloudflare-dns-tool.config'

VERSION = '1.0'

TOKEN_ENV_VAR = 'CF_API_TOKEN'
HOST_ENV_VAR = 'AUTO_UPDATE_HOST'

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


def display_table(table, records):
    headers = table['fields'].items()
    widths = {header: len(header) for header, prop in headers}
    for r in records:
        for header, prop in headers:
            widths[header] = max(widths[header], len(f'{prop(r)}') if callable(prop) else len(f'{r[prop]}'))
    print('')
    print(' '.join([header.ljust(widths[header]) for header, prop in headers]))
    print(' '.join(['-' * widths[header] for header, prop in headers]))
    for r in records:
        print(' '.join([(f'{prop(r)}' if callable(prop) else f'{r[prop]}').ljust(widths[header]) for header, prop in headers]).rstrip())
    print('')


def parseArgs(argv):
    global config
    parser = argparse.ArgumentParser(description=DESCRIPTION.strip())
    parser.add_argument('--verbose', '-v', action='count', default=0)
    parser.add_argument('--config', '-C', action='store',
                        help=f'config file path, default {DEFAULT_CONFIG_PATH}',
                        default=DEFAULT_CONFIG_PATH)
    parser.add_argument('--token', '-T', action='store',
                        help='cloudflare API token')
    parser.add_argument('zones', help='list zones', action='store_true')
    parser.add_argument('dns', help='list zones', nargs=1, metavar='HOST')
    args = parser.parse_args(argv)

    config_parser = configparser.ConfigParser()
    config_parser.read(args.config)
    sections = config_parser.sections()
    if sections and len(sections):
        config = config_parser[sections[0]]

    if args.token is None and 'token' in config:
        args.token = config['token']


    return args


def list_zones(args):
    cf = CloudFlare.CloudFlare(token=args.token)
    zones = cf.zones.get()
    display_table(ZONE_TABLE, zones)


def list_dns_records(args, host):
    domain = host.split('.')[-2:].join('.').lower()
    cf = CloudFlare.CloudFlare(token=args.token)
    zones = cf.zones.get()
    zone = None
    for zone_rec in zones:
        if zone_rec['name'] == domain:
            zone = zone_rec
            break
    zone_id = zone['id']
    dns_records = cf.zones.dns_records(zone_id)
    display_table(DNS_TABLE, dns_records)


def main():
    args = parseArgs(sys.argv)

    if args.zones:
        return list_zones(args)

if __name__ == "__main__":
    main()
