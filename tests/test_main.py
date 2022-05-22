# content of test_sample.py
import random
import re
from subprocess import run
from time import sleep
from os.path import abspath, dirname, join


ABSTOOL = join(dirname(dirname(abspath(__file__))), 'cf-dns-tool')

RANDOM = random.randint(1000000, 10000000-1)

DOMAIN = 'mericacard.com'
HOST = 'test.mericacard.com'
RUN_OPTS = {'capture_output': True, 'encoding': 'utf-8'}
RANDOM_HOST = f'H{RANDOM}.{DOMAIN}'
RANDOM_PRIVATE_IP = f'10.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(0,254)}'


def parse_headings(output):
    headings_line = [line for line in output.split('\n') if 'Name' in line][0]
    headings = re.split(r'\s+', headings_line.replace('|', ' ').strip())
    return headings, headings_line


def test_help():
    results = run([ABSTOOL, '--help'], **RUN_OPTS)
    assert results.returncode == 0
    assert '--help' in results.stdout
    results2 = run([ABSTOOL, '-h'], **RUN_OPTS)
    assert results2.returncode == 0
    assert '--help' in results2.stdout
    assert results.stdout == results2.stdout


def test_list():
    results = run([ABSTOOL, 'list', HOST], **RUN_OPTS)
    assert results.returncode == 0
    assert DOMAIN in results.stdout
    expected_headings = ['ID', 'Name', 'Type', 'Content']
    headings, headings_line = parse_headings(results.stdout)
    assert expected_headings == headings


def test_list_zones():
    results = run([ABSTOOL, 'zones'], **RUN_OPTS)
    assert results.returncode == 0
    assert DOMAIN in results.stdout
    expected_headings = ['ID', 'Name', 'DNS']
    headings, headings_line = parse_headings(results.stdout)
    assert expected_headings == headings


def test_create():
    results = run([ABSTOOL, 'create', RANDOM_HOST, 'A', RANDOM_PRIVATE_IP], **RUN_OPTS)
    assert results.returncode == 0
    results2 = run([ABSTOOL, 'get', RANDOM_HOST], **RUN_OPTS)
    assert results2.returncode == 0
    assert results2.stdout.strip().lower() == f'A {RANDOM_PRIVATE_IP}'.lower()
    results3 = run([ABSTOOL, 'remove', RANDOM_HOST], **RUN_OPTS)
    assert results3.returncode == 0


def test_bad_token():
    results = run([ABSTOOL, '--token', 'testing-bad-token-not-a-token', 'list', RANDOM_HOST], **RUN_OPTS)
    assert results.returncode != 0
    output = results.stderr.lower()
    assert 'error' in output and 'authorization' in output
