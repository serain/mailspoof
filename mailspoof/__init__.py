"""Scans SPF and DMARC records for issues that could allow email spoofing."""

from .scanners import SPFScan, DMARCScan, Scan, TXTFetch

__version__ = '0.1.1'


def get_args():
    import argparse

    parser = argparse.ArgumentParser(prog='mailspoof',
        description='scans SPF and DMARC records for issues that could allow '
                    'email spoofing')
    parser.add_argument('-o', '--output', type=str, default='-',
        help='json output file, default is stdout')
    parser.add_argument('-d', '--domain', type=str, action='append',
        help='a target domain to check, can be passed multiple times')
    parser.add_argument('-iL', '--input-list', type=str,
        help='list of domains to check')
    parser.add_argument('--version', action='version',
        version=f'%(prog)s {__version__}')
    args = parser.parse_args()

    args.domains = []
    if args.input_list:
        with open(args.input_list) as fh:
            args.domains += fh.read().splitlines()
    if args.domain:
        args.domains += args.domain

    return args


def main():
    import json

    args = get_args()
    spoof_check = Scan()

    results = []
    for domain in args.domains:
        results.append({
            'domain': domain,
            'issues': spoof_check(domain)
        })

    if args.output == '-':
        print(json.dumps(results, indent=2))
    else:
        with open(args.output, 'w+') as fh:
            print(json.dumps(results, indent=2), file=fh)
