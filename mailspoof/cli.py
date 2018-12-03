import json
import argparse

from .scanners import Scan


__version__ = '0.1.1'


def get_args():
    parser = argparse.ArgumentParser(prog='mailspoof',
        description='scans SPF and DMARC records for issues that could allow '
                    'email spoofing')
    parser.add_argument('-o', '--output', type=str, default='-',
        help='json output file, default is stdout')
    parser.add_argument('-d', '--domain', type=str, action='append',
        help='a target domain to check, can be passed multiple times')
    parser.add_argument('-iL', '--input-list', type=str,
        help='list of domains to check')
    parser.add_argument('-t', '--timeout', type=int, default='5',
                        help='timeout value for dns and http requests')
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
    args = get_args()
    spoof_check = Scan(timeout=args.timeout)

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