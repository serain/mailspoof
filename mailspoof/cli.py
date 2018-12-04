import json
import logging
import argparse

from .scanners import Scan


__version__ = '0.1.1'
LOG = logging.getLogger('mailspoof')


def main():
    parser = argparse.ArgumentParser(prog='mailspoof',
        description='scans SPF and DMARC records for issues that could allow '
                    'email spoofing')
    parser.add_argument('-o', '--output', type=str, default='-',
        help='json output file, default is stdout')
    parser.add_argument('-d', '--domain', type=str, action='append',
        help='a target domain to check, can be passed multiple times')
    parser.add_argument('-iL', '--input-list', type=str,
        help='list of domains to check')
    parser.add_argument('-t', '--timeout', type=float, default='5',
                        help='timeout value for dns and http requests')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='enable verbose logging')
    parser.add_argument('--version', action='version',
        version=f'%(prog)s {__version__}')
    
    args = parser.parse_args()
    scan = Scan()

    if args.verbose:
        LOG.setLevel(logging.DEBUG)

    args.domains = []
    if args.input_list:
        with open(args.input_list) as fh:
            args.domains += fh.read().splitlines()
    if args.domain:
        args.domains += args.domain
    LOG.info(f'scanning {len(args.domains)} domains')

    if args.timeout:
        scan.spf_check.timeout = args.timeout
        scan.spf_check.fetch.resolver.timeout = args.timeout
        scan.spf_check.fetch.resolver.lifetime = args.timeout
        scan.dmarc_check.fetch.resolver.timeout = args.timeout
        scan.dmarc_check.fetch.resolver.lifetime = args.timeout

    results = []
    for domain in args.domains:
        results.append({
            'domain': domain,
            'issues': scan(domain)
        })

    if args.output == '-':
        print(json.dumps(results, indent=2))
    else:
        with open(args.output, 'w+') as fh:
            print(json.dumps(results, indent=2), file=fh)
            LOG.info(f'saved output in {args.output}')
