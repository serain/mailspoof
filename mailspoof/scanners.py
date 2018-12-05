"""
`mailspoof` provides callable classes for checking SPF and DMARC records for
common issues.
"""

import os
import re
import dns.resolver
import tldextract
import requests
import logging
from functools import wraps

from . import exceptions
from .issues import ISSUES


LOG = logging.getLogger('mailspoof')
LOG.setLevel(logging.DEBUG)
CH = logging.StreamHandler()
FORMATTER = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - '
                              '%(message)s')
CH.setFormatter(FORMATTER)
LOG.addHandler(CH)


TIMEOUT = 5
WHOAPI_URL = 'https://api.whoapi.com/?domain={domain}&r=taken&apikey={key}'

if 'WHOAPI_KEY' in os.environ:
    LOG.debug('found WHOAPI_KEY, will check if domains are registered')
    WHOAPI_KEY = os.environ['WHOAPI_KEY']
else:
    LOG.debug('no WHOAPI_KEY, will not check if domains are registered')
    WHOAPI_KEY = None


class SPFScan():
    """
    A callable for extracting SPF security fails for a domain. Returns an
    SPFResult
    """

    def __init__(self):
        self.fetch = TXTFetch('v=spf1 ')
        self.whoapi_key = WHOAPI_KEY
        self.timeout = TIMEOUT

    def __call__(self, domain):
        """
        Returns a list of dictionaries ("issues") highlighting security
        concerns with the SPF record.
        """

        LOG.debug(f'checking SPF for {domain}')

        try:
            # some big spf records come with double quotes to split them up
            spf_record = self.fetch(domain).replace('"', '')
        except (ValueError, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            LOG.debug(f'no spf record for {domain}')
            return [ISSUES['NO_SPF']]
        except dns.resolver.NXDOMAIN:
            LOG.debug(f'non-existant domain {domain}')
            issue = dict(ISSUES['NX_DOMAIN'])
            issue['detail'] = issue['detail'].format(domain=domain)
            return [issue]
        except dns.exception.Timeout:
            LOG.warning(f'dns timeout for {domain}')
            issue = dict(ISSUES['DNS_TIMEOUT'])
            issue['detail'] = issue['detail'].format(domain=domain)
            return [issue]

        issues = []

        # recursively count the number of lookups and get the domains used
        try:
            included_domains, nb_lookups = self._get_include_domains(domain)
        except exceptions.SPFRecurse as exception:
            issue = ISSUES['SPF_RECURSE']
            issue['detail'] = issue['detail'].format(
                recursive_domain=exception.recursive_domain,
                domain=domain)
            issues.append(issue)
            return [issue]

        if nb_lookups > 10:
            issues.append(ISSUES['SPF_LOOKUP_ERROR'])

        # check for any free domains
        if self.whoapi_key:
            free_domains = set()
            for included_domain in included_domains:
                try:
                    taken = self._domain_taken(included_domain)
                    if not taken:
                        LOG.info('found unregistered domain '
                                 f'{included_domain}')
                        free_domains.add(included_domain)
                except exceptions.WHOAPIException as exception:
                    LOG.error(f'whoapi error on {included_domain}: '
                              f'{str(exception)}')

            if free_domains:
                issue = dict(ISSUES['SPF_UNREGISTERED_DOMAINS'])
                issue['detail'] = issue['detail'].format(domains=', '.join(
                    list(free_domains)))
                issues.append(issue)

        # check the 'all' mechanism
        terms = spf_record.split(' ')
        all_qualifier = None
        all_match = re.match(r'^([-?~+])all$', terms[-1])
        if all_match:
            all_qualifier = all_match.group(1)

        if not all_qualifier:
            issues.append(ISSUES['SPF_NO_ALL'])
        elif all_qualifier == '+':
            issues.append(ISSUES['SPF_PASS_ALL'])
        elif all_qualifier == '~':
            issues.append(ISSUES['SPF_SOFT_FAIL_ALL'])

        return issues

    def _get_include_domains(self, domain):
        """
        Recursively goes through the domain's SPF record and included SPF
        records. Returns a tuple of the root domains encountered and
        Recursively count the number of DNS lookups needed for a recipient to
        validate the SPF record
        """

        domains = set()
        nb_lookups = 0

        def _recurse(domain):
            nonlocal nb_lookups
            nonlocal domains

            try:
                spf_record = self.fetch(domain)
            except (ValueError, dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers):
                return
            except dns.exception.Timeout:
                LOG.warning(f'dns timeout for {domain}')
                return

            terms = spf_record.split(' ')
            includes = []

            for term in terms:
                if ':' not in term:
                    continue

                mechanism, value = term.split(':', 1)

                if value == domain:
                    raise exceptions.SPFTRecurse('trivial recurse in '
                                                 f'{domain}', value)

                if mechanism == 'include':
                    nb_lookups += 1
                    includes.append(value)
                    domains.add(self._get_registered_domain(value))
                elif mechanism in ['a', 'mx']:
                    nb_lookups += 1
                    domains.add(self._get_registered_domain(value))
                elif mechanism in ['ptr', 'exists', 'redirect']:
                    nb_lookups += 1

            for include in includes:
                _recurse(include)

        _recurse(domain)

        return domains, nb_lookups

    def _domain_taken(self, domain):
        """
        Returns True if the domain is already registered. False means the
        domain is open for registration and could be registered by an attacker.
        """
        response = requests.get(WHOAPI_URL.format(domain=domain,
                                                  key=self.whoapi_key,
                                                  timeout=self.timeout
                                                  ))
        data = response.json()
        if data['status'] != '0':
            raise exceptions.WHOAPIException(data['status_desc'])
        return True if data['taken'] else False

    @staticmethod
    def _get_registered_domain(domain):
        """
        Returns the "registered domain" from a given (sub)domain.

        >>> _get_registered_domain('foo.bar.com')
        bar.com
        """
        parsed_domain = tldextract.extract(domain)
        return '.'.join([parsed_domain.domain, parsed_domain.suffix])


class DMARCScan():
    """
    Callable that return a list of dictionaries ("issues") highlighting
    security concerns with the DMARC record.
    """

    def __init__(self):
        self.fetch = TXTFetch('v=DMARC1; ')

    def __call__(self, domain):
        """
        Returns a list of Issues highlighting potential security issues with
        the DMARC record.
        """

        LOG.debug(f'checking DMARC for {domain}')

        dmarc_domain = f'_dmarc.{domain}'

        try:
            dmarc_record = self.fetch(dmarc_domain)
        except (ValueError, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers):
            LOG.debug(f'no DMARC record for domain {domain}')
            return [ISSUES['NO_DMARC']]
        except dns.exception.Timeout:
            LOG.warning(f'dns timeout for {domain}')
            issue = dict(ISSUES['DNS_TIMEOUT'])
            issue['detail'] = issue['detail'].format(domain=domain)
            return [issue]

        issues = []
        terms = [term.strip(' ') for term in dmarc_record.split(';')]

        for term in terms:
            if '=' not in term:
                continue

            tag, value = term.split('=')

            if tag == 'p' and value not in ['quarantine', 'reject']:
                issue = dict(ISSUES['DMARC_LAX_POLICY'])
                issue['detail'] = issue['detail'].format(policy=value)
                issues.append(issue)
            elif tag == 'sp' and value not in ['quarantine', 'reject']:
                # default for 'sp' if not present is the same as 'p'
                issue = dict(ISSUES['DMARC_LAX_SUBDOMAIN_POLICY'])
                issue['detail'] = issue['detail'].format(policy=value)
                issues.append(issue)
            elif tag == 'pct' and int(value) < 100:
                # default for 'pct' if not present is '100'
                issue = dict(ISSUES['DMARC_NOT_100_PCT'])
                issue['detail'] = issue['detail'].format(pct=value)
                issues.append(issue)

        return issues


class TXTFetch():
    """
    A callable for fetching a DNS TXT record with a certain prefix for a
    given domain.
    """

    def __init__(self, txt_prefix):
        # txt_prefix should be `v=DMARC1; ` or `v=spf1 `
        self.txt_prefix = txt_prefix
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = TIMEOUT
        self.resolver.lifetime = TIMEOUT

    def __call__(self, domain):
        """
        Fetches a DNS TXT record with a certain prefix for a given domain.
        """
        txt_records = self.resolver.query(domain, 'TXT')
        for txt_record in txt_records:
            value = str(txt_record).strip('"')
            if value.startswith(self.txt_prefix):
                return value
        raise ValueError(f'No record with prefix {self.txt_prefix} for domain '
                         '{domain}')


class Scan():
    """
    Callable that return a list of dictionaries ("issues") highlighting
    security concerns with the SPF and DMARC records.
    """

    def __init__(self):
        self.spf_check = SPFScan()
        self.dmarc_check = DMARCScan()

    def __call__(self, domain):
        """
        Returns a list of Issues highlighting potential security issues with
        the SPF and DMARC records.
        """
        return self.spf_check(domain) + self.dmarc_check(domain)


SCANNER = Scan()


def scan(domain):
    return SCANNER(domain)
