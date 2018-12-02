"""
Contains a dictionary potential SPF and DMARC issues to be used as template to
populate the main module's outputs.
"""

ISSUES = {
    'NX_DOMAIN': {
        'code': 0,
        'title': 'Non-existent domain',
        'detail': 'The DNS resolver raised an NXDomain error for \'{domain}\''
    },
    'NO_SPF': {
        'code': 1,
        'title': 'No SPF',
        'detail': 'There is no SPF DNS record for the domain.'
    },
    'SPF_NO_ALL': {
        'code': 2,
        'title': 'No \'all\' mechanism',
        'detail': 'There is no all mechanism in the record. It may be possible'
                  ' to spoof the domain without causing an SPF failure.'
    },
    'SPF_PASS_ALL': {
        'code': 3,
        'title': '\'Pass\' qualifer for \'all\' mechanism',
        'detail': 'The \'all\' mechanism uses the \'Pass\' qualifer \'+\'. '
                  'It should be possible to spoof the domain without causing '
                  'an SPF failure.'
    },
    'SPF_SOFT_FAIL_ALL': {
        'code': 4,
        'title': '\'SoftFail\' qualifer for \'all\' mechanism',
        'detail': 'The \'all\' mechanism uses the \'SoftFail\' qualifer \'~\'.'
                  ' It should be possible to spoof the domain by only causing '
                  'a soft SPF failure. Most filters will let this through by '
                  'only raising the total spam score.'
    },
    'SPF_LOOKUP_ERROR': {
        'code': 5,
        'title': 'Too many lookups for SPF validation',
        'detail': 'The SPF record requires more than 10 DNS lookups for the '
                  'validation process. The RFC states that maximum 10 lookups '
                  'are allowed. As a result, recipients may throw a PermError '
                  'instead of proceeding with SPF validation. Recipients will '
                  'treat these errors differently than a hard or soft SPF fail'
                  ' , and some will continue processing the mail.'
    },
    'SPF_UNREGISTERED_DOMAINS': {
        'code': 6,
        'title': 'Unregistered domains in SPF validation chain',
        'detail': 'One or more domains used in the SPF validation process are '
                  'presently unregistered. An attacker could register these '
                  'and configure his own SPF record to be included in the '
                  'validation logic. The affected domains are: {domains}'
    },
    'NO_DMARC': {
        'code': 1,
        'title': 'No DMARC',
        'detail': 'There is no DMARC DNS record associated for the domain.'
    },
    'DMARC_LAX_POLICY': {
        'code': 7,
        'title': 'Lax DMARC policy',
        'detail': 'The DMARC policy is set to \'{policy}\'. If the DMARC '
                  'policy is neither \'reject\' nor \'quarantine\', spoofed '
                  'emails are likely to be accepted.'
    },
    'DMARC_LAX_SUBDOMAIN_POLICY': {
        'code': 8,
        'title': 'Lax DMARC subdomain policy',
        'detail': 'The DMARC policy for subdomains is set to \'{policy}\'. If '
                  'the DMARC policy is neither \'reject\' nor \'quarantine\', '
                  'spoofed emails from subdomains are likely to be accepted.'
    },
    'DMARC_NOT_100_PCT': {
        'code': 9,
        'title': 'Partial DMARC coverage',
        'detail': 'The DMARC \'pct\' value is \'{pct}\', meaning the DMARC '
                  'policy will only be applied to {pct}% of incoming mail.'
    },
}
