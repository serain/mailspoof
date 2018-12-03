# mailspoof [![PyPI version](https://badge.fury.io/py/mailspoof.svg)](https://badge.fury.io/py/mailspoof) [![docs](https://readthedocs.org/projects/mailspoof/badge/?version=latest)](https://mailspoof.readthedocs.io/en/latest/?badge=latest) [![build](https://travis-ci.com/serain/mailspoof.svg?branch=master)](https://travis-ci.com/serain/mailspoof) [![codecov](https://codecov.io/gh/serain/mailspoof/branch/master/graph/badge.svg)](https://codecov.io/gh/serain/mailspoof/branch/master)

> Scans SPF and DMARC records for issues that could allow email spoofing.

## Description

Email spoofing is alive and well. Many organisations' SPF and DMARC records do not provide the necessary guidance for recipients to validate the authenticity of emails bearing their domain names.

`mailspoof` can be used by organisations, pentesters and red-teamers to quickly sift through a large list of domains for lax SPF and DMARC policies.

This can sometimes uncover spoofable domains that may bypass some inbound filter rules. For example, parent and subsidiary organisations may be exempt from rules that prepend `EXTERNAL` tags to subject lines.

In other cases `mailspoof` could highlight spoofable external domains that employees are likely to trust, such as suppliers gathered from OSINT or other known organisations.

Email spoofing may be successful against recipients that manage their filtering themselves. Large email providers like GMail have the big data and the heuristics to efficiently handle spam. For example, GMail will likely forward a spoofed email from a common domain directly to the spam folder, even if the email doesn't fail validation due to lax policies.

## Installation

```
$ pip3 install mailspoof
```

## Examples

### CLI

`mailspoof` outputs JSON, making it easy to query with a tool like [`jq`](https://stedolan.github.io/jq/).

```json
$ printf "google.com\napple.com\nmicrosoft.com" > /tmp/list
$ mailspoof -d github.com -d reddit.com -iL /tmp/list
[
  {
    "domain": "google.com",
    "issues": [
      {
        "code": 4,
        "title": "'SoftFail' qualifer for 'all' mechanism",
        "detail": "The 'all' mechanism uses the 'SoftFail' qualifer '~'. It should be possible to spoof the domain by only causing a soft SPF failure. Most fil
ters will let this through by only raising the total spam score."
      }
    ]
  },
  ...
]
```

### Python

You can use `mailspoof` in your own Python scripts:

```
$ python
>>> from mailspoof import SPFScan, DMARCScan, Scan
>>> scan = Scan()
>>> scan('google.com')
[{'code': 4, 'title': "'SoftFail' qualifer for 'all' mechanism", 'detail': "The 'all' mechanism uses the 'SoftFail' qualifer '~'. It should be possible to spoof the domain by only causing a soft SPF failure. Most filters will let this through by only raising the total spam score."}]
```

Check the docs for details.

## Checking Unregistered Domains

`mailspoof` can check the registration status of domains in an SPF record, including included domains (see issue code 6 below). If any domains are found to be unregistered, attackers may register the domain and inject SPF mechanisms.

The registration status will only be checked if there is an environment variable `WHOAPI_KEY` with a valid key for [whoapi.com](https://whoapi.com/). At the time of writing the service offers 500 API calls with a free account.

## Issues

The following SPF and DMARC issues are currently checked:

| Code | Title                                        | Detail                                                                                                                                                                                                                                                                                                                                              |
| ---- | -------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0    | Non-existent domain                          | The DNS resolver raised an NXDomain error for "{domain}"                                                                                                                                                                                                                                                                                            |
| 1    | No SPF                                       | There is no SPF DNS record for the domain.                                                                                                                                                                                                                                                                                                          |
| 2    | No "all" mechanism                           | There is no all mechanism in the record. It may be possible to spoof the domain without causing an SPF failure.                                                                                                                                                                                                                                     |
| 3    | "Pass" qualifer for "all" mechanism          | The "all" mechanism uses the "Pass" qualifer "+". It should be possible to spoof the domain without causing an SPF failure.                                                                                                                                                                                                                         |
| 4    | "SoftFail" qualifer for "all" mechanism      | The "all" mechanism uses the "SoftFail" qualifer "~". It should be possible to spoof the domain by only causing a soft SPF failure. Most filters will let this through by only raising the total spam score.                                                                                                                                        |
| 5    | Too many lookups for SPF validation          | The SPF record requires more than 10 DNS lookups for the validation process. The RFC states that maximum 10 lookups are allowed. As a result, recipients may throw a PermError instead of proceeding with SPF validation. Recipients will treat these errors differently than a hard or soft SPF fail , and some will continue processing the mail. |
| 6    | Unregistered domains in SPF validation chain | One or more domains used in the SPF validation process are presently unregistered. An attacker could register these and configure his own SPF record to be included in the validation logic. The affected domains are: {domains}                                                                                                                    |
| 7    | No DMARC                                     | There is no DMARC DNS record associated for the domain.                                                                                                                                                                                                                                                                                             |
| 8    | Lax DMARC policy                             | The DMARC policy is set to "{policy}". If the DMARC policy is neither "reject" nor "quarantine", spoofed emails are likely to be accepted.                                                                                                                                                                                                          |
| 9    | Lax DMARC subdomain policy                   | The DMARC policy for subdomains is set to "{policy}". If the DMARC policy is neither "reject" nor "quarantine", spoofed emails from subdomains are likely to be accepted.                                                                                                                                                                           |
| 10   | Partial DMARC coverage                       | The DMARC "pct" value is "{pct}", meaning the DMARC policy will only be applied to {pct}% of incoming mail.                                                                                                                                                                                                                                         |