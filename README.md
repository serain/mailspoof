# mailspoof

> Scans SPF and DMARC records for issues that could allow email spoofing.

## Motivation

Email spoofing is alive and well. Many organisations' SPF and DMARC records do not provide the necessary guidance for recipients to validate the authenticity of emails bearing their domain names.

`mailspoof` can be used by organisations and red-teamers to seek-out domains with lax SPF and DMARC policies.

This can sometimes uncover domains that may bypass filter rules that apply to external emails. For example, parent and subsidiary organisations may be exempt from rules that prepend `[EXTERNAL]` tags to subject lines.

## Installation

```
$ pip3 install mailspoof
```

## Usage

```
$ mailspoof --help
usage: mailspoof [-h] [-o OUTPUT] [-d DOMAIN] [-iL INPUT_LIST]

scans SPF and DMARC records for issues that could allow email spoofing

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        json output file, default is stdout
  -d DOMAIN, --domain DOMAIN
                        a target domain to check, can be passed multiple times
  -iL INPUT_LIST, --input-list INPUT_LIST
                        list of domains to check
```

## To Do

* Add rules for `aspf` and `adkim`.

* Add examples section
