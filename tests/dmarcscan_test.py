import pytest
import dns

from mailspoof import DMARCScan


def test_good(monkeypatch):
    dmarc_scan = DMARCScan()

    def mock_fetch(domain):
        return 'v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com'

    monkeypatch.setattr(dmarc_scan, 'fetch', mock_fetch)

    issues = dmarc_scan('_dmarc.google.com')
    assert not len(issues)


def test_no_dmarc(monkeypatch):
    dmarc_scan = DMARCScan()

    def mock_fetch(domain):
        raise ValueError()

    monkeypatch.setattr(dmarc_scan, 'fetch', mock_fetch)

    issues = dmarc_scan('_dmarc.acme.com')
    assert len(issues) == 1
    assert any(issue['code'] == 7 for issue in issues)


def test_lax_policy_and_low_pct(monkeypatch):
    dmarc_scan = DMARCScan()

    def mock_fetch(domain):
        return 'v=DMARC1; p=none; pct=50'

    monkeypatch.setattr(dmarc_scan, 'fetch', mock_fetch)

    issues = dmarc_scan('_dmarc.acme.com')
    assert len(issues) == 2
    assert any(issue['code'] == 8 for issue in issues)
    assert any(issue['code'] == 10 for issue in issues)


def test_lax_subdomain_policy(monkeypatch):
    dmarc_scan = DMARCScan()

    def mock_fetch(domain):
        return 'v=DMARC1; p=reject; sp=none'

    monkeypatch.setattr(dmarc_scan, 'fetch', mock_fetch)

    issues = dmarc_scan('_dmarc.acme.com')
    assert len(issues) == 1
    assert any(issue['code'] == 9 for issue in issues)


def test_timeout():
    dmarc_scan = DMARCScan()
    dmarc_scan.fetch.resolver.timeout = 0
    dmarc_scan.fetch.resolver.lifetime = 0

    issues = dmarc_scan('_dmarc.acme.com')

    assert len(issues) == 1
    assert any(issue['code'] == 11 for issue in issues)
