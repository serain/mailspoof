import pytest

from mailspoof import DMARCScan


dmarc_scan = DMARCScan()


def test_good(monkeypatch):
    def mock_fetch(domain):
        return 'v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com'

    monkeypatch.setattr(dmarc_scan, 'fetch', mock_fetch)

    issues = dmarc_scan('_dmarc.google.com')
    assert not len(issues)


def test_no_dmarc(monkeypatch):
    def mock_fetch(domain):
        raise ValueError()

    monkeypatch.setattr(dmarc_scan, 'fetch', mock_fetch)

    issues = dmarc_scan('_dmarc.acme.com')
    assert len(issues) == 1
    assert any(issue['code'] == 7 for issue in issues)


def test_lax_policy_and_low_pct(monkeypatch):
    def mock_fetch(domain):
        return 'v=DMARC1; p=none; pct=50'

    monkeypatch.setattr(dmarc_scan, 'fetch', mock_fetch)

    issues = dmarc_scan('_dmarc.acme.com')
    assert len(issues) == 2
    assert any(issue['code'] == 8 for issue in issues)
    assert any(issue['code'] == 10 for issue in issues)


def test_lax_subdomain_policy(monkeypatch):
    def mock_fetch(domain):
        return 'v=DMARC1; p=reject; sp=none'

    monkeypatch.setattr(dmarc_scan, 'fetch', mock_fetch)

    issues = dmarc_scan('_dmarc.acme.com')
    assert len(issues) == 1
    assert any(issue['code'] == 9 for issue in issues)
