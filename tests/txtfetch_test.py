import pytest

from mailspoof import TXTFetch


txt_fetch = TXTFetch('v=spf1 ')


def test_fetch(monkeypatch):
    def mock_query(domain, type):
        return [
            'docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e',
            'facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95',
            'v=spf1 include:_spf.google.com ~all'
        ]

    monkeypatch.setattr(txt_fetch.resolver, 'query', mock_query)

    spf_record = txt_fetch('google.com')
    assert spf_record == 'v=spf1 include:_spf.google.com ~all'
