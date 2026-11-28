import builtins
import ssl
import sys
import types
import urllib.error
import urllib.request

import pytest

from meshroom.core import httpUtils


@pytest.fixture
def noTruststore(monkeypatch):
    """ Make "import truststore" fail. """
    realImport = builtins.__import__

    def fakeImport(name, *args, **kwargs):
        if name == "truststore":
            raise ImportError("No module named 'truststore'")
        return realImport(name, *args, **kwargs)

    monkeypatch.delitem(sys.modules, "truststore", raising=False)
    monkeypatch.setattr(builtins, "__import__", fakeImport)


def test_createSslContext_withoutTruststore(noTruststore):
    context = httpUtils._createSslContext()
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname


def test_createSslContext_truststoreFailure(monkeypatch):
    """ A failing truststore must not prevent the module from working. """
    def failingContext(*args, **kwargs):
        raise RuntimeError("unsupported platform")

    monkeypatch.setitem(sys.modules, "truststore", types.SimpleNamespace(SSLContext=failingContext))
    context = httpUtils._createSslContext()
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED


def test_createSslContext_usesTruststore(monkeypatch):
    sentinel = object()
    monkeypatch.setitem(sys.modules, "truststore", types.SimpleNamespace(SSLContext=lambda protocol: sentinel))
    assert httpUtils._createSslContext() is sentinel


class _FakeResponse:
    status = 200

    def __init__(self):
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True


def test_requestsUseSslContext(monkeypatch):
    """ All requests verify certificates with the module's SSL context, and close their response. """
    calls = []
    responses = []

    def fakeUrlopen(request, timeout=None, context=None):
        calls.append(context)
        responses.append(_FakeResponse())
        return responses[-1]

    monkeypatch.setattr(urllib.request, "urlopen", fakeUrlopen)

    assert httpUtils.fetchStatus("https://example.invalid") == 200
    assert httpUtils.etagMatch("https://example.invalid", "etag") is False

    assert calls == [httpUtils._SSL_CONTEXT] * 2
    assert all(response.closed for response in responses)


def test_etagMatch_notModified(monkeypatch):
    def fakeUrlopen(request, timeout=None, context=None):
        raise urllib.error.HTTPError(request.full_url, 304, "Not Modified", {}, None)

    monkeypatch.setattr(urllib.request, "urlopen", fakeUrlopen)
    assert httpUtils.etagMatch("https://example.invalid", "etag") is True
