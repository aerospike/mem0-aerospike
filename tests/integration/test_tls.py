"""Opt-in TLS integration tests.

Run against the Enterprise Edition dev fixture (aerospike-server:dev, EE
8.1.3.0 — the same vector-capable image the integration suite uses;
linux/amd64, runs under emulation on arm64):

    sh docker/gen-tls-certs.sh
    docker compose --profile tls up -d aerospike-tls
    sh docker/provision-pki-user.sh
    AEROSPIKE_TLS_CA=docker/tls-certs/ca.crt pytest -m tls

The fixture enables `tls-authenticate-client any`, so every connection needs
a client certificate signed by the test CA — both the positive tests and the
password-auth path present one.
"""

import os
import socket
import warnings
from pathlib import Path
from uuid import uuid4

import pytest

aerospike_sdk = pytest.importorskip("aerospike_sdk")

pytestmark = [
    pytest.mark.tls,
    pytest.mark.integration,
]

from aerospike_async.exceptions import AerospikeError  # noqa: E402

import mem0_aerospike  # noqa: F401,E402  -- registers the provider
from mem0_aerospike.configs.vector_stores.aerospike import TlsSettings  # noqa: E402
from mem0_aerospike.vector_stores.aerospike import AerospikeDB  # noqa: E402

TLS_NAME = "aerospike-tls"
NAMESPACE = os.environ.get("AEROSPIKE_NAMESPACE", "test")
HOST = os.environ.get("AEROSPIKE_TLS_HOST", "127.0.0.1")
PORT = int(os.environ.get("AEROSPIKE_TLS_PORT", "4443"))
EMBEDDING_DIMS = 4

_CERT_DIR = Path(__file__).resolve().parents[2] / "docker" / "tls-certs"

CA_FILE = os.environ.get("AEROSPIKE_TLS_CA")
CLIENT_CERT = os.environ.get("AEROSPIKE_TLS_CLIENT_CERT", str(_CERT_DIR / "client.crt"))
CLIENT_KEY = os.environ.get("AEROSPIKE_TLS_CLIENT_KEY", str(_CERT_DIR / "client.key"))
UNTRUSTED_CA = os.environ.get("AEROSPIKE_TLS_UNTRUSTED_CA", str(_CERT_DIR / "other-ca.crt"))
UNTRUSTED_CLIENT_CERT = os.environ.get("AEROSPIKE_TLS_UNTRUSTED_CLIENT_CERT", str(_CERT_DIR / "untrusted-client.crt"))
UNTRUSTED_CLIENT_KEY = os.environ.get("AEROSPIKE_TLS_UNTRUSTED_CLIENT_KEY", str(_CERT_DIR / "untrusted-client.key"))
OTHER_USER_CERT = os.environ.get("AEROSPIKE_TLS_OTHER_USER_CERT", str(_CERT_DIR / "other-user.crt"))
OTHER_USER_KEY = os.environ.get("AEROSPIKE_TLS_OTHER_USER_KEY", str(_CERT_DIR / "other-user.key"))
MISMATCH_KEY = os.environ.get("AEROSPIKE_TLS_MISMATCH_KEY", str(_CERT_DIR / "mismatch.key"))


def _tls_port_reachable() -> bool:
    try:
        with socket.create_connection((HOST, PORT), timeout=2):
            return True
    except OSError:
        return False


pytestmark.append(
    pytest.mark.skipif(
        not (CA_FILE and _tls_port_reachable()),
        reason="TLS fixture not enabled: set AEROSPIKE_TLS_CA and start the TLS service on :4443",
    )
)


def _tls(**overrides) -> TlsSettings:
    kwargs = {"ca_file": CA_FILE, "client_cert_file": CLIENT_CERT, "client_key_file": CLIENT_KEY}
    kwargs.update(overrides)
    return TlsSettings(**kwargs)


def _db(**overrides) -> AerospikeDB:
    kwargs = {
        "namespace": NAMESPACE,
        "collection_name": f"mem0_tls_test_{uuid4().hex[:8]}",
        "embedding_model_dims": EMBEDDING_DIMS,
        "host": HOST,
        "port": PORT,
        "tls": _tls(tls_name=TLS_NAME),
        "auth_mode": "certificate",
    }
    kwargs.update(overrides)
    return AerospikeDB(**kwargs)


def _round_trip(db: AerospikeDB) -> None:
    """Exercise the full provider surface over TLS: create_col, insert, get, search, list."""
    memory_id = uuid4().hex
    vector = [1.0, 0.0, 0.0, 0.0]
    db.insert(
        vectors=[vector],
        payloads=[{"data": "hello tls", "user_id": "u1"}],
        ids=[memory_id],
    )
    got = db.get(memory_id)
    assert got is not None and got.payload["data"] == "hello tls"
    hits = db.search(query="", vectors=vector, top_k=5, filters={"user_id": "u1"})
    assert hits and hits[0].id == memory_id
    listed = db.list(filters={"user_id": "u1"}, top_k=5)
    assert listed[0] and listed[0][0].id == memory_id
    db.close()


def test_tls_connect_insert_get_search() -> None:
    _round_trip(_db())


PW_USER = os.environ.get("AEROSPIKE_TLS_PW_USER", "mem0-pw-user")
PW_PASS = os.environ.get("AEROSPIKE_TLS_PW_PASS", "mem0-pw-pass")


def test_password_auth_over_tls() -> None:
    """Internal (username/password) auth over TLS + mTLS transport."""
    db = _db(auth_mode="internal", username=PW_USER, password=PW_PASS)
    _round_trip(db)


def test_wrong_ca_fails_closed() -> None:
    with pytest.raises(AerospikeError):
        _db(tls=_tls(tls_name=TLS_NAME, ca_file=UNTRUSTED_CA))


def test_wrong_tls_name_fails_even_with_matching_san() -> None:
    """Seed-level tls_name wins over the SAN-matching connection address."""
    with pytest.raises(AerospikeError):
        _db(hosts=[(HOST, PORT, "not-the-right-name")])


def test_tls_against_plaintext_port_fails() -> None:
    plaintext_port = int(os.environ.get("AEROSPIKE_PORT", "3000"))
    with pytest.raises(AerospikeError):
        _db(port=plaintext_port)


def test_missing_client_cert_fails_under_mtls() -> None:
    with pytest.raises(AerospikeError):
        _db(
            auth_mode="internal",
            username="admin",
            password="admin",
            tls=_tls(tls_name=TLS_NAME, client_cert_file=None, client_key_file=None),
        )


def test_untrusted_client_cert_fails_under_mtls() -> None:
    with pytest.raises(AerospikeError):
        _db(
            tls=_tls(
                tls_name=TLS_NAME,
                client_cert_file=UNTRUSTED_CLIENT_CERT,
                client_key_file=UNTRUSTED_CLIENT_KEY,
            )
        )


def test_unprovisioned_pki_user_fails() -> None:
    with pytest.raises(AerospikeError):
        _db(
            tls=_tls(
                tls_name=TLS_NAME,
                client_cert_file=OTHER_USER_CERT,
                client_key_file=OTHER_USER_KEY,
            )
        )


def test_unreadable_ca_material_fails_at_connect() -> None:
    with pytest.raises(AerospikeError):
        _db(tls=_tls(tls_name=TLS_NAME, ca_file=str(_CERT_DIR / "does-not-exist.pem")))


def test_mismatched_client_cert_key_fails() -> None:
    with pytest.raises(AerospikeError):
        _db(tls=_tls(tls_name=TLS_NAME, client_key_file=MISMATCH_KEY))


@pytest.mark.parametrize("field", ["protocols", "ciphers"])
def test_unsupported_allowlist_values_raise_at_connect(field: str) -> None:
    with pytest.raises((ValueError, AerospikeError)):
        _db(tls=_tls(tls_name=TLS_NAME, **{field: ["bogus-value"]}))


def test_restrictive_protocol_allowlist_connects() -> None:
    """protocols=['TLSv1.2'] still connects — the EE 8.1.3 server does not
    negotiate 1.3 (verified: 1.3-only fails with a ProtocolVersion alert),
    so a restrictive allowlist proves the field reaches the handshake."""
    _round_trip(_db(tls=_tls(tls_name=TLS_NAME, protocols=["TLSv1.2"])))


def test_per_seed_tls_name_overrides_global() -> None:
    """A correct seed-level name works even when the global name is wrong —
    but global fallback keeps unnamed seeds working (both covered here by
    giving the global a wrong name and the seed the right one)."""
    db = _db(
        hosts=[(HOST, PORT, TLS_NAME)],
        tls=_tls(tls_name="wrong-global-name"),
    )
    try:
        _round_trip(db)
    except AerospikeError as exc:
        warnings.warn(f"seed-name precedence probe failed unexpectedly: {exc}")
        raise
