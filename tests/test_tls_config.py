"""Unit tests for TLS/auth configuration and connection wiring (no server)."""

import sys
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

import mem0_aerospike  # noqa: F401  -- registers the provider
from mem0_aerospike import create_memory_config
from mem0_aerospike.configs.vector_stores.aerospike import AerospikeConfig, TlsSettings
from mem0_aerospike.vector_stores.aerospike import AerospikeDB

# -- TlsSettings validation ---------------------------------------------------


def test_tls_settings_minimal_is_valid():
    tls = TlsSettings()
    assert tls.ca_file is None  # system trust store; presence still means TLS


def test_tls_settings_full_is_valid():
    tls = TlsSettings(
        ca_file="/certs/ca.pem",
        tls_name="cluster-tls",
        client_cert_file="/certs/client.pem",
        client_key_file="/certs/client.key",
        protocols=["TLSv1.3"],
        ciphers=["TLS13_AES_256_GCM_SHA384"],
    )
    assert tls.protocols == ["TLSv1.3"]


@pytest.mark.parametrize("kwargs", [{"client_cert_file": "/c.pem"}, {"client_key_file": "/k.pem"}])
def test_tls_settings_unpaired_client_material_rejected(kwargs):
    with pytest.raises(ValidationError, match="set together"):
        TlsSettings(**kwargs)


@pytest.mark.parametrize("field", ["protocols", "ciphers"])
def test_tls_settings_empty_allowlist_rejected(field):
    with pytest.raises(ValidationError, match="must not be empty"):
        TlsSettings(**{field: []})


def test_tls_settings_empty_tls_name_rejected():
    with pytest.raises(ValidationError, match="tls_name must not be empty"):
        TlsSettings(tls_name="")


def test_tls_settings_forbids_unknown_keys():
    with pytest.raises(ValidationError):
        TlsSettings(for_login_only=True)


# -- AerospikeConfig validation ------------------------------------------------


def test_config_defaults_plaintext_anonymous():
    cfg = AerospikeConfig()
    assert cfg.tls is None
    assert cfg.username is None and cfg.password is None
    assert cfg.auth_mode == "internal"


@pytest.mark.parametrize("kwargs", [{"username": "u"}, {"password": "p"}])
def test_config_unpaired_credentials_rejected(kwargs):
    with pytest.raises(ValidationError, match="username and password"):
        AerospikeConfig(**kwargs)


def test_config_tls_named_seed_without_tls_rejected():
    with pytest.raises(ValidationError, match="silently bypass"):
        AerospikeConfig(hosts=[("db1", 4433, "node-tls")])


def test_config_empty_seed_tls_name_rejected():
    with pytest.raises(ValidationError, match="tls_name must not be empty"):
        AerospikeConfig(hosts=[("db1", 4433, "")], tls=TlsSettings())


def test_config_bad_hosts_tuple_rejected():
    with pytest.raises(ValidationError):
        AerospikeConfig(hosts=[("db1", 4433, "n", "extra")])


def test_config_certificate_mode_requires_mtls():
    with pytest.raises(ValidationError, match="client_cert_file"):
        AerospikeConfig(auth_mode="certificate", tls=TlsSettings())


def test_config_certificate_mode_forbids_password():
    with pytest.raises(ValidationError, match="forbids"):
        AerospikeConfig(
            auth_mode="certificate",
            tls=TlsSettings(client_cert_file="/c.pem", client_key_file="/k.pem", tls_name="t"),
            username="u",
            password="p",
        )


def test_config_certificate_mode_requires_tls_name_single_seed():
    with pytest.raises(ValidationError, match="tls_name"):
        AerospikeConfig(
            auth_mode="certificate",
            tls=TlsSettings(client_cert_file="/c.pem", client_key_file="/k.pem"),
        )


def test_config_certificate_mode_requires_tls_name_per_seed():
    tls = TlsSettings(client_cert_file="/c.pem", client_key_file="/k.pem")
    with pytest.raises(ValidationError, match="every seed"):
        AerospikeConfig(
            auth_mode="certificate",
            tls=tls,
            hosts=[("db1", 4433, "n1"), ("db2", 4433)],
        )
    # named seed + global name is fine
    cfg = AerospikeConfig(
        auth_mode="certificate",
        tls=TlsSettings(client_cert_file="/c.pem", client_key_file="/k.pem", tls_name="g"),
        hosts=[("db1", 4433, "n1"), ("db2", 4433)],
    )
    assert cfg.auth_mode == "certificate"


def test_config_valid_full_tls_auth():
    cfg = AerospikeConfig(
        hosts=[("db1", 4433, "node1")],
        tls={"ca_file": "/ca.pem", "tls_name": "g"},
        username="u",
        password="p",
    )
    assert isinstance(cfg.tls, TlsSettings)


# -- Connection wiring ----------------------------------------------------------


def _make_db(mocker, **kwargs):
    """Construct AerospikeDB with ClusterDefinition mocked; return (instance, definition)."""
    definition = MagicMock()
    builder = MagicMock()
    definition.with_tls_config_of.return_value = builder
    cluster = MagicMock()
    definition.connect.return_value = cluster
    CD = mocker.patch(
        "mem0_aerospike.vector_stores.aerospike.ClusterDefinition",
        return_value=definition,
    )
    mocker.patch.object(AerospikeDB, "create_col")
    instance = AerospikeDB(
        namespace="test",
        collection_name="unit_test",
        embedding_model_dims=4,
        **kwargs,
    )
    return instance, CD, definition, builder


def test_plaintext_connect_builds_hosts_no_tls(mocker):
    _, CD, definition, _ = _make_db(mocker, host="localhost", port=3000)
    (host_obj,) = CD.call_args.kwargs["hosts"]
    assert (host_obj.name, host_obj.port, host_obj.tls_name) == ("localhost", 3000, None)
    assert not any(c[0] == "with_tls_config_of" for c in definition.mock_calls)


def test_tls_wiring_maps_settings_through_builder(mocker):
    tls = TlsSettings(
        ca_file="/ca.pem",
        tls_name="g",
        client_cert_file="/c.pem",
        client_key_file="/k.pem",
        protocols=["TLSv1.3"],
        ciphers=["TLS13_AES_256_GCM_SHA384"],
    )
    _, _, definition, builder = _make_db(mocker, tls=tls)
    builder.ca_file.assert_called_once_with("/ca.pem")
    builder.tls_name.assert_called_once_with("g")
    builder.client_cert_file.assert_called_once_with("/c.pem")
    builder.client_key_file.assert_called_once_with("/k.pem")
    builder.protocols.assert_called_once_with("TLSv1.3")
    builder.ciphers.assert_called_once_with("TLS13_AES_256_GCM_SHA384")
    builder.done.assert_called_once_with()


def test_tls_dict_form_is_normalized(mocker):
    _, _, _, builder = _make_db(mocker, tls={"ca_file": "/ca.pem"})
    builder.ca_file.assert_called_once_with("/ca.pem")


def test_seed_tls_name_overrides_global_and_unnamed_inherits(mocker):
    tls = TlsSettings(tls_name="global")
    _, CD, _, _ = _make_db(
        mocker,
        hosts=[("db1", 4433, "node1"), ("db2", 4433)],
        tls=tls,
    )
    hosts = CD.call_args.kwargs["hosts"]
    assert [(h.name, h.tls_name) for h in hosts] == [("db1", "node1"), ("db2", "global")]


def test_tls_named_seed_without_tls_raises(mocker):
    mocker.patch(
        "mem0_aerospike.vector_stores.aerospike.ClusterDefinition",
        return_value=MagicMock(),
    )
    with pytest.raises(ValueError, match="silently bypass"):
        AerospikeDB(
            namespace="test",
            collection_name="c",
            embedding_model_dims=4,
            hosts=[("db1", 4433, "n1")],
        )


# -- Direct-construction path gets config-level validation ----------------------


def _db_kwargs(**overrides):
    kwargs = {"namespace": "test", "collection_name": "c", "embedding_model_dims": 4}
    kwargs.update(overrides)
    return kwargs


@pytest.mark.parametrize(
    "overrides",
    [
        {"username": "u"},
        {"password": "p"},
        {"hosts": [("db1", 4433, "")], "tls": TlsSettings()},
        {"hosts": [("db1", 4433, "n", "x")]},
        {"auth_mode": "certificate", "tls": TlsSettings()},
        {
            "auth_mode": "certificate",
            "tls": TlsSettings(client_cert_file="/c.pem", client_key_file="/k.pem", tls_name="t"),
            "username": "u",
            "password": "p",
        },
        {"auth_mode": "bogus"},
        {"hosts": [("db1", 4433, "n1")]},
    ],
)
def test_direct_construction_enforces_config_validation(mocker, overrides):
    """AerospikeDB() built directly must apply the same invariants as the
    pydantic config path — no SDK-boundary surprises."""
    mocker.patch(
        "mem0_aerospike.vector_stores.aerospike.ClusterDefinition",
        return_value=MagicMock(),
    )
    with pytest.raises(ValidationError):
        AerospikeDB(**_db_kwargs(**overrides))


def test_internal_auth_calls_native_credentials(mocker):
    _, _, definition, _ = _make_db(mocker, username="u", password="p")
    definition.with_native_credentials.assert_called_once_with("u", "p")


def test_certificate_auth_calls_certificate_credentials(mocker):
    tls = TlsSettings(client_cert_file="/c.pem", client_key_file="/k.pem", tls_name="t")
    _, _, definition, _ = _make_db(mocker, tls=tls, auth_mode="certificate")
    definition.with_certificate_credentials.assert_called_once_with()
    assert not any(c[0] == "with_native_credentials" for c in definition.mock_calls)


def test_anonymous_default_calls_no_credentials(mocker):
    _, _, definition, _ = _make_db(mocker)
    assert not any(c[0] in ("with_native_credentials", "with_certificate_credentials") for c in definition.mock_calls)


# -- mem0ai config seam ---------------------------------------------------------


def test_create_memory_config_carries_tls_and_seed_names():
    from unittest.mock import patch

    from mem0.utils.factory import VectorStoreFactory

    cfg = create_memory_config(
        vector_store={
            "hosts": [("db1", 4433, "node1-tls"), ("db2", 4433)],
            "tls": {"tls_name": "cluster-tls", "ca_file": "/ca.pem"},
            "username": "u",
            "password": "p",
        }
    )
    vc = cfg.vector_store.config
    # vc.tls is validated by the registered module copy's TlsSettings (a distinct
    # class object); assert on its validated fields rather than isinstance.
    assert (vc.tls.ca_file, vc.tls.tls_name) == ("/ca.pem", "cluster-tls")
    assert vc.hosts == [("db1", 4433, "node1-tls"), ("db2", 4433)]

    store_module = sys.modules["mem0.vector_stores.aerospike"]
    fake_def = MagicMock()
    builder = MagicMock()
    fake_def.with_tls_config_of.return_value = builder
    with (
        patch.object(store_module, "ClusterDefinition", return_value=fake_def) as CD,
        patch.object(store_module.AerospikeDB, "create_col"),
    ):
        VectorStoreFactory.create("aerospike", vc)
        hosts = CD.call_args.kwargs["hosts"]
        assert [(h.name, h.port, h.tls_name) for h in hosts] == [
            ("db1", 4433, "node1-tls"),
            ("db2", 4433, "cluster-tls"),
        ]
        builder.ca_file.assert_called_once_with("/ca.pem")
        builder.tls_name.assert_called_once_with("cluster-tls")
        fake_def.with_native_credentials.assert_called_once_with("u", "p")


def test_unknown_config_key_still_rejected():
    with pytest.raises(ValidationError):
        create_memory_config(vector_store={"tls": {"bogus_option": 1}})
