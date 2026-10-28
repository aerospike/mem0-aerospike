# mem0-aerospike

An Aerospike vector-store provider for [mem0ai](https://github.com/mem0ai/mem0),
packaged as a standalone external plugin. Installing this package alongside
`mem0ai` makes `provider="aerospike"` work in `MemoryConfig` **without any
changes to mem0ai itself**.

## How it works

mem0ai hardcodes provider discovery to the `mem0.vector_stores.<provider>` and
`mem0.configs.vector_stores.<provider>` module paths, and keeps provider
registries on `VectorStoreFactory.provider_to_class` and
`VectorStoreConfig._provider_configs`. There is no public registration API.

On `import mem0_aerospike`, the package:

1. Loads its own `configs/vector_stores/aerospike.py` into `sys.modules` as
   `mem0.configs.vector_stores.aerospike`.
2. Loads its own `vector_stores/aerospike.py` into `sys.modules` as
   `mem0.vector_stores.aerospike`.
3. Registers `"aerospike"` in both mem0ai registries.

This is the same runtime-registration pattern used by `mem0-tcvectordb` and
`mem0-falkordb`. Registration is idempotent and guarded by a mem0ai version
check: if the installed mem0ai is outside the tested range, importing the
package raises an `ImportError` instead of silently corrupting mem0ai state.

## Install

```bash
pip install mem0ai
pip install .            # or: pip install mem0-aerospike once published
```

Requirements: Python >= 3.11 (driven by the `aerospike-sdk` preview client).

> **Note:** `aerospike-sdk` 0.9.0a5 currently depends on `aerospike-async` via
> a direct git URL, which blocks PyPI publication. Until that resolves,
> install `aerospike-sdk` from source or a private index.

## Usage

Recommended — the helper performs registration for you:

```python
from mem0_aerospike import create_memory_config
from mem0 import Memory

config = create_memory_config(
    vector_store={
        "namespace": "test",
        "collection_name": "mem0",
        "embedding_model_dims": 1536,
        "host": "localhost",
        "port": 3000,
    },
    llm={"provider": "openai", "config": {"model": "gpt-4o"}},
    embedder={"provider": "openai", "config": {"model": "text-embedding-3-small"}},
)
m = Memory(config=config)
```

Direct `MemoryConfig` construction also works, but **import order matters**:
`mem0_aerospike` must be imported before the config is validated.

```python
import mem0_aerospike  # noqa: F401  -- registers the provider
from mem0 import Memory
from mem0.configs.base import MemoryConfig

m = Memory(config=MemoryConfig(
    vector_store={"provider": "aerospike", "config": {...}}
))
```

## Configuration

`AerospikeConfig` fields (all validated by Pydantic v2, `extra="forbid"`):

| Field | Default | Description |
|-------|---------|-------------|
| `namespace` | `"test"` | Aerospike namespace |
| `collection_name` | `"mem0"` | Aerospike set name |
| `embedding_model_dims` | `1536` | Embedding vector dimensions |
| `host` | `"localhost"` | Seed host |
| `port` | `3000` | Seed port |
| `hosts` | `None` | Seed nodes as `(host, port)` or `(host, port, tls_name)` tuples; overrides `host`/`port` |
| `tls` | `None` | `TlsSettings` (or its dict form); when set, all connections are TLS-encrypted |
| `username` | `None` | Internal-auth username; must be paired with `password` |
| `password` | `None` | Internal-auth password; must be paired with `username` |
| `auth_mode` | `"internal"` | `"internal"` (username/password) or `"certificate"` (PKI client-cert auth) |
| `allow_scans_with_where` | `False` | Permit filtered queries that do not scope by `user_id`/`agent_id`/`run_id` to fall back to a full scan |
| `max_record_bytes` | `943718` | Client-side record-size guardrail (~0.9 MiB) |
| `order_list_results` | `False` | Order `list()` results by `created_at` descending (adds a `created_at_ms` secondary index) |

`TlsSettings` fields:

| Field | Default | Description |
|-------|---------|-------------|
| `ca_file` | `None` | CA certificate PEM file; omit to verify against the system trust store |
| `tls_name` | `None` | Cluster-wide TLS name; per-seed names in `hosts` take precedence |
| `client_cert_file` | `None` | Client certificate PEM file for mTLS; paired with `client_key_file` |
| `client_key_file` | `None` | Client private key PEM file for mTLS; paired with `client_cert_file` |
| `protocols` | `None` | Allowed TLS protocols (e.g. `["TLSv1.2"]`); omit for SDK defaults |
| `ciphers` | `None` | Allowed cipher suites by rustls name; omit for SDK defaults |

## TLS and authentication

TLS is opt-in: providing `tls` encrypts every cluster connection — there is
no plaintext fallback. The `for_login_only` mode is intentionally not
exposed: on this SDK build the connection cannot drop to cleartext after
login, so TLS is all-or-nothing.

```python
config = create_memory_config(
    vector_store={
        "hosts": [("db1", 4433, "node1-tls"), ("db2", 4433)],  # per-seed TLS names
        "tls": {
            "ca_file": "/certs/ca.pem",          # omit for system trust store
            "tls_name": "cluster-tls",           # fallback for unnamed seeds
            "client_cert_file": "/certs/client.pem",  # mTLS
            "client_key_file": "/certs/client.key",
            "protocols": ["TLSv1.2"],
        },
        "username": "app",     # internal auth, or:
        "password": "secret",
        # "auth_mode": "certificate",  # PKI: requires mTLS + tls_name per seed,
                                       # forbids username/password
    },
)
```

Notes:

- `username`/`password` without TLS is legal (SDK posture) but sends
  credentials in cleartext.
- Every cluster node needs a TLS service and matching certificate identity —
  the client connects to nodes directly.
- `auth_mode="certificate"` maps the client certificate's CN to a provisioned
  `nopassword` user (PKI auth, no password exchange).

## Tests

```bash
pytest                  # mock-based unit tests, no server needed
pytest -m integration   # requires a running Aerospike server (localhost:3000)

# Opt-in TLS suite — Enterprise dev fixture (aerospike-server:dev, amd64;
# runs under emulation on arm64):
sh docker/gen-tls-certs.sh
docker compose --profile tls up -d aerospike-tls
sh docker/provision-pki-user.sh
AEROSPIKE_TLS_CA=docker/tls-certs/ca.crt pytest -m tls
```

## License

Apache-2.0. See `LICENSE` and `NOTICE` (Mem0 attribution).
