from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class TlsSettings(BaseModel):
    """Optional TLS settings for the Aerospike connection.

    Presence of this model enables TLS. `ca_file` may be omitted to verify
    the server certificate against the system trust store. The SDK's TLS
    builder does not support `for_login_only` on this build (it raises
    `NotImplementedError`), so it is intentionally absent.
    """

    model_config = ConfigDict(extra="forbid")

    ca_file: str | None = Field(
        None,
        description="CA certificate PEM file; omit to verify against the system trust store",
    )
    tls_name: str | None = Field(
        None,
        description="Cluster-wide TLS name for certificate validation; per-seed names in `hosts` take precedence",
    )
    client_cert_file: str | None = Field(
        None,
        description="Client certificate PEM file for mutual TLS; must be paired with client_key_file",
    )
    client_key_file: str | None = Field(
        None,
        description="Client private key PEM file for mutual TLS; must be paired with client_cert_file",
    )
    protocols: list[str] | None = Field(
        None,
        description="Allowed TLS protocols (e.g. ['TLSv1.3']); omit for SDK defaults",
    )
    ciphers: list[str] | None = Field(
        None,
        description="Allowed cipher suites by rustls name; omit for SDK defaults",
    )

    @model_validator(mode="after")
    def _validate_pairing(self):
        if (self.client_cert_file is None) != (self.client_key_file is None):
            raise ValueError("client_cert_file and client_key_file must be set together")
        if self.tls_name is not None and not self.tls_name:
            raise ValueError("tls_name must not be empty")
        if self.protocols is not None and not self.protocols:
            raise ValueError("protocols must not be empty; omit it to use SDK defaults")
        if self.ciphers is not None and not self.ciphers:
            raise ValueError("ciphers must not be empty; omit it to use SDK defaults")
        return self


class AerospikeConfig(BaseModel):
    """Configuration for the Aerospike vector store provider."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    namespace: str = Field("test", description="Aerospike namespace for the vector store")
    collection_name: str = Field("mem0", description="Aerospike set name for the collection")
    embedding_model_dims: int = Field(1536, description="Dimensions of the embedding vectors")
    host: str = Field("localhost", description="Aerospike seed host")
    port: int = Field(3000, description="Aerospike seed port")
    hosts: list[tuple[str, int] | tuple[str, int, str]] | None = Field(
        None,
        description=(
            "Aerospike seed nodes as (host, port) or (host, port, tls_name) tuples for "
            "multi-node clusters; overrides host/port when set"
        ),
    )
    tls: TlsSettings | None = Field(
        None,
        description="Optional TLS settings; when set, all cluster connections are TLS-encrypted",
    )
    username: str | None = Field(
        None,
        description="Aerospike internal-auth username; must be paired with password",
    )
    password: str | None = Field(
        None,
        description="Aerospike internal-auth password; must be paired with username",
    )
    auth_mode: Literal["internal", "certificate"] = Field(
        "internal",
        description=(
            "Authentication mode: 'internal' uses username/password; 'certificate' uses "
            "the mTLS client certificate (PKI) and requires tls with client cert/key "
            "plus a resolvable tls_name on every seed"
        ),
    )
    allow_scans_with_where: bool = Field(
        False,
        description=(
            "Allow filtered list/search queries that do not scope by user_id/agent_id/run_id to fall back to a scan"
        ),
    )
    max_record_bytes: int = Field(
        943718,
        description="Maximum serialized record size in bytes before client-side rejection (default ~0.9 MiB)",
    )
    order_list_results: bool = Field(
        False,
        description=(
            "Order list() results by created_at_ms descending and create a created_at_ms "
            "secondary index in create_col() (opt-in; default keeps unordered results)"
        ),
    )

    @model_validator(mode="after")
    def _validate_tls_and_auth(self):
        if (self.username is None) != (self.password is None):
            raise ValueError("username and password must be set together")
        for entry in self.hosts or []:
            if len(entry) not in (2, 3):
                raise ValueError("hosts entries must be (host, port) or (host, port, tls_name) tuples")
            if len(entry) == 3:
                if not entry[2]:
                    raise ValueError("hosts tls_name must not be empty")
                if self.tls is None:
                    raise ValueError(
                        f"seed {entry[0]!r} carries a tls_name but tls is not configured; "
                        "a TLS-named seed on a plaintext connection would silently bypass TLS"
                    )
        if self.auth_mode == "certificate":
            if self.tls is None or self.tls.client_cert_file is None:
                raise ValueError("auth_mode='certificate' requires tls with client_cert_file and client_key_file")
            if self.username is not None:
                raise ValueError(
                    "auth_mode='certificate' forbids username/password; the client certificate authenticates"
                )
            global_tls_name = self.tls.tls_name
            if self.hosts:
                for entry in self.hosts:
                    if len(entry) < 3 and global_tls_name is None:
                        raise ValueError(
                            f"auth_mode='certificate' requires a tls_name for every seed; "
                            f"{entry[0]!r} has none and no global tls_name is set"
                        )
            elif global_tls_name is None:
                raise ValueError("auth_mode='certificate' requires tls.tls_name (or per-seed tls_name) on every seed")
        return self
