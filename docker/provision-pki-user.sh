#!/bin/sh
# Provisions users for the opt-in TLS fixture. The client certificate's CN
# becomes the PKI Aerospike username; `nopassword` marks it as a PKI-only user
# (certificate auth, no password). A second password-authenticated user covers
# the internal-auth path. Idempotent: "already exists" is fine, but any other
# failure fails the script so setup can't silently skip provisioning.
#
# The aerospike-server:dev image ships only `asd` (no asadm), so this runs
# asadm from the aerospike-tools image, connecting over TLS with the fixture's
# client certificate (tls-authenticate-client any requires one).
set -eu

CERT_DIR="$(cd "$(dirname "$0")/tls-certs" && pwd)"
PKI_USER="${AEROSPIKE_TLS_PKI_USER:-mem0-client}"
HOST="${AEROSPIKE_TLS_HOST:-127.0.0.1}"
PORT="${AEROSPIKE_TLS_PORT:-4443}"
TOOLS_IMAGE="${AEROSPIKE_TOOLS_IMAGE:-aerospike/aerospike-tools:latest}"

# The dev image bootstraps `admin`/`admin` with only `user-admin` — enough to
# provision users, not for data ops — so both provisioned users get
# read-write + sindex-admin (create_col makes secondary indexes).
PW_USER="${AEROSPIKE_TLS_PW_USER:-mem0-pw-user}"
PW_PASS="${AEROSPIKE_TLS_PW_PASS:-mem0-pw-pass}"

# Run a single asadm command; tolerate only an "already exists" outcome for
# that specific command — never a global grep over multi-command output.
asadm_cmd() {
  output=$(docker run --rm --network host \
    -v "$CERT_DIR:/certs:ro" \
    "$TOOLS_IMAGE" \
    asadm -h "$HOST" -p "$PORT" \
      --tls-enable --tls-name aerospike-tls \
      --tls-cafile /certs/ca.crt \
      --tls-certfile /certs/client.crt --tls-keyfile /certs/client.key \
      -U admin -P admin \
      -e "$1" 2>&1) || {
    if ! printf '%s' "$output" | grep -qi "already exists"; then
      printf '%s\n' "$output" >&2
      echo "asadm command failed on $HOST:$PORT: $1" >&2
      exit 1
    fi
  }
}

asadm_cmd "enable; manage acl create user $PKI_USER password nopassword roles read-write sindex-admin"
asadm_cmd "enable; manage acl create user $PW_USER password $PW_PASS roles read-write sindex-admin"

echo "PKI user '$PKI_USER' and password user '$PW_USER' provisioned on $HOST:$PORT"
