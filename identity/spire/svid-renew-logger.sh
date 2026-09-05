set -u

SOCKET=/run/spire/sockets/spire-agent.sock
OUTPUT=/etc/svid
TMP=/tmp/svid-next
CYCLE=0

cert_metadata() {
  python3 - "$1" <<'PY'
import datetime
import hashlib
import os
import re
import ssl
import sys
import tempfile
from pathlib import Path

source_path = Path(sys.argv[1])
pem_text = source_path.read_text()

match = re.search(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    pem_text,
    re.DOTALL,
)

if not match:
    raise SystemExit("No certificate found")

leaf_pem = match.group(0) + "\n"

with tempfile.NamedTemporaryFile(
    mode="w",
    suffix=".pem",
    delete=False,
) as temp_file:
    temp_file.write(leaf_pem)
    temp_path = temp_file.name

try:
    info = ssl._ssl._test_decode_cert(temp_path)
finally:
    os.unlink(temp_path)

date_format = "%b %d %H:%M:%S %Y %Z"

not_before = datetime.datetime.strptime(
    info["notBefore"], date_format
).replace(tzinfo=datetime.timezone.utc)

not_after = datetime.datetime.strptime(
    info["notAfter"], date_format
).replace(tzinfo=datetime.timezone.utc)

now = datetime.datetime.now(datetime.timezone.utc)

uris = [
    value
    for key, value in info.get("subjectAltName", [])
    if key == "URI"
]

subject_parts = []
for rdn in info.get("subject", []):
    for key, value in rdn:
        subject_parts.append(f"{key}={value}")

der = ssl.PEM_cert_to_DER_cert(leaf_pem)
fingerprint = hashlib.sha256(der).hexdigest().upper()

print(f"SPIFFE_ID={uris[0] if uris else 'NONE'}")
print(f"SUBJECT={','.join(subject_parts)}")
print(f"SERIAL={info.get('serialNumber', 'UNKNOWN')}")
print(f"NOT_BEFORE_UTC={not_before.isoformat()}")
print(f"NOT_AFTER_UTC={not_after.isoformat()}")
print(
    "CERT_TTL_SECONDS="
    f"{int((not_after - not_before).total_seconds())}"
)
print(
    "REMAINING_SECONDS="
    f"{int((not_after - now).total_seconds())}"
)
print(f"SHA256_FINGERPRINT={fingerprint}")
PY
}

while true; do
  CYCLE=$((CYCLE + 1))
  NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)

  echo
  echo "================================================================"
  echo "ZT-XGUARD SPIFFE IDENTITY RENEWAL REPORT"
  echo "TIMESTAMP_UTC=$NOW"
  echo "CYCLE=$CYCLE"
  echo "POD_HOSTNAME=$(hostname)"
  echo "EXPECTED_SPIFFE_ID=$EXPECTED_SPIFFE_ID"
  echo "RENEW_INTERVAL_SECONDS=$RENEW_INTERVAL_SECONDS"
  echo "================================================================"

  if [ ! -S "$SOCKET" ]; then
    echo "WORKLOAD_API_SOCKET=MISSING"
    echo "ENTITLEMENT_STATUS=UNKNOWN"
    echo "RENEWAL_RESULT=FAILED_NO_SOCKET"
    echo "NEXT_CHECK_IN_SECONDS=$RENEW_INTERVAL_SECONDS"
    sleep "$RENEW_INTERVAL_SECONDS"
    continue
  fi

  echo "WORKLOAD_API_SOCKET=READY"

  OLD_SERIAL=NONE

  if [ -s "$OUTPUT/svid.0.pem" ]; then
    OLD_META=$(cert_metadata "$OUTPUT/svid.0.pem" 2>&1 || true)
    OLD_SERIAL=$(printf '%s\n' "$OLD_META" |
      awk -F= '$1=="SERIAL" {
        print substr($0, index($0, "=") + 1)
      }')

    [ -n "$OLD_SERIAL" ] || OLD_SERIAL=UNKNOWN
  fi

  rm -rf "$TMP"
  mkdir -p "$TMP"

  echo
  echo "----- SPIRE WORKLOAD API RESPONSE -----"

  FETCH_OUTPUT=$(
    /opt/spire/bin/spire-agent api fetch x509 \
      -socketPath "$SOCKET" \
      -write "$TMP" 2>&1
  )
  FETCH_RC=$?

  printf '%s\n' "$FETCH_OUTPUT"

  echo "----- END WORKLOAD API RESPONSE -----"
  echo

  if [ "$FETCH_RC" -eq 0 ] &&
     [ -s "$TMP/svid.0.pem" ] &&
     [ -s "$TMP/svid.0.key" ] &&
     [ -s "$TMP/bundle.0.pem" ]; then

    NEW_META=$(cert_metadata "$TMP/svid.0.pem")
    NEW_SERIAL=$(printf '%s\n' "$NEW_META" |
      awk -F= '$1=="SERIAL" {
        print substr($0, index($0, "=") + 1)
      }')

    cp "$TMP/svid.0.pem" "$OUTPUT/svid.0.pem.new"
    cp "$TMP/svid.0.key" "$OUTPUT/svid.0.key.new"
    cp "$TMP/bundle.0.pem" "$OUTPUT/bundle.0.pem.new"

    chmod 0644 "$OUTPUT/svid.0.pem.new"
    chmod 0600 "$OUTPUT/svid.0.key.new"
    chmod 0644 "$OUTPUT/bundle.0.pem.new"

    mv "$OUTPUT/svid.0.pem.new" "$OUTPUT/svid.0.pem"
    mv "$OUTPUT/svid.0.key.new" "$OUTPUT/svid.0.key"
    mv "$OUTPUT/bundle.0.pem.new" "$OUTPUT/bundle.0.pem"

    echo "ENTITLEMENT_STATUS=ACTIVE"
    echo "FETCH_RESULT=SUCCESS"
    echo "PREVIOUS_SERIAL=$OLD_SERIAL"
    echo "CURRENT_SERIAL=$NEW_SERIAL"

    if [ "$OLD_SERIAL" = "NONE" ]; then
      echo "ROTATION_RESULT=INITIAL_SVID_INSTALLED"
    elif [ "$OLD_SERIAL" = "$NEW_SERIAL" ]; then
      echo "ROTATION_RESULT=SAME_VALID_SVID_RETURNED"
    else
      echo "ROTATION_RESULT=NEW_SVID_ROTATED"
    fi

    echo
    echo "----- INSTALLED CERTIFICATE DETAILS -----"
    printf '%s\n' "$NEW_META"

    BUNDLE_COUNT=$(
      grep -c 'BEGIN CERTIFICATE' \
        "$OUTPUT/bundle.0.pem" 2>/dev/null || true
    )

    echo "CERT_FILE_BYTES=$(wc -c < "$OUTPUT/svid.0.pem")"
    echo "KEY_FILE_BYTES=$(wc -c < "$OUTPUT/svid.0.key")"
    echo "BUNDLE_FILE_BYTES=$(wc -c < "$OUTPUT/bundle.0.pem")"
    echo "BUNDLE_CERTIFICATE_COUNT=$BUNDLE_COUNT"
    echo "EXPECTED_ID_MATCH=$(
      printf '%s\n' "$NEW_META" |
      grep -q "^SPIFFE_ID=$EXPECTED_SPIFFE_ID$" &&
      echo true || echo false
    )"
    echo "----- END CERTIFICATE DETAILS -----"
  else
    echo "ENTITLEMENT_STATUS=DENIED_OR_UNAVAILABLE"
    echo "FETCH_RESULT=FAILED"
    echo "RENEWAL_RESULT=NO_NEW_SVID"

    if [ -s "$OUTPUT/svid.0.pem" ]; then
      echo
      echo "----- CURRENT STORED CERTIFICATE -----"
      cert_metadata "$OUTPUT/svid.0.pem" || true
      echo "----- END CURRENT STORED CERTIFICATE -----"
    else
      echo "CURRENT_STORED_CERTIFICATE=NONE"
    fi
  fi

  echo
  echo "NEXT_CHECK_IN_SECONDS=$RENEW_INTERVAL_SECONDS"
  echo "================================================================"

  sleep "$RENEW_INTERVAL_SECONDS"
done

