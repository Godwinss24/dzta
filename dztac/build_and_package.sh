#!/bin/bash
set -e

export CHAINCODE_LABEL=dzta_contract

echo "Cleaning up older archives..."
rm -f code.tar.gz chaincode.tgz connection.json metadata.json

echo "Compiling static x86_64 release target..."
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-unknown-linux-gnu

echo "Generating Chaincode-as-a-Service routing descriptor..."
cat <<EOF > connection.json
{
  "address": "dzta_contract:7052",
  "dial_timeout": "10s",
  "tls_required": false
}
EOF

# Declare configuration metadata type as modern CCAAS
echo '{"type": "ccaas", "label": "'${CHAINCODE_LABEL}'"}' > metadata.json

echo "Packaging distribution tarball layer assets..."
tar cfz code.tar.gz connection.json
tar cfz chaincode.tgz metadata.json code.tar.gz

rm -f connection.json metadata.json
echo "✓ Success! 'chaincode.tgz' built as a CCAAS routing bundle."