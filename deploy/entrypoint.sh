#!/bin/sh
set -eu
umask 077

if [ "${TLS_MODE:-self-signed}" = "self-signed" ]; then
  dir="$DATA_DIR/tls"
  mkdir -p "$dir"
  if [ ! -f "$dir/keystore.p12" ]; then
    : "${PUBLIC_HOST:?Set PUBLIC_HOST to the IP or domain clients connect to}"
    case "$PUBLIC_HOST" in
      *[!0-9.]*) san="dns:$PUBLIC_HOST" ;;
      *) san="ip:$PUBLIC_HOST" ;;
    esac
    head -c 32 /dev/urandom | base64 | tr -d '\n' > "$dir/password"
    keytool -genkeypair -alias auka -keyalg EC -groupname secp256r1 -sigalg SHA256withECDSA \
      -validity 3650 -dname "CN=$PUBLIC_HOST" -ext "SAN=$san" \
      -keystore "$dir/keystore.p12" -storetype PKCS12 -storepass "$(cat "$dir/password")" 2>/dev/null
  fi
  export TLS_KEYSTORE="$dir/keystore.p12"
  TLS_KEYSTORE_PASSWORD="$(cat "$dir/password")"
  export TLS_KEYSTORE_PASSWORD
  # Compare this with what the app shows the first time it connects.
  echo "TLS certificate SHA-256 fingerprint:"
  keytool -list -keystore "$TLS_KEYSTORE" -storepass "$TLS_KEYSTORE_PASSWORD" -alias auka 2>/dev/null | sed -n 's/.*SHA-256): //p'
fi

exec java \
  -Xmx96m -Xss512k -XX:MaxMetaspaceSize=64m -XX:ReservedCodeCacheSize=32m \
  -XX:+UseSerialGC -XX:TieredStopAtLevel=1 -XX:+ExitOnOutOfMemoryError \
  --enable-native-access=ALL-UNNAMED \
  -cp '/app/lib/*' io.vainslab.auka.Main
