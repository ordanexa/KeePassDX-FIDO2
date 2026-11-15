#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
classes=$(mktemp -d)
trap 'rm -rf "$classes"' EXIT
"${JAVA_HOME:+$JAVA_HOME/bin/}javac" -d "$classes" \
  app/src/main/java/com/kunzisoft/keepass/fido2/{Cbor,Crypto,Hid,FidoToken,UnlockRecord,EnrollmentSet}.java \
  tests/fido2/FidoTest.java
"${JAVA_HOME:+$JAVA_HOME/bin/}java" -cp "$classes" com.kunzisoft.keepass.fido2.FidoTest
