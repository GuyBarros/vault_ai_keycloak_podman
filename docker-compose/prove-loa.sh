#!/bin/sh
# Prove the Level of Assurance (LoA) claim: token-exchange issues loa=1 on a
# plain password login; mfa-client only ever issues loa=2, and Keycloak's
# built-in Direct Grant flow refuses to issue it at all unless the caller
# supplies a valid TOTP code for the user's configured OTP credential.
set -eu

KC_URL="${KC_URL:-http://localhost:8081}"

pass=0
fail=0

expect() {
  _title=$1
  _got=$2
  _want=$3
  if [ "${_got}" = "${_want}" ]; then
    echo "PASS  ${_title} (${_got})"
    pass=$((pass + 1))
  else
    echo "FAIL  ${_title} (got ${_got}, want ${_want})"
    fail=$((fail + 1))
  fi
}

decode_claim() {
  # $1 = JWT access_token, $2 = claim name
  printf '%s' "$1" | python3 -c "
import sys, base64, json
tok = sys.stdin.read().strip()
seg = tok.split('.')[1]
seg += '=' * (-len(seg) % 4)
claims = json.loads(base64.urlsafe_b64decode(seg))
print(claims.get('$2', ''))
"
}

token_field() {
  # $1 = token response body, $2 = field name
  printf '%s' "$1" | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(d.get('$2', ''))
"
}

totp_code() {
  # Keycloak's own OTP verifier HMACs the raw ASCII bytes of the stored
  # secret string directly — it does NOT base32-decode it first, unlike a
  # real authenticator app reading the same string off a QR code. Confirmed
  # empirically against this realm's mfa-user credential (secret below
  # matches templates/demo-realm.json).
  python3 -c "
import hmac, hashlib, struct, time
secret = b'JBSWY3DPEHPK3PXP'
counter = int(time.time() // 30)
msg = struct.pack('>Q', counter)
h = hmac.new(secret, msg, hashlib.sha1).digest()
offset = h[-1] & 0x0F
code = (struct.unpack('>I', h[offset:offset+4])[0] & 0x7fffffff) % 1000000
print(str(code).zfill(6))
"
}

echo "--- LoA=1: single-factor password login via token-exchange ---"
BODY=$(curl -sS -X POST "${KC_URL}/realms/demo/protocol/openid-connect/token" \
  -d client_id=token-exchange -d client_secret=token-exchange-secret \
  -d grant_type=password -d username=user -d password=user -d scope="openid users.read")
TOK=$(token_field "${BODY}" access_token)
if [ -z "${TOK}" ]; then
  echo "FAIL  token-exchange password login (no access_token: ${BODY})"
  fail=$((fail + 1))
else
  echo "PASS  token-exchange password login issued a token"
  pass=$((pass + 1))
  LOA=$(decode_claim "${TOK}" loa)
  expect "token carries loa=1" "${LOA}" "1"
fi

echo "--- LoA=2: mfa-client refuses without a TOTP code ---"
NO_OTP=$(curl -sS -X POST "${KC_URL}/realms/demo/protocol/openid-connect/token" \
  -d client_id=mfa-client -d client_secret=mfa-client-secret \
  -d grant_type=password -d username=mfa-user -d password=mfa-user -d scope="openid users.read")
ERR=$(token_field "${NO_OTP}" error)
expect "mfa-user login without OTP is rejected" "${ERR}" "invalid_grant"

echo "--- LoA=2: mfa-client refuses a wrong TOTP code ---"
WRONG_OTP=$(curl -sS -X POST "${KC_URL}/realms/demo/protocol/openid-connect/token" \
  -d client_id=mfa-client -d client_secret=mfa-client-secret \
  -d grant_type=password -d username=mfa-user -d password=mfa-user -d scope="openid users.read" \
  -d totp=000000)
ERR=$(token_field "${WRONG_OTP}" error)
expect "mfa-user login with wrong OTP is rejected" "${ERR}" "invalid_grant"

echo "--- LoA=2: mfa-client issues a token with a correct TOTP code ---"
CODE=$(totp_code)
MFA_BODY=$(curl -sS -X POST "${KC_URL}/realms/demo/protocol/openid-connect/token" \
  -d client_id=mfa-client -d client_secret=mfa-client-secret \
  -d grant_type=password -d username=mfa-user -d password=mfa-user -d scope="openid users.write" \
  -d totp="${CODE}")
MFA_TOK=$(token_field "${MFA_BODY}" access_token)
if [ -z "${MFA_TOK}" ]; then
  echo "FAIL  mfa-user login with correct OTP (${CODE}) (no access_token: ${MFA_BODY})"
  fail=$((fail + 1))
else
  echo "PASS  mfa-user login with correct OTP (${CODE}) issued a token"
  pass=$((pass + 1))
  LOA=$(decode_claim "${MFA_TOK}" loa)
  expect "token carries loa=2" "${LOA}" "2"
  USERNAME=$(decode_claim "${MFA_TOK}" preferred_username)
  expect "token identifies mfa-user" "${USERNAME}" "mfa-user"
fi

echo ""
echo "PASS=${pass} FAIL=${fail}"
[ "${fail}" -eq 0 ]
