#!/usr/bin/env bash
# Bash helper to test /phonebook/import
# Usage: ./import_phonebook_csv.sh HOST USER PASS /path/to/contacts.csv

# All parameters are mandatory. TOKEN cannot be supplied externally.
if [ "$#" -lt 4 ]; then
  cat <<EOF >&2
Usage: $0 HOST USER PASS CSV_FILE

HOST       Base URL of the API (e.g. https://cti.gs.nethserver.net)
USER       Username to log in (required)
PASS       Password for the user (required)
CSV_FILE   Path to CSV file to upload
EOF
  exit 2
fi

HOST="$1"
USER="$2"
PASS="$3"
CSV_FILE="$4"

# Only valid login endpoint
LOGIN_ENDPOINT="/api/login"

extract_token_from_file() {
  local file="$1"
  if command -v jq >/dev/null 2>&1; then
    jq -r '.token // .data.token // .access_token // empty' "$file" 2>/dev/null || true
  else
    sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$file" || true
  fi
}

try_login_endpoint() {
  local url="$1"
  local tmp_hdr=$(mktemp)
  local tmp_body=$(mktemp)
  # JSON POST
  curl -s -D "$tmp_hdr" -o "$tmp_body" -X POST "$url" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${USER}\",\"password\":\"${PASS}\"}" || true

  # try extract
  local tok
  tok=$(extract_token_from_file "$tmp_body" )
  if [ -n "$tok" ]; then
    echo "$tok"
    rm -f "$tmp_hdr" "$tmp_body"
    return 0
  fi

  # form POST
  curl -s -D "$tmp_hdr" -o "$tmp_body" -X POST "$url" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "username=${USER}" --data-urlencode "password=${PASS}" || true

  tok=$(extract_token_from_file "$tmp_body" )
  if [ -n "$tok" ]; then
    echo "$tok"
    rm -f "$tmp_hdr" "$tmp_body"
    return 0
  fi

  # Nothing found; print a short debug snippet and return failure
  echo "Tried $url; response headers:" >&2
  sed -n '1,200p' "$tmp_hdr" >&2
  echo "... response body (first 200 chars):" >&2
  tr -d '\r' < "$tmp_body" | sed -n '1,10p' >&2
  rm -f "$tmp_hdr" "$tmp_body"
  return 1
}


if [ ! -f "$CSV_FILE" ]; then
  echo "CSV file not found: $CSV_FILE" >&2
  exit 2
fi

 # Attempt to login using the single endpoint and obtain a JWT token
echo "Attempting to login against ${LOGIN_ENDPOINT} to obtain JWT token..." >&2
TOKEN=""
url="$HOST$LOGIN_ENDPOINT"
echo "Trying $url" >&2
tok=$(try_login_endpoint "$url" 2>/dev/null || true)
if [ -n "$tok" ]; then
  TOKEN="$tok"
  echo "Obtained token from $url" >&2
else
  echo "Failed to obtain token from $url; aborting." >&2
  exit 4
fi

# Perform CSV import
echo "Uploading CSV to $HOST/api/phonebook/import" >&2
response=$(curl -s -S -w "\n%{http_code}" -X POST "$HOST/api/phonebook/import" \
  -H "Authorization: Bearer ${TOKEN}" \
  -F "file=@${CSV_FILE};type=text/csv")

http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | sed '$d')

echo "HTTP $http_code"
if command -v jq >/dev/null 2>&1; then
  echo "$body" | jq .
else
  echo "$body"
fi

[ "$http_code" -ge 200 ] && [ "$http_code" -lt 300 ]
exit $? 
