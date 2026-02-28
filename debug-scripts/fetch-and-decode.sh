#!/usr/bin/env bash
# Fetch latest gift wraps for a pubkey and decrypt them.
# Usage: ./fetch-and-decode.sh <nsec1...> <hex-pubkey> [relay...]
NSEC="${1:?Usage: $0 <nsec1...> <hex-pubkey> [relay...]}"
PUBKEY="${2:?Missing pubkey}"
shift 2
RELAYS="${*:-wss://nos.lol wss://relay.damus.io wss://relay.primal.net}"

echo "Fetching kind:1059 events for ${PUBKEY:0:16}... from: $RELAYS"
# shellcheck disable=SC2086
nak req -k 1059 -p "$PUBKEY" $RELAYS 2>/dev/null > /tmp/raw-dms.json
COUNT=$(wc -l < /tmp/raw-dms.json)
echo "Got $COUNT events. Decrypting..."
echo ""

IDX=0
while IFS= read -r event; do
  [[ -z "$event" ]] && continue
  IDX=$((IDX+1))
  CREATED=$(echo "$event" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('created_at','?'))" 2>/dev/null)
  OUTER_PK=$(echo "$event" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('pubkey','?')[:16])" 2>/dev/null)
  result=$(echo "$event" | nak gift unwrap --sec "$NSEC" 2>/dev/null)
  if [[ -n "$result" ]]; then
    FROM=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('pubkey','?')[:16])" 2>/dev/null)
    CONTENT=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('content','')[:120])" 2>/dev/null)
    echo "[$IDX] ts=$CREATED outer=${OUTER_PK}... from=${FROM}..."
    echo "     $CONTENT"
  else
    echo "[$IDX] ts=$CREATED outer=${OUTER_PK}... → DECRYPT FAILED"
  fi
done < /tmp/raw-dms.json
