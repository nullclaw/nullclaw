#!/usr/bin/env bash
# Decrypt NIP-17 gift wrap events from a file.
# Usage: ./decode-dms.sh nsec1... [r.json]
NSEC="${1:?Usage: $0 <nsec1...> [r.json]}"
FILE="${2:-r.json}"
IDX=0
while IFS= read -r event; do
  [[ -z "$event" ]] && continue
  IDX=$((IDX+1))
  CREATED=$(echo "$event" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('created_at','?'))" 2>/dev/null)
  OUTER_PK=$(echo "$event" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('pubkey','?')[:16])" 2>/dev/null)
  result=$(echo "$event" | nak gift unwrap --sec "$NSEC" 2>/dev/null)
  if [[ -n "$result" ]]; then
    KIND=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('kind','?'))" 2>/dev/null)
    FROM=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('pubkey','?')[:16])" 2>/dev/null)
    CONTENT=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('content','')[:120])" 2>/dev/null)
    echo "[$IDX] ts=$CREATED outer=${OUTER_PK}... → kind:$KIND from=${FROM}..."
    echo "     $CONTENT"
  else
    echo "[$IDX] ts=$CREATED outer=${OUTER_PK}... → DECRYPT FAILED"
  fi
done < "$FILE"
