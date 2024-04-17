#!/bin/bash

set -e

BUCKET=ruddarr
ACCOUNT=
API_KEY=
R2_KEY=
R2_SECRET=

curl -s -g -X GET \
  "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT}/logs/retrieve?start=2024-01-01T00:00:00Z&end=2025-01-01T00:00:00Z&bucket=${BUCKET}" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "R2-Access-Key-Id: ${R2_KEY}" \
  -H "R2-Secret-Access-Key: ${R2_SECRET}" \
  | while IFS= read -r line; do
    rayId=$(echo "$line" | jq -r '.Event.RayID')
    echo "------ $rayId ------"
    echo "$line" | jq '.Logs[].Message[]' | sed 's/\\"/"/g' 
    echo -e "\n\n"
  done
