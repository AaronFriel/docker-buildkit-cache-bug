#!/usr/bin/env bash
set -euo pipefail

# set to true to see output from build and push
VERBOSE=false
IMAGE_NAME="afriel/test-caching:latest"
ITERATIONS=6

REDIRECT="/dev/null"
if $VERBOSE; then REDIRECT="/dev/stdout"; fi

GOWORK=off go build -o ./bin/main ./main.go

docker pull node:lts-alpine
for i in $(seq 1 "${ITERATIONS}")
do
  docker image rm "${IMAGE_NAME}" > "${REDIRECT}" || true
  docker image prune -f > "${REDIRECT}"
  docker builder prune -af > "${REDIRECT}"
  echo "1.${i}" > ./app/version.txt
  echo "Iteration ${i}"
  time ./bin/main "${IMAGE_NAME}" ./app > "${REDIRECT}"
done
