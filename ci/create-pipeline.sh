#!/bin/bash

set -e
set -x

PIPELINE=create-boshrelease-le-responder
TARGET=${TARGET:-local}

fly validate-pipeline --config pipeline.yml

fly --target ${TARGET} set-pipeline --config pipeline.yml --pipeline "${PIPELINE}" -n

# Check all resources for errors
RESOURCES="$(fly -t "${TARGET}" get-pipeline -p "${PIPELINE}" | yq -r '.resources[].name')"
for RESOURCE in $RESOURCES; do
  fly -t ${TARGET} check-resource --resource "${PIPELINE}/${RESOURCE}"
done

fly -t ${TARGET} unpause-pipeline -p create-boshrelease-le-responder
