#!/usr/bin/env bash

# Create the secrets shared across all pipelines in the cloud.gov.au apps team.
# Where possible, credentials are rotated each time this script is run.
# This might interfere with any CI jobs that are currently running.

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

echo "Ensuring you are logged in to credhub"
if ! https_proxy=socks5://localhost:8112 credhub find > /dev/null; then
  https_proxy=socks5://localhost:8112 credhub login --sso
fi

function assert_credhub_value() {
  KEY="$1"
  if ! https_proxy=socks5://localhost:8112 credhub get -n "/concourse/main/${KEY}" > /dev/null 2>&1 ; then
    echo "${KEY} not set in credhub. Add it to your environment (e.g. use .envrc) and re-run this script"
    exit 1
  fi
}

# Add an ssh deploy key to a github repo, and save it to credhub
function do_github_deploy_key() {
  ORG_REPO="$1"
  CREDHUB_KEY_NAME="$2"

  # You'll need a github token from https://github.com/settings/tokens
  : "${GITHUB_USER:?Need to set GITHUB_USER}"
  : "${GITHUB_PERSONAL_ACCESS_TOKEN:?Need to set GITHUB_PERSONAL_ACCESS_TOKEN}"
  CREDS="${GITHUB_USER}:${GITHUB_PERSONAL_ACCESS_TOKEN}"
  URL=https://api.github.com
  KEY_NAME=concourse
  
  DEPLOY_KEY_IDS="$(curl -s -u $CREDS $URL/repos/${ORG_REPO}/keys | jq -r .[].id)"

  # Delete old key if we find it
  for deploy_key_id in $DEPLOY_KEY_IDS; do
    deploy_key_title="$(curl -u $CREDS $URL/repos/${ORG_REPO}/keys/${deploy_key_id} | jq -r .title)"
    if [[ $deploy_key_title == ${KEY_NAME} ]]; then
      curl \
        -s \
        -X DELETE \
        -u $CREDS \
        $URL/repos/${ORG_REPO}/keys/${deploy_key_id}
    fi
  done

  #Create new key
  rm -f ./secret-deploy-key*
  ssh-keygen -t rsa -C "${KEY_NAME}" -b 4096 -f secret-deploy-key -N '' >&2
  DEPLOY_KEY="$(cat ./secret-deploy-key)"
  https_proxy=socks5://localhost:8112 credhub set -n "/concourse/main/${CREDHUB_KEY_NAME}" --type ssh --private "$DEPLOY_KEY"

  DEPLOY_KEY_PUB="$(cat ./secret-deploy-key.pub)"
  rm -f ./secret-deploy-key*
  curl \
    -s \
    -u $CREDS \
    -H "Content-Type: application/json" \
    -d@- \
    $URL/repos/${ORG_REPO}/keys >&2 <<EOF
    {
      "title": "${KEY_NAME}",
      "key":"${DEPLOY_KEY_PUB}",
      "read_only": false
    }
EOF
}

do_github_deploy_key "govau/le-responder" "create-boshrelease-le-responder/git_private_key"
