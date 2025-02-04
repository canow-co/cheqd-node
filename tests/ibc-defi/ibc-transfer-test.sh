#!/bin/bash

set -euox pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

function info() {
    printf "${GREEN}[info] %s${NC}\n" "${1}"
}

function err() {
    printf "${RED}[err] %s${NC}\n" "${1}"
}

function assert_tx_successful() {
  RES="$1"

  if [[ $(echo "${RES}" | jq --raw-output '.code') == 0 ]]
  then
    info "tx successful"
  else
    err "non zero tx return code"
    exit 1
  fi
}

function assert_network_running() {
  RES="$1"
  LATEST_HEIGHT=$(echo "${RES}" | jq --raw-output '.SyncInfo.latest_block_height')
  info "latest height: ${LATEST_HEIGHT}"

  if [[ $LATEST_HEIGHT -gt 1 ]]
  then
      info "network is running"
  else
      err "network is not running"
      exit 1
  fi
}


info "Cleanup"
docker compose down --volumes --remove-orphans

info "Running cheqd network"
docker compose up -d cheqd
docker compose cp cheqd/cheqd-init.sh cheqd:/home/cheqd/cheqd-init.sh
docker compose exec cheqd bash /home/cheqd/cheqd-init.sh
docker compose exec -d cheqd cheqd-noded start

info "Running osmosis network"
docker compose up -d osmosis
docker compose cp osmosis/osmosis-init.sh osmosis:/home/osmosis/osmosis-init.sh
docker compose exec osmosis bash /home/osmosis/osmosis-init.sh
docker compose exec -d osmosis osmosisd start

info "Waiting for chains"
# TODO: Get rid of this
sleep 20

info "Checking statuses"
CHEQD_STATUS=$(docker compose exec cheqd cheqd-noded status 2>&1)
assert_network_running "${CHEQD_STATUS}"

OSMOSIS_STATUS=$(docker compose exec osmosis osmosisd status 2>&1)
assert_network_running "${OSMOSIS_STATUS}"


info "Create relayer user on cheqd"  # ---
CHEQD_RELAYER_KEY_NAME="cheqd-relayer"
CHEQD_RELAYER_ACCOUNT=$(docker compose exec cheqd cheqd-noded keys add ${CHEQD_RELAYER_KEY_NAME} --keyring-backend test --output json 2>&1)
CHEQD_RELAYER_ADDRESS=$(echo "${CHEQD_RELAYER_ACCOUNT}" | jq --raw-output '.address')
CHEQD_RELAYER_MNEMONIC=$(echo "${CHEQD_RELAYER_ACCOUNT}" | jq --raw-output '.mnemonic')

echo "${CHEQD_RELAYER_MNEMONIC}" > cheqd_relayer_mnemonic.txt

info "Send some tokens to it" # ---
RES=$(docker compose exec cheqd cheqd-noded tx bank send cheqd-user "${CHEQD_RELAYER_ADDRESS}" 1000000000000zarx --gas-prices 50zarx --chain-id cheqd -y --keyring-backend test)
assert_tx_successful "${RES}"

info "Create relayer user on osmosis" # ---
OSMOSIS_RELAYER_KEY_NAME="osmosis-relayer"
OSMOSIS_RELAYER_ACCOUNT=$(docker compose exec osmosis osmosisd keys add ${OSMOSIS_RELAYER_KEY_NAME} --output json --keyring-backend test 2>&1)
OSMOSIS_RELAYER_ADDRESS=$(echo "${OSMOSIS_RELAYER_ACCOUNT}" | jq --raw-output '.address')
OSMOSIS_RELAYER_MNEMONIC=$(echo "${OSMOSIS_RELAYER_ACCOUNT}" | jq --raw-output '.mnemonic')

echo "${OSMOSIS_RELAYER_MNEMONIC}" > osmo_relayer_mnemonic.txt

info "Send some tokens to it" # ---
RES=$(docker compose exec osmosis osmosisd tx bank send osmosis-user "${OSMOSIS_RELAYER_ADDRESS}" 10000000uosmo --chain-id osmosis -y --keyring-backend test --output json)
assert_tx_successful "${RES}"
sleep 10 # Wait for state


info "Import accounts in hermes" # ---
docker compose up -d hermes

# Create dirs for keys
docker compose exec --user root hermes mkdir -p /home/hermes/.hermes/keys/cheqd/keyring-test
docker compose exec --user root hermes mkdir -p /home/hermes/.hermes/keys/osmosis/keyring-test

# Hand over ownership to hermes user
docker compose exec --user root hermes chown -R hermes:hermes /home/hermes/.hermes/keys

# Copy keys
docker compose cp cheqd_relayer_mnemonic.txt hermes:/home/hermes
docker compose cp osmo_relayer_mnemonic.txt hermes:/home/hermes

# Import keys
docker compose exec hermes hermes keys add --chain cheqd --mnemonic-file cheqd_relayer_mnemonic.txt --key-name cheqd-key
docker compose exec hermes hermes keys add --chain osmosis --mnemonic-file osmo_relayer_mnemonic.txt --key-name osmosis-key

info "Open channel" # ---
docker compose exec hermes hermes create channel --a-chain cheqd --b-chain osmosis --a-port transfer --b-port transfer --new-client-connection

info "Start hermes" # ---
docker compose exec -d hermes hermes start


info "Get balances" # ---
CHEQD_USER_ADDRESS=$(docker compose exec cheqd cheqd-noded keys show --address cheqd-user --keyring-backend test | sed 's/\r//g')
OSMOSIS_USER_ADDRESS=$(docker compose exec osmosis osmosisd keys show --address osmosis-user --keyring-backend test | sed 's/\r//g')

CHEQD_BALANCE_1=$(docker compose exec cheqd cheqd-noded query bank balances "$CHEQD_USER_ADDRESS" --output json)
docker compose exec osmosis osmosisd query bank balances "$OSMOSIS_USER_ADDRESS"

info "Transfer cheqd -> osmosis" # ---
PORT="transfer"
CHANNEL="channel-0"
docker compose exec cheqd cheqd-noded tx ibc-transfer transfer $PORT $CHANNEL "$OSMOSIS_USER_ADDRESS" 10000000000zarx --from cheqd-user --chain-id cheqd --gas-prices 50zarx --keyring-backend test -y
sleep 30 # Wait for relayer

info "Get balances" # ---
CHEQD_BALANCE_2=$(docker compose exec cheqd cheqd-noded query bank balances "$CHEQD_USER_ADDRESS" --output json)
BALANCES=$(docker compose exec osmosis osmosisd query bank balances "$OSMOSIS_USER_ADDRESS" --output json)

info "Denom trace" # ---
DENOM=$(echo "$BALANCES" | jq --raw-output '.balances[0].denom')
DENOM_CUT=$(echo "$DENOM" | cut -c 5-)
docker compose exec osmosis osmosisd query ibc-transfer denom-trace "$DENOM_CUT"

info "Transfer osmosis -> cheqd" # ---
PORT="transfer"
CHANNEL="channel-0"
docker compose exec osmosis osmosisd tx ibc-transfer transfer $PORT $CHANNEL "$CHEQD_USER_ADDRESS" 10000000000"${DENOM}" --from osmosis-user --chain-id osmosis --keyring-backend test -y
sleep 30 # Wait for relayer

info "Get balances" # ---
CHEQD_BALANCE_3=$(docker compose exec cheqd cheqd-noded query bank balances "$CHEQD_USER_ADDRESS" --output json)
docker compose exec osmosis osmosisd query bank balances "$OSMOSIS_USER_ADDRESS"

CHEQD_BALANCE_1=$(echo "$CHEQD_BALANCE_1" | jq --raw-output '.balances[0].amount')
CHEQD_BALANCE_2=$(echo "$CHEQD_BALANCE_2" | jq --raw-output '.balances[0].amount')
CHEQD_BALANCE_3=$(echo "$CHEQD_BALANCE_3" | jq --raw-output '.balances[0].amount')

info "Assert balances" # ---
if [[ $CHEQD_BALANCE_2 < $CHEQD_BALANCE_1 ]]
then
  info "cheqd -> osmosis transfer is successful"
else
  err "cheqd -> osmosis transfer error"
  exit 1
fi

if [[ $CHEQD_BALANCE_3 > $CHEQD_BALANCE_2 ]]
then
  info "osmosis -> cheqd transfer is successful"
else
  err "osmosis -> cheqd transfer error"
  exit 1
fi

if [[ $CHEQD_BALANCE_3 < $CHEQD_BALANCE_1 ]]
then
  info "fee processed successfully"
else
  err "fee error"
  exit 1
fi

info "Tear down" # ---
docker compose down --timeout 20