#! /bin/bash
set -eu

DOCKER_IMAGE=$1
NETWORK_NAME=$2
ID=$3
CMD=$4

NAME=test_container_$ID

echo "starting test client container with CMD=$CMD"
# run the test container on the local network
docker run -t --rm \
	-v "$GOPATH/src/my-tendermint/tendermint/test/p2p/:/go/src/my-tendermint/tendermint/test/p2p" \
	--net="$NETWORK_NAME" \
	--ip=$(test/p2p/ip.sh "-1") \
	--name "$NAME" \
	--entrypoint bash \
	"$DOCKER_IMAGE" $CMD
