#!/bin/bash
. epid.config

DOCKER_BUILDKIT=1 docker build --target=sign-srv-hw \
                --build-arg SPID=$SPID --build-arg EPID_SUBSCRIPTION_KEY=$EPID_SUBSCRIPTION_KEY \
                --build-arg QUOTE_TYPE=$QUOTE_TYPE -t sign-srv-hw .
DOCKER_BUILDKIT=1 docker build --target=aesm \
                --build-arg SPID=$SPID --build-arg EPID_SUBSCRIPTION_KEY=$EPID_SUBSCRIPTION_KEY \
                --build-arg QUOTE_TYPE=$QUOTE_TYPE -t aesm .
DOCKER_BUILDKIT=1 docker build --target=attestation-client \
                --build-arg SPID=$SPID --build-arg EPID_SUBSCRIPTION_KEY=$EPID_SUBSCRIPTION_KEY \
                --build-arg QUOTE_TYPE=$QUOTE_TYPE -t attestation-client .

docker volume create --driver local --opt type=tmpfs --opt device=tmpfs --opt o=rw aesmd-sock
