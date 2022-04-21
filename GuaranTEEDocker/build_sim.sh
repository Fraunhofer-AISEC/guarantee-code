#!/bin/bash

DOCKER_BUILDKIT=1 docker build --target=sign-srv-sim -t sign-srv-sim .
