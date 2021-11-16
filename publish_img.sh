#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

REPO=andrewgaul/s3proxy

docker login -u "$DOCKER_USER" -p "$DOCKER_PASS" docker.io
docker buildx build --platform linux/amd64 -t $REPO:latest .

if [[ "$GITHUB_EVENT_NAME" == "push" && $GITHUB_REF == refs/heads/master ]]; then
  docker tag $REPO:latest $REPO:${GITHUB_SHA::8}
  docker push --all-tags $REPO
elif [[ "$GITHUB_EVENT_NAME" == "create" && $GITHUB_REF == refs/tags/* ]]; then
  docker tag $REPO:latest $REPO:${GITHUB_REF#refs/tags/}
  docker push --all-tags $REPO
fi
