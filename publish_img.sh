#!/usr/bin/env bash

docker login -u "$DOCKER_USER" -p "$DOCKER_PASS"
docker buildx build --platform linux/amd64 -t $GITHUB_REPOSITORY:latest .

if [[ "$GITHUB_EVENT_NAME" == "push" && $GITHUB_REF == refs/heads/master ]]; then
  docker tag $GITHUB_REPOSITORY:latest $GITHUB_REPOSITORY:${GITHUB_SHA::8}
  docker push --all-tags $GITHUB_REPOSITORY
elif [[ "$GITHUB_EVENT_NAME" == "create" && $GITHUB_REF == refs/tags/* ]]; then
  docker tag $GITHUB_REPOSITORY:latest $GITHUB_REPOSITORY:${GITHUB_REF#refs/tags/}
  docker push --all-tags $GITHUB_REPOSITORY
fi
