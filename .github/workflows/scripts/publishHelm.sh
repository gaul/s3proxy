#!/usr/bin/env bash
set -ev
helm push $(ls ${GITHUB_REPOSITORY#*/}*.tgz) oci://ghcr.io/$GITHUB_REPOSITORY/charts
#
mkdir /tmp/gh-pages
wget https://${GITHUB_REPOSITORY_OWNER}.github.io/${GITHUB_REPOSITORY#*/}/index.yaml -P /tmp/
helm repo index . --url https://github.com/${GITHUB_REPOSITORY}/releases/download/$1 --merge /tmp/index.yaml
cp -f index.yaml /tmp/index.yaml
#
gh repo clone ${GITHUB_REPOSITORY} /tmp/gh-pages/
pushd /tmp/gh-pages
gh auth setup-git
git checkout gh-pages
cp -f /tmp/index.yaml .
git add index.yaml
git commit -m "chore(helm): Publish $1"
git push
#test3

