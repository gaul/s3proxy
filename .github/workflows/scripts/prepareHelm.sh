#!/usr/bin/env bash
#
yq -i ".version = \"${1}\" | .appVersion style=\"double\" | .appVersion = \"${1}\"" chart/Chart.yaml
helm package chart