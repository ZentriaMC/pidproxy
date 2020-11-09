#!/bin/sh
set -e

docker build \
	-t zentria/pidproxy \
	-t docker.zentria.ee/component/pidproxy \
	-f docker/Dockerfile .
