#!/usr/bin/bash

UNICORN_ARCHS="arm aarch64" \
UNICORN_STATIC="yes" \
UNICORN_SHARED="no" \
UNICORN_QEMU_FLAGS="--static" \
bash ./make.sh cross-win64
