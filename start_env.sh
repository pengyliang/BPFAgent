#!/bin/bash

VERSION=$1

sudo lvh run --image env/${VERSION}/ebpf.qcow2 --kernel env/${VERSION}/vmlinuz-${VERSION} --host-mount .