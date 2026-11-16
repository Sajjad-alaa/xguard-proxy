#!/bin/sh
CONFIG=/etc/xguard/proxy.toml

if [ ! -f "${CONFIG}" ]; then
    cp "${CONFIG}.sample" "${CONFIG}"
fi
