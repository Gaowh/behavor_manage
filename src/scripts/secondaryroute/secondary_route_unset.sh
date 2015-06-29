#!/bin/sh

iptables -t mangle -D PREROUTIGN -i eth0.2 -j TTL --ttl-set 2
