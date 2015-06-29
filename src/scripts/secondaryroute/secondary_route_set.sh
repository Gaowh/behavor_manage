#!/bin/sh

iptables -t mangle -I PREROUTING -i eth0.2 -j TTL --ttl-set 2
