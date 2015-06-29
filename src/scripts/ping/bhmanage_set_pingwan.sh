#!/bin/sh

wan_ip=`ifconfig eth0.2 | sed -n 2p | awk '{print $2}' | awk -F: '{print $2}'`
iptables -t filter -I INPUT -p icmp --icmp-type 8 -d $wan_ip -j DROP
