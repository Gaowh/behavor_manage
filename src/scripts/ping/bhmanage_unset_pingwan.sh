#!/bin/sh

res=`iptables -t filter -L INPUT --line-numbers | grep icmp | grep echo-request | awk '{print $1}'`
if [ -n "$res" ] ; then
	iptables -t filter -D INPUT $res
fi
