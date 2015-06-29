#!/bin/sh

DEBUG=N;
FLAG=`cat ./config |grep config_mac= | awk -F= '{print $2}'`
ULOG=`cat ./config | grep config_mac_ulog= | awk -F= '{print $2}'`

#echo "$FLAG $ULOG"
#echo "get config"
#clear all the rules and reset it 
if [ "$FLAG" == "off" ]; then

	res=`iptables -L FORWARD | grep bhmanage_mac_chain`
	if [ -n "$res" ] ;then
		iptables -t filter -D FORWARD -s 192.168.1.0/24 -j bhmanage_mac_chain
		iptables -t filter -F bhmanage_mac_chain
		iptables -t filter -X bhmanage_mac_chain
	fi
else
	
	res=`iptables -L FORWARD | grep bhmanage_mac_chain`
	if [ -n "$res" ] ;then
	
		iptables -t filter -F bhmanage_mac_chain
	else
		iptables -t filter -N bhmanage_mac_chain
		iptables -t filter -I FORWARD -s 192.168.1.0/24 -j bhmanage_mac_chain
	fi
	
	#BLACK means we will set blacklist
	if [ "$FLAG" == "BLACK" ] ; then
		
		if [ "$DEBUG" == "Y" ] ;then
			echo "in black"
		fi
		#     default policy for qqblacklsit
		iptables -t filter -A bhmanage_mac_chain -j RETURN

		for mac in `grep -v config_mac ./config` ; do 
			if [ "$ULOG" == "Y" ] ; then
				if [ "$DEBUG" == "Y" ];then
					echo "do ulog"
				fi
				iptables -t filter -I bhmanage_mac_chain -m mac --mac-source $mac -j DROP
				iptables -t filter -I bhmanage_mac_chain -m mac --mac-source $mac -j ULOG --ulog-nlgroup 8 --ulog-cprang 20 --ulog-prefix "3mac$mac"
			
			else 
				iptables -t filter -I bhmanage_mac_chain -m mac --mac-source $mac -j DROP
			fi

		done 
		
	#WHITE means we will set whitelist
	elif [ "$FLAG" == "WHITE" ] ; then
		if [ "$DEBUG" == "Y" ] ;then
			echo "in white"
		fi
		iptables -t filter -A bhmanage_mac_chain -j DROP
		
		for mac in `grep -v config_mac ./config` ; do
			iptables -t filter -I bhmanage_mac_chain -m mac --mac-source $mac -j RETURN
		done 
	fi
fi
















