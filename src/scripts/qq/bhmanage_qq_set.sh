#!/bin/sh

flag=`grep config_qq= ./config | awk -F= '{print $2}'`
#echo $flag
if [ "$flag" == "off" ] ; then
	
	res=`iptables -L FORWARD | grep bhmanage_qqudp_chain`
	
	if [ -n "$res" ] ;then 
		iptables -t filter -D FORWARD -p tcp -m layer7 --l7proto qq -j bhmanage_qqtcp_chain
		iptables -t filter -D FORWARD -p udp -m layer7 --l7proto qq -j bhmanage_qqudp_chain

		iptables -F bhmanage_qqudp_chain
		iptables -F bhmanage_qqtcp_chain
		iptables -X bhmanage_qqudp_chain
		iptables -X bhmanage_qqtcp_chain
	fi
else

	set_ulog=`grep config_qq_ulog= ./config | awk -F= '{print $2}'`
	#echo "$set_ulog"
	#clear all the rules and reset it 
	echo $set_ulog
	res=`iptables -L FORWARD | grep bhmanage_qqudp_chain`
	if [ -n "$res" ] ; then
	
		iptables -F bhmanage_qqudp_chain
		iptables -F bhmanage_qqtcp_chain
	else
		
		iptables -t filter -N bhmanage_qqudp_chain
		iptables -t filter -N bhmanage_qqtcp_chain
		
		iptables -t filter -I FORWARD -p tcp -m layer7 --l7proto qq -j bhmanage_qqtcp_chain
		iptables -t filter -I FORWARD -p udp -m layer7 --l7proto qq -j bhmanage_qqudp_chain
	fi
	
	if [ ! -e /etc/l7-protocols/qq.pat ]; then 
		cp ./qq.pat /etc/l7-protocols/
	fi
	
	#BLACK means we will set blacklist
	if [ "$flag" == "BLACK" ] ; then

		#     default policy for qqblacklsit
		iptables -t filter -A bhmanage_qqudp_chain -j ACCEPT
		iptables -t filter -A bhmanage_qqtcp_chain -j ACCEPT

		for qqnum in `grep -v config_qq ./config` ; do 
			#echo "qq num is $qqnum"
			hexqq=`echo $qqnum | awk '{printf "%x", $0}'`  #translate qq number decimal to hex
			hexqq=`echo ${hexqq:0:8}`
			qqlen=${#hexqq}
			#echo $hexqq":"$qqlen

			case $qqlen in
			4)
				expression_udp="35&0xffff0000>>16=0x$hexqq"
				expression_tcp="49&0xffff0000>>16=0x$hexqq";;
			5)
				expression_udp="35&0xfffff000>>12=0x$hexqq"
				expression_tcp="49&0xfffff000>>12=0x$hexqq";;
			6) 	
				expression_udp="35&0xffffff00>>8=0x$hexqq"
				expression_tcp="49&0xffffff00>>8=0x$hexqq";;
			7)
				expression_udp="35&0xfffffff0>>4=0x$hexqq"
				expression_tcp="49&0xfffffff0>>4=0x$hexqq";;
			8)	
				expression_udp="35=0x$hexqq"		
				expression_tcp="49=0x$hexqq";;
			esac

					
			if [ "$set_ulog" == "Y" ] ; then

				iptables -t filter -I bhmanage_qqudp_chain 1 -m u32 --u32 "$expression_udp" -j DROP # SAY NO TO UDPQQ
				iptables -t filter -I bhmanage_qqtcp_chain 1 -m u32 --u32 "$expression_tcp" -j DROP # SAY NO TO TCPQQ
				
				iptables -t filter -I bhmanage_qqudp_chain 1 -m u32 --u32 "$expression_udp" -j ULOG --ulog-nlgroup 8 --ulog-cprange 100 --ulog-prefix "2qq$qqnum"
				iptables -t filter -I bhmanage_qqtcp_chain 1 -m u32 --u32 "$expression_tcp" -j ULOG --ulog-nlgroup 8 --ulog-cprange 100 --ulog-prefix "2qq$qqnum"

			
			else 
				
				iptables -t filter -I bhmanage_qqudp_chain 1 -m u32 --u32 "$expression_udp" -j DROP # SAY NO TO UDPQQ
				iptables -t filter -I bhmanage_qqtcp_chain 1 -m u32 --u32 "$expression_tcp" -j DROP # SAY NO TO TCPQQ

			fi


		done 
		
		
	#BLACK means we will set blacklist
	elif [ "$flag" == "WHITE" ] ; then

		iptables -t filter -A bhmanage_qqudp_chain -j DROP     #default policy for qq_whitelist_chain
		iptables -t filter -A bhmanage_qqtcp_chain -j DROP
		
		for qqnum in `grep -v config_qq ./config` ; do
			#echo "qqnum is $qqnum"
			hexqq=`echo $qqnum | awk '{printf "%x", $0}'`
			#echo "hexqq is $hexqq"
			hexqq=`echo ${hexqq:0:8}`
			#echo $hexqq
			qqlen=${#hexqq}

			case $qqlen in 
			4)
				expression_udp="35&0xffff0000>>16=0x$hexqq"
				expression_tcp="49&0xffff0000>>16=0x$hexqq";;
			5)
				expression_udp="35&0xfffff000>>12=0x$hexqq"
				expression_tcp="49&0xfffff000>>12=0x$hexqq";;
			6) 	
				expression_udp="35&0xffffff00>>8=0x$hexqq"
				expression_tcp="49&0xffffff00>>8=0x$hexqq";;
			7)
				expression_udp="35&0xfffffff0>>4=0x$hexqq"
				expression_tcp="49&0xfffffff0>>4=0x$hexqq";;
			8)	
				expression_udp="35=0x$hexqq"		
				expression_tcp="49=0x$hexqq";;

			esac
			
			if [ "$set_ulog" == "Y" ] ; then

				iptables -t filter -I bhmanage_qqudp_chain 1 -m u32 --u32 "$expression_udp" -j ACCEPT # SAY NO TO UDPQQ
				iptables -t filter -I bhmanage_qqtcp_chain 1 -m u32 --u32 "$expression_tcp" -j ACCEPT # SAY NO TO TCPQQ
				
				iptables -t filter -I bhmanage_qqudp_chain 1 -m u32 --u32 "$expression_udp" -j ULOG --ulog-nlgroup 8 --ulog-cprange 100 --ulog-prefix "2qq$qqnum"
				iptables -t filter -I bhmanage_qqtcp_chain 1 -m u32 --u32 "$expression_tcp" -j ULOG --ulog-nlgroup 8 --ulog-cprange 100 --ulog-prefix "2qq$qqnum"

			else 
			
				iptables -t filter -I bhmanage_qqudp_chain 1 -m u32 --u32 "$expression_udp" -j ACCEPT    #say yes to udp qq	
				iptables -t filter -I bhmanage_qqtcp_chain 1 -m u32 --u32 "$expression_tcp" -j ACCEPT    #say yes to tcp qq 
			
			fi
		done 
	fi
fi
















