#!/bin/sh




flag=`cat ./config | grep config_aliww= | awk -F= '{print $2}'`
if [ "$flag" == "off" ] ; then 

	res=`iptables -L FORWARD | grep bhmanage_aliset_chain`

	if [ -n "$res" ] ; then
		iptables -t filter -D FORWARD  -m string --string "cntaobao" --algo bm -j bhmanage_aliset_chain 
		iptables -t filter -F bhmanage_aliset_chain
		iptables -t filter -X bhmanage_aliset_chain
	fi

else
	res=`iptables -L FORWARD | grep bhmanage_aliset_chain`
	if [ -n "$res" ] ; then
		
		iptables -t filter -F bhmanage_aliset_chain
	else
		iptables -t filter -N bhmanage_aliset_chain 
		iptables -t filter -I FORWARD  -m string --string "cntaobao" --algo bm -j bhmanage_aliset_chain 
	fi
	
	set_ulog=`cat ./config | grep config_aliww_ulog= | awk -F= '{print $2}'`
	echo "set_ulog: "$set_ulog
	#BLACK means we will set blacklist
	echo "flag: "$flag
	if [ "$flag" == "BLACK" ] ; then
		echo black	
		# default policy for bhmanage_aliset_chain
		iptables -t filter -A bhmanage_aliset_chain -j RETURN

		for alinum in `grep -v config_aliww ./config` ; do 
			echo "alinum: "$alinum
			if [ "$set_ulog" == "Y" ] ; then 
					iptables -t filter -I bhmanage_aliset_chain -m string --string "cntaobao$alinum" --algo bm -j DROP
				
				#touch /etc/l7-protocols/ali_$alinum.pat
				#echo "ali_$alinum" >> /etc/l7-protocols/ali_$alinum.pat
				#echo "cntaobao$alinum" >> /etc/l7-protocols/ali_$alinum.pat
				
				#iptables -t filter -I bhmanage_aliset_chain -m layer7 --l7proto ali_$alinum -j ULOG --ulog-nlgroup 8 --ulog-cprange 100 --ulog-prefix "3ali$alinum"
				iptables -t filter -I bhmanage_aliset_chain -m string --string "cntaobao$alinum" --algo bm -j ULOG --ulog-nlgroup 8 --ulog-cprange 100 --ulog-prefix "3ali$alinum"

				
			else 
				iptables -t filter -I bhmanage_aliset_chain -m string --string "cntaobao$alinum" --algo bm -j DROP
			fi
		done 

	#WHITE means we will set whitelist 	
	elif [ "$flag" == "WHITE" ] ; then
		
		#default policy for bhmanage_aliset_chain
		iptables -t filter -A bhmanage_aliset_chain -j DROP
		for alinum in `grep -v config_aliww ./config` ; do
		
			if [ "$set_ulog" == "Y" ] ; then
			
				iptables -t filter -I bhmanage_aliset_chain -m string --string "cntaobao$alinum" --algo bm -j RETURN 
				
				#touch /etc/l7-protocols/ali_$alinum.pat
				#echo "ali_$alinum" >> /etc/l7-protocols/ali_$alinum.pat
				#echo "cntaobao$alinum" >> /etc/l7-protocols/ali_$alinum.pat
				
				#iptables -t filter -I bhmanage_aliset_chain -m layer7 --l7proto ali_$alinum -j ULOG --ulog-nlgroup 8 --ulog-cprange 100 --ulog-prefix "3ali$alinum"
			
				iptables -t filter -I bhmanage_aliset_chain -m string --string "cntaobao$alinum" --algo bm -j ULOG --ulog-nlgroup 8 --ulog-cprange 100 --ulog-prefix "3ali$alinum"
			else
				
				iptables -t filter -I bhmanage_aliset_chain -m string --string "cntaobao$alinum" --algo bm -j RETURN
			
			fi
			
		done 
	fi
fi














