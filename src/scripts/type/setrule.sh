#!/bin/sh


flag=`cat ./config | grep config_downloadtype | awk -F= '{print $2}'`

if [ "$flag" == "off" ] ; then
	
	res=`iptables -L FORWARD | grep download_chain`
	
	if [ -n "$res" ] ; then
		iptables -t filter -F download_chain
		iptables -t filter -X download_chain
	fi
	
else

	res=`iptables -L FORWARD | grep download_chain`
	if [ -n "$res" ] ; then

		iptables -F download_chain	
	else 

		iptables -N download_chain
		iptables -I FORWARD -p tcp --dport 80 -j download_chain
	fi
	#rule present like this: description&state&ip&type&log&weektime&daytime
	#if option is NULL use '*' replace 
	for eachrule in `cat ./rules` ; do
		echo $eachrule
		STATE=`echo $eachrule | awk -F# '{print $2}'`
		IP=`echo $eachrule | awk -F# '{print $3}'`
		TYPE=`echo $eachrule | awk -F# '{print $4}'`
		LOG=`echo $eachrule | awk -F# '{print $5}'`
		WEEKTIME=`echo $eachrule | awk -F# '{print $6}'`
		DAYTIME=`echo $eachrule | awk -F# '{print $7}'`
		

		### get the ip or iprange of current rule
		if [  "$IP" != "*" ] ; then
			
			ip1=`echo $IP | awk -F- '{print $1}'`
			ip2=`echo $IP | awk -F- '{print $2}'`
			echo "ip1: "$ip1
			echo "ip2: "$ip2
			if [ -n "$ip2" ]; then
				setiprange="-m iprange --src-range $ip1-$ip2"
			else
				setiprange="-m iprange --src-range $ip1"
			fi
		fi
		echo $setiprange

		### get the weektime of current rule
		if [ "$WEEKTIME" != "*" ] ; then 
			setweektime="-m time --weekdays $WEEKTIME"
			extension_time="1";
		fi
		echo $setweektime

		### get the daytime of current rule
		if [ "$DAYTIME" != "*" ] ; then
			echo $DAYTIME
			daytimestart=`echo $DAYTIME | awk -F- '{print $1}'`
			daytimeend=`echo $DAYTIME | awk -F- '{print $2}'`
			if [ "$extension_time" == "1" ] ; then
				setdaytime="--timestart $daytimestart --timestop $daytimeend"
			else
				setdaytime="-m time --timestart $daytimestart --timestop $daytimeend"
			fi
		fi
		echo $setdaytime
		
		echo "$STATE"
		if [  "$STATE" == "ON" ] ; then
			
			onetype=`echo $TYPE | awk -F, '{print $1}'`
			TYPE=`echo $TYPE | sed 's/,/-/'`
			TYPE=`echo $TYPE | awk -F- '{print $2}'`
			
			while [ -n "$onetype" ] ; do
				
				if [ ! -e /etc/l7-protocols/"$onetype".pat ] ; then
					cp ./pat/"$onetype".pat /etc/l7-protocols/
				fi
				
				if [ "$LOG" == "Y" ] ; then 
					iptables -t filter -I download_chain $setiprange $setweektime $setdaytime -m layer7 --l7proto $onetype -j DROP
					iptables -t filter -I download_chain $setiprange $setweektime $setdaytime -m layer7 --l7proto $onetype -j ULOG --ulog-nlgroup 8 --ulog-prefix "8download$onetype" --ulog-cprange 20		
				else 
					iptables -t filter -I download_chain $setiprange $setweektime $setdaytime -m layer7 --l7proto $onetype -j DROP
				fi
				
				onetype=`echo $TYPE | awk -F, '{print $1}'`
				TYPE=`echo $TYPE | sed 's/,/-/'`
				TYPE=`echo $TYPE | awk -F- '{print $2}'`
				
			done
		fi 
	done 
fi























