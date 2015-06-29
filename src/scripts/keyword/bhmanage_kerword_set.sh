#!/bin/sh

flag=`grep config_keyword= ./config | awk -F= '{print $2}'`
if [ "$flag" == "off" ] ; then
	
	res=`iptables -L FORWARD | grep bhmanage_keyword_chain`
	if [ -n "$res" ] ; then 
		iptables -t filter -D FORWARD -m layer7 --l7proto webkey -j bhmanage_keyword_chain
		iptables -F bhmanage_keyword_chain
		iptables -X bhmanage_keyword_chain
	fi
	
	if [ -e /etc/l7-protocols/webkey.pat ] ;then

		rm -rf /etc/l7-protocols/webkey.pat
	fi 
else
	#if user's set has changed , empty the bhmanage_keyword_chain and reset it with new set option
	res=`iptables -L FORWARD | grep bhmanage_keyword_chain`
	if [ -n "$res" ] ; then 
		iptables -F bhmanage_keyword_chain
	else
		iptables -t filter -N bhmanage_keyword_chain
		iptables -t filter -I FORWARD -m layer7 --l7proto webkey -j bhmanage_keyword_chain
	fi
	
	if [ ! -e /etc/l7-protocols/webkey.pat ] ; then
		cp ./webkey.pat /etc/l7-protocols/
	fi

	iptables -A bhmanage_keyword_chain -j RETURN

	set_ulog=`grep config_keyword_ulog= ./config | awk -F= '{print $2}'`
	#set the rules in bhmanage_keyword_chain
	#file in/in2 keep  the words that forbidden to search 
	#in keep the ANSI code and in2 keep the UTF-8 code
	i=1

	while read userin ; do

		u8code=''
		tmp=`echo $userin | od -a| sed 's/ /:/'| awk -F: '{print $2}'`
		
		for byte in `echo $tmp` ; do

			if [ $byte != "lf" ] ; then
				len=`echo ${#byte}`
				
				if [ $len -eq 2 ] ; then
					byte=`echo $byte | tr '[a-z]' '[A-Z]'`
					u8code="$u8code%$byte"
				else
					u8code="$u8code$byte"
				fi
				
			else
				break
			fi
			
		done
		
		if [ "$set_ulog" == "Y" ] ; then
			iptables -t filter -I bhmanage_keyword_chain 1 -m string --string "=$u8code" --algo bm -j DROP
			iptables -t filter -I bhmanage_keyword_chain 1 -m string --string "=$u8code" --algo bm -j ULOG --ulog-nlgroup 8 --ulog-cprange 100 --ulog-prefix "2kw$u8code"
		else
			iptables -t filter -I bhmanage_keyword_chain 1 -m string --string "=$u8code" --algo bm -j DROP
		fi
		
	done < ../in

	while read userin ; do
		u8code=''
		tmp=`echo $userin | od -a| sed 's/ /:/'| awk -F: '{print $2}'`
		
		for byte in `echo $tmp` ; do
			if [ $byte != "lf" ] ; then
				len=`echo ${#byte}`
				if [ $len -eq 2 ] ; then
					byte=`echo $byte | tr '[a-z]' '[A-Z]'`
					u8code="$u8code%$byte"
				else
					u8code="$u8code$byte"
				fi
			else
				break
			fi	
		done
		
		if [ "$set_ulog" == "Y" ] ; then
		
			iptables -t filter -I bhmanage_keyword_chain 1 -m string --string "=$u8code" --algo bm -j DROP
			iptables -t filter -I bhmanage_keyword_chain 1 -m string --string "=$u8code" --algo bm -j ULOG --ulog-nlgroup 8 --ulog-cprange 100 --ulog-prefix "2kw$u8code"
		else
			iptables -t filter -I bhmanage_keyword_chain 1 -m string --string "=$u8code" --algo bm -j DROP
		fi
	done < ../in2
fi


