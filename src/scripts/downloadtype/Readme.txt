1、config文件中有一个全局的选项config_downloadtype=(on/off)  开启过滤或者关闭

2、config文件中保存每一条规则description#state#ip#type#ulog#weektime#daytime

	desctription:对于该规则的描述
	state：该条规则是否开启或关闭（on/off）
	ip：该条规则适用的ip范围{ip \ ip1-ip2} 不选代表所有IP
	type：该规则过滤的下载类型(在pat目录下的类型 用逗号分开)
	ulog：该条规则是否进行日志记录(Y/N)
	weektime：是否设置该规则每周的某些时间有效（一周的七天） 不选代表所有时间
	daytime：设置该规则每天的有效时间（每天的时间段） 不选代表所有时间
	
‘*’号代表该选项不选