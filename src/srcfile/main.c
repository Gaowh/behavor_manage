#include"../include/ulog.h"


void main()
{
	struct	sockaddr_nl local_addr;
	struct  sockaddr_nl kpeer_addr;
	char 	buf[BUF_SIZE];
	int	nf_sock;
	int 	addrlen;
	int 	res;	
	struct 	sem mysem;
	int 	shmid;
	void 	*share_mem;
	struct 	pretime *ptime;

	int group = NETLINK_GROUP;

	if((shmid = shmget((key_t)MEM_ID, sizeof(struct pretime), 0666 | IPC_CREAT)) == -1){
	
		fprintf(stderr,"shmget error: %s\n",strerror(errno));
		exit(EXIT_FAILURE);
	}

	share_mem = shmat(shmid, (void *)0, 0);
	ptime = (struct pretime *)share_mem;

	ptime->tmqq = 0;
	ptime->tmali = 0;
	ptime->tmwmail = 0;
	ptime->tmmac = 0;
	ptime->tmkeyword = 0;
	ptime->tmdownload = 0;

	mysem.sem_id_qq = semget((key_t)QQ_ID,1,0666 | IPC_CREAT);
	mysem.sem_id_mac = semget((key_t)MAC_ID, 1, 0666 | IPC_CREAT);
	mysem.sem_id_ali = semget((key_t)ALI_ID, 1, 0666 | IPC_CREAT);
	mysem.sem_id_keyword = semget((key_t)KEYWORD_ID, 1, 0666 | IPC_CREAT);
	mysem.sem_id_wmail = semget((key_t)WMAIL_ID, 1, 0666 | IPC_CREAT);
	mysem.sem_id_download = semget((key_t)DOWNLOAD_ID,1,0666 | IPC_CREAT);

	set_semvalue(mysem.sem_id_qq);
	set_semvalue(mysem.sem_id_mac);
	set_semvalue(mysem.sem_id_ali);
	set_semvalue(mysem.sem_id_keyword);
	set_semvalue(mysem.sem_id_wmail);
	set_semvalue(mysem.sem_id_download);


	addrlen = sizeof(struct sockaddr_nl);
	
	nf_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_NFLOG);
	if(nf_sock < 0 ){
		fprintf(stderr,"socket error:%s\n",strerror(errno));
		exit(EXIT_FAILURE);
	}
	bzero(&local_addr,addrlen);
	bzero(&kpeer_addr,addrlen);

	local_addr.nl_family = AF_NETLINK;
	local_addr.nl_pid = getpid();
	local_addr.nl_groups = 6;

	if(bind(nf_sock, (struct sockaddr *)&local_addr, sizeof(local_addr)) != 0){
		fprintf(stderr,"bind error: %s\n",strerror(errno));
		exit(EXIT_FAILURE);
	}

	res = setsockopt(nf_sock, 270, NETLINK_ADD_MEMBERSHIP , &group, sizeof(group));
	if(res == -1){
		fprintf(stderr,"setsockopt error:%s...\n",strerror(errno));
		exit(EXIT_FAILURE);
	}

	while(1){
		res = recvfrom(nf_sock, buf, BUF_SIZE, 0, ( struct sockaddr *)&kpeer_addr, &addrlen);
		if(res < 0){
			fprintf(stderr,"recv from kernel error:%s...\n",strerror(errno));
			continue;
		}

		signal(SIGCHLD, sig_chld);

		if(fork() == 0) parase_log(buf,res,&mysem);
	}
}

