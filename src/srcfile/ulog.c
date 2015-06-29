#include"../include/ulog.h"
#include<linux/ip.h>


void  parase_log(char *buf, int buflen, struct sem *mysem)
{
	struct 	nlmsghdr *nlhdr;
	struct 	ulog_packet_msg *ulog_msg;
	struct 	iphdr *iph;
	struct 	in_addr	saddr;
	char 	*msg;
	char 	*prefix;
	FILE 	*fp;
	char 	*flag;
	char 	*logtype;
	long	timesec;
	

	nlhdr = (struct nlmsghdr *)buf;
	nlhdr++;

	ulog_msg = (struct ulog_packet_msg *)nlhdr;
	prefix = ulog_msg->prefix;
	printf("prefix: %s\n", prefix);

	timesec = ulog_msg->timestamp_sec;

	int typelen = (int)(prefix[0] - '0');
	
	/*get logtype*/
	flag = prefix;
	flag++;
	
	logtype = (char *)malloc(8);
	strncpy(logtype,flag,typelen);
	
	/*get msg in prefix*/
	flag += typelen;
	msg = (char *)malloc(20);
	strcpy(msg,flag);

	/*get user's ip*/
	iph = (struct iphdr *)ulog_msg->payload;
	saddr.s_addr = iph->saddr;

	time_t	now;
	struct	tm *timenow;
	char 	*mytime;
	
	/*get time of now*/
	mytime = (char *)malloc(20);
	time(&now);
	timenow = localtime(&now);
	mytime = asctime(timenow);

	char 	*log_msg;
	log_msg = (char *)malloc(100);
	
	sprintf(log_msg,"%s+%s+%s+%s",logtype,msg,inet_ntoa(saddr),mytime);
	
	int len = strlen(log_msg);
	log_msg[len-1] == '\0';
	
	long 	addtime;

	int 	shmid;
	struct 	pretime *ptime;
	void 	*shared_mem;

	if(strncmp(logtype,"qq",2) == 0){
		
		if(!semaphore_p(mysem->sem_id_qq)) {
			
			fprintf(stderr,"semaphore_p error: %s\n",strerror(errno));
			exit(-1);
		}	
	
		if(debug) printf("get access\n");

		if((shmid =  shmget((key_t)888, sizeof(struct pretime), 0666 | IPC_CREAT)) == -1){
			
			fprintf(stderr,"shmget error: %s\n",strerror(errno));
			
			if(!semaphore_v(mysem->sem_id_qq)) {
				
				set_semvalue(mysem->sem_id_qq);
			}
			exit(-1);
		}

		shared_mem = shmat(shmid, (void *)0, 0) ;
		ptime = (struct pretime *)shared_mem;

		if(debug) printf("nowtime: %ld pretime: %ld\n",timesec, ptime->tmqq);
		
		addtime = timesec - ptime->tmqq;	
		ptime->tmqq = timesec;
		
		if(debug) printf("addtime: %ld\n",addtime);
		if(addtime > 5){
			
			do_log(log_msg,strlen(log_msg),"/bh_manage/logfile/qq_log");
		}
		
		if(!semaphore_v(mysem->sem_id_qq)) {
			
			set_semvalue(mysem->sem_id_qq);
		}
		if(debug) printf("lost access\n\n");
	}

	else if(strncmp(logtype,"ali",3) == 0){
	
		if(!semaphore_p(mysem->sem_id_ali)){
		
			fprintf(stderr,"semaphore_p error: %s\n",strerror(errno));
			exit(-1);
		}

		if((shmid = shmget((key_t)888, sizeof(struct pretime), 0666 | IPC_CREAT)) == -1){
			
			fprintf(stderr,"shmget error: %s\n",strerror(errno));
			
			if(!semaphore_v(mysem->sem_id_ali)){
				
				set_semvalue(mysem->sem_id_ali);
			}
			exit(-1);
		}
	
		shared_mem = shmat(shmid, (void *)0, 0);
		ptime = (struct pretime *)shared_mem;

		addtime = timesec - ptime->tmali;
		ptime->tmali = timesec;

		if(addtime > 5){
			
			do_log(log_msg,strlen(log_msg),"/bh_manage/logfile/ali_log");
		}

		if(!semaphore_v(mysem->sem_id_ali))  set_semvalue(mysem->sem_id_ali);
	}

	else if(strncmp(logtype, "mac", 3) == 0){
		
		if(!semaphore_p(mysem->sem_id_mac)) {
		
			fprintf(stderr, "semaphore_p error: %s\n",strerror(errno));
			exit(-1);
		}	
		
		if((shmid =  shmget((key_t)888, sizeof(struct pretime), 0666 | IPC_CREAT)) == -1){
			
			fprintf(stderr,"shmget error: %s\n",strerror(errno));
			
			if(!semaphore_v(mysem->sem_id_qq)) set_semvalue(mysem->sem_id_mac);
			exit(-1);
		}

		shared_mem = shmat(shmid, (void *)0, 0) ;
		ptime = (struct pretime *)shared_mem;

		addtime = timesec - ptime->tmmac;	
		ptime->tmmac = timesec;
		
		if(addtime > 5){
			
			do_log(log_msg,strlen(log_msg),"/bh_manage/logfile/mac_log");
		}
		if(!semaphore_v(mysem->sem_id_mac)) set_semvalue(mysem->sem_id_mac);
	}

	else if(strncmp(logtype,"kw",2) == 0){
		
		if(!semaphore_p(mysem->sem_id_keyword)) {
			
			fprintf(stderr,"semaphore_p error: %s\n",strerror(errno));
			exit(-1);
		}	
		
		if((shmid =  shmget((key_t)888, sizeof(struct pretime), 0666 | IPC_CREAT)) == -1){
			
			fprintf(stderr,"shmget error: %s\n",strerror(errno));
			
			if(!semaphore_v(mysem->sem_id_keyword)) set_semvalue(mysem->sem_id_keyword);
			exit(-1);
		}

		shared_mem = shmat(shmid, (void *)0, 0) ;
		ptime = (struct pretime *)shared_mem;

		addtime = timesec - ptime->tmkeyword;	
		ptime->tmkeyword = timesec;
		
		if(addtime > 5){
			
			do_log(log_msg,strlen(log_msg),"/bh_manage/logfile/keyword_log");
		}
		
		if(!semaphore_v(mysem->sem_id_keyword))  set_semvalue(mysem->sem_id_keyword);
	}

	else if(strncmp(logtype,"wbmail",6) == 0){
		

		if(!semaphore_p(mysem->sem_id_wmail)) exit(-1);	
		
		if((shmid =  shmget((key_t)888, sizeof(struct pretime), 0666 | IPC_CREAT)) == -1){
			
			fprintf(stderr,"shmget error: %s\n",strerror(errno));
			
			if(!semaphore_v(mysem->sem_id_wmail)) set_semvalue(mysem->sem_id_wmail);
			
			exit(-1);
		}

		shared_mem = shmat(shmid, (void *)0, 0) ;
		ptime = (struct pretime *)shared_mem;

		addtime = timesec - ptime->tmwmail;	
		ptime->tmwmail = timesec;
		
		if(addtime > 5){
			
			do_log(log_msg,strlen(log_msg),"/bh_manage/logfile/webmail_log");
		}
		
		if(!semaphore_v(mysem->sem_id_wmail)) set_semvalue(mysem->sem_id_wmail);
	}
	
	else if(strncmp(logtype,"download",8) == 0){
	
		if(! semaphore_p(mysem->sem_id_download)) exit(-1);

		if((shmid = shmget((key_t)888,sizeof(struct pretime), 0666 | IPC_CREAT)) == -1){
		
			fprintf(stderr,"shmegt error: %s\n",strerror(errno));
			
			if(! semaphore_v(mysem->sem_id_download)) set_semvalue(mysem->sem_id_download);

			exit(-1);
		}

		shared_mem = shmat(shmid, (void *)0,0);
		ptime = (struct pretime *)shared_mem;

		addtime = timesec-ptime->tmdownload;
		ptime->tmdownload = timesec;

		if(addtime > 5){
		
			do_log(log_msg, strlen(log_msg), "/bh_manage/logfile/download_log");
		}

		if(! semaphore_v(mysem->sem_id_download)) set_semvalue(mysem->sem_id_download);
	}
	else{
		printf("format error!\n");
		exit(-1);
	}

	free(logtype);
	free(log_msg);
	free(msg);
	
	exit(0);
}

void sig_chld(int signo)
{
	pid_t 	pid;
	int 	stat;

	while((pid = waitpid(-1, &stat, WNOHANG)) > 0){
		
	}
	return ; 
}


int do_log(char *buf, int buflen, char *log_dir){
	
	FILE *fp;
	int nres;
	printf("dir: %s\n",log_dir);	
	fp = fopen(log_dir, "a+");
	
	if(fp == NULL){
		fprintf(stderr,"open logfile error:%s\n",strerror(errno));
		return -1;
	}

	int fd = fileno(fp);
	nres = write(fd,buf,buflen);
	
	if(nres != buflen){
	
		fprintf(stderr,"write error:%s\n",strerror(errno));
		return -1;
	}

	fclose(fp);
	return 1;
}


int semaphore_p(int sem_id){
	
	struct sembuf sem_b;

	sem_b.sem_num = 0;
	sem_b.sem_op = -1;
	sem_b.sem_flg = SEM_UNDO;

	if(semop(sem_id, &sem_b, 1) == -1) {
		
		fprintf(stderr,"set semop error: %s\n", strerror(errno));
		return 0;
	}
	
	return 1;

}

int semaphore_v(int sem_id){

	struct sembuf sem_b;

	sem_b.sem_num = 0;
	sem_b.sem_op = 1;
	sem_b.sem_flg = SEM_UNDO;

	if(semop(sem_id, &sem_b, 1) == -1){
		
		fprintf(stderr,"set semop  error: %s\n",strerror(errno));
		return 0;
	}

	return 1;
}


int set_semvalue(int sem_id){

	union semun sem_un;

	sem_un.val = 1;
	
	if(semctl(sem_id, 0, SETVAL, sem_un) == -1){
		
		fprintf(stderr,"set semctl error: %s\n", strerror(errno));
		return 0;	
	}
	return 1;
}


void del_semvalue(int sem_id){

	union semun sem_un;

	if(semctl(sem_id, 0 , IPC_RMID, sem_un) == -1){
		
		fprintf(stderr,"failed to delete semaphore\n");

	}
}
