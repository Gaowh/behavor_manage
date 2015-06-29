#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<sys/socket.h>
#include<curses.h>
#include<netinet/in.h>
#include<errno.h>
#include<signal.h>
#include<arpa/inet.h>
#include<sys/select.h>
#include<sys/time.h>
#include<sys/wait.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<linux/netlink.h>
#include<sys/un.h>
#include<pthread.h>
#include<sys/shm.h>
#include<sys/sem.h>
#include <linux/netfilter_ipv4/ipt_ULOG.h>

#ifndef NETLINK_NFLOG
#define NETLINK_NFLOG 5
#endif

#define NETLINK_GROUP 8
#define BUF_SIZE 4096

#define debug 1

#define QQ_ID 666
#define MAC_ID 667
#define ALI_ID 668
#define KEYWORD_ID 669
#define WMAIL_ID 670
#define DOWNLOAD_ID 671

#define MEM_ID 888
struct pretime{
	
	long tmqq;
	long tmali;
	long tmwmail;
	long tmkeyword;
	long tmmac;
	long tmdownload;
};

struct sem {
	
	int sem_id_qq;
	int sem_id_mac;
	int sem_id_ali;
	int sem_id_keyword;
	int sem_id_wmail;
	int sem_id_download;
};

#ifndef semun
union semun {
	
	int val;
	struct semid_ds *buf;
	unsigned short *array;
};

#endif
void sig_chld(int signo);

void parase_log(char *buf, int buflen, struct sem *mysem);

int do_log(char *buf, int buflen, char *log_dir);

int semaphore_p(int sem_id);

int semaphore_v(int sem_id);

int set_semvalue(int sem_id);

void del_semvalue(int sem_id);
