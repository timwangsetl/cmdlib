#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/stat.h>
#include <net/if.h>
#include <fcntl.h>
#include <sys/file.h>
#include <syslog.h>
#include <termios.h>

#include <arpa/inet.h>

#include "console.h"
#include "cmdparse.h"
#include "parameter.h"
#include "bcmutils.h"

#include "cli_trunk_func.h"

/*---------------------------------------------------load_balance--------------------------------------*/
int func_set_trunk_load_balance(char *mode)
{
	nvram_set("h_load_mode", mode);
	return CLI_SUCCESS;
}

/*---------------------------------------no trunk load balance-------------------------*/
int nfunc_trunk_load_balance(char *mode)
{
	nvram_set("h_load_mode", mode);
	return CLI_SUCCESS;
}

/*---------------------------------------no lacp mode-------------------------*/
int nfunc_lacp_interval_mode(void)
{
	FILE *fp;
	pid_t pid;
	union sigval mysigval;
	char lacp_buf[128]={'\0'};
	char *lacp_mode = nvram_safe_get("lacp_mode");
	
	if((fp = fopen("/var/run/lacp.pid","r"))!=NULL){
		while(fgets(lacp_buf, 128, fp)!=NULL){
			pid = (pid_t)atoi(lacp_buf);
			printf("pid = %d\n",atoi(lacp_buf));
		}
		fclose(fp);
	}

	mysigval.sival_int = 0;
	if(sigqueue(pid,SIGRTMIN,mysigval)<0)
		printf("Send signal to lacp fail!\n");
	
	nvram_set("lacp_mode", "0");
	free(lacp_mode);
}

/*---------------------------------------lacp mode select-------------------------*/
int func_lacp_interval_mode_select(int mode)
{
	FILE *fp;
	pid_t pid;
	union sigval mysigval;
	char lacp_buf[128]={'\0'};
	char *lacp_mode = nvram_safe_get("lacp_mode");
	char int_to_str[5]={'\0'};
	
	if((fp = fopen("/var/run/lacp.pid","r"))!=NULL){
		while(fgets(lacp_buf, 128, fp)!=NULL){
			pid = (pid_t)atoi(lacp_buf);
		}
		fclose(fp);
	}
	/*if mode is 1,means mode is fast.
	 *if mode is 0,means mode is normal.*/
	mysigval.sival_int = mode;
	if(sigqueue(pid,SIGRTMIN,mysigval)<0)
		printf("Send signal to lacp fail!\n"); 
	
	sprintf(int_to_str,"%d",mode);
	nvram_set("lacp_mode", int_to_str);
	free(lacp_mode);
}




















