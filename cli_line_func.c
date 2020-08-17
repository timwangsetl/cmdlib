/**
 * console / line
 *
 * Arthor: Yezhong Li
 * date: 2012.3.31
 */

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
#include <sys/un.h>
#include <arpa/inet.h>

#include "console.h"
#include "cmdparse.h"
#include "parameter.h"

#include "cli_line_func.h"
#include "cli_clear_func.h"
#include "sk_define.h"

#ifdef CLI_AAA_MODULE

/* 
 * line login in nvram
 * format:
 * aaa_line_login = 1|<authentication_name>,<authorization_name>,<accout_name>;2|,,;3|,,;4|;  ... ;16|,,; 
 */

struct line_login {
	int id;						/* line id */
	char authx_name[MAX_ARGV_LEN];  /* authentication name */
	char authz_name[MAX_ARGV_LEN];  /* authorization name */
	char acct_name[MAX_ARGV_LEN];   /*  accout name */
};


static int get_line_login_mount(struct line_login *aaa_line, int count)
{
	char *aaa_line_login = nvram_safe_get("aaa_line_login");
	char *entry = aaa_line_login;
	char *buf;
	int i;
	if(strlen(aaa_line_login)< count){
		for (i = 0; i < count; i++) {
			strcpy(aaa_line[i].authx_name,"");
			strcpy(aaa_line[i].authz_name, "");
			strcpy(aaa_line[i].acct_name, "");
			aaa_line[i].id = i;
		}
	}else{
		for (i = 0; i < count; i++) {
			buf = strsep(&entry, ";");
			aaa_line[i].id = atoi(buf);
			strsep(&buf, "|");
			strcpy(aaa_line[i].authx_name, strsep(&buf, ","));//strcpy can cpy null pointer
			strcpy(aaa_line[i].authz_name, strsep(&buf, ","));
			strcpy(aaa_line[i].acct_name, strsep(&buf, ","));
		}
	}
	free(aaa_line_login);
	
	return 0;
}


static int set_line_login_mount(struct line_login *aaa_line, int count)
{
	char *aaa_line_login = calloc(16, sizeof(struct line_login));
	int i;

	if (aaa_line_login == NULL)
		return -1;

	for (i = 0; i < count; i++) {
		sprintf(aaa_line_login, "%s%d|%s,%s,%s;", 
				aaa_line_login, aaa_line[i].id, aaa_line[i].authx_name,
				aaa_line[i].authz_name, aaa_line[i].acct_name);
	}
	
	nvram_set("aaa_line_login", aaa_line_login);

	free(aaa_line_login);

	return 0;
}


int func_login_method_name(struct users *u) 
{
	char name[MAX_ARGV_LEN] = {'\0'};
	char method[MAX_ARGV_LEN] = {'\0'};
	struct line_login aaa_line[16];
	int line_id[2], i;

	cli_param_get_string(STATIC_PARAM, 0, name, u);

	/* get aaa method name, eg. authentication, authorzation, acct */
	cli_param_get_string(DYNAMIC_PARAM, 0, method, u);

	char *aaa_auth_login = nvram_safe_get("aaa_auth_login");
	char *aaa_authz_exec = nvram_safe_get("aaa_authz_exec");
	char *aaa_acct_exec = nvram_safe_get("aaa_acct_exec");

	if (*name != '\0') {
		strcat(name, "@");

		/* check "name" whether exist */
		if (!strncasecmp(method, "acc", 3)) {
			if (strstr(aaa_acct_exec, name) == NULL) {
				name[strlen(name) - 1] = '\0';
				vty_output("AAA: Warning accouting list \"%s\" "
						"is not defined for EXEC.\n", name);
				goto out;
			}
		} else if (!strncasecmp(method, "authe", 5)) {
			if (strstr(aaa_auth_login, name) == NULL) {
				name[strlen(name) - 1] = '\0';
				vty_output("AAA: Warning authentication list \"%s\" "
						"is not defined for LOGIN.\n", name);
				goto out;
			}
		} else {
			if (strstr(aaa_authz_exec, name) == NULL) {
				name[strlen(name) - 1] = '\0';
				vty_output("AAA: Warning authorization list \"%s\" "
						"is not defined for EXEC.\n", name);
				goto out;
			}
		}

		name[strlen(name) - 1] = '\0';
	}

	cli_param_get_int(DYNAMIC_PARAM, 0, &line_id[0], u);
	cli_param_get_int(DYNAMIC_PARAM, 1, &line_id[1], u);

	/* get line id */
	sscanf(u->promptbuf, "%d,%d", &line_id[0], &line_id[1]);

	memset(&aaa_line, '\0', sizeof(aaa_line));
	get_line_login_mount(aaa_line, 16);


	if (line_id[1] == 0) {
		/* single, line id */
		if (!strncasecmp(method, "acc", 3))
			strcpy(aaa_line[line_id[0]-1].acct_name, name);
		else if (!strncasecmp(method, "authe", 5))
			strcpy(aaa_line[line_id[0]-1].authx_name, name);
		else
			strcpy(aaa_line[line_id[0]-1].authz_name, name);
	} else {
		/* range, line id */
		for (i = line_id[0] - 1; i < line_id[1]; i++) {
			if (!strncasecmp(method, "acc", 3))
				strcpy(aaa_line[i].acct_name, name);
			else if (!strncasecmp(method, "authe", 5))
				strcpy(aaa_line[i].authx_name, name);
			else
				strcpy(aaa_line[i].authz_name, name);
		}
	}

	set_line_login_mount(aaa_line, 16);
	free(aaa_auth_login);
	free(aaa_authz_exec);
	free(aaa_acct_exec);

	return 0;

out:
	free(aaa_auth_login);
	free(aaa_authz_exec);
	free(aaa_acct_exec);
	return -1;
}


int nfunc_login_method(struct users *u) 
{
	char method[MAX_ARGV_LEN] = {'\0'};
	struct line_login aaa_line[16];
	int line_id[2], i;

	/* get aaa method name, eg. authentication, authorzation, acct */
	cli_param_get_string(DYNAMIC_PARAM, 0, method, u);

	memset(aaa_line, '\0', sizeof(aaa_line));
	get_line_login_mount(aaa_line, 16);
	
	/* get line id */
	sscanf(u->promptbuf, "%d,%d", &line_id[0], &line_id[1]);

	if (line_id[1] == 0) {
		/* single, line id */
		if (!strncasecmp(method, "acc", 3))
			aaa_line[line_id[0]-1].acct_name[0] = '\0';
		else if (!strncasecmp(method, "authe", 5))
			aaa_line[line_id[0]-1].authx_name[0] = '\0';
		else
			aaa_line[line_id[0]-1].authz_name[0] = '\0';
	} else { 		
		/* range, line id */
		for (i = line_id[0] - 1; i < line_id[1]; i++) {
			if (!strncasecmp(method, "acc", 3))
				aaa_line[i].acct_name[0] = '\0';
			else if (!strncasecmp(method, "authe", 5))
				aaa_line[i].authx_name[0] = '\0';
			else
				aaa_line[i].authz_name[0] = '\0';
		}
	}

	set_line_login_mount(aaa_line, 16);

	return 0;
}


/*
 *  Function : func_set_absolute_timeout
 *  Purpose:
 *     set absolute time out
 *  Parameters: 
 *  
 *  Returns:
 *
 *  Author  : wei.zhang
 *  Date    :2012/4/16
 */
int func_set_absolute_timeout(struct users *u, int line_id0, int line_id1, int absolute_time)
{
 	struct tm *p_show_time;
	int skfd;
	struct sockaddr_un server_sock_addr, client_sock_addr;
	IPC_SK tx, rx;
	int cnt = 0;
	fd_set rfds;
	int line[2] = {0, 0};
	char *nvram_data = NULL, *p1 = NULL, *p2 = NULL, i_to_char[8], buff[100];
	char client_path[30] = "";
	
	
	memset( client_path, 0, sizeof(client_path) );
	sprintf( client_path, "%s%d", SOCK_PATH_CLIENT, sta_info.nas_port );
	if (creat_sk_client(&skfd, &server_sock_addr, SOCK_PATH_SERVER, &client_sock_addr, client_path, 0)){
		return -1;
	}
	
	if( (line_id0 == 0) && (line_id1 == 0) ){ 
		sscanf(u->promptbuf, "%d,%d", &line[0], &line[1]);
	}
	else{
		line[0] = line_id0;
		line[1] = line_id1;
	}
	
	/*sending data initial*/
	for( cnt=0; cnt<MAX_VTY; cnt++){
		tx.acData[ 2*cnt ] = -1;
		tx.acData[ 2*cnt+1 ] = -1;
	}
	
	/*set parameter according user set*/
	if ( line[1] == 0 ){				/*set a single line vty*/
		tx.acData[0] = line[0];			/*vty line_id*/
		tx.acData[1] = absolute_time;
		nvram_data = nvram_safe_get("line_vty");
		
		memset( buff, 0, sizeof(buff) );
		memset( i_to_char, 0, sizeof(i_to_char) );

		sprintf( i_to_char, "%d", line[0] );
		strcat( i_to_char, ":" );
		p1 = strstr(nvram_data, i_to_char);
		if(p1 != NULL){
			p1 = strchr(p1, ':');
			p2 = strchr(p1, ';');
			memcpy(buff, nvram_data, p1-nvram_data+1);
		}else{
			if(strlen(nvram_data)>2)
				memcpy(buff, nvram_data, strlen(nvram_data));
			
			strcat(buff, i_to_char );
		}

		memset( i_to_char, 0, sizeof(i_to_char) );
		sprintf( i_to_char, "%d", absolute_time );
		strcat( buff, i_to_char );
		if(p2!= NULL)
			strcat( buff, p2 );
		else
			strcat( buff, ";" );
			
		nvram_set("line_vty", buff);
		free( nvram_data );
	}
	else{								/*set many line vty*/
		for( cnt=line[0]; cnt<=line[1]; cnt++ ){
			tx.acData[ 2*(cnt-line[0]) ] = cnt;
			tx.acData[ 2*(cnt-line[0])+1 ] = absolute_time;
			
			nvram_data = nvram_safe_get("line_vty");
			
			memset( buff, 0, sizeof(buff) );
			memset( i_to_char, 0, sizeof(i_to_char) );
			p2 = NULL;

			sprintf( i_to_char, "%d", cnt );
			strcat( i_to_char, ":" );
			p1 = strstr(nvram_data, i_to_char);
			if(p1 != NULL){
				p1 = strchr(p1, ':');
				p2 = strchr(p1, ';');
				memcpy( buff, nvram_data, p1-nvram_data+1);
			}else{
				if(strlen(nvram_data)>2)
					memcpy(buff, nvram_data, strlen(nvram_data));
				strcat(buff, i_to_char );
			}
			memset( i_to_char, 0, sizeof(i_to_char) );
			sprintf( i_to_char, "%d", absolute_time );
			strcat( buff, i_to_char );
			if(p2 != NULL)
				strcat( buff, p2 );
			else
				strcat( buff, ";" );

			nvram_set("line_vty", buff);
			free( nvram_data );
		}
	}
	
	/*prepare data for sending*/
	tx.stHead.enCmd = IPC_CMD_SET;
	tx.stHead.cOpt = 2;
	tx.stHead.cBack = IPC_SK_BACK;
		
	/*sending data to server*/	
	if(ipc_send(skfd, &tx, &server_sock_addr) == -1){
		unlink(client_sock_addr.sun_path);
		return -1;
	}

	unlink(client_sock_addr.sun_path);
 	
 	return 1;
}


/*
 *  Function : func_create_vty_users
 *  Purpose:
 *     check login_file if vty_first or vty_last > login user num
 *	then, create new vty line
 *  Parameters: 
 *  
 *  Returns:
 *	-1: no vty user has been created, n>=1 created user amount
 *  Author  : wei.zhang
 *  Date    :2012/4/16
 */
int func_create_vty_users(struct users *u, int vty_first, int vty_last)
{
	int skfd, fd, count;
	struct sockaddr_un server_sock_addr, client_sock_addr;
	IPC_SK tx, rx;
	fd_set rfds;
	struct flock lock;
	char buff[128], tmp[32];
	char client_path[30] = "";
	char *nvram_get_line_max_vty = NULL;
	
	nvram_get_line_max_vty = nvram_safe_get("line_max_vty");
	count = atoi(nvram_get_line_max_vty);
	free(nvram_get_line_max_vty);
	
	if ( (count < vty_first) && (vty_last == 0) ){
		tx.acData[0] = vty_first;
		tx.acData[1] = -1;
		memset(tmp, 0, sizeof(tmp));
		sprintf(tmp, "%d", vty_first);
		nvram_set("line_max_vty", tmp);
	}else if( count < vty_last ){
		tx.acData[0] = vty_last;
		tx.acData[1] = -1;
		memset(tmp, 0, sizeof(tmp));
		sprintf(tmp, "%d", vty_last);
		nvram_set("line_max_vty", tmp);
	}
	
	memset( client_path, 0, sizeof(client_path) );
	sprintf( client_path, "%s%d", SOCK_PATH_CLIENT, sta_info.nas_port );
	if (creat_sk_client(&skfd, &server_sock_addr, SOCK_PATH_SERVER, &client_sock_addr, SOCK_PATH_CLIENT, 0)){
		return -1;
	}
	/*prepare data for sending*/
	tx.stHead.enCmd = IPC_CMD_SET;
	tx.stHead.cOpt = 3;
	tx.stHead.cBack = IPC_SK_BACK;
	
	/*sending data to server*/	
	if(ipc_send(skfd, &tx, &server_sock_addr) == -1){
		
		unlink(client_sock_addr.sun_path);
		return -1;
	}
	unlink(client_sock_addr.sun_path);
}

/* copy eagles.zhou in utelnetd.c by wei.zhang for file lock */
static int setlock(int fd, int type){
	int count = 5;
	struct flock lock;

	/* Describe the lock we want */
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	while(count--) {
		lock.l_type   =   type;

		/* Set the lock and return to caller */
		if((fcntl(fd,F_SETLK,&lock))==0)
			return 0;

		sleep(1);
		
		//printf( "locking\n ");
	}

	return -1;
}
/* end */

/*
 *  Function : nfunc_line_vty
 *  Purpose:
 *     clear line vty
 *  Parameters: 
 *  
 *  Returns:
 *	-1: no vty user has been deleted, n>=1 deleted user amount
 *  Author  : wei.zhang
 *  Date    :2012/4/23
 */
int nfunc_line_vty(struct users *u)
{
	int cli_parm[2] = {0, 0};
	int i;
	char *line_max_vty = NULL, new_max_vty[5]="";
	int max_vty;
	
	cli_param_get_int(STATIC_PARAM, 0, &cli_parm[0], u);
	cli_param_get_int(STATIC_PARAM, 1, &cli_parm[1], u);
	line_max_vty = nvram_safe_get("line_max_vty");
	max_vty = atoi( line_max_vty );
	free( line_max_vty );
		
	if( cli_parm[0] > 5 ){
		if( cli_parm[0] <= max_vty ){
			for(i = cli_parm[0]; i <= max_vty; i++){
				func_clear_ssh(u, i);
				func_clear_telnet(u, i);
			}
			func_set_absolute_timeout( u, cli_parm[0], max_vty, 30);
			sprintf(new_max_vty, "%d", cli_parm[0]-1);
			nvram_set("line_max_vty", new_max_vty);
		}
	}
	else{
		vty_output("Can't remove line 1-5!\n");
	}
	
	return 0;
}

/*
 *  Function : func_set_exec_timeout
 *  Purpose:
 *  Parameters: 
 *  Returns:
 *	-1: no vty user has been deleted, n>=1 deleted user amount
 *  Author  : wei.zhang
 *  Date    :2012/5/3
 */
int func_set_exec_timeout(struct users *u)
{
	int cli_parm;
	char *login_timeout = NULL;
	char buf[128] = "", tmp_buf[10] = "", *p = NULL, i = 0;
	int line[2], exec_time_read[17];
	
	cli_param_get_int(STATIC_PARAM, 0, &cli_parm, u);
	sscanf(u->promptbuf, "%d,%d", &line[0], &line[1]);

	login_timeout = nvram_safe_get("login_timeout");
	p = login_timeout;
	for(i = 0; i < 17; i++){
		p = strchr(p, ':') + 1;
		exec_time_read[i] = atoi(p);
	}
	
	line[1] = (line[1] == 0)? line[0] : line[1];
	for(i = line[0] - 1; i <= line[1] - 1; i++)
		exec_time_read[i] = cli_parm;
		
	bzero(buf, sizeof(buf));
	for(i = 0; i < 17; i++){
		bzero(tmp_buf, sizeof(tmp_buf));
		snprintf(tmp_buf, sizeof(tmp_buf), "%d:%d;", i + 1, exec_time_read[i]);
		strcat(buf, tmp_buf);
	}
	nvram_set("login_timeout", buf);

	free(login_timeout);
	
	return 0;
}
/*
 *  Function : nfunc_set_exec_timeout
 *  Purpose:
 *  Parameters: 
 *  Returns:
 *	-1: no vty user has been deleted, n>=1 deleted user amount
 *  Author  : wei.zhang
 *  Date    :2012/5/3
 */
int nfunc_set_exec_timeout(struct users *u)
{
	char *login_timeout = NULL;
	char buf[128] = "", tmp_buf[10] = "", *p = NULL, i = 0;
	int line[2], exec_time_read[17];
	
	sscanf(u->promptbuf, "%d,%d", &line[0], &line[1]);

	login_timeout = nvram_safe_get("login_timeout");
	p = login_timeout;
	for(i = 0; i < 17; i++){
		p = strchr(p, ':') + 1;
		exec_time_read[i] = atoi(p);
	}
	line[1] = (line[1] == 0)? line[0] : line[1];
	for(i = line[0] - 1; i <= line[1] - 1; i++)
		exec_time_read[i] = 0;
		
	bzero(buf, sizeof(buf));
	for(i = 0; i < 17; i++){
		bzero(tmp_buf, sizeof(tmp_buf));
		snprintf(tmp_buf, sizeof(tmp_buf), "%d:%d;", i + 1, exec_time_read[i]);
		strcat(buf, tmp_buf);
	}
	nvram_set("login_timeout", buf);

	free(login_timeout);
	
	return 0;
}
#endif
