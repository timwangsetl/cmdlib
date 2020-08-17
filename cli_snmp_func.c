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

#include "cli_snmp_func.h"
#include "bcmutils.h"
#define SNMP_PASSWORD_LEN_MIN 8
#define SNMP_PASSWORD_LEN_MAX 32


int func_snmp_enable(struct users *u)
{
	nvram_set("snmp_enable", "1");
	system("rc snmp restart  > /dev/null 2>&1");
	
	return 0;
}

int nfunc_snmp_enable(struct users *u)
{
	nvram_set("snmp_enable", "0");
	system("rc snmp stop  > /dev/null 2>&1");
	
	return 0;
}

/* cli add snmp server */
static int cli_snmp_set(void)
{
    system("rc snmp restart  > /dev/null 2>&1");
	return 0;
}

/* cli add snmp server */
static int cli_snmp_set_info(void)
{
	char *enable=nvram_safe_get("snmp_enable");
	if(*enable=='1')
	{
		SYSTEM("rc snmp restart");
	}
	free(enable);

	return 0;
}

/* cli add snmp server */
static int cli_snmp_set_location(char *argv)
{
	int len = 0;
	
	len = strlen(argv);

	if(len > 1023)
		vty_output("  The string length is too long\n");

	nvram_set("snmp_location", argv);

	char *enable=nvram_safe_get("snmp_enable");
	if(*enable=='1')
	{
		SYSTEM("rc snmp restart");
	}
	free(enable);
	
	return CLI_SUCCESS;
}

/*
 *  Function : cli_snmp_set_user
 *  Purpose:
 *     create snmp user
 *  Parameters:
 *     name         - User Nmae
 *     auth         - Authentication
 *     auth_passwd  - Authentication password
 *     priv         - Encryption
 *     priv_passwd  - Encryption password
 *     mode         - Mode (CLI_SNMP_RONLY, CLI_SNMP_RWRITE)
 *  Returns:
 *     CLI_SUCCESS - Success
 *     CLI_FAILED  - Failure
 *
 *  Author  : eagles.zhou
 *  Date    :2011/5/20
 */
static int cli_snmp_set_user(char *name, char *auth, char *auth_passwd, char *priv, char *priv_passwd, int mode)
{
	int index;
	cli_snmp_user *s_snmp = NULL;
	cli_snmp_user_info *p_snmp = NULL;
	
	memset(&cur_snmp_user, 0, sizeof(cli_snmp_user));
	cli_nvram_conf_get(CLI_SNMP_USER, (unsigned char *)&cur_snmp_user);

	s_snmp = &cur_snmp_user;
	p_snmp = s_snmp->cur_snmp_user_info;

	if(s_snmp->user_count >= MAX_SNMP_USER) {
		vty_output("  The Max SNMP user is %d!\n", MAX_SNMP_USER);
		cli_nvram_conf_free(CLI_SNMP_USER, (unsigned char *)&cur_snmp_user);
		return CLI_FAILED;
	}

	for(index = 1; index <= s_snmp->user_count; index++) {
		if(0 == strcmp(p_snmp->name, name)) {
			vty_output("  SNMP user name %s has exist!\n", name);
			cli_nvram_conf_free(CLI_SNMP_USER, (unsigned char *)&cur_snmp_user);
			return CLI_FAILED;
		}

		p_snmp++;
	}

    /*shanming.ren 2011-9-7 begin*/
    if(strlen(auth_passwd) > SNMP_PASSWORD_LEN_MAX)
    {
        vty_output("  Authentication password length is more than %d!\n", SNMP_PASSWORD_LEN_MAX);
		cli_nvram_conf_free(CLI_SNMP_USER, (unsigned char *)&cur_snmp_user);
		return CLI_FAILED;
    }
    if(strlen(auth_passwd) < SNMP_PASSWORD_LEN_MIN)
    {
        vty_output("  Authentication password length is less than %d!\n", SNMP_PASSWORD_LEN_MIN);
		cli_nvram_conf_free(CLI_SNMP_USER, (unsigned char *)&cur_snmp_user);
        return CLI_FAILED;
    }
    if(strlen(priv_passwd) > SNMP_PASSWORD_LEN_MAX)
    {
        vty_output("  Encryption password length is more than %d!\n", SNMP_PASSWORD_LEN_MAX);
		cli_nvram_conf_free(CLI_SNMP_USER, (unsigned char *)&cur_snmp_user);
		return CLI_FAILED;
    }
    if(strlen(priv_passwd) < SNMP_PASSWORD_LEN_MIN)
    {
        vty_output("  Encryption password length is less than %d!\n",SNMP_PASSWORD_LEN_MIN);
		cli_nvram_conf_free(CLI_SNMP_USER, (unsigned char *)&cur_snmp_user);
        return CLI_FAILED;
    }
    /*shanming.ren 2011-9-7 end*/

	p_snmp = &s_snmp->cur_snmp_user_info[s_snmp->user_count];
	s_snmp->user_count++;

	strcpy(p_snmp->name, name);
	strcpy(p_snmp->auth, auth);
	strcpy(p_snmp->auth_passwd, auth_passwd);
	strcpy(p_snmp->priv, priv);
	strcpy(p_snmp->priv_passwd, priv_passwd);
	p_snmp->mode = mode;

	cli_nvram_conf_set(CLI_SNMP_USER, (unsigned char *)&cur_snmp_user);
	cli_nvram_conf_free(CLI_SNMP_USER, (unsigned char *)&cur_snmp_user);

	char *enable = nvram_safe_get("snmp_enable");
	if('1' == *enable)
	{
		SYSTEM("rc snmp restart");
	}
	free(enable);

	return CLI_SUCCESS;
}

/*
 * Function : remove string in string 
 * Created : 03/07/2012
 * Author : gujiajie
 */
int rmstr_instr(char *buf, const char *dst)
{
	char *p, *next;

	p = buf;
	while (p) {
		if (strncmp(p, dst, strlen(dst)) == 0 && (p[strlen(dst)] == '|' || p[strlen(dst)] == '\0'))
			break;
		p = strchr(p, '|');
		if (p == NULL)
			break;
		p++;
	}
	if (p) {
		next = strchr(p, '|');
		if (next) {			//dst at the middle of buf
			next++;
			memmove(p, next, strlen(next) + 1);
			return 1;
		} else if( *(p - 1) == '|') {		//dst at the end of buf
			*(p - 1) = '\0';
			return 1;
		} else {		//dst equal to buf
			*p = '\0';
			return 1;
		}
	}

	return 0;		//not found
}

/* cli remove snmp server */
static void cli_remove_snmp_server(int type, char *param)
{
	char *enable = nvram_safe_get("snmp_enable");
    char *snmp_rcomm = nvram_safe_get("snmp_rcomm");
    char *snmp_rwcomm = nvram_safe_get("snmp_rwcomm");
    char *snmp_gateway = nvram_safe_get("snmp_gateway");
    char *snmp_user = NULL;
	
	if(0 == type) {
#if 0
		if(0 == strcmp(snmp_rcomm, param))
			nvram_set("snmp_rcomm", "");
		else if(0 == strcmp(snmp_rwcomm, param))
			nvram_set("snmp_rwcomm", "");
		else
			vty_output("  Community string %s doesn't exist\n",param);
#endif
		/* add by gujiajie start */
		if (rmstr_instr(snmp_rcomm, param) ^ rmstr_instr(snmp_rwcomm, param)) {
			nvram_set("snmp_rcomm", snmp_rcomm);
			nvram_set("snmp_rwcomm", snmp_rwcomm);
			syslog(LOG_NOTICE, "[CONFIG-5-NO]: Removed the SNMP server %s,type is community, %s\n",param, getenv("LOGIN_LOG_MESSAGE"));
		} else
			vty_output("  Community string %s doesn't exist\n",param);
		/* add by gujiajie end */

	} else {
		if(0 == strcmp(snmp_gateway, param)) {
			nvram_set("snmp_gateway", "");
			syslog(LOG_NOTICE, "[CONFIG-5-NO]: Removed the SNMP server %s,type is trap IP, %s\n",param, getenv("LOGIN_LOG_MESSAGE"));
		}
		else
			vty_output("  Trap IP %s doesn't exist\n",param);
	}
	
    free(snmp_rcomm);
    free(snmp_rwcomm);
    free(snmp_gateway);

	if('1' == *enable)
	{
	    snmp_rcomm = nvram_safe_get("snmp_rcomm");
	    snmp_rwcomm = nvram_safe_get("snmp_rwcomm");
	    snmp_gateway = nvram_safe_get("snmp_gateway");
	    snmp_user = nvram_safe_get("snmp_user");

//	    if( (0 == strlen(snmp_rcomm))&&(0 == strlen(snmp_rwcomm))&&(0 == strlen(snmp_gateway))&&(0 == strlen(snmp_user))  ) {
//			nvram_set("snmp_enable", "0");
//			SYSTEM("rc snmp stop");
//	    } else {
	    	system("rc snmp restart > /dev/null 2>&1");
//	    }

	    free(snmp_rcomm);
	    free(snmp_rwcomm);
	    free(snmp_gateway);
	    free(snmp_user);
    }
    free(enable);

    return;
}


/*
 *  Function : cli_remove_snmp_user
 *  Purpose:
 *     remove special snmp user
 *  Parameters:
 *     name         - User Nmae
 *  Returns:
 *     CLI_SUCCESS - Success
 *     CLI_FAILED  - Failure
 *
 *  Author  : eagles.zhou
 *  Date    :2011/5/20
 */
static int cli_remove_snmp_user(char *name)
{
	int index, flag = 0;
	char *enable;
	cli_snmp_user *s_snmp = NULL;
	cli_snmp_user_info *p_snmp = NULL;

    char *snmp_rcomm = NULL;
    char *snmp_rwcomm = NULL;
    char *snmp_gateway = NULL;
    char *snmp_user = NULL;

	memset(&cur_snmp_user, 0, sizeof(cli_snmp_user));
	cli_nvram_conf_get(CLI_SNMP_USER, (unsigned char *)&cur_snmp_user);

	s_snmp = &cur_snmp_user;
	p_snmp = s_snmp->cur_snmp_user_info;

	for(index = 1; index <= s_snmp->user_count; index++) {
		if(0 == strcmp(p_snmp->name, name)) {
			flag = 1;
			break;
		}

		p_snmp++;
	}

	if(1 == flag) {
		for(; index < s_snmp->user_count; index++) {
			memcpy(&s_snmp->cur_snmp_user_info[index-1], &s_snmp->cur_snmp_user_info[index], sizeof(cli_snmp_user_info));
		}

		s_snmp->user_count--;
		cli_nvram_conf_set(CLI_SNMP_USER, (unsigned char *)&cur_snmp_user);
		
		enable = nvram_safe_get("snmp_enable");
		if('1' == *enable)
		{
    		snmp_rcomm = nvram_safe_get("snmp_rcomm");
    		snmp_rwcomm = nvram_safe_get("snmp_rwcomm");
    		snmp_gateway = nvram_safe_get("snmp_gateway");
    		snmp_user = nvram_safe_get("snmp_user");

//		    if( (0 == strlen(snmp_rcomm))&&(0 == strlen(snmp_rwcomm))&&(0 == strlen(snmp_gateway))&&(0 == strlen(snmp_user))  ) {
//				nvram_set("snmp_enable", "0");
//				SYSTEM("rc snmp stop");
//		    } else {
		    	system("rc snmp restart > /dev/null 2>&1");
//		    }

		    free(snmp_rcomm);
		    free(snmp_rwcomm);
		    free(snmp_gateway);
		    free(snmp_user);
		}
		free(enable);

	} else
		vty_output("  SNMP user name %s does not exist!\n", name);

	cli_nvram_conf_free(CLI_SNMP_USER, (unsigned char *)&cur_snmp_user);

	return 	CLI_SUCCESS;
}

int nfunc_snmp_commu(struct users *u)
{
	char name[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_string(DYNAMIC_PARAM, 0, name, u);

	/* remove snmp server param, type 0 means community */
	cli_remove_snmp_server(0, name);

	return 0;
}


static char *findstr(char *buf, char *dst) 
{
	char *p = NULL;
	char *p1 = NULL;
	char *p2 = NULL;

	p1 = buf;

	while (p1) {
		p = strstr(p1, dst);	
		if (p == NULL) {
			break;
		}
		p2 = strchr(p, '|');
		if (p2) {
			if (memcmp(p, dst, p2 - p)== 0) {
				break;
			}
			p1 = p2 + 1;
		} else {
			if (strlen(p) != strlen(dst) || memcmp(p, dst, strlen(p))) {
				p = NULL;
			}

			break;
		}
	}

	return p;
}


/*
 *  Function: func_snmp_commu_ro
 *  Purpose:  Enable SNMP; set community string and access privs
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  modified: gujiajie
 *  Date:    2011/11/26
 */
int func_snmp_commu_ro(struct users *u)
{
	char *p = NULL;
	char name[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_string(DYNAMIC_PARAM, 0, name, u);
	
	/* set read-only community */
	char *snmp_rcomm = nvram_safe_get("snmp_rcomm");
	char *snmp_rwcomm = nvram_safe_get("snmp_rwcomm");


	p = findstr(snmp_rcomm, name);

	if (snmp_rcomm == NULL || snmp_rwcomm == NULL) 
		printf("snmp_community\n");


	if (p) {
		free(snmp_rcomm);
		free(snmp_rwcomm);
		return 0;
	} else {
		size_t len = strlen(snmp_rcomm);
		snmp_rcomm = realloc(snmp_rcomm, strlen(snmp_rcomm) + strlen(name) + 2);
		p = snmp_rcomm + len;
		memset(p, '\0', strlen(name)+1);
		if (len) {
			strcat(p, "|");
		}
		strcat(p, name);
		nvram_set("snmp_rcomm", snmp_rcomm);
		
		p = findstr(snmp_rwcomm, name);
		char *tmp = calloc(1, strlen(snmp_rwcomm)+1);
		if (tmp == NULL) {
			fprintf(stderr, "alloc memory error.");
			free(snmp_rcomm);
			free(snmp_rwcomm);
			return -1;
		}

		if (p) {
			strncpy(tmp, snmp_rwcomm, p - snmp_rwcomm);
			p = strchr(p, '|');
			if (p) {
				strcat(tmp, p+1);
			} else {
				tmp[strlen(tmp) - 1] = '\0';
			}
			nvram_set("snmp_rwcomm", tmp);
			free(tmp);
		}
	}

	cli_snmp_set();
	syslog(LOG_NOTICE, "[CONFIG-5-SNMP]: Set SNMP community %s to read-only community, %s\n", name, getenv("LOGIN_LOG_MESSAGE"));

	free(snmp_rcomm);
	free(snmp_rwcomm);
	return 0;
}

/*
 *  Function: func_snmp_commu_rw
 *  Purpose:  Enable SNMP; set community string and access privs
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  modified: gujiajie
 *  Date:    2011/11/26
 */

int func_snmp_commu_rw(struct users *u)
{
	char *p = NULL;
	char name[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_string(DYNAMIC_PARAM, 0, name, u);
	
	/* set set read-write community */
	char *snmp_rcomm = nvram_safe_get("snmp_rcomm");
	char *snmp_rwcomm = nvram_safe_get("snmp_rwcomm");

	p = findstr(snmp_rwcomm, name);	
	if (p) {
		free(snmp_rcomm);
		free(snmp_rwcomm);
		return 0;
	} else {
		size_t len = strlen(snmp_rwcomm);
		snmp_rwcomm = realloc(snmp_rwcomm, strlen(snmp_rwcomm) + strlen(name) + 2);
		p = snmp_rwcomm + len;
		memset(p, '\0', strlen(name)+1);
		if (len) {
			strcat(p, "|");
		}
		strcat(p, name);
		nvram_set("snmp_rwcomm", snmp_rwcomm);
		
		p = findstr(snmp_rcomm, name);
		char *tmp = calloc(1, strlen(snmp_rcomm)+1);
		if (p) {
			strncpy(tmp, snmp_rcomm, p - snmp_rcomm);
			p = strchr(p, '|');
			if (p) {
				strcat(tmp, p+1);
			} else {
				tmp[strlen(tmp) - 1] = '\0';
			}
			nvram_set("snmp_rcomm", tmp);
			free(tmp);
		}
	}

	cli_snmp_set();
	syslog(LOG_NOTICE, "[CONFIG-5-SNMP]: Set SNMP community %s to read-write community, %s\n", name, getenv("LOGIN_LOG_MESSAGE"));

	free(snmp_rcomm);
	free(snmp_rwcomm);
	return 0;
}

/*
 *  Function: func_snmp_contact
 *  Purpose:  Text for mib object sysContact
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/11/26
 */

int func_snmp_contact(struct users *u)
{
	char name[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_string(DYNAMIC_PARAM, 0, name, u);
	
	nvram_set("snmp_contact", name);
	cli_snmp_set_info();
	syslog(LOG_NOTICE, "[CONFIG-5-SNMP]: Set SNMP contact to %s, %s\n", name, getenv("LOGIN_LOG_MESSAGE"));
	
	return 0;
}

int nfunc_snmp_contact(struct users *u)
{	
	/* remove snmp server sysContact */
	nvram_set("snmp_contact", "");
	cli_snmp_set_info();
	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Remove SNMP contact, %s\n", getenv("LOGIN_LOG_MESSAGE"));

	return 0;
}

/*
 *  Function: func_snmp_host
 *  Purpose:  Specify hosts to receive SNMP TRAPs
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/11/26
 */

int func_snmp_host(struct users *u)
{
	struct in_addr s;
	char ip_addr[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_ipv4(DYNAMIC_PARAM, 0, &s, ip_addr, sizeof(ip_addr), u);
	if(!strcmp(ip_addr, "0.0.0.0")) {
		vty_output("ERROR:Invalid IP address!\n");
		return 0;
	}
	
	/* set trap host address */
	nvram_set("snmp_gateway", ip_addr);
	cli_snmp_set();
	syslog(LOG_NOTICE, "[CONFIG-5-SNMP]: Set SNMP gateway to %s, %s\n", ip_addr, getenv("LOGIN_LOG_MESSAGE"));

	return 0;
}

int nfunc_snmp_host(struct users *u)
{
	struct in_addr s;
	char ip_addr[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_ipv4(DYNAMIC_PARAM, 0, &s, ip_addr, sizeof(ip_addr), u);
	if(!strcmp(ip_addr, "0.0.0.0")) {
		vty_output("ERROR:Invalid IP address!\n");
		return 0;
	}
	
	/* remove snmp server param, type 1 means trap ip */
	cli_remove_snmp_server(1, ip_addr);
	
	return 0;
}

/*
 *  Function: func_snmp_location
 *  Purpose: Text for mib object sysLocation
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/11/28
 */

int func_snmp_location(struct users *u)
{
	char name[1024] = {'\0'};
	int pstr = 0;
	cli_param_get_int(DYNAMIC_PARAM, 0, &pstr, u);
	char *p;
	p = pstr;
	strcpy(name, p);
	
	/* set trap host address */
	cli_snmp_set_location(name);
	syslog(LOG_NOTICE, "[CONFIG-5-SNMP]: Set SNMP location to %s, %s\n", name, getenv("LOGIN_LOG_MESSAGE"));
	
	return 0;
}

int nfunc_snmp_location(struct users *u)
{
	/* remove snmp server sysLocation */
	nvram_set("snmp_location", "");
	cli_snmp_set_info();
	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Remove SNMP location, %s\n", getenv("LOGIN_LOG_MESSAGE"));

	return 0;
}


/*
 *  Function: func_md5
 *  Purpose: Use HMAC MD5 algorithm for authentication
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/11/26
 */

int func_md5(struct users *u)
{
	char name[MAX_ARGV_LEN] = {'\0'};
	char passwd[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_string(STATIC_PARAM, 0, name, u);
	cli_param_get_string(DYNAMIC_PARAM, 0, passwd, u); 
	cli_snmp_set_user(name, "MD5", passwd, "DES", passwd, CLI_SNMP_RONLY);
	cli_snmp_set();

	return 0;
}

/*
 *  Function: func_sha
 *  Purpose:Use HMAC SHA algorithm for authentication
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/11/26
 */

int func_sha(struct users *u)
{
	char name[MAX_ARGV_LEN] = {'\0'};
	char passwd[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_string(STATIC_PARAM, 0, name, u);
	cli_param_get_string(DYNAMIC_PARAM, 0, passwd, u); 
	cli_snmp_set_user(name, "SHA", passwd, "DES", passwd, CLI_SNMP_RONLY);
	cli_snmp_set();

	return 0;
}

/*
 *  Function: func_ro
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/11/26
 */

int func_ro(struct users *u)
{
	char name[MAX_ARGV_LEN] = {'\0'};
	char passwd[MAX_ARGV_LEN] = {'\0'};
	char encrpasswd[MAX_ARGV_LEN] = {'\0'};
	int auth = 0;
	int priv = 0;
	
	cli_param_get_int(DYNAMIC_PARAM, SNMP_USER_AUTH, &auth, u);
	cli_param_get_int(DYNAMIC_PARAM, SNMP_USER_PRIV, &priv, u);
	cli_param_get_string(STATIC_PARAM, 0, name, u);
	cli_param_get_string(DYNAMIC_PARAM, 0, passwd, u); 
	cli_param_get_string(DYNAMIC_PARAM, 1, encrpasswd, u);
	
	switch(priv) {
		case SNMP_USER_PRIV_3DES:
			if(auth == SNMP_USER_AUTH_MD5)
				{
					cli_snmp_set_user(name, "MD5", passwd, "3DES", encrpasswd, CLI_SNMP_RONLY);
					cli_snmp_set();
				}
			else if(auth == SNMP_USER_AUTH_SHA)
				{
					cli_snmp_set_user(name, "SHA", passwd, "3DSE", encrpasswd, CLI_SNMP_RONLY);
					cli_snmp_set();
				}
			break;

		case SNMP_USER_PRIV_AES:
			if(auth == SNMP_USER_AUTH_MD5)
				{
					cli_snmp_set_user(name, "MD5", passwd, "AES", encrpasswd, CLI_SNMP_RONLY);
					cli_snmp_set();
				}
			else if(auth == SNMP_USER_AUTH_SHA)
				{
					cli_snmp_set_user(name, "SHA", passwd, "AES", encrpasswd, CLI_SNMP_RONLY);
					cli_snmp_set();
				}
			break;
			
		case SNMP_USER_PRIV_DES:
			if(auth == SNMP_USER_AUTH_MD5)
				{
					cli_snmp_set_user(name, "MD5", passwd, "DES", encrpasswd, CLI_SNMP_RONLY);
					cli_snmp_set();
				}
			else if(auth == SNMP_USER_AUTH_SHA)
				{
					cli_snmp_set_user(name, "SHA", passwd, "DES", encrpasswd, CLI_SNMP_RONLY);
					cli_snmp_set();
				}
			break;

		default:return -1;
		}
	return 0;
}

/*
 *  Function: func_rw
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   dawei.hu
 *  Date:    2011/11/26
 */

int func_rw(struct users *u)
{
	char name[MAX_ARGV_LEN] = {'\0'};
	char passwd[MAX_ARGV_LEN] = {'\0'};
	char encrpasswd[MAX_ARGV_LEN] = {'\0'};
	int auth = 0;
	int priv = 0;
	
	cli_param_get_int(DYNAMIC_PARAM, SNMP_USER_AUTH, &auth, u);
	cli_param_get_int(DYNAMIC_PARAM, SNMP_USER_PRIV, &priv, u);
	cli_param_get_string(STATIC_PARAM, 0, name, u);
	cli_param_get_string(DYNAMIC_PARAM, 0, passwd, u); 
	cli_param_get_string(DYNAMIC_PARAM, 1, encrpasswd, u);
	
	switch(priv) {
		case SNMP_USER_PRIV_3DES:
			if(auth == SNMP_USER_AUTH_MD5)
				{
					cli_snmp_set_user(name, "MD5", passwd, "3DES", encrpasswd, CLI_SNMP_RWRITE);
					cli_snmp_set();
				}
			else if(auth == SNMP_USER_AUTH_SHA)
				{
					cli_snmp_set_user(name, "SHA", passwd, "3DSE", encrpasswd, CLI_SNMP_RWRITE);
					cli_snmp_set();
				}
			break;

		case SNMP_USER_PRIV_AES:
			if(auth == SNMP_USER_AUTH_MD5)
				{
					cli_snmp_set_user(name, "MD5", passwd, "AES", encrpasswd, CLI_SNMP_RWRITE);
					cli_snmp_set();
				}
			else if(auth == SNMP_USER_AUTH_SHA)
				{
					cli_snmp_set_user(name, "SHA", passwd, "AES", encrpasswd, CLI_SNMP_RWRITE);
					cli_snmp_set();
				}
			break;
			
		case SNMP_USER_PRIV_DES:
			if(auth == SNMP_USER_AUTH_MD5)
				{
					cli_snmp_set_user(name, "MD5", passwd, "DES", encrpasswd, CLI_SNMP_RWRITE);
					cli_snmp_set();
				}
			else if(auth == SNMP_USER_AUTH_SHA)
				{
					cli_snmp_set_user(name, "SHA", passwd, "DES", encrpasswd, CLI_SNMP_RWRITE);
					cli_snmp_set();
				}
			break;

		default:return -1;
		}
	return 0;
}

int nfunc_snmp_users(struct users *u)
{
	char name[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_string(DYNAMIC_PARAM, 0, name, u);
	
	cli_remove_snmp_user(name);

	return 0;
}
