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
#include "acl_utils.h"
#include "memutils.h"
#include "bcmutils.h"
#include "cli_radius_func.h"
#include "cli_dot1x_func.h"

int func_set_radius_ip_port(char *ip, char *port1, char *port2)
{
    char *aaa_port, *radius_port;
	char buf[64] = {0};
	db_ra("ip:%s port1:%s port2:%s\n",ip,port1,port2);
    radius_port = port1;
    aaa_port = port2;
	
	sprintf(buf,"%s,%s,%s;",ip,port1,port2);
    nvram_set("radius_server", buf);
    nvram_set("aaa_server", ip);
    nvram_set("radius_port", radius_port);
    nvram_set("aaa_port", aaa_port);
        
    cli_stop_dot1x();
  	cli_start_dot1x();
  	syslog(LOG_NOTICE, "[CONFIG-5-RADIUS]: Set auth-port to %s,set acct-port to %s,IP is %s, %s\n", port1, port2, ip, getenv("LOGIN_LOG_MESSAGE"));

	/* Yezhong Li : send signal to reload config file for aaa */
	SYSTEM("killall -SIGTERM aaa ");
	//SYSTEM("aaa -B > /dev/null 2>&1");
	SYSTEM("aaa &");
  	return CLI_SUCCESS;
}

int func_set_radius_key(char *key)
{
    nvram_set("radius_prekey", key);
    nvram_set("aaa_prekey", key);
    nvram_set("radius_defkey_ena", "1");
    
    cli_stop_dot1x();
  	cli_start_dot1x();
  	syslog(LOG_NOTICE, "[CONFIG-5-RADIUS]: The radius key was set to %s, %s\n", key, getenv("LOGIN_LOG_MESSAGE"));

	/* Yezhong Li : send signal to reload config file for aaa */
	SYSTEM("killall -SIGTERM aaa ");
	//SYSTEM("aaa -B > /dev/null 2>&1");
	SYSTEM("aaa &");
  	return CLI_SUCCESS;
}

int nfunc_radius_host()
{
	nvram_set("radius_server", "");
	nvram_set("aaa_server", "");
	nvram_set("radius_port", "");
	nvram_set("aaa_port", "");
	nvram_set("radius_local", "1");

	/* Yezhong Li : send signal to reload config file for aaa */
/* 	SYSTEM("killall -SIGUSR2 aaa > /dev/null 2>&1");
 */

	SYSTEM("killall -SIGTERM aaa ");
	SYSTEM("aaa &");
	return 0;
}

int nfunc_radius_key()
{
	nvram_set("radius_prekey", "");
	nvram_set("aaa_prekey", "");
	nvram_set("radius_defkey_ena", "0");

	/* Yezhong Li : send signal to reload config file for aaa */
/* 	SYSTEM("killall -SIGUSR2 aaa > /dev/null 2>&1");
 */
	SYSTEM("killall -SIGTERM aaa ");
	SYSTEM("aaa &");
	return 0;
}

