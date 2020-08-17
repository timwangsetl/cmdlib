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

#include "cli_stp_func.h"
#include "bcmutils.h"
#include "nvram.h"

#define MSTP_HELLOTIME	3
#define MSTP_FWDDELAY	4
#define MSTP_MAXAGE		5

#define MAX_VLAN 4096
#define MAX_INSTANCE 16
#define MAX_INSTANCE_STRING_LEN 2*MAX_ARGV_LEN + 1

static uint64_t cur_port_int = 0x0ULL;
static cli_rstp_conf cur_rstp_port[PNUM];

static int cli_analysis_string(int tmp, const char *entry_in, int arr[])
{
	char *item, *entry;
	int begin, end;

	entry = (char *)malloc(MAX_ARGV_LEN);
	strcpy(entry, entry_in);
	
	while (entry && *entry) {
		item = strsep(&entry, ",");
		if (strchr(item, '-')) {

			begin = atoi(item);
			end = atoi(strchr(item, '-') + 1);
			while (begin <= end)
				arr[begin++] = tmp;
		} else {
			arr[atoi(item)] = tmp;
		}
	}
	free(entry);
	return 0;
}

static int cli_modify_mst_instance(char *old_str, int instance, char *vlanStr, char *new_str)
{
	int vlan[MAX_VLAN] = {0};
	char instanceStr[MAX_INSTANCE][MAX_INSTANCE_STRING_LEN] = {""};
	int count, inTmp, len;
	int begin, end;
	char *p, *entry;
	char strTmp[10];
	
	p = old_str;	
	/* analysis old vlan-to-msti config to vlan array which element contain mstid */
	while (p && *p) {
		entry = strsep(&p, ";");
		inTmp = atoi(strsep(&entry, ":"));
		cli_analysis_string(inTmp, entry, vlan);
	}
	
	/* modify the mstid which the vlan array element contain*/
	if (vlanStr != NULL) {
		for (count = 1; count < MAX_VLAN-1; count++) {
			if (vlan[count] == instance) {
				vlan[count] = 0;
			}
		}
		cli_analysis_string(instance, vlanStr, vlan);
	} else {
		for (count = 1; count < MAX_VLAN-1; count++) {
			if (vlan[count] == instance) {
				vlan[count] = 0;
			}
		}
	}
	
	/* change the vlan array which element contain msti to vlan-to-msti string */
	for (count = 1; count < MAX_VLAN-1; count++) {
		strcpy(strTmp, "");
		begin = count;
		while ((vlan[count] == vlan[count+1]) && (count + 1 < MAX_VLAN-1))
		{
			count++;
		}
		end = count;
		if (begin == end) {
			sprintf(strTmp, "%d,", begin);
		} else {
			sprintf(strTmp, "%d-%d,", begin, end);
		}
		strncat(instanceStr[vlan[begin]], strTmp, strlen(strTmp));
	}
	
	strcpy(new_str, "");
	for (count = 0; count < MAX_INSTANCE; count++) {
		if (0 == strcmp(instanceStr[count], "")) {
			continue;
		} else {
			len = strlen(instanceStr[count]);
			*(instanceStr[count] + len - 1) = ';';
			sprintf(new_str, "%s%d:%s", new_str, count, instanceStr[count]);
	
		}
	}

	return 0;
}


/*
 *  Function:  cli_check_rstp_time
 *  Purpose:   forward-time/hello-time/max-age check function
 *  Parameters: 
 *              int flag, int time
 *  Returns:
 *  
 *  Author:  
 *  Date:    
 */
/* modified for mstp by luole */
static int cli_check_stp_time(int flag, int time)
{
    int hello_time = 0;
    int fwd_delay = 0;
    int max_age = 0;
	char *stp_hello_time = NULL;
	char *stp_fwd_delay = NULL;
	char *stp_max_age = NULL;
	if(flag > 2) {
		stp_hello_time = nvram_safe_get("mstp_hello_time");
		stp_fwd_delay = nvram_safe_get("mstp_fwd_delay");
		stp_max_age = nvram_safe_get("mstp_max_age");
	} else {
		stp_hello_time = nvram_safe_get("rstp_hello_time");
		stp_fwd_delay = nvram_safe_get("rstp_fwd_delay");
		stp_max_age = nvram_safe_get("rstp_max_age");
	}
    
    hello_time = (0 == strlen(stp_hello_time)) ? 2 : atoi(stp_hello_time);
    fwd_delay  = (0 == strlen(stp_fwd_delay)) ? 15 : atoi(stp_fwd_delay);
    max_age    = (0 == strlen(stp_max_age)) ? 20 : atoi(stp_max_age);	
    	
    free(stp_hello_time);
    free(stp_fwd_delay);
    free(stp_max_age);
    
    switch(flag)
    {
		case 0:
		case MSTP_HELLOTIME:
            hello_time = time;
            break;
    		
		case 1:
		case MSTP_FWDDELAY:
            fwd_delay = time;
            break;
    		
		case 2:
		case MSTP_MAXAGE:
            max_age = time;
            break;
    		
        default:
            break;
    }
    
    if((2*(fwd_delay-1) < max_age) || (2*(hello_time+1) > max_age))
    {
        vty_output("It is suggested that the relationship between protocol timer values be enforced by ensuring that\n");
        vty_output("2 x (fwd_delay - 1) >= max_age\n");
        vty_output("max_age >= (hello_time + 1) x 2\n");
        return -1;
    }   
    return 0;
}

/*
 *  Function:  func_stp_mode_rstp
 *  Purpose:   Setup rapid spanning-tree protocol mode
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/22
 */
int func_stp_mode_stp(struct users *u)
{
    char *rstp_enable = nvram_safe_get("rstp_enable");
	char *mstp_enable = nvram_safe_get("mstp_enable");
   // char *rstp_config = cli_nvram_safe_get(CLI_RSTP_CONFIG, "rstp_config");

    if( '1' == *mstp_enable )
		nfunc_stp_mode_mstp();

    nvram_set("rstp_enable", "1");
    nvram_set("rstp_version", "1");
    system("rc rstp restart >/dev/null 2>&1");
    syslog(LOG_NOTICE, "[CONFIG-5-RSTP]: Enabled STP, %s\n", getenv("LOGIN_LOG_MESSAGE"));

	free(rstp_enable);
	free(mstp_enable);
	
	return 0;
}

int func_stp_mode_rstp(struct users *u)
{
    char *rstp_enable = nvram_safe_get("rstp_enable");
	char *mstp_enable = nvram_safe_get("mstp_enable");
   // char *rstp_config = cli_nvram_safe_get(CLI_RSTP_CONFIG, "rstp_config");

    if( '1' == *mstp_enable )
		nfunc_stp_mode_mstp();

    nvram_set("rstp_enable", "1");
    nvram_set("rstp_version", "2");
    system("rc rstp restart >/dev/null 2>&1");
    syslog(LOG_NOTICE, "[CONFIG-5-RSTP]: Enabled RSTP, %s\n", getenv("LOGIN_LOG_MESSAGE"));

	free(rstp_enable);
	free(mstp_enable);
	return 0;
}

/* Disable RSTP Function */
int nfunc_stp_mode_rstp(struct users *u)
{
    char *rstp_enable = nvram_safe_get("rstp_enable");
   // char *rstp_config = cli_nvram_safe_get(CLI_RSTP_CONFIG, "rstp_config");

    if ('1' == *rstp_enable)
    {
        nvram_set("rstp_enable", "0");
        SYSTEM("/usr/bin/killall rstp >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-RSTP]: Disabled RSTP, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }
	free(rstp_enable);
	return 0;
}

/*
 *  Function:  func_stp_rstp_forwardtime
 *  Purpose:   Rstp mode forward time
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/22
 */
int func_stp_rstp_forwardtime(struct users *u)
{
    char *rstp_enable = nvram_safe_get("rstp_enable");
   // char *rstp_config = cli_nvram_safe_get(CLI_RSTP_CONFIG, "rstp_config");

    int time = 0;
    char forwardtime[MAX_ARGV_LEN] = {'\0'}; 
    cli_param_get_int(DYNAMIC_PARAM, 0, &time, u);
    /*Convert int to string*/
    sprintf(forwardtime, "%d", time);
    
    if(0 == cli_check_stp_time(1, time))
    {
        nvram_set("rstp_fwd_delay", forwardtime);
        if('1' == *rstp_enable)
        SYSTEM("/usr/bin/killall -SIGUSR2 rstp >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-RSTP]: Set the RSTP mode forward time to %s, %s\n", forwardtime, getenv("LOGIN_LOG_MESSAGE"));
    }
	free(rstp_enable);
	return 0;
}

/*
 *  Function:  func_stp_rstp_hellotime
 *  Purpose:   Rstp mode hello time
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/22
 */
int func_stp_rstp_hellotime(struct users *u)
{
    char *rstp_enable = nvram_safe_get("rstp_enable");
    //char *rstp_config = cli_nvram_safe_get(CLI_RSTP_CONFIG, "rstp_config");

    int time = 0;
    char hellotime[MAX_ARGV_LEN] = {'\0'}; 
    cli_param_get_int(DYNAMIC_PARAM, 0, &time, u);
    /*Convert int to string*/
    sprintf(hellotime, "%d", time);
    
    if(0 == cli_check_stp_time(0, time))
    {
        nvram_set("rstp_hello_time", hellotime);
        if('1' == *rstp_enable)
        SYSTEM("/usr/bin/killall -SIGUSR2 rstp >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-RSTP]: Set the RSTP mode hello time to %s, %s\n", hellotime, getenv("LOGIN_LOG_MESSAGE"));
    }
	free(rstp_enable);
	return 0;
}

/*
 *  Function:  func_stp_rstp_maxage
 *  Purpose:   Rstp mode max age 
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/22
 */
int func_stp_rstp_maxage(struct users *u)
{
    char *rstp_enable = nvram_safe_get("rstp_enable");
   // char *rstp_config = cli_nvram_safe_get(CLI_RSTP_CONFIG, "rstp_config");
    
    int time = 0;
    char maxage[MAX_ARGV_LEN] = {'\0'}; 
    cli_param_get_int(DYNAMIC_PARAM, 0, &time, u);
    /*Convert int to string*/
    sprintf(maxage, "%d", time);
    
    if(0 == cli_check_stp_time(2, time))
    {
        nvram_set("rstp_max_age", maxage);
        if('1' == *rstp_enable)
        SYSTEM("/usr/bin/killall -SIGUSR2 rstp >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-RSTP]: Set the RSTP mode max age to %s, %s\n", maxage, getenv("LOGIN_LOG_MESSAGE"));
    }
	free(rstp_enable);
	return 0;
}

/*
 *  Function:  func_stp_rstp_priority
 *  Purpose:  Rstp mode priority value 
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/22
 */
int func_stp_rstp_priority(struct users *u)
{
    char *rstp_enable = nvram_safe_get("rstp_enable");
   // char *rstp_config = cli_nvram_safe_get(CLI_RSTP_CONFIG, "rstp_config");

    int priority_int = 0;
    char priority[MAX_ARGV_LEN] = {'\0'};
    cli_param_get_int(DYNAMIC_PARAM, 0, &priority_int, u);
    /*Convert int to string*/
    sprintf(priority, "%d", priority_int);
    
    if(0 == priority_int % 4096) 
    {
        nvram_set("rstp_priority", priority);
		/* modified by luole */
		if('1'==*rstp_enable)
        SYSTEM("/usr/bin/killall -SIGUSR2 rstp >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-RSTP]: Set the RSTP mode priority value to %s, %s\n", priority, getenv("LOGIN_LOG_MESSAGE"));
    } 
    else 
    { 
        vty_output("RSTP priority should be one of the following values:\n");
        vty_output("0     4096  8192  12288 16384 20480 24576 28672\n");
        vty_output("32768 36864 40960 45056 49152 53248 57344 61440\n");
    }
	free(rstp_enable);
	return 0;
}

/*
 *  Function:  func_stp_portfast_bpdu_defau
 *  Purpose:   spanning-tree portfast bpdufilter for all ports enable
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/22
 */
int func_stp_portfast_bpdu_defau(struct users *u)
{
    char *rstp_enable = nvram_safe_get("rstp_enable");
   // char *rstp_config = cli_nvram_safe_get(CLI_RSTP_CONFIG, "rstp_config");

    nvram_set("rstp_bpdufilter_default", "1");
    if('1' == *rstp_enable)
    {   
        SYSTEM("/usr/bin/killall -SIGUSR2 rstp >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-RSTP]: Enable bdpu filter by default on all portfast ports, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }
	free(rstp_enable);
    return 0;
}

/*
 *  Function:  nfunc_stp_enable
 *  Purpose:   Disable spanning-tree protocol
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/22
 */
int nfunc_stp_enable(struct users *u)
{
    char *rstp_enable = nvram_safe_get("rstp_enable");
	char *mstp_enable = nvram_safe_get("mstp_enable");
    if('1' == *rstp_enable)
    {
        nvram_set("rstp_enable", "0");
//        SYSTEM("/usr/bin/killall rstp > /dev/null 2>&1");
        system("rc rstp restart");
    }
	if ('1' == *mstp_enable) {
		nvram_set("mstp_enable", "0");
//		SYSTEM("/usr/bin/killall mstpd >/dev/null 2>&1");
        system("rc rstp restart");
	}
    free(rstp_enable);
	free(mstp_enable);
    syslog(LOG_NOTICE, "[CONFIG-5-STP]: Disable spanning-tree protocol, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    return 0;
}

/*
 *  Function:  nfunc_stp_rstp_forwardtime
 *  Purpose:   Set the forward-time to default(15s)
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/22
 */
int nfunc_stp_rstp_forwardtime(struct users *u)
{
    char *rstp_temp = nvram_get_def("rstp_fwd_delay");
    char *rstp_enable;
    
    if(NULL == rstp_temp)
    {
        if(-1 == cli_check_stp_time(1, 15))
        {
            vty_output("Set the forward-time to default(15s) failed!\n");
            return -1;
        }
        else
        {
            nvram_set("rstp_fwd_delay", "15"); 
        }
    }
    
    else
    {
        if(-1 == cli_check_stp_time(1, atoi(rstp_temp)))
        {
            vty_output("Set the forward-time to default(15s) failed!\n");
			free(rstp_temp);
            return -1;
        }
        else
        {
            nvram_set("rstp_fwd_delay", rstp_temp);
            free(rstp_temp);
        }
    }
    rstp_enable = nvram_safe_get("rstp_enable");
   
    if('1' == *rstp_enable)
    {
        SYSTEM("/usr/bin/killall -SIGUSR2 rstp >/dev/null 2>&1");
    }
    free(rstp_enable);
    syslog(LOG_NOTICE, "[CONFIG-5-RSTP]: The RSTP mode forward time was set to 15s, %s\n", getenv("LOGIN_LOG_MESSAGE")); 
    return 0;
}

/*
 *  Function:  nfunc_stp_rstp_hellotime
 *  Purpose:   Set the hello-time to default(2s)
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/22
 */
int nfunc_stp_rstp_hellotime(struct users *u)
{
    char *rstp_temp = nvram_get_def("rstp_hello_time");
    char *rstp_enable;
    
    if(NULL == rstp_temp)
    {
        if(-1 == cli_check_stp_time(0, 2))
        {
            vty_output("Set the hello-time to default(2s) failed!\n");
            return -1;
        }
        else
        {
            nvram_set("rstp_hello_time", "2"); 
        }
    }
    
    else
    {
        if(-1 == cli_check_stp_time(0, atoi(rstp_temp)))
        {
	        free(rstp_temp);
            vty_output("Set the hello-time to default(2s) failed!\n");
            return -1;
        }
        else
        {
            nvram_set("rstp_hello_time", rstp_temp);
            free(rstp_temp);
        }
    }
	rstp_enable = nvram_safe_get("rstp_enable");   
    if('1' == *rstp_enable)
    {
        SYSTEM("/usr/bin/killall -SIGUSR2 rstp >/dev/null 2>&1");
    }
    free(rstp_enable);
    syslog(LOG_NOTICE, "[CONFIG-5-RSTP]: The RSTP mode hello time was set to 2s, %s\n", getenv("LOGIN_LOG_MESSAGE")); 
    return 0;
}

/*
 *  Function:  nfunc_stp_rstp_maxage
 *  Purpose:   Set the max-age to default(20s)
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/22
 */
int nfunc_stp_rstp_maxage(struct users *u)
{
    char *rstp_temp = nvram_get_def("rstp_max_age");
    char *rstp_enable;
    
    if(NULL == rstp_temp)
    {
        if(-1 == cli_check_stp_time(2, 20))
        {
            vty_output("Set the max-age to default(20s) failed!\n");
            return -1;
        }
        else
        {
            nvram_set("rstp_max_age", "20"); 
        }
    }
    
    else
    {
        if(-1 == cli_check_stp_time(2, atoi(rstp_temp)))
        {
            free(rstp_temp);
            vty_output("Set the max-age to default(20s) failed!\n");
            return -1;
        }
        else
        {
            nvram_set("rstp_max_age", rstp_temp);
            free(rstp_temp);
        }
    }
	rstp_enable = nvram_safe_get("rstp_enable");   
    if('1' == *rstp_enable)
    {
        SYSTEM("/usr/bin/killall -SIGUSR2 rstp >/dev/null 2>&1");
    }
    free(rstp_enable);
    syslog(LOG_NOTICE, "[CONFIG-5-RSTP]: The RSTP max age was set to 20s, %s\n", getenv("LOGIN_LOG_MESSAGE")); 
    return 0;
}

/*
 *  Function:  nfunc_stp_rstp_priority
 *  Purpose:   Set the priority value to default(32768)
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/22
 */
int nfunc_stp_rstp_priority(struct users *u)
{
    char *rstp_temp = nvram_get_def("rstp_priority");
    char *rstp_enable = nvram_safe_get("rstp_enable");
    
    if(NULL == rstp_temp)
    {
        nvram_set("rstp_priority", "32768");
    }    
    else
    {
        nvram_set("rstp_priority", rstp_temp);
        free(rstp_temp);
    }
    
    if('1'==*rstp_enable)
    {
        SYSTEM("/usr/bin/killall -SIGUSR2 rstp >/dev/null 2>&1");
    }
    free(rstp_enable);
    syslog(LOG_NOTICE, "[CONFIG-5-RSTP]: The RSTP mode priority value was set to 32768, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    return 0;
}

/*
 *  Function:  nfunc_stp_portfast_bpdu_defau
 *  Purpose:   Disable bdpu filter by default on all portfast ports
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   chunli.wu
 *  Date:    2011/11/22
 */
int nfunc_stp_portfast_bpdu_defau(struct users *u)
{
    char *rstp_temp = nvram_get_def("rstp_bpdufilter_default");
    char *rstp_enable = nvram_safe_get("rstp_enable");
    
    nvram_set("rstp_bpdufilter_default", rstp_temp);
            
    if('1'==*rstp_enable)
    {
	    SYSTEM("/usr/bin/killall -SIGUSR2 rstp >/dev/null 2>&1");
    }
    free(rstp_temp);
    free(rstp_enable);
    syslog(LOG_NOTICE, "[CONFIG-5-RSTP]: Disable bdpu filter by default on all portfast ports, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    return 0;
}
// 0 = no stp 
// 1 = rstp 
// 2 = mstp 
/* MST function */
int func_stp_mode_mstp(struct users *u)
{
	char *mstp_enable = nvram_safe_get("mstp_enable");

    if('1' != *mstp_enable)
    {
		nfunc_stp_mode_rstp(u);
        nvram_set("mstp_enable", "1");
        SYSTEM("/usr/sbin/mstpd >/dev/null 2>&1");
		usleep(1300000);/* mstp process init time is 1.2 seconds */
        syslog(LOG_NOTICE, "[CONFIG-5-SPANNINGTREE]: Enabled MSTP, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    }
	free(mstp_enable);
	return 0;
}

int func_stp_mst_word_priority(struct users *u)
{	
	char *mstp_enable = nvram_safe_get("mstp_enable");
	char *mstp_instance_priority = nvram_safe_get("mstp_instance_priority");
	char entry[MAX_ARGV_LEN] = {'\0'};
	char *p;
	int iPrio[MAX_INSTANCE] = {32768};
	int iFlag[MAX_INSTANCE] = {0}, mstp_priority[256];
	int count, tmp, flag = 1;
	p = mstp_instance_priority;

	cli_param_get_int(STATIC_PARAM, 0, &tmp, u);

	if (0 != tmp % 4096) {
		vty_output("MSTP priority should be one of the following values:\n");
        vty_output("0     4096  8192  12288 16384 20480 24576 28672\n");
        vty_output("32768 36864 40960 45056 49152 53248 57344 61440\n");
	} else {
		for (count = 0; count < MAX_INSTANCE; count++) {
			if(!(p && *p)) {
				break;
			}
			iPrio[count] = atoi(strsep(&p, ";"));
		}

		cli_param_get_string(STATIC_PARAM, 0, entry, u);
		cli_analysis_string(tmp, entry, iPrio);
		cli_analysis_string(flag, entry, iFlag);
		
		memset(mstp_priority, '\0', sizeof(mstp_priority));
		for (count = 0; count < MAX_INSTANCE; count++) {
			sprintf(mstp_priority, "%s%d;", mstp_priority, iPrio[count]);
		
			if (('1' == *mstp_enable) && (1 == iFlag[count])) {
				SYSTEM("/usr/sbin/mstpctl treeprio %d %d >/dev/null 2>&1", count, tmp/4096);
			}
		}

		syslog(LOG_NOTICE, "[CONFIG-5-SPANNINGTREE]: Set the MSTI %s priority to %d, %s\n", entry, tmp, getenv("LOGIN_LOG_MESSAGE"));
		nvram_set("mstp_instance_priority", mstp_priority);
	}

	free(mstp_instance_priority);
	free(mstp_enable);
	return 0;
}

// mstp_instance_root 
// 0 = no root
// 1 = primary
// 2 = secondary
int func_stp_mst_word_root(struct users *u)
{
	char *mstp_enable = nvram_safe_get("mstp_enable");
	char *mstp_instance_root = nvram_safe_get("mstp_instance_root");
	char entry[MAX_ARGV_LEN] = {'\0'};
	char *p;
	int tmp, count;
	int root[MAX_INSTANCE] = {0};
	p = mstp_instance_root;

	cli_param_get_string(STATIC_PARAM, 0, entry, u);
	if (ISSET_CMD_MSKBIT(u, INSTANCE_ROOT_PRIMARY)) {
		tmp = 1;
	} else if (ISSET_CMD_MSKBIT(u, INSTANCE_ROOT_SECONDARY)) {
		tmp = 2;
	} else {
		tmp = 0;
	}

	for (count = 0; count < MAX_INSTANCE; count++) {
		if(!(p && *p)) {
			break;
		}
		root[count] = atoi(strsep(&p, ";"));
	}

	cli_analysis_string(tmp, entry, root);

	strcpy(mstp_instance_root, "");
	for (count = 0; count < MAX_INSTANCE; count++) {
		sprintf(mstp_instance_root, "%s%d;", mstp_instance_root, root[count]);
	}
	nvram_set("mstp_instance_root", mstp_instance_root);
	if ('1' == *mstp_enable) {
		//SYSTEM("...");
	}
	free(mstp_instance_root);
	free(mstp_enable);
	return 0;
}
/* mstp_instance_vlan is MSTI-VLAN mapping old config, mstid is new instance id.
   vlan is one instance map vlan new config.
   this function is set new vlan entry's MSTID , from new config*/
int cli_set_vlan_entry_mstid(int skfd, char *mstp_instance_vlan, uint16 instance, char *vlan)
{
	uint16 vlanid;
	uint16 msti_vlan_old[VLAN_MAX_NUM];
	uint16 msti_vlan_new[VLAN_MAX_NUM];
	char *p_str = strdup(mstp_instance_vlan);
	char *p = p_str;
	char *entry, *vlan_str;
	uint16 begin_num, end_num, iLoop, mstid;

	memset(msti_vlan_old, 0, sizeof(msti_vlan_old));
	/* get last instance contain vlans */
	while(p && *p) 
	{
		entry = strsep(&p, ";");/* get one instance config */
		mstid = atoi(strsep(&entry, ":")); /* get instance number */

		while(entry && *entry) {
			vlan_str = strsep(&entry, ",");
			if (strchr(vlan_str, '-')) /* if the vlan is range */
			{
				begin_num = atoi(strsep(&vlan_str, "-"))-1; /* the first vlan id of the range vlan */
				end_num = atoi(vlan_str);	/* the last vlan id of the range vlan */
				for(iLoop = begin_num; iLoop < end_num; iLoop++) 
				{
					msti_vlan_old[iLoop] = mstid; /* set the vlan's msti */
				}
			}
			else /* if the vlan is one number */
			{
				end_num = atoi(vlan_str)-1;
				msti_vlan_old[end_num] = mstid;
			}
		}
		
	}
	free(p_str);
	/* get now instance contain vlans */
	p_str = strdup(vlan);
	p = p_str;
	memset(msti_vlan_new, 0, sizeof(msti_vlan_new));
	while(p && *p) {
		entry = strsep(&p, ",");
		if (strchr(entry, '-')) {
			begin_num = atoi(strsep(&entry, "-"))-1;/* the first vlan id */
			end_num = atoi(entry); /* the last vlan id */
			for(iLoop = begin_num; iLoop < end_num; iLoop++) {
				msti_vlan_new[iLoop] = instance;
			}
		}
		else
		{
			end_num = atoi(entry)-1;
			msti_vlan_new[end_num] = instance;
		}
	}

	/* check the instance's vlan between the old and new config */
	for (vlanid = 0; vlanid < VLAN_MAX_NUM; vlanid++) {
		if (msti_vlan_old[vlanid] != msti_vlan_new[vlanid]) {
			if (msti_vlan_new[vlanid]== instance) {
				/* add vlan to this instance */
				bcm_mstp_msti_map_vlan(skfd, msti_vlan_new[vlanid], vlanid+1);
//				fprintf(stderr, "[%s:%d] add mst %d vlan %d\n", __FUNCTION__, __LINE__, msti_vlan_new[vlanid], vlanid+1);
			}
			if (msti_vlan_old[vlanid] == instance) {
				/* delete vlan from this instance */
				bcm_mstp_msti_remove_vlan(skfd, instance, vlanid+1);
//				fprintf(stderr, "[%s:%d] remove mst %d vlan %d\n", __FUNCTION__, __LINE__, instance, vlanid+1);
			}
		}
	}
	
	free(p_str);
	return 0;
}
int func_mst_instance_id_vlan_line(struct users *u)
{
	int instance = 0, skfd;
	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return CLI_FAILED;

	char *mstp_enable = nvram_safe_get("mstp_enable");
	char *instance_vlan = nvram_safe_get("mstp_instance_vlan");
	char instance_buff[4096], vlan[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_int(STATIC_PARAM, 0, &instance, u);
	
	cli_param_get_string(STATIC_PARAM, 0, vlan, u);
	cli_set_vlan_entry_mstid(skfd, instance_vlan, instance, vlan);
	cli_modify_mst_instance(instance_vlan, instance, vlan, instance_buff);
	nvram_set("mstp_instance_vlan", instance_buff);

	if ('1' == *mstp_enable) {
		SYSTEM("/usr/sbin/mstpctl vid2mstid %d:%s >/dev/null 2>&1", instance, vlan);
	}
	syslog(LOG_NOTICE, "[CONFIG-5-SPANNINGTREE]: MSTI %d vlan mapping set to %s, %s\n", instance, vlan, getenv("LOGIN_LOG_MESSAGE"));
	free(instance_vlan);
	free(mstp_enable);
	close(skfd);
	return 0;
}

int func_mst_name_word(struct users *u)
{
	char *mstp_enable = nvram_safe_get("mstp_enable");
	char *revision = nvram_safe_get("mstp_revision");

	char name[33] = {'\0'};
	char cname[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_string(STATIC_PARAM, 0, cname, u);
	if (strlen(cname) > 32) {
		vty_output("Configuration name has been truncated to 32 characters!\n");
		strncpy(name, cname, 32);
	} else {
		strncpy(name, cname, strlen(cname));
	}

	nvram_set("mstp_name", name);
	if('1' == *mstp_enable)
	{
		SYSTEM("/usr/sbin/mstpctl setmstconfid %s:%s >/dev/null 2>&1", revision, name);
	}
	syslog(LOG_NOTICE, "[CONFIG-5-SPANNINGTREE]: MSTP configuration name set to %s, %s\n", name, getenv("LOGIN_LOG_MESSAGE"));
	free(revision);
	free(mstp_enable);
	return 0;
}

int func_mst_privlan_sync(struct users *u)
{
	char *mstp_enable = nvram_safe_get("mstp_enable");

	nvram_set("mstp_privlan_sync", "1");
	if('1' == *mstp_enable)
	{
	//	SYSTEM("/usr/bin/killall -SIGUSR2 rstp >/dev/null 2>&1");
		syslog(LOG_NOTICE, "[CONFIG-5-SPANNINGTREE]: Enabled private vlan synchronize, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	}
	free(mstp_enable);
	return 0;
}

int func_mst_revision_param(struct users *u)
{
	char *mstp_enable = nvram_safe_get("mstp_enable");
	char *name = nvram_safe_get("mstp_name");

    int rev = 0;
    char revision[MAX_ARGV_LEN] = {'\0'}; 
    cli_param_get_int(STATIC_PARAM, 0, &rev, u);
    /*Convert int to string*/
    sprintf(revision, "%d", rev);

	nvram_set("mstp_revision", revision);
	if('1' == *mstp_enable)
	{
		SYSTEM("/usr/sbin/mstpctl setmstconfid %d:%s >/dev/null 2>&1", rev, name);
	}
	syslog(LOG_NOTICE, "[CONFIG-5-SPANNINGTREE]: MSTP configuration revision set to %d, %s\n", rev, getenv("LOGIN_LOG_MESSAGE"));
	free(name);
	free(mstp_enable);
	return 0;
}

int func_mst_show(struct users *u)
{
	char *instance_vlan = nvram_safe_get("mstp_instance_vlan");
	char *fwd_delay = nvram_safe_get("mstp_fwd_delay");
	char *hello_time = nvram_safe_get("mstp_hello_time");
	char *max_age = nvram_safe_get("mstp_max_age");
	char *max_hops = nvram_safe_get("mstp_max_hops");
	char *name = nvram_safe_get("mstp_name");
	char *revision = nvram_safe_get("mstp_revision");
	char *p = instance_vlan;
	char *inTmp, *vlanTmp;

	vty_output("MST configuration\n");
	vty_output("%-15s%s\n", "ForwardTime", fwd_delay);
	vty_output("%-15s%s\n", "HelloTime", hello_time);
	vty_output("%-15s%s\n", "MaxAge", max_age);
	vty_output("%-15s%s\n", "MaxHops", max_hops);
	vty_output("%-15s[%s]\n", "Name", name);
	vty_output("%-15s%s\n", "Revision", revision);
	vty_output("%-15s%s\n","Instance", "Vlans mapped");
	vty_output("-------------- --------------------------------------------------\n");
	while (p && *p) {
		inTmp = strsep(&p, ":");
		vlanTmp = strsep(&p, ";");
		vty_output("%-15s%s\n", inTmp, vlanTmp);
	}
	vty_output("-----------------------------------------------------------------\n");
	free(instance_vlan);
	free(fwd_delay);
	free(hello_time);
	free(max_age);
	free(max_hops);
	free(name);
	free(revision);
	return 0;
}

int func_mst_show_current(struct users *u)
{
	return 0;
}

int func_stp_mst_fwdtime_param(struct users *u)
{
	char *mstp_enable = nvram_safe_get("mstp_enable");

    int time = 0;
    char forwardtime[MAX_ARGV_LEN] = {'\0'}; 
    cli_param_get_int(STATIC_PARAM, 0, &time, u);
    /*Convert int to string*/
    sprintf(forwardtime, "%d", time);
    
    if(0 == cli_check_stp_time(MSTP_FWDDELAY, time))
    {
        nvram_set("mstp_fwd_delay", forwardtime);
        if('1' == *mstp_enable)
		{
			SYSTEM("/usr/sbin/mstpctl fdelay %d >/dev/null 2>&1", time);
		}
        syslog(LOG_NOTICE, "[CONFIG-5-SPANNINGTREE]: Set the MSTP forward time to %ss, %s\n", forwardtime, getenv("LOGIN_LOG_MESSAGE"));
    }
	free(mstp_enable);
	return 0;
}

int func_stp_mst_hellotime_param(struct users *u)
{
	char *mstp_enable = nvram_safe_get("mstp_enable");

    int time = 0;
    char hellotime[MAX_ARGV_LEN] = {'\0'}; 
    cli_param_get_int(STATIC_PARAM, 0, &time, u);
    /*Convert int to string*/
    sprintf(hellotime, "%d", time);
    
    if(0 == cli_check_stp_time(MSTP_HELLOTIME, time))
    {
        nvram_set("mstp_hello_time", hellotime);
        if('1' == *mstp_enable)
        {
			SYSTEM("/usr/sbin/mstpctl hello %d >/dev/null 2>&1", time);
		}
        syslog(LOG_NOTICE, "[CONFIG-5-SPANNINGTREE]: Set the MSTP hello time to %ss, %s\n", hellotime, getenv("LOGIN_LOG_MESSAGE"));
    }
	free(mstp_enable);
	
	return 0;
}

int func_stp_mst_maxage_param(struct users *u)
{
	char *mstp_enable = nvram_safe_get("mstp_enable");
	    
    int time = 0;
    char maxage[MAX_ARGV_LEN] = {'\0'}; 
    cli_param_get_int(STATIC_PARAM, 0, &time, u);
    /*Convert int to string*/
    sprintf(maxage, "%d", time);
    
    if(0 == cli_check_stp_time(MSTP_MAXAGE, time))
    {
        nvram_set("mstp_max_age", maxage);
        if('1' == *mstp_enable){
        SYSTEM("/usr/sbin/mstpctl maxage %d >/dev/null 2>&1", time);
		}
        syslog(LOG_NOTICE, "[CONFIG-5-SPANNINGTREE]: Set the MSTP max age to %ss, %s\n", maxage, getenv("LOGIN_LOG_MESSAGE"));
    }
	free(mstp_enable);
	return 0;
}

int func_stp_mst_maxhops_param(struct users *u)
{
	char *mstp_enable = nvram_safe_get("mstp_enable");
	    
    int time = 0;
    char maxhops[MAX_ARGV_LEN] = {'\0'}; 
    cli_param_get_int(STATIC_PARAM, 0, &time, u);
    /*Convert int to string*/
    sprintf(maxhops, "%d", time);
    nvram_set("mstp_max_hops", maxhops);

	if('1' == *mstp_enable){
		SYSTEM("/usr/sbin/mstpctl maxhops %d >/dev/null 2>&1", time);
	}
    syslog(LOG_NOTICE, "[CONFIG-5-SPANNINGTREE]: Set the MSTP max hops to %s, %s\n", maxhops, getenv("LOGIN_LOG_MESSAGE"));
	free(mstp_enable);
	return 0;
}

int func_stp_portfast_bpdufilter(struct users *u)
{
	char *mstp_enable = nvram_safe_get("mstp_enable");

	nvram_set("mstp_bpdufilter_global", "1");

	if('1' == *mstp_enable)
	{
		SYSTEM("/usr/sbin/mstpctl bpdufilterglobal yes >/dev/null 2>&1");
	}
	syslog(LOG_NOTICE, "[CONFIG-5-SPANNINGTREE]: Enable bdpu filter by default on all portfast ports, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	free(mstp_enable);
	return 0;
}

/* Disable mst function */
int nfunc_stp_mode_mstp(void)
{
	char *mstp_enable = nvram_safe_get("mstp_enable");

	if('1' == *mstp_enable) {
		nvram_set("mstp_enable", "0");
		SYSTEM("/usr/bin/killall mstpd >/dev/null 2>&1");
        syslog(LOG_NOTICE, "[CONFIG-5-SPANNINGTREE]: Disabled MSTP, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	}
	free(mstp_enable);
	return 0;
}

int nfunc_stp_mst_word_prio(struct users *u)
{
	char *mstp_enable = nvram_safe_get("mstp_enable");
	char *mstp_instance_priority = nvram_safe_get("mstp_instance_priority");
	char entry[MAX_ARGV_LEN] = {'\0'};
	char *p;
	int iPrio[MAX_INSTANCE] = {32768};
	int iFlag[MAX_INSTANCE] = {0};
	int count, flag = 1;
	p = mstp_instance_priority;

	for (count = 0; count < MAX_INSTANCE; count++) {
		if(!(p && *p)) {
			break;
		}
		iPrio[count] = atoi(strsep(&p, ";"));
	}

	cli_param_get_string(STATIC_PARAM, 0, entry, u);
	cli_analysis_string(32768, entry, iPrio);
	cli_analysis_string(flag, entry, iFlag);

	strcpy(mstp_instance_priority, "");
	for (count = 0; count < MAX_INSTANCE; count++) {
		sprintf(mstp_instance_priority, "%s%d;", mstp_instance_priority, iPrio[count]);
		
		if (('1' == *mstp_enable) && (1 == iFlag[count])) {
			SYSTEM("/usr/sbin/mstpctl treeprio %d %d >/dev/null 2>&1", count, 8);
		}
	}
	nvram_set("mstp_instance_priority", mstp_instance_priority);
	syslog(LOG_NOTICE, "[CONFIG-5-SPANNINGTREE]: MSTI %s priority was set to default, %s\n", entry, getenv("LOGIN_LOG_MESSAGE"));
	free(mstp_instance_priority);
	free(mstp_enable);
	return 0;
}

int nfunc_stp_mst_word_rt(struct users *u)
{
	char *mstp_enable = nvram_safe_get("mstp_enable");
	char *mstp_instance_root = nvram_safe_get("mstp_instance_root");
	char entry[MAX_ARGV_LEN] = {'\0'};
	char *p;
	int count;
	int root[MAX_INSTANCE] = {0};
	p = mstp_instance_root;

	for (count = 0; count < MAX_INSTANCE; count++) {
		if(!(p && *p)) {
			break;
		}
		root[count] = atoi(strsep(&p, ";"));
	}

	cli_param_get_string(STATIC_PARAM, 0, entry, u);
	cli_analysis_string(0, entry, root);

	strcpy(mstp_instance_root, "");
	for (count = 0; count < MAX_INSTANCE; count++) {
		sprintf(mstp_instance_root, "%s%d;", mstp_instance_root, root[count]);
	}
	nvram_set("mstp_instance_root", mstp_instance_root);
	if ('1' == *mstp_enable) {
		//SYSTEM("...");
	}

	free(mstp_instance_root);
	free(mstp_enable);
	return 0;
}
int cli_set_instance_vlan_default(int skfd, char *mstp_vlan_instance, uint16 instance)
{
	char *p_str = strdup(mstp_vlan_instance);
	char *p = p_str;
	char *entry, *vlan_str;
	uint16 begin_num, end_num, iLoop, mstid;

	while(p && *p) 
	{
		entry = strsep(&p, ";");/* get one instance config */
		mstid = atoi(strsep(&entry, ":")); /* get instance number */
		if (mstid == instance) 
		{
			while(entry && *entry) 
			{
				vlan_str = strsep(&entry, ",");
				if (strchr(vlan_str, '-')) /* if the vlan is range */
				{
					begin_num = atoi(strsep(&vlan_str, "-"))-1; /* the first vlan id of the range vlan */
					end_num = atoi(vlan_str);	/* the last vlan id of the range vlan */
					for(iLoop = begin_num; iLoop < end_num; iLoop++) 
					{
						bcm_mstp_msti_map_vlan(skfd, 0, iLoop+1); /* set the vlan's msti to 0*/
					}
				}
				else /* if the vlan is one number */
				{
					end_num = atoi(vlan_str);
					bcm_mstp_msti_map_vlan(skfd, 0, end_num); /* set the vlan's msti to 0*/
				}
			}
		}
	}
	free(p_str);
	return 0;
}
int nfunc_mst_instance_id(struct users *u)
{
	int skfd;
	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return CLI_FAILED;

	char *mstp_enable = nvram_safe_get("mstp_enable");
	char *instance_vlan = nvram_safe_get("mstp_instance_vlan");
	char instance_buff[4096], *p = instance_vlan;

	int instance = 0;
	cli_param_get_int(STATIC_PARAM, 0, &instance, u);
	cli_set_instance_vlan_default(skfd, instance_vlan, instance);
	cli_modify_mst_instance(instance_vlan, instance, NULL, instance_buff);

	nvram_set("mstp_instance_vlan", instance_buff);
	if ('1' == *mstp_enable) {
		while (p && *p) {
			SYSTEM("/usr/sbin/mstpctl vid2mstid %s >/dev/null 2>&1", strsep(&p, ";"));
		}
	}
	syslog(LOG_NOTICE, "[CONFIG-5-SPANNINGTREE]: MSTI %d vlan mapping was set to default, %s\n", instance, getenv("LOGIN_LOG_MESSAGE"));
	free(instance_vlan);
	free(mstp_enable);
	close(skfd);
	return 0;
}

int cli_set_vlan_mstid(int skfd, char *vlan, uint16 mstid)
{
	char *p, *p_str, *entry;
	uint16 begin_num, end_num, iLoop;
	p_str = strdup(vlan);
	p = p_str;
vty_output("%s:%d\n", __FILE__, __LINE__);	
	while(p && *p) {
		entry = strsep(&p, ",");
		if (strchr(entry, '-')) {
			begin_num = atoi(strsep(&entry, "-"))-1;/* the first vlan id */
			end_num = atoi(entry); /* the last vlan id */
			for(iLoop = begin_num; iLoop < end_num; iLoop++) {
				bcm_mstp_msti_map_vlan(skfd, mstid, iLoop+1);
				vty_output("%s:%d:vlan %d new msti %d\n", __FILE__, __LINE__, iLoop+1, mstid);/*renshanming: for debug*/
			}
		}
		else
		{
			end_num = atoi(entry);
			bcm_mstp_msti_map_vlan(skfd, mstid, end_num);
			vty_output("%s:%d:vlan %d new msti %d\n", __FILE__, __LINE__, end_num, mstid);/*renshanming: for debug*/
		}
		
	}
	free(p_str);
	return 0;
}
int nfunc_mst_instance_id_vlan_line(struct users *u)
{
	int skfd;
	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return CLI_FAILED;
	char *mstp_enable = nvram_safe_get("mstp_enable");
	char instance_buff[4096], *instance_vlan = nvram_safe_get("mstp_instance_vlan");

	char vlan[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_string(STATIC_PARAM, 0, vlan, u);
	cli_set_vlan_mstid(skfd, vlan, 0);
	cli_modify_mst_instance(instance_vlan, 0, vlan, instance_buff);
	nvram_set("mstp_instance_vlan", instance_buff);
	if ('1' == *mstp_enable) {
		SYSTEM("/usr/sbin/mstpctl vid2mstid 0:%s >/dev/null 2>&1", vlan);
	}
	syslog(LOG_NOTICE, "[CONFIG-5-SPANNINGTREE]: Vlan %s mapping to CST, %s\n", vlan, getenv("LOGIN_LOG_MESSAGE"));
	free(instance_vlan);
	free(mstp_enable);
	close(skfd);
	return 0;
}

int nfunc_mst_name(struct users *u)
{
	char *mstp_enable = nvram_safe_get("mstp_enable");
	char *revision = nvram_safe_get("mstp_revision");

	nvram_set("mstp_name", "");
	if ('1' == *mstp_enable) {
		SYSTEM("/usr/sbin/mstpctl setmstconfid %s: >/dev/null 2>&1", revision);
	}
	syslog(LOG_NOTICE, "[CONFIG-5-SPANNINGTREE]: MSTP configuration name set to default, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	free(revision);
	free(mstp_enable);
	return 0;
}

int nfunc_mst_revision(struct users *u)
{
	char *mstp_enable = nvram_safe_get("mstp_enable");
	char *name = nvram_safe_get("mstp_name");

	nvram_set("mstp_revision", "0");
	if ('1' == *mstp_enable) {
		SYSTEM("/usr/sbin/mstpctl setmstconfid %d:%s >/dev/null 2>&1", 0, name);
	}
	syslog(LOG_NOTICE, "[CONFIG-5-SPANNINGTREE]: MSTP configuration revision set to default, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	free(name);
	free(mstp_enable);
	return 0;
}

int nfunc_stp_mst_fwdtime(struct users *u)
{
	char *mstp_temp = nvram_get_def("mstp_fwd_delay");
    char *mstp_enable;
    
    if(NULL == mstp_temp)
    {
        if(-1 == cli_check_stp_time(MSTP_FWDDELAY, 15))
        {
            vty_output("Set the forward-delay to default(15s) failed!\n");
            return -1;
        } else {
            nvram_set("mstp_fwd_delay", "15"); 
        }
    } else {
        if(-1 == cli_check_stp_time(MSTP_FWDDELAY, atoi(mstp_temp)))
        {
            free(mstp_temp);
			vty_output("Set the forward-delay to default(15s) failed!\n");
            return -1;
        } else {
            nvram_set("mstp_fwd_delay", mstp_temp);
            free(mstp_temp);
        }
    }
    mstp_enable = nvram_safe_get("mstp_enable");
    if('1' == *mstp_enable)
    {
        SYSTEM("/usr/sbin/mstpctl fdelay %d >/dev/null 2>&1", 15);
    }
    free(mstp_enable);
    syslog(LOG_NOTICE, "[CONFIG-5-NO]: The MSTP forword time has been set to 15s, %s\n", getenv("LOGIN_LOG_MESSAGE")); 
    return 0;
}

int nfunc_stp_mst_hellotime(struct users *u)
{
	char *mstp_temp = nvram_get_def("mstp_hello_time");
    char *mstp_enable;
    
    if(NULL == mstp_temp)
    {
        if(-1 == cli_check_stp_time(MSTP_HELLOTIME, 2))
        {
            vty_output("Set the hello-time to default(2s) failed!\n");
            return -1;
        } else {
            nvram_set("mstp_hello_time", "2"); 
        }
    } else {
        if(-1 == cli_check_stp_time(MSTP_HELLOTIME, atoi(mstp_temp)))
        {
            vty_output("Set the hello-time to default(2s) failed!\n");
            free(mstp_temp);
			return -1;
        } else {
            nvram_set("mstp_hello_time", mstp_temp);
            free(mstp_temp);
        }
    }
    mstp_enable = nvram_safe_get("mstp_enable");   
    if('1' == *mstp_enable)
    {
        SYSTEM("/usr/sbin/mstpctl hello %d >/dev/null 2>&1", 2);
    }
    free(mstp_enable);
    syslog(LOG_NOTICE, "[CONFIG-5-NO]: The MSTP hello time has been set to 2s, %s\n", getenv("LOGIN_LOG_MESSAGE")); 
    return 0;
}

int nfunc_stp_mst_maxage(struct users *u)
{
	char *mstp_temp = nvram_get_def("mstp_max_age");
    char *mstp_enable;
    
    if(NULL == mstp_temp)
    {
        if(-1 == cli_check_stp_time(MSTP_MAXAGE, 20))
        {
            vty_output("Set the max-age to default(20s) failed!\n");
            return -1;
        } else {
            nvram_set("mstp_max_age", "20"); 
        }
    } else {
        if(-1 == cli_check_stp_time(MSTP_MAXAGE, atoi(mstp_temp)))
        {
            vty_output("Set the max-age to default(20s) failed!\n");
            free(mstp_temp);
			return -1;
        } else {
            nvram_set("mstp_max_age", mstp_temp);
            free(mstp_temp);
        }
    }
    mstp_enable = nvram_safe_get("mstp_enable");
    if('1' == *mstp_enable)
    {
        SYSTEM("/usr/sbin/mstpctl maxage %d >/dev/null 2>&1", 20);
    }
    free(mstp_enable);
    syslog(LOG_NOTICE, "[CONFIG-5-NO]: The MSTP max age has been set to 20s, %s\n", getenv("LOGIN_LOG_MESSAGE")); 
    return 0;
}

int nfunc_stp_mst_maxhops(struct users *u)
{
	char *mstp_temp = nvram_get_def("mstp_max_hops");
    char *mstp_enable;
    
    if(NULL == mstp_temp)
    {
        nvram_set("mstp_max_hops", "20"); 
    } else {
		nvram_set("mstp_max_hops", mstp_temp);
		free(mstp_temp);
    }
    mstp_enable = nvram_safe_get("mstp_enable");
    if('1' == *mstp_enable)
    {
        SYSTEM("/usr/sbin/mstpctl maxhops %d >/dev/null 2>&1", 20);
    }
    free(mstp_enable);
    syslog(LOG_NOTICE, "[CONFIG-5-NO]: The MSTP max hops has been set to 20, %s\n", getenv("LOGIN_LOG_MESSAGE")); 
    return 0;
}

int nfunc_stp_portfast_bpdufilter(struct users *u)
{
	char *mstp_enable = nvram_safe_get("mstp_enable");

	nvram_set("stp_bpdufilter_global", "0");

	if('1' == *mstp_enable)
	{
		SYSTEM("/usr/sbin/mstpctl bpdufilterglobal no >/dev/null 2>&1");
	}
	syslog(LOG_NOTICE, "[CONFIG-5-SPANNINGTREE]: Disable bdpu filter by default on all portfast ports, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	free(mstp_enable);
	return 0;
}
