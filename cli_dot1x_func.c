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
#include "cli_dot1x_func.h"

/*dot1x enable*/
int func_do_guest_vlan_enable()
{
	char *dot1x_enable = nvram_safe_get("dot1x_enable");
	char *guest_vlan = nvram_safe_get("guest_vlan_enable");
	
	if('1' == *dot1x_enable)
    {
        if(*guest_vlan != '1')
        {    
        	nvram_set("guest_vlan_enable", "1");
            memset(cur_dot1x_conf, 0, sizeof(cli_dot1x_conf)*PNUM);
            cli_nvram_conf_get(CLI_DOT1X_CONF, (unsigned char *)&cur_dot1x_conf);
            
            system("/usr/bin/killall -SIGUSR1 vlinkscan >/dev/null 2>&1");
    		system("/usr/bin/killall -SIGHUP hostapd > /dev/null 2>&1");
      	    syslog(LOG_NOTICE, "[CONFIG-5-DOT1X]: Enable 802.1X Guest vlan %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	    }
  	    else
    	{
            vty_output("Warning: 802.1X Guest vlan is enable, don't reconfigure again!\n");
    	}
	}else
	{
        vty_output("Error: 802.1X is disable, guest vlan can't been configure!\n");
	}   
	
	free(dot1x_enable); 
	free(guest_vlan); 
	return CLI_SUCCESS;
}

int func_no_guest_vlan_enable()
{
    int portid;
	char *dot1x_enable = nvram_safe_get("dot1x_enable");
	char *guest_vlan = nvram_safe_get("guest_vlan_enable");

	if('1' == *dot1x_enable)
	{    
	    if('1' == *guest_vlan)
    	{
        	nvram_set("guest_vlan_enable", "0");
        	
            memset(cur_dot1x_conf, 0, sizeof(cli_dot1x_conf)*PNUM);
            cli_nvram_conf_get(CLI_DOT1X_CONF, (unsigned char *)&cur_dot1x_conf);
        	for(portid = 1; portid<=PNUM; portid++) 
        	{
        	    cur_dot1x_conf[portid-1].guest_id = 0;
    	    }
            cli_nvram_conf_set(CLI_DOT1X_CONF, (unsigned char *)&cur_dot1x_conf);
    		cli_nvram_conf_free(CLI_DOT1X_CONF, (unsigned char *)&cur_dot1x_conf);
    		
            system("/usr/bin/killall -SIGUSR1 vlinkscan >/dev/null 2>&1");
    		system("/usr/bin/killall -SIGHUP hostapd > /dev/null 2>&1");
      	    syslog(LOG_NOTICE, "[CONFIG-5-DOT1X]: Disable 802.1X Guest vlan %s\n", getenv("LOGIN_LOG_MESSAGE"));
    	}
    	else
    	{
            vty_output("Warning: 802.1X Guest vlan is disable, don't reconfigure again!\n");
    	}	
    }	
    else
	{
        vty_output("Error: 802.1X is disable, guest vlan can't been configure!\n");
	}	
	
	free(dot1x_enable); 
	free(guest_vlan); 
	return CLI_SUCCESS;
}

int func_set_dot1x_enable()
{

	int portid;

	//if(check_hostapd_conf() == 1)
	//{
	//	vty_output("  Please set Radius Server Host or Radius Key first\n");
	//	return CLI_SUCCESS;
	//}

	/* check port trunk mode, dot1x mode */
	memset(cur_port_conf, 0, sizeof(cli_port_conf)*PNUM);
	memset(cur_dot1x_conf, 0, sizeof(cli_dot1x_conf)*PNUM);
	cli_nvram_conf_get(CLI_VLAN_PORT, (unsigned char *)&cur_port_conf);
	cli_nvram_conf_get(CLI_DOT1X_CONF, (unsigned char *)&cur_dot1x_conf);

	for(portid = 1; portid<=PNUM; portid++) {
		if( (cur_port_conf[portid-1].mode == '3') && (cur_dot1x_conf[portid-1].auth_mode != CLI_DOT1X_FAUTH) ) {
			vty_output("  Command rejected: Dot1x is supported only on Ethernet interfaces configured in Access!\n");
			cli_nvram_conf_free(CLI_VLAN_PORT, (unsigned char *)&cur_port_conf);
			cli_nvram_conf_free(CLI_DOT1X_CONF, (unsigned char *)&cur_dot1x_conf);
			syslog(LOG_WARNING, "[CONFIG-4-FAILED]: Command rejected: Dot1x is supported only on ethernet interfaces configured in access, %s\n", getenv("LOGIN_LOG_MESSAGE"));
			return CLI_SUCCESS;
		}
	}
	nvram_set("dot1x_enable","1");
	cli_stop_dot1x();
	cli_start_dot1x();
 
  	syslog(LOG_NOTICE, "[CONFIG-5-DOT1X]: Enabled IEEE 802.1X protocols, %s\n", getenv("LOGIN_LOG_MESSAGE"));
  	return CLI_SUCCESS;
}

int check_hostapd_conf(void)
{
	char *radius_server = nvram_safe_get("radius_server");
	char *radius_port = nvram_safe_get("radius_port"); 
	char *radius_prekey = nvram_safe_get("radius_prekey"); 

	if( (strlen(radius_server) == 0)||(strlen(radius_port) == 0)||(strlen(radius_prekey) == 0) )
	{
		free(radius_server);
		free(radius_port); 
		free(radius_prekey); 
		return 1;
	}
	
	free(radius_server);
	free(radius_port); 
	free(radius_prekey); 
	return 0;
}

int check_is_local(void)
{
	char *list = nvram_safe_get("aaa_auth_login");  
	char *ptr;
	ptr = list;
	if(ptr = strstr(list,"default")){
		ptr = strchr(ptr,':') + 1;
		if(!memcmp(ptr,"local",5)){
			free(list);
			return 1;	
		}else{
			free(list);
			return 0;
		}
		
	}
	free(list);
	return 0;
}


int create_hostapd_conf()
{	
	FILE *fp;
	char *reauth_enable;
	char *reauth_time;
	char *radius_server;
	char *radius_port; 
	char *radius_prekey; 
	char *aaa_server;
	char *aaa_port;
	char *aaa_prekey;
	
    if((fp=fopen("/etc/wired.conf","w"))==NULL){ 

        return 0;
	}

	reauth_enable = nvram_safe_get("reauth_enable");
	reauth_time = nvram_safe_get("reauth_time");
	radius_server = nvram_safe_get("radius_server");
	radius_port = nvram_safe_get("radius_port"); 
	radius_prekey = nvram_safe_get("radius_prekey"); 
	aaa_server = nvram_safe_get("aaa_server");
	aaa_port = nvram_safe_get("aaa_port");
	aaa_prekey = nvram_safe_get("aaa_prekey");

	if (!strlen(reauth_time))    
		strcpy(reauth_time,"3600");
	if (!strlen(reauth_enable))
		*reauth_enable='0';

    /*  move to the beginning of the file */
    fseek(fp,0,SEEK_SET);
    
    /*  create common configures  */
    fprintf(fp,"interface=%s\n", IMP);
    fprintf(fp,"driver=wired\n");
    fprintf(fp,"logger_stdout=-1\n");
    fprintf(fp,"logger_stdout_level=0\n");
    fprintf(fp,"debug=0\n");
    fprintf(fp,"dump_file=/tmp/hostapd.dump\n");

    fprintf(fp,"h3c_clinet=0\n");
    fprintf(fp,"ieee8021x=1\n");
   //if( check_is_local()){
//	fprintf(fp,"eap_authenticator=1\n");
 //  }
   fprintf(fp,"eap_authenticator=0\n");
   // fprintf(fp,"eap_authenticator=1\n");
	/* chaiwanjun 110803 */
    fprintf(fp,"eap_reauth_enable=%s\n", reauth_enable);
    fprintf(fp,"eap_reauth_period=%s\n", reauth_time);

    fprintf(fp,"eap_user_file=/etc/hostapd.eap_user\n");
   // fprintf(fp,"radius_server_clients=/etc/hostapd.radius_clients\n");

    fprintf(fp,"own_ip_addr=127.0.0.1\n");
    fprintf(fp,"nas_identifier=ap.example.com\n");

	if(strlen(radius_server) > 0)
    	fprintf(fp,"auth_server_addr=%s\n", radius_server);
    if(strlen(radius_port) > 0)
    	fprintf(fp,"auth_server_port=%s\n", radius_port);
    if(strlen(radius_prekey) > 0){
		fprintf(fp,"auth_server_shared_secret=%s\n", radius_prekey);
	}else{
		fprintf(fp,"auth_server_shared_secret=%s\n", "radius");
	}

    if(strlen(aaa_server) > 0){
        fprintf(fp,"acct_server_addr=%s\n", aaa_server);
        fprintf(fp,"acct_server_port=%s\n", aaa_port);
		if(strlen(aaa_prekey)){
			fprintf(fp,"acct_server_shared_secret=%s\n", aaa_prekey);
		}else{
        	fprintf(fp,"acct_server_shared_secret=%s\n", "radius");
		}
    }
    free(reauth_enable);
    free(reauth_time);
    free(radius_server);
    free(radius_port); 
    free(radius_prekey); 
    free(aaa_server);
    free(aaa_port);
    free(aaa_prekey);
    
    fclose(fp);
    
    chmod("/etc/wired.conf", 0x777); 

    return 0;
}

int func_set_dot1x_reauth_enable()
{
	char * dot1x_enable = nvram_safe_get("dot1x_enable");
	
	nvram_set("reauth_enable", "1");

	if ('1' == *dot1x_enable){
		//cli_stop_dot1x();
		//cli_start_dot1x(0);
		create_hostapd_conf(); 
		system("/usr/bin/killall -SIGHUP hostapd > /dev/null 2>&1");
	}
	free(dot1x_enable);
  	syslog(LOG_NOTICE, "[CONFIG-5-DOT1X]: Enable 802.1X periodic reauth  %s\n", getenv("LOGIN_LOG_MESSAGE"));
	return CLI_SUCCESS;
}

int func_set_dot1x_quietperiod(char *time)
{
	char * dot1x_enable = nvram_safe_get("dot1x_enable");
	
	nvram_set("quiet_period", time);

	if ('1' == *dot1x_enable){
		create_hostapd_conf(); 
		system("/usr/bin/killall -SIGHUP hostapd > /dev/null 2>&1");
	}
	free(dot1x_enable);
  	syslog(LOG_NOTICE, "[CONFIG-5-DOT1X]: Set period between reauthentication attempts to %s seconds, %s\n", time, getenv("LOGIN_LOG_MESSAGE"));
	return CLI_SUCCESS;
}

int func_set_dot1x_reauth_time(char *time)
{
	char * dot1x_enable = nvram_safe_get("dot1x_enable");
	
	nvram_set("reauth_time", time);

	if ('1' == *dot1x_enable){
		create_hostapd_conf(); 
		system("/usr/bin/killall -SIGHUP hostapd > /dev/null 2>&1");
	}
	free(dot1x_enable);
  	syslog(LOG_NOTICE, "[CONFIG-5-DOT1X]: Set period between reauthentication attempts to %s seconds, %s\n", time, getenv("LOGIN_LOG_MESSAGE"));
	return CLI_SUCCESS;
}

int func_set_dot1x_txperiod(char *time)
{
	char * dot1x_enable = nvram_safe_get("dot1x_enable");
	
	nvram_set("tx_period", time);

	if ('1' == *dot1x_enable){
		create_hostapd_conf(); 
		system("/usr/bin/killall -SIGHUP hostapd > /dev/null 2>&1");
	}
	free(dot1x_enable);	
  	syslog(LOG_NOTICE, "[CONFIG-5-DOT1X]: Set period between reauthentication attempts to %s seconds, %s\n", time, getenv("LOGIN_LOG_MESSAGE"));
	return CLI_SUCCESS;
}

int nfunc_set_dot1x_disable()
{        
    nvram_set("dot1x_enable", "0");
	nvram_set("guest_vlan_enable", "0");
    
    cli_stop_dot1x();
    syslog(LOG_NOTICE, "[CONFIG-5-NO]: Stop the Dot1x, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	return CLI_SUCCESS;
}

int nfunc_set_dot1x_quietperiod_default()
{
	char * dot1x_enable = nvram_safe_get("dot1x_enable");
	nvram_set("quiet_period", "10");

	if ('1' == *dot1x_enable){
		create_hostapd_conf(); 
		system("/usr/bin/killall -SIGHUP hostapd > /dev/null 2>&1");
	}
	
	free(dot1x_enable);
	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Set reauth period timeout to default value, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	return CLI_SUCCESS;
}


int nfunc_set_dot1x_timeout_default()
{
	char * dot1x_enable = nvram_safe_get("dot1x_enable");
	nvram_set("reauth_time", "3600");

	if ('1' == *dot1x_enable){
		create_hostapd_conf(); 
		system("/usr/bin/killall -SIGHUP hostapd > /dev/null 2>&1");
	}
	free(dot1x_enable);	
	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Set reauth period timeout to default value, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	return CLI_SUCCESS;
}


int nfunc_set_dot1x_txperiod_default()
{ 
	char * dot1x_enable = nvram_safe_get("dot1x_enable");
	nvram_set("tx_period", "3");
	if ('1' == *dot1x_enable){
		create_hostapd_conf(); 
		system("/usr/bin/killall -SIGHUP hostapd > /dev/null 2>&1");
	}
	free(dot1x_enable);
	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Set reauth period timeout to default value, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	return CLI_SUCCESS;
}

































