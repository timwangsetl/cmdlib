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

#include "cli_mirror_func.h"
#include "bcmutils.h"

static int cli_set_mirror_destination(char *session,char *desinter)
{
	char buff[128] = {0};
	char *mirror_enable = NULL;
    char *session_config = NULL;
    char *destination_config = NULL;	
    char *egress_config,*ingress_config = NULL;
    //char mirror[256],tmp[32];
  
    uint64_t e_port_maps,in_port_maps;
	int session_num = atoi(session);

	session_config = nvram_safe_get("con_session");
	mirror_enable  = nvram_safe_get("mirror_enable");
    egress_config  = nvram_safe_get("egress_config");
    ingress_config = nvram_safe_get("ingress_config");
    destination_config = nvram_safe_get("destination_config");
   
    str2bit(egress_config, &e_port_maps);
    str2bit(ingress_config, &in_port_maps);
    if(( in_port_maps & (0x01ULL << phy[atoi(desinter)]))||( e_port_maps & (0x01ULL << phy[atoi(desinter)])))
    {
        if(atoi(desinter) <= FNUM)
        {    
            vty_output(" Interface FastEthernet 0/%d already configured as mirror source\n",atoi(desinter));
        }
        else
        {
            vty_output(" Interface GigaEthernet 0/%d already configured as mirror source\n",(atoi(desinter)-FNUM));
        }
		
		free(mirror_enable);
		free(egress_config);		
		free(ingress_config);
		free(session_config);
		free(destination_config);
		
        return 0;
    }

	memset(buff, '\0', sizeof(buff));
	nvram_string_insert(buff, destination_config, desinter, session_num);	
    nvram_set("destination_config", buff);
	
	memset(buff, '\0', sizeof(buff));
	nvram_string_insert(buff, mirror_enable, "1", session_num);	
   	nvram_set("mirror_enable", buff);

	memset(buff, '\0', sizeof(buff));
	nvram_string_insert(buff, session_config, session, session_num);	
   	nvram_set("con_session", buff);
	
	free(mirror_enable);
	free(egress_config);		
	free(ingress_config);
	free(session_config);
	free(destination_config);

    system("rc mirror restart &");

	SYSTEM("/usr/bin/killall -SIGUSR2 rstp >/dev/null 2>&1");/*shanming.ren 2012-5-24 14:13:40*/
    syslog(LOG_NOTICE, "[CONFIG-5-MIRROR]: The session was set to %s and mirror destination was set to %s, %s\n", session, desinter, getenv("LOGIN_LOG_MESSAGE"));

	return 0;
}

static int cli_set_mirror_source(char *session,char *souinter,int type)
{
    char *egress_config,*ingress_config,*destination_config,*p_eg,*p_in,*p_eg2,*p_in2;	
	char *egress_config_tmp, *ingress_config_tmp;
	char *mirror_enable;
  //  char mirror_capture[256], type_str[32],tmp[32];
    char *ptr_1;//*ptr_2;
    uint64_t port_maps,mirror_egress,mirror_ingress; 
	char buff[128];
	int i = 0;
	char tmp1[128], tmp2[128];	
	char *tmp3 = NULL, *tmp4 = NULL;
    
    str2bit(souinter, &port_maps);    
    nvram_set("con_session",session);
	
    destination_config = nvram_safe_get("destination_config");
    egress_config_tmp = nvram_safe_get("egress_config");
    ingress_config_tmp = nvram_safe_get("ingress_config");
	mirror_enable = nvram_safe_get("mirror_enable");
	
	strcpy(tmp1, egress_config_tmp);	
	strcpy(tmp2, ingress_config_tmp);

	tmp3 = tmp1;
	tmp4 = tmp2;

	int session_num = atoi(session);

	for(i=1; i<=4; i++)
	{
		egress_config = strsep(&tmp3, ";");		
		ingress_config = strsep(&tmp4, ";");
	
		if(i != session_num)
			continue;
		
	    p_eg=egress_config;
	    p_in=ingress_config;

	    if(strlen(p_eg)==0)
	    {
	        mirror_egress= 0x00ULL;
	    }
	    else
	    {
	        str2bit(p_eg, &mirror_egress);
	    }
	    if(strlen(p_in)==0)
	    {
	        mirror_ingress= 0x00ULL;
	    }
	    else
	    {
	        str2bit(p_in, &mirror_ingress);
	    }
	}
    ptr_1 = destination_config;

    if(port_maps & (0x01ULL << phy[atoi(ptr_1)]))
    {
        if(atoi(ptr_1) <= FNUM)
        {
            vty_output(" Interface FastEthernet 0/%d already configured as mirror destinations\n",atoi(ptr_1));
        }
        else
        {
            vty_output(" Interface GigaEthernet 0/%d already configured as mirror destinations\n",(atoi(ptr_1)-FNUM));
        }
		free(destination_config);
		free(egress_config_tmp);
		free(ingress_config_tmp);
		return 0;
    }
    switch(type)
    {    
         case 0:mirror_egress|=port_maps;
                mirror_ingress|=port_maps;
                break;
         case 1:mirror_egress&=(~port_maps);
                mirror_ingress|=port_maps;
                break;    
         case 2:mirror_egress|=port_maps;
                mirror_ingress&=(~port_maps);
                break;            
    }

    if(mirror_egress|0x00ULL)    
    {
        p_eg2 =bit2str(mirror_egress);
    }
    else
    {
        p_eg2="";    
    }
    if(mirror_ingress|0x00ULL)    
    {
        p_in2 =bit2str(mirror_ingress);
    }
    else
    {
        p_in2="";
    }

	memset(buff, '\0', sizeof(buff));
	nvram_string_insert(buff, egress_config_tmp, p_eg2, session_num);
    nvram_set("egress_config",buff);

	memset(buff, '\0', sizeof(buff));
	nvram_string_insert(buff, ingress_config_tmp, p_in2, session_num);	
    nvram_set("ingress_config",buff);  
	
	memset(buff, '\0', sizeof(buff));
	nvram_string_insert(buff, mirror_enable, "1", session_num);	
    nvram_set("mirror_enable", buff);

	free(mirror_enable);
    free(destination_config);
    free(egress_config_tmp);
    free(ingress_config_tmp);
    
    system("rc mirror restart &");
    
    switch(type) {    
         case 0:
            syslog(LOG_NOTICE, "[CONFIG-5-MIRROR]: The session was set to %s and source was set to %s and type was monitor received and transmitted traffic, %s\n", session, souinter, getenv("LOGIN_LOG_MESSAGE"));
            break;
         case 1:
            syslog(LOG_NOTICE, "[CONFIG-5-MIRROR]: The session was set to %s and source was set to %s and type was monitor received traffic only, %s\n", session, souinter, getenv("LOGIN_LOG_MESSAGE"));
            break;    
         case 2:
            syslog(LOG_NOTICE, "[CONFIG-5-MIRROR]: The session was set to %s and source was set to %s and type was monitor transmitted traffic only, %s\n", session, souinter, getenv("LOGIN_LOG_MESSAGE"));
            break;    
         default:
            break;        
    }
    return 0;
}

static int cli_mirror_source_disable(char *souinter,int type)    
{
    uint64_t egress_int,ingress_int,modify_int,original_int,destination_int;
    char *destination,*egress,*ingress,*p_eg2,*p_in2;;
    destination=nvram_safe_get("destination_config");
    egress=nvram_safe_get("egress_config");
    ingress=nvram_safe_get("ingress_config");

    str2bit(egress,&egress_int);
    str2bit(ingress,&ingress_int);
    str2bit(souinter,&modify_int);
    str2bit(destination,&destination_int);
    original_int=(ingress_int&egress_int);
    
    if((destination_int&egress_int)||(destination_int&ingress_int))
    {
        vty_output("  In the source config exist destination port\n");
		free(destination);
		free(egress);
		free(ingress);
        return CLI_FAILED;
    }
    if(strlen(egress)||strlen(ingress))
    {
        switch(type)
        {
            case 4:
                egress_int=((~modify_int)&egress_int);
                ingress_int=((~modify_int)&ingress_int);
                break;
             case 1:
                if((original_int|modify_int)==original_int)
                {
                    egress_int=((~modify_int)&egress_int);
                    ingress_int=((~modify_int)&ingress_int);
                }
                else
                {
                    vty_output("  Source port select error\n");
					free(destination);
					free(egress);
					free(ingress);
                    return CLI_FAILED;
                }
                break;
            case 2:
                if((ingress_int|modify_int)==ingress_int)
                {
                    ingress_int=((~modify_int)&ingress_int);
                }
                else
                {
                    vty_output("  Source port select error\n");
					free(destination);
					free(egress);
					free(ingress);

					return CLI_FAILED;
                }
                break;
            case 3: 
                if((egress_int|modify_int)==egress_int)
                {
                    egress_int=((~modify_int)&egress_int);
                }
                else
                {
                    vty_output("  Source port select error\n");
					free(destination);
					free(egress);
					free(ingress);

					return CLI_FAILED;
                }
                break;
        }            
    }
    else
    {
        vty_output("  Undefined mirror source\n");
		free(destination);
		free(egress);
		free(ingress);

        return CLI_FAILED;
    }
    
    if(egress_int|0x00ULL)    
    {
        p_eg2 =bit2str(egress_int);
    }
    else
    {
        p_eg2="";
    }
    if(ingress_int|0x00ULL)    
    {
        p_in2 =bit2str(ingress_int);
    }
    else
    {
        p_in2="";
    }
    nvram_set("egress_config",p_eg2);
    nvram_set("ingress_config",p_in2); 

    free(destination);
    free(egress);
    free(ingress);
    
    system("rc mirror restart &");
    
    switch(type) {
        case 4:
            syslog(LOG_NOTICE, "[CONFIG-5-NO]: Delete the mirror source of port %s, %s\n", souinter, getenv("LOGIN_LOG_MESSAGE"));
            break;
        case 1:
            syslog(LOG_NOTICE, "[CONFIG-5-NO]: Delete the mirror source of port %s, %s\n", souinter, getenv("LOGIN_LOG_MESSAGE"));
            break;
        case 2:
            syslog(LOG_NOTICE, "[CONFIG-5-NO]: Delete the type RX on the mirror source of port %s, %s\n", souinter, getenv("LOGIN_LOG_MESSAGE"));
            break;
        case 3:
            syslog(LOG_NOTICE, "[CONFIG-5-NO]: Delete the type TX on the mirror source of port %s, %s\n", souinter, getenv("LOGIN_LOG_MESSAGE"));
            break;
    }
    return 0;
}

/*
 *  Function:  func_mirror_interface_dst
 *  Purpose:  mirror session 1 destination interface fastEthernet/gigaEthernet <0/N> <cr>
 *  Parameters:
 *     struct users *u
 *  Returns:
 *     0
 *  Author:   chunli.wu
 *  Date:     2011/12/01
 */

int func_mirror_interface_dst(struct users *u)
{
    int session_num = 0;
    int port_num = 0;
    uint64 bmaps1 = 0x00ULL;
    char session_str[MAX_ARGV_LEN] = {'\0'};
    char port_str[MAX_ARGV_LEN] = {'\0'};
    char *gport_str = NULL;
	char buff[128];
    
    cli_param_get_int(STATIC_PARAM, 0, &session_num, u);
    cli_param_get_int(STATIC_PARAM, 1, &port_num, u);
    
    /*Convert int to string*/
    sprintf(session_str, "%d", session_num);
    sprintf(port_str, "%d", port_num);
    
     /*fast port*/
    if(ISSET_CMD_MSKBIT(u, MIRROR_IF_FAST_PORT))
    {
        cli_set_mirror_destination(session_str,port_str);
    }
    /*giga port*/
    else if(ISSET_CMD_MSKBIT(u, MIRROR_IF_GIGA_PORT))
    {
        str2bit(port_str, &bmaps1);
        bmaps1 <<= (phy[FNUM+1]-phy[1]);
        gport_str = bit2str(bmaps1);									//置配置的目的端口的位。
        cli_set_mirror_destination(session_str,gport_str);
    }
    else
    {
        DEBUG_MSG(1, "Unknow interface type!!\n", NULL);
    }
    
    return 0;
}


int func_mirror_soure_vlan(struct users *u)
{
    int session_num = 0;
    int vlan_num = 0;
    char vlan_str[32];
    
    cli_param_get_int(STATIC_PARAM, 0, &session_num, u);
    cli_param_get_int(STATIC_PARAM, 1, &vlan_num, u);
    
    memset(vlan_str, '\0', sizeof(vlan_str));
    sprintf(vlan_str, "%d", vlan_num); 

    nvram_set("mirror_vlan", vlan_str);
    nvram_set("mirror_enable", "1");
    system("rc mirror restart");

    return 0;
}

/*
 *  Function:  func_mirror_interface_src
 *  Purpose:  mirror session 1 source interface fastEthernet/gigaEthernet <0/P,N-M> both/tx/rx/<cr>
 *  Parameters:
 *     struct users *u
 *  Returns:
 *     0
 *  Author:   chunli.wu
 *  Date:     2011/12/01
 */

int func_mirror_interface_src(struct users *u)
{
    int session_num = 0;
    int type = 0;
    uint64 bmaps1 = 0x00ULL;
    char session_str[MAX_ARGV_LEN] = {'\0'};
    char port_range[MAX_ARGV_LEN] = {'\0'};
    char *gport_str = NULL;
    
    cli_param_get_int(STATIC_PARAM, 0, &session_num, u);
    sprintf(session_str, "%d", session_num);

    /* range format: f0/P,N-M */
    cli_param_get_range(STATIC_PARAM, port_range, u);
    
    /*fast port*/
    if(ISSET_CMD_MSKBIT(u, MIRROR_IF_FAST_PORT))
    {
        if(ISSET_CMD_MSKBIT(u, MIRROR_IF_RX))
        {
            /* rx */
            type = 1;
        }
        else if(ISSET_CMD_MSKBIT(u, MIRROR_IF_TX))
        {
            /* tx */
            type = 2;
        }
        else
        {
            /* both and no option */
            type = 0;
        }
    cli_set_mirror_source(session_str, port_range+3, type);
    }
    
    /*giga port*/
    else if(ISSET_CMD_MSKBIT(u, MIRROR_IF_GIGA_PORT))
    {
        str2bit(port_range+3, &bmaps1);
        bmaps1 <<= (phy[FNUM+1]-phy[1]);
        gport_str = bit2str(bmaps1);
        if(ISSET_CMD_MSKBIT(u, MIRROR_IF_RX))
        {
            /* rx */
            type = 1;
        }
        else if(ISSET_CMD_MSKBIT(u, MIRROR_IF_TX))
        {
            /* tx */
            type = 2;
        }
        else
        {
            /* both and no option */
            type = 0;
        }            
        cli_set_mirror_source(session_str, gport_str, type);            
    }
    else
    {
        DEBUG_MSG(1, "Unknow interface type!!\n", NULL);
    }
 
    return 0;
}

int func_mirror_vlan_set(struct users *u)
{
	int i = 0;														//用来对应session数据的位置
	int ret = 0;
	int skfd = -1;
	int monitor = 0;
    int vlan_num = 0;
    int session_num = 0;
	char *mirror_enable = NULL;
	char *session_config = NULL;
	char *mirror_vlan_config = NULL;
	char *destination_config = NULL;	
	char *mirror_enable_tmp = NULL;
	char *destination_config_tmp = NULL;
	
	char buff[128] = {0};
	char vlan_str[32] = {0};
	char session_str[32] = {0};
	char mirror_enable_strsep[32] = {0};							//存储用于字符串切割的一段栈内存
	char destination_config_strsep[32] = {0};

	char *p1 = NULL;												//用来指向mirror_enable_strsep栈内存
	char *p2 = NULL;												//用来指向destination_config_tmp栈内存

	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0)
		return CLI_FAILED;
    
    cli_param_get_int(STATIC_PARAM, 0, &session_num, u);
    cli_param_get_int(STATIC_PARAM, 1, &vlan_num, u);
	
	session_config = nvram_safe_get("con_session");
	mirror_vlan_config = nvram_safe_get("mirror_vlan");
	mirror_enable_tmp = nvram_safe_get("mirror_enable");
  	destination_config_tmp = nvram_safe_get("destination_config");

	memset(vlan_str, 0, sizeof(vlan_str));
	memset(session_str, 0, sizeof(session_str));
	sprintf(vlan_str, "%d", vlan_num);
	sprintf(session_str, "%d", session_num);

	/*
	此处用一段栈内存来存储用于切割的字符串
	目的是防止因为strsep()切割指针指向的堆内存时，指针发生偏移导致没办法正确的释放空间内存造成内存泄漏
	后续若有更好的处理方法，再进行修改
	*/
	memset(mirror_enable_strsep, 0, sizeof(mirror_enable_strsep));
	memset(destination_config_strsep, 0, sizeof(destination_config_strsep));
	sprintf(mirror_enable_strsep, "%s", mirror_enable_tmp);
	sprintf(destination_config_strsep, "%s", destination_config_tmp);

	p1 = mirror_enable_strsep;
	p2 = destination_config_strsep;

	do
	{
		mirror_enable = strsep(&p1, ";");
		destination_config = strsep(&p2, ";");
		i++;
	}while((i != session_num) && (i <= 4));

	if('1' == *mirror_enable)
	{
		if(strlen(destination_config))            
        	monitor = atoi(destination_config);   
		
		ret = set_bcm_mirror_vlan(skfd, 1, session_num, monitor, vlan_num);
	}
	else
	{
        DEBUG_MSG(1, "Please set the destination port first!!\n", NULL);
	}	

	if(!ret)
	{
		memset(buff, '\0', sizeof(buff));
		nvram_string_insert(buff, mirror_vlan_config, vlan_str, session_num);
		nvram_set("mirror_vlan",buff);

		memset(buff, '\0', sizeof(buff));
		nvram_string_insert(buff, session_config, session_str, session_num);
		nvram_set("con_session",buff);
	}

	close(skfd);    

	free(session_config);
	free(mirror_vlan_config);
	free(mirror_enable_tmp);
	free(destination_config_tmp);

    //system("rc mirror restart");

    return 0;
}


/*
 *  Function:  nfunc_session_num
 *  Purpose:  no mirror session 1 <cr>
 *  Parameters:
 *     struct users *u
 *  Returns:
 *     0
 *  Author:   chunli.wu
 *  Date:     2011/12/01
 */

int nfunc_session_num(struct users *u)
{
    uint64 phymaps=0x00ULL;
    
    nvram_set("mirror_enable", "0");
    nvram_set("con_session", "0");
    nvram_set("destination_config", "");
    nvram_set("egress_config", "");
    nvram_set("ingress_config", "");
    nvram_set("mirror_vlan", "");
    
    system("rc mirror stop &");
    
    SYSTEM("/usr/bin/killall -SIGUSR2 rstp >/dev/null 2>&1");/*shanming.ren 2012-5-24 14:13:40*/
    syslog(LOG_NOTICE, "[CONFIG-5-NO]: Disable the mirror function, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    
    return 0;
}

/*
 *  Function:  nfunc_mirror_interface_src
 *  Purpose:  no mirror session 1 source interface fastEthernet/gigaEthernet <0/P,N-M> both/tx/rx/<cr>
 *  Parameters:
 *     struct users *u
 *  Returns:
 *     0
 *  Author:   chunli.wu
 *  Date:     2011/12/01
 */

int nfunc_mirror_interface_src(struct users *u)
{
    int type = 0;
    uint64 bmaps1 = 0x00ULL;
    char *gport_str = NULL;
    char port_range[MAX_ARGV_LEN] = {'\0'};

    /* range format: f0/P,N-M */
    cli_param_get_range(STATIC_PARAM, port_range, u);
    
    /*fast port*/
    if(ISSET_CMD_MSKBIT(u, MIRROR_IF_FAST_PORT))
    {
        if(ISSET_CMD_MSKBIT(u, MIRROR_IF_BOTH))
        {
            /* both */
            type = 1;
        }
        else if(ISSET_CMD_MSKBIT(u, MIRROR_IF_RX))
        {
            /* rx */
            type = 2;
        }
        else if(ISSET_CMD_MSKBIT(u, MIRROR_IF_TX))
        {
            /* tx */
            type = 3;
        }
        else
        {
            /* no option */
            type = 4;
        }
        cli_mirror_source_disable(port_range+3,type);
    }
    
    /*giga port*/
    else if(ISSET_CMD_MSKBIT(u, MIRROR_IF_GIGA_PORT))
    {
        str2bit(port_range+3, &bmaps1);
        bmaps1 <<= FNUM;
        gport_str = bit2str(bmaps1);
        if(ISSET_CMD_MSKBIT(u, MIRROR_IF_BOTH))
        {
            /* both */
            type = 1;
        }
        else if(ISSET_CMD_MSKBIT(u, MIRROR_IF_RX))
        {
            /* rx */
            type = 2;
        }
        else if(ISSET_CMD_MSKBIT(u, MIRROR_IF_TX))
        {
            /* tx */
            type = 3;
        }
        else
        {
            /* no option */
            type = 4;
        }
        cli_mirror_source_disable(gport_str,type);
    }
    else
        DEBUG_MSG(1, "Unknow interface type!!\n", NULL);

    return 0;
}


int nfunc_mirror_vlan_by_session(struct users *u)
{
	int skfd;
	int session_num;

	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0)
		return CLI_FAILED;

	cli_param_get_int(STATIC_PARAM, 0, &session_num, u);

	del_bcm_mirror_vlan(skfd, session_num);

	return 0;
}

