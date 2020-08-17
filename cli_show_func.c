
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
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

#include <if_info.h>

#include "bcmutils.h"
#include "console.h"
#include "cmdparse.h"
#include "parameter.h"
#include "cli_show_func.h"

#include "../err_disable/err_disable.h"
extern int ip_ext_acl_set(char *name, IP_EXTENDED_ACL_ENTRY *entry, int method, int location, uint64 bmaps);
extern int ip_std_acl_set(char *name, IP_STANDARD_ACL_ENTRY *entry, int method, int location, uint64 bmaps);
extern int mac_acl_set(char *name, MAC_ACL_ENTRY *entry, int method, int location, uint64 bmaps);

#define show_fun(fmt,arg...)		//printf("[%s %d]"fmt,__FUNCTION__,__LINE__,##arg)

int c_type=0, c_port=0, c_vid=0; 
uint64_t c_mac=0x00ULL, c_multi=0x00ULL;
/*-------------------------------show access list-----------------------------------*/
/* read running config file */                              
static void cli_read_config(char *file)                     
{                                                           
	char line[256];                                         
	FILE *fp;                                               
//	int cli_cnt = 0, cli_r = 0;                             
                                                            
	if(access(file,F_OK) == 0)                              
    {                                                       
    	fp=fopen(file,"r");                                 
		if(fp == NULL)                                      
			return;                                         
                                                            
		fseek(fp, 0, SEEK_SET);                             
   		memset(&line, '\0', 256);                           
    	                                                    
   		while(fgets(line, 256, fp)!=NULL)                   
			vty_output("%s", line);                   
                                                            
   		fclose(fp);			                                
 	}                                                        
}                                                           
                                                            
/* show ip extended acl , betty add*/                       
 static int cli_show_running_ip_ext_acl()                   
{                                                           
	IP_EXTENDED_ACL_ENTRY entry;                            
	                                                        
	memset(&entry, '\0', sizeof(IP_EXTENDED_ACL_ENTRY));    
	ip_ext_acl_set("", &entry, ACL_LIST_PRINT, -1, 0x00ULL);
	                                                        
	return 0;                                               
}                                                           
/* show ip standard acl , betty add*/                       
static int cli_show_running_ip_std_acl()                    
{                                                           
	IP_STANDARD_ACL_ENTRY entry;                            
	                                                        
	memset(&entry, '\0', sizeof(IP_STANDARD_ACL_ENTRY));    
	ip_std_acl_set("", &entry, ACL_LIST_PRINT, -1, 0x00ULL);
	                                                        
	return 0;                                               
} 
static int cli_show_running_ipv6_std_acl()                    
{                                                           
	IPV6_STANDARD_ACL_ENTRY entry;                            
	                                                        
	memset(&entry, '\0', sizeof(IPV6_STANDARD_ACL_ENTRY));    
	ipv6_std_acl_set("", &entry, ACL_LIST_PRINT, -1, 0x00ULL);
	                                                        
	return 0;                                               
}  
static int cli_show_running_mac_acl()                       
{                                                           
	MAC_ACL_ENTRY entry;                                    
	                                                        
	memset(&entry, '\0', sizeof(MAC_ACL_ENTRY));            
	mac_acl_set("", &entry, ACL_LIST_PRINT, -1, 0x00ULL);   
	                                                        
	return 0;                                               
}                                                           

int func_show_aaa_user()
{
#ifdef CLI_AAA_MODULE
	struct aaa_user_info *aaa_user;
	int num, i;
	char port[11], time_str[15];
	char time[10];
	struct timeval now;
	uint32_t hour, minute, second;

	gettimeofday(&now, NULL);
	num = aaa_user_read_config(&aaa_user);

	if (aaa_user == NULL)
		return -1;

	vty_output(" %-10s%-20s%-8s%-10s%-20s\n", "Port", "User", "Service", "Duration", "Peer Address");
	vty_output(" ====================================================================\n");

	for (i = 0; i < num; i++) {
		if (aaa_user[i].port[0] == 'v') 
			sprintf(port, "vty %d", aaa_user[i].port[1]);
		else 
			sprintf(port, "console %d", aaa_user[i].port[1]);

		aaa_user[i].time.tv_sec = now.tv_sec - aaa_user[i].time.tv_sec;
		aaa_user[i].time.tv_usec = now.tv_usec - aaa_user[i].time.tv_usec;

		hour = aaa_user[i].time.tv_sec / 3600;
		minute = aaa_user[i].time.tv_sec % 3600 / 60;
		second = aaa_user[i].time.tv_sec % 3600 % 60;
		sprintf(time_str, "%02u:%02u:%02u", hour, minute, second);

		vty_output(" %-10s%-20s%-8s%-10s%-20s\n", port, aaa_user[i].user, 
								aaa_user[i].service, time_str, aaa_user[i].ip);

	}

	free(aaa_user);
#endif
	return 0;
}

int func_show_access_list()                       
{                                                
	FILE * fp;

	if(NULL == (fp=fopen(SHOW_RUNNING_ACL, "w")))
	{
		return -1;
	}
	fclose(fp);
	cli_show_running_mac_acl();
	cli_show_running_ip_std_acl();
	cli_show_running_ip_ext_acl();
	cli_show_running_ipv6_std_acl();	
	cli_read_config(SHOW_RUNNING_ACL);

	return 0;
}                                                
/*---------------------------------xxxxxxxxxxx-----------------------------*/

int func_show_interface_port(struct users *u)
{
	int port_num = 0;
	
	if(ISSET_CMD_MSKBIT(u, SHOW_DOT1X_IF_PORT))
	{
		/* show dot1x interface */
		vty_output("the command does't support this version\n");
		
		/* port_num: fast_port(1~FNUM) giga_port(1~GNUM) */
	}
	else if(ISSET_CMD_MSKBIT(u, SHOW_MAC_DYNAMIC_IF_PORT))
	{
		/* show mac dynamic interface */
		if(ISSET_CMD_MSKBIT(u, SHOW_IF_FAST_PORT))
		{
			/* fast port */
			cli_param_get_int(STATIC_PARAM, 0, &port_num, u);
			cli_get_l2_mac_list(c_type,port_num,c_vid,c_mac,c_multi);	
		}
#if (XPORT==0)	
		else if(ISSET_CMD_MSKBIT(u, SHOW_IF_GIGA_PORT))
		{
			/* giga port */
		 	cli_param_get_int(STATIC_PARAM, 0, &port_num, u);
			cli_get_l2_mac_list(c_type,port_num,c_vid,c_mac,c_multi);	
		}
#endif		
#if (XPORT==1)
		else if(ISSET_CMD_MSKBIT(u, SHOW_IF_GIGA_PORT))
		{
			/* giga port */
		 	cli_param_get_int(STATIC_PARAM, 0, &port_num, u);
			cli_get_l2_mac_list(c_type,port_num,c_vid,c_mac,c_multi);	
		}
		else if(ISSET_CMD_MSKBIT(u, SHOW_IF_XE_PORT))
		{
			/* giga port */
		 	cli_param_get_int(STATIC_PARAM, 0, &port_num, u);
		 	port_num += GNUM;
			cli_get_l2_mac_list(c_type,port_num,c_vid,c_mac,c_multi);	
		}
#endif			
		else
		{
			DEBUG_MSG(1, "Unknow show interface type!!\n", NULL);
			return -1;
		}
			
		/* port_num: fast_port(1~FNUM) giga_port(1~GNUM) */
	}
	#if 0
	else if(ISSET_CMD_MSKBIT(u, SHOW_MAC_IF_PORT))
	{	
		vty_output("mac if port\n");
		/* show mac interface */
		cli_param_get_int(STATIC_PARAM, 0, &port_num, u);
		
		/* port_num: fast_port(1~FNUM) giga_port(1~GNUM) */
	}
	#endif
	else if(ISSET_CMD_MSKBIT(u, SHOW_RUN_IF_PORT))
	{
		/* show run interface */
		cli_param_get_int(STATIC_PARAM, 0, &port_num, u);
		
		/* port_num: fast_port(1~FNUM) giga_port(1~GNUM) */
		if(ISSET_CMD_MSKBIT(u, SHOW_IF_FAST_PORT))
		{
			/* fast port */
			func_show_running(CLI_SHOW_INTER, port_num);
		}
#if (XPORT==0)		
		else if(ISSET_CMD_MSKBIT(u, SHOW_IF_GIGA_PORT))
		{
			/* giga port */
			port_num += FNUM;
			func_show_running(CLI_SHOW_INTER, port_num);
		}
#endif		
#if (XPORT==1)		
		else if(ISSET_CMD_MSKBIT(u, SHOW_IF_GIGA_PORT))
		{
			func_show_running(CLI_SHOW_INTER, port_num);
		}	
		else if(ISSET_CMD_MSKBIT(u, SHOW_IF_GIGA_PORT))
		{
			/* giga port */
			port_num += GNUM;
			func_show_running(CLI_SHOW_INTER, port_num);
		}
#endif			
	}
	else if(ISSET_CMD_MSKBIT(u, SHOW_VLAN_IF_PORT))
	{
		/* show vlan interface */
		cli_param_get_int(STATIC_PARAM, 0, &port_num, u);

		/* port_num: fast_port(1~FNUM) giga_port(1~GNUM) */
		if(ISSET_CMD_MSKBIT(u, SHOW_IF_FAST_PORT))
		{
			/* fast port */
			cli_show_vlan_interface(u, port_num);
		}
#if (XPORT==0)	
		else if(ISSET_CMD_MSKBIT(u, SHOW_IF_GIGA_PORT))
		{
			/* giga port */
			port_num += FNUM;
			cli_show_vlan_interface(u, port_num);
		}
#endif		
#if (XPORT==1)	
		else if(ISSET_CMD_MSKBIT(u, SHOW_IF_GIGA_PORT))
		{
			/* giga port */
			cli_show_vlan_interface(u, port_num);
		}
		else if(ISSET_CMD_MSKBIT(u, SHOW_IF_XE_PORT))
		{
			/* giga port */
			port_num += GNUM;
			cli_show_vlan_interface(u, port_num);
		}
#endif		
	}
	else if(ISSET_CMD_MSKBIT(u, SHOW_GVRP_IF_PORT))
	{
		/* show vlan interface */
		cli_param_get_int(STATIC_PARAM, 0, &port_num, u);

		/* port_num: fast_port(1~FNUM) giga_port(1~GNUM) */
		if(ISSET_CMD_MSKBIT(u, SHOW_IF_FAST_PORT))
		{
			/* fast port */
			cli_show_gvrp_interface(u, port_num);
		}
#if (XPORT==0)	
		else if(ISSET_CMD_MSKBIT(u, SHOW_IF_GIGA_PORT))
		{
			/* giga port */
			port_num += FNUM;
			cli_show_gvrp_interface(u, port_num);
		}
#endif		
#if (XPORT==1)
		else if(ISSET_CMD_MSKBIT(u, SHOW_IF_GIGA_PORT))
		{
			/* giga port */
			cli_show_gvrp_interface(u, port_num);
		}
		else if(ISSET_CMD_MSKBIT(u, SHOW_IF_XE_PORT))
		{
			/* giga port */
			port_num += GNUM;
			cli_show_gvrp_interface(u, port_num);
		}
#endif		
	}
	else if(ISSET_CMD_MSKBIT(u, SHOW_GARP_IF_PORT))
	{
		/* show vlan interface */
		cli_param_get_int(STATIC_PARAM, 0, &port_num, u);

		/* port_num: fast_port(1~FNUM) giga_port(1~GNUM) */
		if(ISSET_CMD_MSKBIT(u, SHOW_IF_FAST_PORT))
		{
			/* fast port */
			cli_show_garp_interface(u, port_num);
		}
#if (XPORT==0)	
		else if(ISSET_CMD_MSKBIT(u, SHOW_IF_GIGA_PORT))
		{
			/* giga port */
			port_num += FNUM;
			cli_show_garp_interface(u, port_num);
		}
#endif		
#if (XPORT==1)	
		else if(ISSET_CMD_MSKBIT(u, SHOW_IF_GIGA_PORT))
		{
			/* giga port */
			cli_show_garp_interface(u, port_num);
		}	
		else if(ISSET_CMD_MSKBIT(u, SHOW_IF_XE_PORT))
		{
			/* giga port */
			port_num += GNUM;
			cli_show_garp_interface(u, port_num);
		}
#endif		
	}
	else if(ISSET_CMD_MSKBIT(u, SHOW_GMRP_IF_PORT))
	{
		/* show vlan interface */
		cli_param_get_int(STATIC_PARAM, 0, &port_num, u);

		/* port_num: fast_port(1~FNUM) giga_port(1~GNUM) */
		if(ISSET_CMD_MSKBIT(u, SHOW_IF_FAST_PORT))
		{
			/* fast port */
			cli_show_gmrp_interface(u, port_num);
		}
#if (XPORT==0)	
		else if(ISSET_CMD_MSKBIT(u, SHOW_IF_GIGA_PORT))
		{
			/* giga port */
			port_num += FNUM;
			cli_show_gmrp_interface(u, port_num);
		}
#endif		
#if (XPORT==1)	
		else if(ISSET_CMD_MSKBIT(u, SHOW_IF_GIGA_PORT))
		{
			/* giga port */
			cli_show_gmrp_interface(u, port_num);
		}
		else if(ISSET_CMD_MSKBIT(u, SHOW_IF_XE_PORT))
		{
			/* giga port */
			port_num += GNUM;
			cli_show_gmrp_interface(u, port_num);
		}
#endif		
	}
	else if(ISSET_CMD_MSKBIT(u, SHOW_LLDP_IF_PORT))
	{
		/* show vlan interface */
		cli_param_get_int(STATIC_PARAM, 0, &port_num, u);

		/* port_num: fast_port(1~FNUM) giga_port(1~GNUM) */
		if(ISSET_CMD_MSKBIT(u, SHOW_IF_FAST_PORT))
		{
			/* fast port */
			cli_show_lldp_interface(u, port_num);
		}
#if (XPORT==0)	
		else if(ISSET_CMD_MSKBIT(u, SHOW_IF_GIGA_PORT))
		{
			/* giga port */
			port_num += FNUM;
			cli_show_lldp_interface(u, port_num);
		}
#endif		
#if (XPORT==1)
		else if(ISSET_CMD_MSKBIT(u, SHOW_IF_GIGA_PORT))
		{
			/* giga port */
			cli_show_lldp_interface(u, port_num);
		}
		else if(ISSET_CMD_MSKBIT(u, SHOW_IF_XE_PORT))
		{
			/* giga port */
			port_num += GNUM;
			cli_show_lldp_interface(u, port_num);
		}
#endif		
	}
	else
	{
		DEBUG_MSG(1, "Unknow show command!!\n", NULL);
		return -1;
	}	
	return 0;
}

int func_show_interface_vlan(struct users *u)
{
	int vlan_id = 0;
	
	if(ISSET_CMD_MSKBIT(u, SHOW_IF_VLAN_PORT))
	{
		/* show interface vlan */
		cli_param_get_int(STATIC_PARAM, 0, &vlan_id, u);
        cli_show_running_interface_vlan_n(vlan_id);
	}
	else
	{
		DEBUG_MSG(1, "Unknow show interface type!!\n", NULL);
		return -1;
	}
	
	return 0;
}

int func_show_interface(struct users *u)
{
	uint64_t port_int = 0x00ULL;
	char port_range[MAX_ARGV_LEN] = {'\0'};
	
	show_fun("cmd_mskbits:0x%x\n",u->cmd_mskbits);
	show_fun("0x%x\n",ISSET_CMD_MSKBIT(u, SHOW_MAC_IF_PORT));
		//return 0;
	if(ISSET_CMD_MSKBIT(u, SHOW_MAC_IF_PORT))
	{
		//return 0;
		/* show interface */
		if(ISSET_CMD_MSKBIT(u, SHOW_IF_FAST_PORT))
		{	
			/* fast port */	
			cli_param_get_range(STATIC_PARAM, port_range, u);
			cli_str2bitmap(port_range, &port_int);		
		}
		else if(ISSET_CMD_MSKBIT(u, SHOW_IF_GIGA_PORT))
		{			
			/* giga port */	
			cli_param_get_range(STATIC_PARAM, port_range, u);
			cli_str2bitmap(port_range, &port_int);
		}
		else if(ISSET_CMD_MSKBIT(u, SHOW_IF_XE_PORT))
		{
			/* giga port */	
			cli_param_get_range(STATIC_PARAM, port_range, u);
			cli_str2bitmap(port_range, &port_int);	
		}
		else
		{
			DEBUG_MSG(1, "Unknow show interface type!!\n", NULL);
			return -1;
		}
				
		
		if(port_int != 0x00ULL)
		{
            FILE *fp;
            uint8 mac[6], name[16];
            char line[128], *p;
            int skfd, count = 0, port,vid, tgid, mtype; 
        
        	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
        		return -1;
        	
            bcm_get_special_mac(skfd, 0, 0, &port_int);
        	close(skfd);
        		
            fp=fopen("/var/mac","r+");
            if( fp == NULL) return 0;
            
            fseek(fp,0,SEEK_SET);
            memset(line, '\0', 128); 

			vty_output("    %-18s%-12s%-10s%-10s\n", "MAC Address", "VLAN ID", "Type", "Interface");
			vty_output(" ====================================================================\n");
        	    
            while(fgets(line,128,fp)!=NULL)
            {
                p = line;       
                sscanf(p,"%02x-%02x", &mac[0], &mac[1]);
                p += 6;       
                sscanf(p,"%02x-%02x", &mac[2], &mac[3]);     
                p += 6;       
                sscanf(p,"%02x-%02x", &mac[4], &mac[5]);       
                p += 6;    
                sscanf(p, "%d %d %d %d", &vid, &port, &tgid, &mtype);    
        
        	    if(phy2port[port]!=0 && phy2port[port]!= -1)
        	    {
        	        memset(name, '\0', sizeof(name));    
        	        
        	        if(tgid > 0)
        	            sprintf(name, "port-agg %d", tgid);
#if (XPORT==0)        	            
        	        else if (port <= FNUM)
        	            sprintf(name, "f0/%d", port);  
        	        else
        	            sprintf(name, "g0/%d", port-FNUM); 
#endif      
#if (XPORT==1)        	            
        	        else if (port <= GNUM)
        	            sprintf(name, "g0/%d", port);  
        	        else
        	            sprintf(name, "t0/%d", port-GNUM); 
#endif        	              	            

					vty_output(" %02x:%02x:%02x:%02x:%02x:%02x		%-9d%-13s%-10s\n", 
								mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], vid, (mtype==1)?"Static":"Dynamic",	name);

        		}
        		memset(line, '\0', 128); 
            }
            
            fclose(fp);    		  
            unlink("/var/mac");
		}    
		
	}
	else if(ISSET_CMD_MSKBIT(u, SHOW_IF_PORT))
	{	
		FILE *fp;
		int portid = 0;
		
		cli_param_get_range(STATIC_PARAM, port_range, u);

		if(ISSET_CMD_MSKBIT(u, SHOW_IF_FAST_PORT))
		{
			fp = fopen(SHOW_INTERFACE,"w+");
            if(fp == NULL)
                return 0;
            for(portid = 1; portid<=FNUM; portid++) 
            {
                if(CLI_SUCCESS == check_port_include(portid, port_range)) 
                {
                    cli_show_interface(fp, portid);
                }
            }
            fclose(fp);
            cli_read_config(SHOW_INTERFACE);
		}
#if (XPORT==0)		
		else if(ISSET_CMD_MSKBIT(u, SHOW_IF_GIGA_PORT))
		{
			fp = fopen(SHOW_INTERFACE,"w+");
            	if(fp == NULL)
                    return 0;
                    
            	for(portid = 1; portid<=GNUM; portid++) 
            	{	
               		if(CLI_SUCCESS == check_port_include((portid+FNUM), port_range)) 
               	 	{
                    	cli_show_interface(fp, (portid+FNUM));
                	}
            	}
            	fclose(fp);
            cli_read_config(SHOW_INTERFACE);
		}
#endif
#if (XPORT==1)		
		else if(ISSET_CMD_MSKBIT(u, SHOW_IF_GIGA_PORT))
		{
			fp = fopen(SHOW_INTERFACE,"w+");
            	if(fp == NULL)
                    return 0;
                    
            	for(portid = 1; portid<=GNUM; portid++) 
            	{	
               		if(CLI_SUCCESS == check_port_include(portid, port_range)) 
               	 	{
                    	cli_show_interface(fp, portid);
                	}
            	}
            	fclose(fp);
            cli_read_config(SHOW_INTERFACE);
		}
		else if(ISSET_CMD_MSKBIT(u, SHOW_IF_XE_PORT))
		{
			fp = fopen(SHOW_INTERFACE,"w+");
            	if(fp == NULL)
                    return 0;
                    
            	for(portid = 1; portid<=(PNUM-GNUM); portid++) 
            	{	
               		if(CLI_SUCCESS == check_port_include((portid+GNUM), port_range)) 
               	 	{
                    	cli_show_interface(fp, (portid+GNUM));
                	}
            	}
            	fclose(fp);
            cli_read_config(SHOW_INTERFACE);
		}
#endif		
	}
	else
	{
		DEBUG_MSG(1, "Unknow show command!!\n", NULL);
		return -1;
	}
	
	return 0;
}
static int cli_show_interface_brief()
{
    int portid, index, skfd, m_duplex, m_speed;
    uint64_t link, val64;
    char *s_duplex, *s_speed, *r_duplex, r_speed[16];
    uint8 r_stp_state;

    bcm_get_swlink_status(&link);
    
   	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return CLI_FAILED;

    char descri[1024], tmp[32];
    char *p,*p1;	
    char *port_speed = cli_nvram_safe_get(CLI_SPEED_ALL_AUTO, "port_speed");
    char *port_enable = cli_nvram_safe_get(CLI_ALL_ONE, "port_enable");
    char *port_duplex = cli_nvram_safe_get(CLI_DUPLEX_ALL_AUTO, "port_duplex");
    char *port_description=cli_nvram_safe_get(CLI_ALL_DES, "port_description");
    char *link_type = cli_nvram_safe_get(CLI_ALL_ONE, "vlan_link_type");
    char *pvid_str = cli_nvram_safe_get(CLI_COMMA_ONE, "pvid_config");

    char *pvid_str_tmp = pvid_str;


    memset(descri,'\0',sizeof(descri));

    p=port_description;

    vty_output("%-7s%-14s%-16s%-13s%-13s%-13s%s\n","Port","Description","Status","Vlan","Duplex","Speed","Type");	
    for(portid = 1; portid<=PNUM; portid++)
    {
#if (XPORT==0)
        if(portid <= FNUM)
           vty_output("f0/%-4d", portid);
        else
           vty_output("g0/%-4d", portid-FNUM);
#endif
#if (XPORT==1)
        if(portid <= GNUM)
           vty_output("g0/%-4d", portid);
        else
           vty_output("t0/%-4d", portid-FNUM);
#endif
        /* port description */
        p1=strchr(p,';');
        memset(descri,'\0',sizeof(descri));
        memcpy(descri,p,p1-p);
        p=p1+1;
        descri[12] = '\0';
        vty_output("%-12s  ",descri);	

        /*port states*/
        if(*(port_enable+portid-1)=='1') 
        {
			bcm_get_rstp_stp(skfd, 0, portid, &r_stp_state);/*shanming.ren 2011-11-9 9:42:13*/
			if(((r_stp_state) & 0xe0) == 0x20)
			{
				vty_output("%-16s","err-disabled");/*shanming.ren 2011-11-9 9:42:17*/
			}
            else if( ((link>>phy[portid])&0x01ULL)==0x00ULL) 
            {
                vty_output("%-16s","down");
            } 
            else 
            {
                vty_output("%-16s","up");
            }
        } 
        else 
        {
            vty_output("%-16s","admin down");
        }

        /* vlan */
        if('1' == *(link_type+portid-1))
           vty_output("%-13d",atoi(pvid_str_tmp));
        else if('3' == *(link_type+portid-1)) 
        {
            sprintf(tmp, "Trunk(%d)", atoi(pvid_str_tmp));
           vty_output("%-13s",tmp);
        }
        pvid_str_tmp = strchr(pvid_str_tmp, ',');
        pvid_str_tmp++;

        /* speed */
        if(0 == strcmp(port_speed, "")) 
        {
            if(portid <= FNUM)
                s_speed  ="100M";
            else 
                s_speed  ="1000M";
        }
        else 
        {
            switch(*(port_speed+portid-1)-'0')
            {
                case PORT_SPEED_AUTO:		
                    s_speed  = "Auto";
                    break;
                case PORT_SPEED_10:
                    s_speed  ="10M";
                    break;
                case PORT_SPEED_100:
                    s_speed  ="100M";
                    break;
                case PORT_SPEED_1000:
                    s_speed  ="1000M";
                    break;       			
                default:
                    s_speed  ="100M";
                    break;
            }
        }

        /* duplex */
        if(0 == strcmp(port_duplex, ""))
            s_duplex ="FULL";
        else
        {
            switch(*(port_duplex+portid-1)-'0')
            {
                case PORT_DUPLEX_AUTO:
                    s_duplex = "Auto";
                    break;
                case PORT_DUPLEX_FULL:
                    s_duplex ="FULL";
                    break;
                case PORT_DUPLEX_HALF:
                    s_duplex ="HALF";
                    break;
            }
        }

        bcm_get_port_duplex(skfd, 0, portid, &m_duplex);
        bcm_get_port_speed(skfd, 0, portid, &m_speed);
        if(((link>>phy[portid])&1ULL)==0x00ULL)
        {
            memset(r_speed, '\0', sizeof(r_speed));
            r_duplex= "";	
        }
        else
        {
            /* betty modified */
            memset(r_speed, '\0', sizeof(r_speed));
            if(m_speed != 0)
                sprintf(r_speed, "%dM", m_speed);
                
            if(m_duplex == 0x00)
                r_duplex = "HALF";
            else
                r_duplex = "FULL";
        }

        sprintf(tmp, "%s(%s)",s_duplex,r_duplex);
        vty_output("%-13s",tmp);

        sprintf(tmp, "%s(%s)",s_speed,r_speed);
        vty_output("%-13s",tmp);

#if (XPORT==0)
        if(portid <= FNUM)
                vty_output("%s","FastEthernet-TX");
        else
                vty_output("%s","GigaEthernet-TX");
#else
        if(portid <= GNUM)
                vty_output("%s","GigaEthernet-TX");
        else
                vty_output("%s","TenGigaEthernet-TX");
#endif                
        vty_output("\n");
    }

/* check aggregator group exist */
    memset(&cur_trunk_conf, 0, sizeof(cli_trunk_conf));
    cli_nvram_conf_get(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);

    for(index = 0; index < cur_trunk_conf.group_count; index++) 
    {
        vty_output("Po%-5d", cur_trunk_conf.cur_trunk_list[index].group_no);

        if(cli_get_port_trunk_status(skfd, cur_trunk_conf.cur_trunk_list[index].group_no, &val64) == 0) 
        {
            val64 = ((val64 & 0x6FFFFFF000000ULL) & (link & 0x6FFFFFF000000ULL));
            if(val64) 
            {
                vty_output("%-14s%-8s\n", " ", "up");
            } 
            else 
            {
                vty_output("%-14s%-8s\n", " ", "down");
            }
        } 
        else
        {
            vty_output("%-14s%-8s\n", " ", "down");
        }
    }
    cli_nvram_conf_free(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);

    free(port_enable);
    free(port_speed);
    free(port_duplex);
    free(link_type);
    free(port_description); 
    free(pvid_str);
    
    close(skfd);
	return 0;                                                                                                                                      
}

//Jil DDM show
static int cli_show_interface_ddm()
{
    int index, skfd;
	int portid;
    int channel, addr=0x50, offset, size; 
	int val;
	int is_int_diag = 0, is_ext_diag = 0;

	char* wave[]={"850", "1310", "1490", "1550", "unknown"};
	
    uint8 val8[256];
	float t;

   	if((skfd = open(DEVICE_FILE_NAME, O_RDWR)) < 0) 
		return CLI_FAILED;

    vty_output("%-7s%-11s%-10s%-10s%-12s%-10s%s\n","Port","Wavelength","Tx Power","Rx Power","Temperature","Current","Voltage");	
    for(portid = 1; portid<5; portid++)
    {
    	channel = (portid%2)?portid:(portid-2);
        vty_output("t0/%-4d", portid);

		//Check the SFP Type, it must be GBIC/SFP
		offset  = 0;
		size    = 1;
		if((bcm_ddm_read(skfd, channel, addr, offset, size, val8)) < 0)
		{
			vty_output("%8s\n", "N/A");
			continue;
		}

		val = val8[0];
		if((val != 0x03) && (val != 0x01))
		{
			vty_output("%s\n", "N/A");
			continue;
		}

		//Waveform -- 60 & 61
		offset  = 60;
		size    = 2;
		if((bcm_ddm_read(skfd, channel, addr, offset, size, val8)) < 0)
		{
			vty_output("\n");
			continue;
		}
		else
		{
			val = val8[0] << 8 | val8[1];

			switch(val)
			{
				case 0x352:
					index = 0;
					break;
				case 0x51E:
					index = 1;
					break;
				case 0x5d2:
					index = 2;
					break;
				case 0x60E:
					index = 3;
					break;
				default:
					index = 4;
					break;
			}
        	vty_output("%-10s",wave[index]);	
		}


		//Get the Diagnostic options here!
		offset = 92;
		size   = 1;
		if((bcm_ddm_read(skfd, channel, addr, offset, size, val8)) < 0)
		{
			vty_output("\n");
			continue;
		}
		else
		{
			if(val8[0] & 0x20)
			{
				//Internal Diagnostics
				is_int_diag = 1;
			}
			else if(val8[0] & 0x10)
			{
				//External Diagnostics
				is_ext_diag = 1;
			}
			else
			{
				vty_output(" diag option = %x\n", val8[0]);
				continue;
			}
		}

		//Tx Power
		offset  = 102;
		size    = 2;
		if((bcm_ddm_read(skfd, channel, addr+1, offset, size, val8)) < 0)
		{
			vty_output("\n");
			continue;
		}
		else if(is_int_diag)
		{
			float uw, dbm;
			
			val = val8[0] * 256 + val8[1];


			uw = val / 10.0;
			dbm = 10 * log10(uw /1000);
			vty_output("%6.2fdbm", dbm);
		}
		else if(is_ext_diag)
		{
			int ad = val8[0] * 256 + val8[1];
			float slope;
			int off;
			float uw, dbm;

			//Get the slope! -- 80 & 81
			offset = 80;
			size   = 2;
			bcm_ddm_read(skfd, channel, addr+1, offset, size, val8);
			slope = val8[0] + val8[1] * 1.0/256;
			
			off = 82;
			size   = 2;
			bcm_ddm_read(skfd, channel, addr+1, offset, size, val8);
			off = val8[0]*256 + val8[1];

			uw = slope * ad + off;
			uw = uw / 10;
			dbm = 10 * log10(uw/1000);
			vty_output("%6.2fdbm", dbm);
		}

		//Rx Power
		offset  = 104;
		size    = 2;
		if((bcm_ddm_read(skfd, channel, addr+1, offset, size, val8)) < 0)
		{
			vty_output("\n");
			continue;
		}
		else if(is_int_diag)
		{
			float uw, dbm;
			
			val = val8[0] * 256 + val8[1];

			uw = val / 10.0;
			dbm = 10 * log10(uw /1000);
			if((val8[0] == 0) && (val8[1] == 0))
			{
				vty_output("%10s", "N/A");
			}
			else
			{
				vty_output("%7.2fdbm", dbm);
			}
		}
		else if(is_ext_diag)
		{
			float r1, r2, r3, r4;
			int ad = val8[0] * 256 + val8[1];
			char p;
			float off;
			int  i;
			float uw, dbm;

			union B_F
			{
			  unsigned char b[4];
			  float f;
			} b_f;

			offset = 56;
			size   = 4;

			bcm_ddm_read(skfd, channel, addr+1, offset, size, val8);
			{
				b_f.b[0]=val8[3];
				b_f.b[1]=val8[2];
				b_f.b[2]=val8[1];
				b_f.b[3]=val8[0];
			}
			r4 = b_f.f;

			offset = 60;
			size   = 4;
			bcm_ddm_read(skfd, channel, addr+1, offset, size, val8);
			{
				b_f.b[0]=val8[3];
				b_f.b[1]=val8[2];
				b_f.b[2]=val8[1];
				b_f.b[3]=val8[0];
			}
			r3 = b_f.f;

			offset = 64;
			size   = 4;
			bcm_ddm_read(skfd, channel, addr+1, offset, size, val8);
			{
				b_f.b[0]=val8[3];
				b_f.b[1]=val8[2];
				b_f.b[2]=val8[1];
				b_f.b[3]=val8[0];
			}
			r2 = b_f.f;

			offset = 68;
			size   = 4;
			bcm_ddm_read(skfd, channel, addr+1, offset, size, val8);
			{
				b_f.b[0]=val8[3];
				b_f.b[1]=val8[2];
				b_f.b[2]=val8[1];
				b_f.b[3]=val8[0];
			}
			r1 = b_f.f;
			
			offset = 72;
			size   = 4;
			bcm_ddm_read(skfd, channel, addr+1, offset, size, val8);
			{
				b_f.b[0]=val8[3];
				b_f.b[1]=val8[2];
				b_f.b[2]=val8[1];
				b_f.b[3]=val8[0];
			}
			off = b_f.f;

			uw = r4 * (ad ^ 4) + r3 * (ad ^ 3) + r2 * (ad ^ 2) + r1 * ad + off;
			uw = uw/10;
			dbm = 10 * log10(uw /1000);
			vty_output("%7.2fdbm", dbm);
		}

		//Temperature
		offset  = 96;
		size    = 2;
		if((bcm_ddm_read(skfd, channel, addr+1, offset, size, val8)) < 0)
		{
			vty_output("\n");
			continue;
		}
		else if(is_int_diag)
		{
			t = val8[0] + val8[1] * (1.0)/256;
			vty_output("%11.2fC", t);
		}
		else if(is_ext_diag)
		{
			int ad = val8[0] * 256 + val8[1];
			float slope;
			int off;
			float t;

			//Get the slope! -- 80 & 81
			offset = 84;
			size   = 2;
			bcm_ddm_read(skfd, channel, addr+1, offset, size, val8);
			slope = val8[0] + val8[1] * 1.0/256;
			
			offset = 86;
			size   = 2;
			bcm_ddm_read(skfd, channel, addr+1, offset, size, val8);
			off = val8[0]*256 + val8[1];

			t = slope * ad + off;
			t = t / 256;
			vty_output("%11.2fC", t);
		}

		//Tx Bias Current
		offset  = 100;
		size    = 2;
		if((bcm_ddm_read(skfd, channel, addr+1, offset, size, val8)) < 0)
		{
			vty_output("\n");
			continue;
		}
		else if(is_int_diag)
		{
			val = val8[0] * 256 + val8[1];
			t = val * 2 /1000.0;
			vty_output("%8.2fmA", t);
		}
		else if(is_ext_diag)
		{
			int ad = val8[0] * 256 + val8[1];
			float slope;
			int off;
			float current;

			//Get the slope! -- 80 & 81
			offset = 76;
			size   = 2;
			bcm_ddm_read(skfd, channel, addr+1, offset, size, val8);
			slope = val8[0] + val8[1] * 1.0/256;
			
			offset = 78;
			size   = 2;
			bcm_ddm_read(skfd, channel, addr+1, offset, size, val8);
			off = val8[0]*256 + val8[1];

			current = slope * ad + off;
			current = current * 2 /1000.0;
			vty_output("%8.2fmA", current);
		}

		//Voltage
		offset  = 98;
		size    = 2;
		if((bcm_ddm_read(skfd, channel, addr+1, offset, size, val8)) < 0)
		{
			vty_output("\n");
			continue;
		}
		else if(is_int_diag)
		{
			val = val8[0] * 256 + val8[1];
			t = val/10000.0;
			vty_output("%7.2fV", t);
		}
		else if(is_ext_diag)
		{
			int ad = val8[0] * 256 + val8[1];
			float slope;
			int off;
			float val;

			//Get the slope! -- 80 & 81
			offset = 88;
			size   = 2;
			bcm_ddm_read(skfd, channel, addr+1, offset, size, val8);
			slope = val8[0] + val8[1] * 1.0/256;
			
			offset = 90;
			size   = 2;
			bcm_ddm_read(skfd, channel, addr+1, offset, size, val8);
			off = val8[0]*256 + val8[1];

			val = slope * ad + off;
			val = val /10000.0;
			vty_output("%7.2fV", val);
		}

        vty_output("\n");
    }
    close(skfd);
	
    return 0;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           
}
//End of Jil

int cli_show_agg_brief(void)
{
    int portid, index, skfd, m_duplex, m_speed;
    uint64_t link, val64;
    char *s_duplex, *s_speed, *r_duplex, r_speed[16];
    uint8 r_stp_state;

    bcm_get_swlink_status(&link);
    
   	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return CLI_FAILED;

    char descri[1024], tmp[32];
    char *p,*p1;	
    char *port_speed = cli_nvram_safe_get(CLI_SPEED_ALL_AUTO, "port_speed");
    char *port_enable = cli_nvram_safe_get(CLI_ALL_ONE, "port_enable");
    char *port_duplex = cli_nvram_safe_get(CLI_DUPLEX_ALL_AUTO, "port_duplex");
    char *port_description=cli_nvram_safe_get(CLI_ALL_DES, "port_description");
    char *link_type = cli_nvram_safe_get(CLI_ALL_ONE, "vlan_link_type");
    char *pvid_str = cli_nvram_safe_get(CLI_COMMA_ONE, "pvid_config");

    char *pvid_str_tmp = pvid_str;


    memset(descri,'\0',sizeof(descri));

    p=port_description;

    vty_output("%-7s%-14s%-16s%-13s%-13s%-13s%s\n","Port","Description","Status","Vlan","Duplex","Speed","Type");	
    
    /* check aggregator group exist */
    memset(&cur_trunk_conf, 0, sizeof(cli_trunk_conf));
    cli_nvram_conf_get(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);

    for(index = 0; index < cur_trunk_conf.group_count; index++) 
    {
        vty_output("Po%-5d", cur_trunk_conf.cur_trunk_list[index].group_no);
        if(cli_get_port_trunk_status(skfd, cur_trunk_conf.cur_trunk_list[index].group_no, &val64) == 0) 
        {
            val64 = val64 & link;
            if(val64) 
            {
                vty_output("%-14s%-8s\n", " ", "up");
            } 
            else 
            {
                vty_output("%-14s%-8s\n", " ", "down");
            }
        } 
        else
        {
            vty_output("%-14s%-8s\n", " ", "down");
        }
    }
    cli_nvram_conf_free(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);

    free(port_enable);
    free(port_speed);
    free(port_duplex);
    free(link_type);
    free(port_description); 
    free(pvid_str);
    
    close(skfd);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        

    return 0;                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                		
}

void func_show_inter_bri()
{
//	FILE *fp;
//   fp = fopen(SHOW_INTERFACE,"w+");
//        if(fp == NULL)
 //               return 0;
        cli_show_interface_brief();
 //       fclose(fp);
  //      cli_read_config(SHOW_INTERFACE); 
}

void func_show_inter_ddm()
{
	cli_show_interface_ddm();
}

int check_port_include(int portid, char *port_str)
{
	uint64_t port_int = 0;
	cli_str2bitmap(port_str, &port_int);
	
	if(port_int&(0x1ULL<<phy[portid]))
		return CLI_SUCCESS;
	else
    	return CLI_FAILED;
}
/*----------------------------show_inter_agg---------------------------------*/
int func_show_inter_agg(struct users *u)
{
	char *port_enable = cli_nvram_safe_get(CLI_ALL_ONE, "port_enable");
	char *port_flow = cli_nvram_safe_get(CLI_ALL_ZERO, "port_flow");
	char *port_speed = cli_nvram_safe_get(CLI_SPEED_ALL_AUTO, "port_speed");
	char *port_duplex = cli_nvram_safe_get(CLI_DUPLEX_ALL_AUTO, "port_duplex");
	char *port_description = cli_nvram_safe_get(CLI_ALL_DES, "port_description");
	char *agg_port_description = cli_nvram_safe_get(CLI_ALL_DES, "agg_port_description");
	char *p_des1, *p_des2;
	char printf_port[100];
	int  group = 0,description_index;
	cli_param_get_int(DYNAMIC_PARAM, 0, &group, u);
	
	int skfd, portid, all_flag=0, trunk_flag = 0,portid_flag=0,select=0;
	int trunk_flag_total=0,index, flag = 0;
	uint32 high_data1,high_data2;
	uint32 low_data1,low_data3=0,low_data5=0,low_data7=0,low_data9=0,low_data11=0;
	uint32 low_data2,low_data4=0,low_data6=0,low_data8=0,low_data10=0,low_data12=0;
	uint32 low_data13=0,low_data15=0,low_data17=0,low_data19=0,low_data21=0,low_data23=0;
	uint32 low_data14=0,low_data16=0,low_data18=0,low_data20=0,low_data22=0,low_data24=0,low_data25=0;
	uint64_t tmp_total=0,tmp_total1=0;
	uint32 total1,total2,total3=0,total4=0,total5=0,total6=0;
	uint32 tmp_good1,tmp_good2,tmp_good3,tmp_good4,tmp_good5=0,tmp_good6=0,tmp_good_received=0,tmp_good_transmited=0;

	uint64_t link_status = 0x0ULL;
	int m_duplex, m_speed;
	char s_duplex[32]="", s_speed[32]="", r_duplex[32]="", r_speed[32]="";
	
	memset(printf_port,'\0',strlen(printf_port));
	bcm_get_swlink_status(&link_status);
	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0){ 
		free(port_enable);
		free(port_speed);
		free(port_duplex);
		free(port_flow);
		free(port_description);
		free(agg_port_description);
		return CLI_FAILED;
	}
	/* check aggregator group exist */
	memset(&cur_trunk_conf, 0, sizeof(cli_trunk_conf));
	cli_nvram_conf_get(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);
		
	for(index = 0; index < cur_trunk_conf.group_count; index++) 
	{
		if(cur_trunk_conf.cur_trunk_list[index].group_no == group) 
		{
			flag = 1;
			break;
		}
	}
	
	if(1 == flag)
	{
		for(index = 0; index < cur_trunk_conf.group_count; index++) 
		{
			if(cur_trunk_conf.cur_trunk_list[index].group_no == group) 
			{
				for(portid = 1; portid <= PNUM; portid++)
				{
					if(cur_trunk_conf.cur_trunk_list[index].port_int&(0x1ULL<<phy[portid]))
					{
						if( link_status&(0x1ULL<<phy[portid]) || (cur_trunk_conf.cur_trunk_list[index].mode == CLI_STATIC))
						{
							if(link_status&(0x1ULL<<phy[portid]))
							{
								all_flag = 1;
							}
							if(CLI_SUCCESS == cli_check_interface_include_trunk(skfd, group, portid) )
							{
								trunk_flag = 1;
								
								trunk_flag_total+=1;
								sprintf(printf_port,"%sf0/%d ",printf_port,portid);
								if(portid>FNUM) portid_flag=1;
								
								get_port_txrx_status(skfd, portid, RxOctets, &high_data1, &low_data1);
								get_port_txrx_status(skfd, portid, RxBroadcastPkts, &tmp_good4, &tmp_good1);
								get_port_txrx_status(skfd, portid, RxMulticastPkts, &tmp_good4, &tmp_good2);
								get_port_txrx_status(skfd, portid, RxUnicastPkts, &tmp_good4, &tmp_good3);
	
								tmp_total+=(uint64_t)((high_data1*4294967296ull)+ low_data1);
								//total1=(uint32)(tmp_total/10000000000);
								//total2=(uint32)(tmp_total%10000000000)
								//total3+=total1;
								//total4+=total2;
								tmp_good5=(tmp_good1+tmp_good2+tmp_good3);
								tmp_good_received+=tmp_good5;
								
								get_port_txrx_status(skfd, portid, TxOctets, &high_data1, &low_data1); 
								get_port_txrx_status(skfd, portid, TxBroadcastPkts, &tmp_good4, &tmp_good1); 
								get_port_txrx_status(skfd, portid, TxMulticastPkts, &tmp_good4, &tmp_good2); 
								get_port_txrx_status(skfd, portid, TxUnicastPkts, &tmp_good4, &tmp_good3); 
								tmp_total1+=high_data1*4294967296+ low_data1; 
								//total1=tmp_total/10000000000; total2=tmp_total%10000000000;

								//total5+=total1; total6+=total2; 
								tmp_good6=(tmp_good1+tmp_good2+tmp_good3);
								tmp_good_transmited+=tmp_good6;
								
								get_port_txrx_status(skfd, portid, RxBroadcastPkts, &high_data1, &low_data1);
								get_port_txrx_status(skfd, portid, RxMulticastPkts, &high_data2, &low_data2);
								low_data3+=low_data1;
								low_data4+=low_data2;
	
								get_port_txrx_status(skfd, portid, RxDropPkts, &high_data1, &low_data1);
								get_port_txrx_status(skfd, portid, RxPausePkts, &high_data2, &low_data2);
								low_data5+=low_data1;
								low_data6+=low_data2;
	
								get_port_txrx_status(skfd, portid, RxAlignmentErrors, &high_data1, &low_data1);
								get_port_txrx_status(skfd, portid, RxFCSErrors, &high_data2, &low_data2);
								low_data7+=low_data1;
								low_data8+=low_data2;
	
								get_port_txrx_status(skfd, portid, RXSymbolError, &high_data1, &low_data1);
								get_port_txrx_status(skfd, portid, RxFragments, &high_data2, &low_data2);
								low_data9+=low_data1;
								low_data10+=low_data2;
	
								get_port_txrx_status(skfd, portid, RxJabbers, &high_data1, &low_data1);
								get_port_txrx_status(skfd, portid, RxOversizePkts, &high_data2, &low_data2);
								low_data11+=low_data1;
								low_data12+=low_data2;
	
								get_port_txrx_status(skfd, portid, RxUndersizePkts, &high_data1, &low_data1);
								get_port_txrx_status(skfd, portid, RxExcessSizeDisc, &high_data2, &low_data2);
								low_data13+=low_data1;
								low_data14+=low_data2;
	

	
								get_port_txrx_status(skfd, portid, TxBroadcastPkts, &high_data1, &low_data1);
								get_port_txrx_status(skfd, portid, TxMulticastPkts, &high_data2, &low_data2);
								low_data15+=low_data1;
								low_data16+=low_data2;
	
								get_port_txrx_status(skfd, portid, TxDropPkts, &high_data1, &low_data1);
								get_port_txrx_status(skfd, portid, TxPausePkts, &high_data2, &low_data2);
								low_data17+=low_data1;
								low_data18+=low_data2;
	
								get_port_txrx_status(skfd, portid, TxCollisions, &high_data1, &low_data1);
								get_port_txrx_status(skfd, portid, TxFrameInDisc, &high_data2, &low_data2);
								low_data19+=low_data1;
								low_data20+=low_data2;
	
								get_port_txrx_status(skfd, portid, TxDeferredTransmit, &high_data1, &low_data1);
								get_port_txrx_status(skfd, portid, TxSingleCollision, &high_data2, &low_data2);
								low_data21+=low_data1;
								low_data22+=low_data2;
		
								get_port_txrx_status(skfd, portid, TxMultipleCollision, &high_data1, &low_data1);
								get_port_txrx_status(skfd, portid, TxExcessiveCollision, &high_data2, &low_data2);
								low_data23+=low_data1;
								low_data24+=low_data2;
								
								get_port_txrx_status(skfd, portid, TxLateCollision, &high_data1, &low_data2);
								low_data25=low_data2;
								
								
								/*port speed set*/ 
								switch(*(port_speed+portid-1)-'0')
								{
									case PORT_SPEED_AUTO:
										strcpy(s_speed,"Auto_Speed");
										break;

									case PORT_SPEED_10:
										strcpy(s_speed,"10M");
										break;
			
									case PORT_SPEED_100:
										strcpy(s_speed,"100M");
										break;
		
									case PORT_SPEED_1000:
										strcpy(s_speed,"1000M");
										break;
			
									default:
										strcpy(s_speed,"100M");
										break;
								}

								/*port duplex set*/ 
								switch(*(port_duplex+portid-1)-'0')
								{
									case PORT_DUPLEX_AUTO:
										strcpy(s_duplex,"Auto_Duplex");
										break;
			
									case PORT_DUPLEX_FULL:
										strcpy(s_duplex,"FULL_Duplex");
										break;
			
									case PORT_DUPLEX_HALF:
										strcpy(s_duplex,"HALF_Duplex");
										break;
			
									default:
										strcpy(s_duplex,"FULL_Duplex");
										break;			
								}
	
								/*real port speed*/
							    bcm_get_port_duplex(skfd, 0, portid, &m_duplex);
                                bcm_get_port_speed(skfd, 0, portid, &m_speed);
								
								if(phy[portid]<phy[0])
									{
										if(m_speed == 0x00)
											strcpy(r_speed,"10M");
										else
											strcpy(r_speed,"100M");
									}
								else
									{				
										if(m_speed == 0x00)
											strcpy(r_speed,"10M");
	       					 			else if(m_speed == 0x01)
	        								strcpy(r_speed,"100M");
	    				  		 	 	else
	        								strcpy(r_speed,"1000M");
									}
									
				 				if(m_duplex==0x00)
									strcpy(r_duplex,"HALF");
								else
									strcpy(r_duplex,"FULL");

								/*set flow control*/
								select=(*(port_flow+portid-1)=='1');			
								
							}
						}
					}
				}
				if(trunk_flag == 1)
				{
					if(all_flag == 0)
					{
						vty_output("port aggregator %d is down,",group);
						vty_output("lines protocol is down \n");
					}
					else
					{
						vty_output("port aggregator %d is up,",group);
						vty_output("lines protocol is up \n");
					}
						
					vty_output("Description: ");
					
					p_des1 = port_description;
					for (description_index = 0; description_index < PNUM; description_index++)
					{
						p_des2 = strchr(p_des1, ';');
						p_des1 = p_des2+1;
					}
					
					p_des1 = agg_port_description;
					for(description_index = 1; description_index <= CLI_TRUNK_GROUP; description_index++)
					{
						p_des2 = strchr(p_des1, ';');
						if(description_index == group)
						{
							*p_des2 = '\0';
							vty_output("%s", p_des1);
							break;
						}
						p_des1 = p_des2+1;
					}
					
					vty_output("\n");
					
					if(trunk_flag_total == 0) 
					{
						if(portid_flag == 0 )
							vty_output("MTU 1500 bytes, BW 100000 kbit, DLY 10 usec\n");
						else vty_output("MTU 1500 bytes, BW 1000000 kbit, DLY 10 usec\n");
					}
					else 
					{
						if(portid_flag == 0 )
							vty_output("MTU 1500 bytes, BW %d kbit, DLY 10 usec\n",trunk_flag_total*100000);
						else vty_output("MTU 1500 bytes, BW %d kbit, DLY 10 usec\n",trunk_flag_total*1000000);
					}
					vty_output("Encapsulation ARPA\n");
					vty_output("%s(%s),%s(%s)\n",s_duplex,r_duplex,s_speed,r_speed);
	
					if (select)
			   			vty_output("flow_control on\n");
					else 
							vty_output("flow_control off\n");
						
		 			vty_output("Members in this port aggregator: %s\n",printf_port);
		 			vty_output("     %s %d %s, %llu %s\n","Received",tmp_good_received,"packets",tmp_total,"bytes");
		 			#if 0
		 			if(total3 == 0)
						vty_output("     %s %d %s, %d %s\n","Received",tmp_good_received,"packets",total4,"bytes");
	   		 		else
						vty_output("     %s %d, %s %d%d %s\n","Received",tmp_good_received,"packets",total3,total4," bytes");
	    			#endif
	    			vty_output("     %d %s, %d %s\n",low_data3,"broadcasts",low_data4,"multicasts");	
	   		  		vty_output("     %d %s, %d %s\n",low_data5,"discard",low_data6,"PAUSE");
	    			vty_output("     %d %s, %d %s\n",low_data7,"align",low_data8,"FCS");
	    			vty_output("     %d %s, %d %s\n",low_data9,"symbol",low_data10,"fragment");
	    			vty_output("     %d %s, %d %s\n",low_data11,"jabber",low_data12,"oversize");
	    			vty_output("     %d %s, %d %s\n",low_data13,"undersize",low_data14,"excesssize");
	    			vty_output("     %s %d %s, %llu %s\n","Transmited",tmp_good_transmited,"packets",tmp_total1,"bytes");
	    			#if 0
	    			if(total5 == 0)
		    			vty_output("     %s %d %s, %d %s\n","Transmited",tmp_good_transmited,"packets",total6,"bytes");
					else
		    			vty_output("     %s %d %s, %d%d %s\n","Transmited",tmp_good_transmited,"packets",total5,total6," bytes");	    
						#endif
					vty_output("     %d %s, %d %s\n",low_data15,"broadcasts",low_data16,"multicasts");
					vty_output("     %d %s, %d %s\n",low_data17,"discard",low_data18,"PAUSE");
					vty_output("     %d %s, %d %s\n",low_data19,"collision",low_data20,"indisc");
					vty_output("     %d %s, %d %s\n",low_data21,"deferred",low_data22,"single");
					vty_output("     %d %s, %d %s\n",low_data23,"multiple",low_data24,"excessive");
					vty_output("     %d %s\n",low_data25,"late");
					vty_output("\n");
				}
				else 
				{
					vty_output("  Port aggregator Group %d is not up!\n",group);
				}
			}
		}
	}
	else 
		vty_output("  Port aggregator Group %d is not exist!\n",group);
	
	free(port_enable);
	free(port_speed);
	free(port_duplex);
	free(port_flow);
	free(port_description);
	free(agg_port_description);								
	return 0;
}

/*------------------------------func_show_aggregator_group-----------------------------*/
int cli_check_interface_include_trunk(int skfd, int group, int portid)
{
	uint64_t val64;

	if(-1 == cli_get_port_trunk_status(skfd, group, &val64)) {
		return CLI_FAILED;
	} else {
		if( val64 & (0x1ULL<<phy[portid]) )
		{
			return CLI_SUCCESS;
		}
	}


	return CLI_FAILED;
}

/*
 *  function: cli show aggregator group
 *	author  : eagles.zhou
 *  Example :
 *  	Flags:  D - down       A - Use In port-aggregator
 *		        U - Up         I - Not In port-aggregator
 				mode :1 - static,3 - lacp
 *		Group      mode    Port-aggregator  Ports
 *		-----+-----------+-----------------+--------------------------------------------
 *		1           1             Po1(D)      F0/3(DI)
 *
 *		2           3            Po2(D)      F0/5(DI)   F0/4(DI)
 *
 */
int func_show_aggregator_group(int group)
{
	char *trunk_list = nvram_safe_get("trunk_list");
	char *trunk_enable = nvram_safe_get("h_aggregation_enable");

	char *p3, *p1, *p;
	int skfd, cur_group, portid, flag, all_flag, link_flag, trunk_flag, mode;
	char buff[256], tmp[32];
	uint64_t cur_port, link_status = 0x0ULL;

	vty_output("Flags:  D - down       A - Use In port-aggregator\n");
	vty_output("        U - Up         I - Not In port-aggregator\n");
	vty_output("Group   mode     Port-aggregator  Ports\n");
	vty_output("-----+---------+-----------------+-------------------------------------------------------------\n");

//	if('1' == *trunk_enable)
	{
		bcm_get_swlink_status(&link_status);

		if((skfd = open(DEVICE_FILE_NAME, 0)) < 0){
			free(trunk_list);
			free(trunk_enable);
			return -1;
		}
		p = trunk_list;
		while((p3=strchr(p, ';')) != NULL)
		{
			memset(buff, '\0', sizeof(buff));
			memset(tmp, '\0', sizeof(tmp));

			flag = 0;
			all_flag = 0;
			link_flag = 0;
			trunk_flag = 0;

			cur_group = atoi(p+6);
			mode = atoi (p+8);
			//printf("%d\n",mode);
			if( (group == cur_group)||(0 == group) )
			{
				p1 = strchr(p, '|');
				p = ++p1;
				p1 = strchr(p, '|');
				p = ++p1;
				p1 = strchr(p, '|');
				p = ++p1;

				memcpy(tmp, p1, p3-p1);

				str2bit(tmp, &cur_port);

				for(portid = 1; portid <= PNUM; portid++) {
					if( cur_port&(0x1ULL<<phy[portid]) ){
						flag = 1;
						if( link_status&(0x1ULL<<phy[portid]) ) {
							link_flag = 1;
							if(CLI_SUCCESS == cli_check_interface_include_trunk(skfd, cur_group, portid) ) {
								trunk_flag = 1;
								all_flag = 1;
							} else {
								trunk_flag = 0;
							}
						} else {
							link_flag = 0;
							trunk_flag = 0;
						}
						/* betty modofied for giga port */
						if(portid <= FNUM)
							sprintf(tmp, "F0/%d(%c%c)   ", portid, link_flag?'U':'D', trunk_flag?'A':'I');
						else
							sprintf(tmp, "G0/%d(%c%c)   ", portid-FNUM, link_flag?'U':'D', trunk_flag?'A':'I');
						strcat(buff, tmp);
					}
				}
				if(0 == flag)
					all_flag = 0;
				if (mode == 3) {
					vty_output("%d       lacp     Po%d(%c)           %s\n", cur_group, cur_group, all_flag?'U':'D', buff);
					vty_output("\n");
				} else if (mode == 0){
					vty_output("%d                Po%d(%c)           %s\n", cur_group, cur_group, all_flag?'U':'D', buff);
					vty_output("\n");
				} else if (mode == 1){
					vty_output("%d       static   Po%d(%c)           %s\n", cur_group, cur_group, all_flag?'U':'D', buff);
					vty_output("\n");
				}

				if(group != 0)
					break;
			}
			p = p3+1;
		}
		close(skfd);
	}

	free(trunk_list);
	free(trunk_enable);
	return 0;
}

void func_show_aggregator_load_balance()
{
	char *load_mode = nvram_safe_get("h_load_mode");
	int mode = atoi(load_mode);
 
	free(load_mode);
	switch(mode)
	{
	    case 1:
			vty_output("aggregator-group load-balance both-mac\n");
			break;
		case 2:
			vty_output("aggregator-group load-balance src-mac\n");
			break;
		case 3:
			vty_output("aggregator-group load-balance dst-mac\n");
			break;
		case 4:
			vty_output("aggregator-group load-balance both-ip\n");
			break;
		case 5:
			vty_output("aggregator-group load-balance src-ip\n");
			break;
		case 6:
			vty_output("aggregator-group load-balance dst-ip\n");
			break;
		case 7:
			vty_output("aggregator-group load-balance both-port\n");
			break;
		case 8:
			vty_output("aggregator-group load-balance src-port\n");
			break;
		case 9:
			vty_output("aggregator-group load-balance dst-port\n");
			break;
		default:
			break;	
	}
	
	return;
}
/*
---
----------------------------------------show arp---------------------------------*/
int func_show_arp()
{
	return 0;	
}
/*
---
----------------------------------------show clock---------------------------------*/
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  func_show_clock
 *  Description:  Used to show now time
 * 		 Author:  gujiajie
 *		   Date:  05/14/2012
 * =====================================================================================
 */
//fix time_zone error by grant 02/26/2005
int time_adjust(char *tz)
{
    int time=0;
    char a=tz[4];
    char b=tz[5];

    if('0' == a)
        return 0;
    if('0' <= b && '9' >= b){
        time = (10*(a-'0')+(b-'0'))*60;
        if('0' == tz[7])
            time += 30;
    }
    else
    {
        if('0' <= a && '9' >= a)
            time = (a-'0')*60;
        if('0' == tz[6])
            time += 30;
    }

    if('+' == tz[3])
        return time;
    else
        return 0-time;
}
 
int func_show_clock()
{
	time_t now;
	struct timeval tv;
	struct timezone tz;
	struct tm *nowtime;
	char timebuf[12] = {'\0'};
	char date[30] = {'\0'};
	char *timezone = nvram_safe_get("time_zone");

	now = time(NULL);
	now += time_adjust(timezone)*60;  
	nowtime = gmtime(&now);
	gettimeofday(&tv, &tz);
	nowtime->tm_hour -= tz.tz_minuteswest/60;

	strftime(timebuf, 12, "%T", nowtime);
	strftime(date, 30, "%a %b %d %Y", nowtime);

	vty_output("%s %s %s\n", timebuf, timezone, date);

	free(timezone);
}
/*
---
----------------------------------------show dot1x---------------------------------*/
void func_show_dot1x(int type, int portid)
{
    FILE *fp_status;
    char *p, line[512];
	int show_type=type;
	int reAuthPeriod=3600,quietPeriod=60,serverTimeout=30,reAuthMax=2,reAuthCount=0,reqCount=0;//MAX_entry=0;
	char reAuth[5]={'F','A','L','S','E'};
	char suppMAC[12],identity[50],flags[4],AuthState[15],portMode[15],BKDState[15],portEnabled[5];
	
	char *dot1x_enable = nvram_safe_get("dot1x_enable");
	char *dot1x_config = nvram_safe_get("dot1x_config");
	char *reauth_enable = nvram_safe_get("reauth_enable");
	char *reauth_time = nvram_safe_get("reauth_time");
	
	char *radius_server = nvram_safe_get("radius_server");
	char *radius_port = nvram_safe_get("radius_port");
	char *radius_prekey = nvram_safe_get("radius_prekey");
	
//
//	char *aaa_server = nvram_safe_get("aaa_server");
	char *aaa_port = nvram_safe_get("aaa_port");
//	char *aaa_prekey = nvram_safe_get("aaa_prekey");

	if ( 1 != atoi(dot1x_enable) )
	{
        vty_output("  802.1X System \n");
        vty_output("-----------------------------------------------\n");
        vty_output("802.1X STATUS ......DISABLE \n");
	}
    else
	{   

		//memset(reAuth, '\0', sizeof(reAuth));
		memset(suppMAC, '\0', sizeof(suppMAC));
		memset(identity, '\0', sizeof(identity));
		memset(flags, '\0', sizeof(flags));
		memset(AuthState, '\0', sizeof(AuthState));
		memset(portMode, '\0', sizeof(portMode));
		memset(BKDState, '\0', sizeof(BKDState));
		memset(portEnabled, '\0', sizeof(portEnabled));

		if (!strlen(reauth_time))    
			strcpy(reauth_time,"3600");
//		if (!strlen(reauth_enable))
//			*reauth_enable='0';	

		system("/usr/bin/killall -SIGUSR1 hostapd > /dev/null 2>&1");
		usleep(5000);
		
	
	if(access(SHOW_DOT1X,F_OK) == 0)
		{
			fp_status=fopen(SHOW_DOT1X,"r");
			if(fp_status != NULL)
			{

				fseek(fp_status,0,SEEK_SET); 
				memset(&line, '\0', 512);
				

				while(fgets(line, 512, fp_status)!=NULL)
				{

					p = strchr(line, '=');				
					if(NULL == p)
					
	continue;
					
if (strstr(line,"reAuthEnabled")) 
					
{
					
	p=p+1;
					
	strcpy(reAuth, p);
					
}
					
else if (strstr(line,"reAuthPeriod")) 
					
					{
						p=p+1;
						reAuthPeriod=atoi(p);
					}
					else if (strstr(line,"quietPeriod")) 
					{
						p=p+1;
						quietPeriod=atoi(p);
					}
					else if (strstr(line,"serverTimeout")) 
					{
						p=p+1;
						serverTimeout=atoi(p);
					}
					else if (strstr(line,"reAuthMax")) 
					{
						p=p+1;
						reAuthMax=atoi(p);
					}
					else if ((strstr(line,"STA")) && (CLI_SHOW_INTERFACE == show_type)  )
					{
						p=p+1;
						memcpy(suppMAC,p,12);
					}
					else if ( (CLI_SHOW_INTERFACE == show_type) && (strstr(line,"portEnabled")) )
					{
						p=p+1;
						strcpy(portEnabled, p);
					}
					else if ( (CLI_SHOW_INTERFACE == show_type) && (strstr(line,"portControl")) )
					{
						p=p+1;
						strcpy(portMode, p);
					}
					else if ( (CLI_SHOW_INTERFACE == show_type) && (strstr(line,"identity")) )
					{
						p=p+1;
						strcpy(identity, p);
					}
					else if ( (CLI_SHOW_INTERFACE == show_type) && (strstr(line,"flags")) )
					{
						p=p+1;
						strcpy(flags, p);
					}
					else if ( (CLI_SHOW_INTERFACE == show_type) && (strstr(line,"AuthenticatorState")) )
					{
						p=p+1;
						strcpy(AuthState, p);
					}
					else if ( (CLI_SHOW_INTERFACE == show_type) && (strstr(line,"reAuthCount")) )
					{
						p=p+1;
						reAuthCount=atoi(p);
					}
					else if ( (CLI_SHOW_INTERFACE == show_type) && (strstr(line,"BackendState")) )
					{
						p=p+1;
						strcpy(BKDState, p);
					}
					else if ( (CLI_SHOW_INTERFACE == show_type) && (strstr(line,"backendOtherRequestsToSupplicant")) )
					{
						p=p+1;
						reqCount=atoi(p);
					}
				}
			}
		}
		vty_output( "  Radius Parameters\n");
		vty_output( "--------------------------------------------------\n");
		vty_output( "Radius Server        : %s\n"
				"Radius Key           : %s\n"
				"Radius Auth Port     : %s\n"
				"Radius Account Port  : %s\n",
				radius_server,radius_prekey,radius_port,aaa_port);
		vty_output( "\n");
		vty_output( "  802.1X Parameters\n");
		vty_output( "--------------------------------------------------\n");
		vty_output( "reAuth               : %s\n"
				"reAuth-Period        : %d\n"
				"quiet-Period         : %d\n"
				"Server-timeout       : %d\n"
				"reAuth-max           : %d\n"
				"authen-type          : EAP\n",
				strlen(reauth_enable) ? "TRUE":"FALSE",atoi(reauth_time),quietPeriod,serverTimeout,reAuthMax);

		if ( CLI_SHOW_INTERFACE == show_type )
		{
			vty_output( "\n\n");
			vty_output( "IEEE 802.1x on ");
			vty_output( "%s0/%-2d", (portid<=FNUM)?"F":"G", (portid<=FNUM)?portid:(portid-FNUM));
			vty_output( " %s\n",(portEnabled=="TRUE") ? "ENABLE":"UNABLE");

			if ( "TRUE" == portEnabled)
				vty_output( "  Port control          : %s\n"
						"  Authen Type           : EAP\n"
						"  Authen Method         : DEFAULT\n"
						"  Account Method        : DEFAULT\n"
						"  Permit Users          : %s\n"
						"    Current Supplicant  : %s\n"
						"    Authorized          : %s\n"
						"    Authenticator State Machine\n"
						"      State             : %s\n"
						"      reAuthCount       : %d\n"
						"    Backend State Machine\n"
						"      State             : %s\n"
						"      Request Count     : %d\n",
						portMode,identity,suppMAC,(flags=="0x02") ? "YES":"NO",
						AuthState,reAuthCount,BKDState,reqCount);	
		}
	}
	free(dot1x_enable);
	free(dot1x_config);
	free(reauth_enable);
	free(reauth_time);
	free(radius_server);
	free(radius_port);
	free(radius_prekey);
//	free(aaa_server);
	free(aaa_port);
//	free(aaa_prekey);
	return;	
}
void show_dot1x_info()
{
	vty_output("%-4s%-12s%-26s%-8s%-20s\n","ID","PortId","MAC ADRRESS","VID","STATE");
	vty_output("%-4s%-12s%-26s%-8s%-20s\n","---","------","-------------","---","------");
    FILE *fp;
	int id = 0;
	char buf[128];
	char dot1x_info[128];
	char *p1=NULL, *p2=NULL;
	
	system("/usr/bin/killall -SIGUSR1 hostapd > /dev/null 2>&1");
	usleep(500000);

	memset(buf, 0, sizeof(buf));
	memset(dot1x_info, 0, sizeof(dot1x_info));
	
	if((fp=fopen("/tmp/hostapd.dump","r"))!=NULL)
	{
    	while(fgets(buf, 128, fp)!=NULL)
    	{
			p1 = buf;
			p2 = strchr(p1, '\n');
			memcpy(dot1x_info, p1, p2-p1+1);
			id++;
			vty_output("%-4d%s",id, dot1x_info);
    	}
		fclose(fp);
	}	
}
/*----------------------------------------show_exec_timeout---------------------------------*/
#if 0
int func_show_exec_timeout()
{
    char *exec_timeout = nvram_safe_get("login_exec_timeout");
	/*modified by xuanyunchang for exec_timeout show*/
	if(0 == strlen(exec_timeout)){
		vty_output("The exec_timeout is default:300(s)\n");
	}else if(0 == atoi(exec_timeout)){
        vty_output("The exec_timeout is unlimited\n");
    }else{
		vty_output("The exec_timeout is %s(s)\n", exec_timeout);
	}
	free(exec_timeout);
    return 0;
}
#endif

/*modify by wei.zhang*/
int func_show_exec_timeout()
{
    char *exec_timeout = nvram_safe_get("login_timeout");	
	int i, time_out;
	char *p = exec_timeout;

	for(i = 0; i < 17; i++)
		p = strchr( p, ':' ) + 1;
	time_out = atoi(p);

	if(300 == time_out){
		vty_output("The exec_timeout is default:300(s)\n");
	}else if(0 == time_out){
        vty_output("The exec_timeout is unlimited\n");
    }else{
		vty_output("The exec_timeout is %d(s)\n", time_out);
	}
	free(exec_timeout);
    return 0;
}

int func_show_flow_interval()
{
    char *flow_interval = nvram_safe_get(NVRAM_STR_FLOW_INTERVAL);	
    int time_out=0;

    if(flow_interval == NULL)
        return 0;
    
    time_out = atoi(flow_interval);

    if(300 == time_out){
        vty_output("The flow_interval is default:%d(s)\n",time_out);
    }else{
        vty_output("The flow_interval is %d(s)\n", time_out);
    }
    
    free(flow_interval);
    return 0;
}

/*---------------------------------------show mac----------------------------------*/
void func_show_mac_add()
{
    FILE *fp;
    uint8 mac[6], name[16];
    char line[128], *p;
    int skfd, count = 0, port,vid, tgid, mtype; 

	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return -1;
	
    bcm_get_all_mac(skfd);
	close(skfd);
		
    fp=fopen("/var/mac","r+");
    if( fp == NULL) return 0;
    
    fseek(fp,0,SEEK_SET);
    memset(line, '\0', 128); 


	vty_output(" %-10s%-20s%-18s%-20s\n", "Interface", "VLAN ID", "Type", "MAC Address");
	vty_output(" ====================================================================\n");
	    
    while(fgets(line,128,fp)!=NULL)
    {
        p = line;       
        sscanf(p,"%02x-%02x", &mac[0], &mac[1]);
        p += 6;       
        sscanf(p,"%02x-%02x", &mac[2], &mac[3]);     
        p += 6;       
        sscanf(p,"%02x-%02x", &mac[4], &mac[5]);       
        p += 6;    
        sscanf(p, "%d %d %d %d", &vid, &port, &tgid, &mtype);    

	    if(phy2port[port]!=0 && phy2port[port]!= -1)
	    {
	        memset(name, '\0', sizeof(name));    
	        
	        if(tgid > 0)
	            sprintf(name, "port-agg %d", tgid);
#if (XPORT==0)        	            
	        else if (port <= FNUM)
	            sprintf(name, "f0/%d", port);  
	        else
	            sprintf(name, "g0/%d", port-FNUM); 
#endif      
#if (XPORT==1)        	            
	        else if (port <= GNUM)
	            sprintf(name, "g0/%d", port);  
	        else
	            sprintf(name, "t0/%d", port-GNUM); 
#endif        	              	            
	                 
			vty_output(" %-10s%-20d%-8s     %02x-%02x-%02x-%02x-%02x-%02x\n", name, vid, (mtype==1)?"Static":"Dynamic", 
			        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		}
		memset(line, '\0', 128); 
    }
    
    fclose(fp);    		  
    unlink("/var/mac");
	return 0;	
}

void func_show_mac_add_dy()
{
    FILE *fp;
	uint64_t port_int = 0x00ULL;
    uint8 mac[6], name[16];
    char line[128], *p;
    int skfd, count = 0, port,vid, tgid, mtype; 

	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return -1;
	
    bcm_get_special_mac(skfd, 1, 0, &port_int);
	close(skfd);
		
    fp=fopen("/var/mac","r+");
    if( fp == NULL) return 0;
    
    fseek(fp,0,SEEK_SET);
    memset(line, '\0', 128); 

	vty_output("    %-18s%-12s%-10s%-10s\n", "MAC Address", "VLAN ID", "Type", "Interface");
	vty_output(" ====================================================================\n");

    while(fgets(line,128,fp)!=NULL)
    {
        p = line;       
        sscanf(p,"%02x-%02x", &mac[0], &mac[1]);
        p += 6;       
        sscanf(p,"%02x-%02x", &mac[2], &mac[3]);     
        p += 6;       
        sscanf(p,"%02x-%02x", &mac[4], &mac[5]);       
        p += 6;    
        sscanf(p, "%d %d %d %d", &vid, &port, &tgid, &mtype);    

	    if(phy2port[port]!=0 && phy2port[port]!= -1)
	    {
	        memset(name, '\0', sizeof(name));    
	        
	        if(tgid > 0)
	            sprintf(name, "port-agg %d", tgid);
#if (XPORT==0)        	            
	        else if (port <= FNUM)
	            sprintf(name, "f0/%d", port);  
	        else
	            sprintf(name, "g0/%d", port-FNUM); 
#endif      
#if (XPORT==1)        	            
	        else if (port <= GNUM)
	            sprintf(name, "g0/%d", port);  
	        else
	            sprintf(name, "t0/%d", port-GNUM); 
#endif        	              	            

			if(1 != mtype)
				vty_output(" %02x:%02x:%02x:%02x:%02x:%02x      %-9d%-13s%-10s\n", 
							mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], vid, "Dynamic",  name);
		}
		memset(line, '\0', 128); 
    }
    
    fclose(fp);    		  
    unlink("/var/mac");
    
	return 0;	
}
void func_show_mac_addr_value(struct users *u)
{	
	char tmp[32];
	char mac_addr[MAX_ARGV_LEN] = {'\0'};
    FILE *fp;
    uint8 mac[6], name[16], *p1;
    char line[128], *p;
    int skfd, count = 0, port,vid, tgid, mtype; 
	
	cli_param_get_string(STATIC_PARAM, 0, mac_addr, u);
	strcpy(tmp, mac_addr);
    convert_mac_address(tmp);
    input_num(tmp, 1, 8, &c_mac);

	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return -1;
	
    bcm_get_all_mac(skfd);
	close(skfd);
		
    fp=fopen("/var/mac","r+");
    if( fp == NULL) return 0;
    
    fseek(fp,0,SEEK_SET);
    memset(line, '\0', 128); 

	vty_output("    %-18s%-12s%-10s%-10s\n", "MAC Address", "VLAN ID", "Type", "Interface");
	vty_output(" ====================================================================\n");
	    
    while(fgets(line,128,fp)!=NULL)
    {
        p = line;       
        sscanf(p,"%02x-%02x", &mac[0], &mac[1]);
        p += 6;       
        sscanf(p,"%02x-%02x", &mac[2], &mac[3]);     
        p += 6;       
        sscanf(p,"%02x-%02x", &mac[4], &mac[5]);       
        p += 6;    
        sscanf(p, "%d %d %d %d", &vid, &port, &tgid, &mtype);    
        
        p1 = (uint8 *)&c_mac;
        
	    if((phy2port[port]!=0) && (phy2port[port]!= -1) && (*(p1+5) == mac[0]) && (*(p1+4) == mac[1]) && (*(p1+3) == mac[2])&& (*(p1+2) == mac[3]) && (*(p1+1) == mac[4]) && (*(p1+0) == mac[5]))
	    {
	        memset(name, '\0', sizeof(name));    
	        
	        if(tgid > 0)
	            sprintf(name, "port-agg %d", tgid);
#if (XPORT==0)        	            
	        else if (port <= FNUM)
	            sprintf(name, "f0/%d", port);  
	        else
	            sprintf(name, "g0/%d", port-FNUM); 
#endif      
#if (XPORT==1)        	            
	        else if (port <= GNUM)
	            sprintf(name, "g0/%d", port);  
	        else
	            sprintf(name, "t0/%d", port-GNUM); 
#endif        	              	            

			vty_output(" %02x:%02x:%02x:%02x:%02x:%02x      %-9d%-13s%-10s\n", 
							mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], vid, (mtype==1)?"Static":"Dynamic",  name);

		}
		memset(line, '\0', 128); 
    }
    
    fclose(fp);    		  
    unlink("/var/mac");
	return 0;	
}
void func_show_mac_addr_mul()
{    
    FILE *fp;
    uint8 mac[6], name[16];
    char line[128], *p;
	uint64 pmap = 0x00ULL;
	uint32 p1, p2;
    int skfd, count = 0, port,vid; 
	int is_first=1;
	int index;

    unlink("/var/mct");
	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return -1;
	
    bcm_get_multi_mac(skfd);
	close(skfd);
		
    fp=fopen("/var/mct","r+");
    if( fp == NULL) return 0;
    
    fseek(fp,0,SEEK_SET);
    memset(line, '\0', 128); 
	
	vty_output("    %-18s%-12s%-10s%-10s\n", "MAC Address", "VLAN ID", "Type", "Interface");
	vty_output(" ====================================================================\n");
	    
    while(fgets(line,128,fp)!=NULL)
    {
       	p = strtok(line, ":");
		sscanf(p,"%02X%02X%02X%02X%02X%02X", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
       	p = strtok(NULL, ":");
		sscanf(p,"%d", &vid);
       	p = strtok(NULL, ":");
        sscanf(p, "%08x%08x", &p1, &p2);    
		
		pmap = (p1 << 32 ) | p2;

		vty_output(" %02x:%02x:%02x:%02x:%02x:%02x		%-9d%-13s%", 
									mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], vid, "Multicast");

		index = 0;
		is_first =1;
		for(port=0;port < PNUM; port++)
		{
			if(pmap & (1ULL << port))
			{
				if(is_first == 0)
				{
					vty_output(",");
				}
				else
				{
					is_first = 0;
				}

				index ++;
				if(index == 4)
				{
					index = 0;
					vty_output("\n                            | ");
				}
#if (XPORT==0)	
				if(port < FNUM)
				{
					vty_output("f0/%d", port);  
				}
				else
				{
					vty_output("g0/%d", port-FNUM); 
				}
#endif		
#if (XPORT==1)	
				if(port < GNUM)
				{
					vty_output("g0/%d", port);  
				}
				else
				{
					vty_output("t0/%d", port-GNUM); 
				}
#endif						
			}
		}
		vty_output("\n");
		
		memset(line, '\0', 128); 
    }
    
    fclose(fp);    		  
//    unlink("/var/mct");
    
	return 0;	
}
void func_show_mac_addr_static()
{
    FILE *fp = NULL;
	uint64_t port_int = 0x00ULL;
    uint8 mac[6], name[16];
    char line[128], *p = NULL;
    int skfd, count = 0, port,vid, tgid, mtype; 
	int i = 0;
	
   	unlink("/var/mac");
	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return -1;
	
    bcm_get_special_mac(skfd, 2, 0, &port_int);
	close(skfd);
		
    fp=fopen("/var/mac", "r+");
    if( fp == NULL) return 0;
    
    fseek(fp, 0 ,SEEK_SET);
    memset(line, '\0', 128); 

	vty_output("    %-18s%-12s%-10s%-10s\n", "MAC Address", "VLAN ID", "Type", "Interface");
	vty_output(" ====================================================================\n");
	    
    while(fgets(line, 128, fp)!=NULL)
    {
        p = line;       
        sscanf(p,"%02x-%02x", &mac[0], &mac[1]);
        p += 6;       
        sscanf(p,"%02x-%02x", &mac[2], &mac[3]);     
        p += 6;       
        sscanf(p,"%02x-%02x", &mac[4], &mac[5]);       
        p += 6;    
        sscanf(p, "%d %d %d %d", &vid, &port, &tgid, &mtype);    

	    if(phy2port[port]!=0 && phy2port[port]!= -1)
	    {
	        memset(name, '\0', sizeof(name));    
	        
	        if(tgid > 0)
	            sprintf(name, "port-agg %d", tgid);
#if (XPORT==0)        	            
	        else if (port <= FNUM)
	            sprintf(name, "f0/%d", port);  
	        else
	            sprintf(name, "g0/%d", port-FNUM); 
#endif      
#if (XPORT==1)        	            
	        else if (port <= GNUM)
	            sprintf(name, "g0/%d", port);  
	        else
	            sprintf(name, "t0/%d", port-GNUM); 
#endif        	              	            
	        if(1 == mtype)
				vty_output(" %02x:%02x:%02x:%02x:%02x:%02x      %-9d%-13s%-10s\n", 
							mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], vid, "Static",  name);
			
		}
		memset(line, '\0', 128); 
    }
    
    fclose(fp);    		  
   //	unlink("/var/mac");
    
	return 0;	
}

void func_show_mac_addr_vlan(struct users *u)
{	
    FILE *fp;
	uint64_t port_int = 0x00ULL;
    uint8 mac[6], name[16];
    char line[128], *p;
    int skfd, count = 0, port, vid, tgid, mtype, c_vid; 

	cli_param_get_int(DYNAMIC_PARAM, 0, &c_vid, u);
   	
	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
		return -1;
	
    bcm_get_special_mac(skfd, 0, c_vid, &port_int);
	close(skfd);
		
    fp=fopen("/var/mac","r+");
    if( fp == NULL) return 0;
    
    fseek(fp,0,SEEK_SET);
    memset(line, '\0', 128); 

	vty_output("    %-18s%-12s%-10s%-10s\n", "MAC Address", "VLAN ID", "Type", "Interface");
	vty_output(" ====================================================================\n");
	    
    while(fgets(line,128,fp)!=NULL)
    {
        p = line;       
        sscanf(p,"%02x-%02x", &mac[0], &mac[1]);
        p += 6;       
        sscanf(p,"%02x-%02x", &mac[2], &mac[3]);     
        p += 6;       
        sscanf(p,"%02x-%02x", &mac[4], &mac[5]);       
        p += 6;    
        sscanf(p, "%d %d %d %d", &vid, &port, &tgid, &mtype);    

	    if(phy2port[port]!=0 && phy2port[port]!= -1)
	    {
	        memset(name, '\0', sizeof(name));    
	        
	        if(tgid > 0)
	            sprintf(name, "port-agg %d", tgid);
#if (XPORT==0)	            
	        else if (port <= FNUM)
	            sprintf(name, "f0/%d", port);  
	        else
	            sprintf(name, "g0/%d", port-FNUM); 
#endif	            
#if (XPORT==1)	            
	        else if (port <= GNUM)
	            sprintf(name, "g0/%d", port);  
	        else
	            sprintf(name, "t0/%d", port-GNUM); 
#endif	            

			vty_output(" %02x:%02x:%02x:%02x:%02x:%02x      %-9d%-13s%-10s\n", 
							mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], vid, (mtype==1)?"Static":"Dynamic",  name);  

		}
		memset(line, '\0', 128); 
    }
    
    fclose(fp);    		  
    unlink("/var/mac");
    
	return 0;	
}

void func_show_mac_addr_blackhole()
{
    char mac[24] = {0};
	char vid[8] = {0};
	char *mac_bloackhole = nvram_safe_get("mac_bloackhole");
	char *pt, *p_tok;
	
	vty_output("    %-18s%-12s%-10s\n", "MAC Address", "VLAN ID", "Type");
	vty_output(" =========================================\n");


	pt = mac_bloackhole;

	p_tok = strtok(pt, ",");
	while( p_tok ){	
		sprintf(mac, "%s", p_tok);
		p_tok = strtok(NULL, ";");
		sprintf(vid, "%s", p_tok);
		
		vty_output(" %-24s%-8s%-12s\n", mac, vid, "Blackhole");

		if(p_tok)
			p_tok = strtok(NULL, ",");
	}

	free(mac_bloackhole);
	return 0; 
	
}

static int cli_show_interface(FILE * fp, int portid)
{
	char *port_enable = cli_nvram_safe_get(CLI_ALL_ONE, "port_enable");
	char *port_flow = cli_nvram_safe_get(CLI_ALL_ZERO, "port_flow");
	char *port_speed = cli_nvram_safe_get(CLI_SPEED_ALL_AUTO, "port_speed");
	char *port_duplex = cli_nvram_safe_get(CLI_DUPLEX_ALL_AUTO, "port_duplex");
	char *port_description = cli_nvram_safe_get(CLI_ALL_DES, "port_description");
    uint8_t r_stp_state;

	int skfd, mtu;
	int cnt = 1, m_duplex, m_speed;	//by zhangwei
	uint64_t link;
	char *s_duplex, *s_speed, *r_duplex, r_speed[16], *p,*p1;
	char descri[1024] = {0};
	
	memset(descri,'\0',sizeof(descri));
	p=port_description;
	
	if((skfd = open(DEVICE_FILE_NAME, 0)) < 0){ 
		free(port_enable);
		free(port_speed);
		free(port_duplex);
		free(port_flow);
		free(port_description);
		return CLI_FAILED;
	}
	/*port states*/
	bcm_get_swlink_status(&link);
	
    bcm_get_rstp_stp(skfd, 0, portid, &r_stp_state);/*shanming.ren 2011-11-9 9:42:13*/
	
	/*get port_enable set*/
	/*  betty modified for giga port */
	if(*(port_enable+portid-1)=='1')
    {
        if(((r_stp_state) & 0xe0) == 0x20)
        {
#if (XPORT==0)            
            fprintf(fp, "%s 0/%d is err-disabled,", (portid<=FNUM)?"FastEthernet":"GigaEthernet", (portid<=FNUM)?portid:(portid-FNUM));
#endif
#if (XPORT==1)            
            fprintf(fp, "%s 0/%d is err-disabled,", (portid<=GNUM)?"GigaEthernet":"TenGigaEthernet", (portid<=GNUM)?portid:(portid-GNUM));
#endif
			if( ((link>>phy[portid])&0x01ULL)==0x00ULL)
			{
				fprintf(fp, "lines protocol is down (notconnect)\n");
			}
			else
			{
				fprintf(fp, "lines protocol is up (connected)\n");
			}
        }
		else if( ((link>>phy[portid])&0x01ULL)==0x00ULL)
        {
#if (XPORT==0)   
			fprintf(fp, "%s 0/%d is down,", (portid<=FNUM)?"FastEthernet":"GigaEthernet", (portid<=FNUM)?portid:(portid-FNUM));
#endif
#if (XPORT==1)    
			fprintf(fp, "%s 0/%d is down,", (portid<=GNUM)?"GigaEthernet":"TenGigaEthernet", (portid<=GNUM)?portid:(portid-GNUM));
#endif			
			fprintf(fp, "lines protocol is down (notconnect)\n");
		}
        else
        {
#if (XPORT==0)   
			fprintf(fp, "%s 0/%d is up,", (portid<=FNUM)?"FastEthernet":"GigaEthernet", (portid<=FNUM)?portid:(portid-FNUM));
#endif
#if (XPORT==1)  
			fprintf(fp, "%s 0/%d is up,", (portid<=GNUM)?"GigaEthernet":"TenGigaEthernet", (portid<=GNUM)?portid:(portid-GNUM));
#endif 
			fprintf(fp, "lines protocol is up (connected)\n");
		}
	}
    else
    {
#if (XPORT==0)   
		fprintf(fp, "%s 0/%d is administratively down,lines protocol is down (disabled)\n", (portid<=FNUM)?"FastEthernet":"GigaEthernet", (portid<=FNUM)?portid:(portid-FNUM));
#endif
#if (XPORT==1)   
		fprintf(fp, "%s 0/%d is administratively down,lines protocol is down (disabled)\n", (portid<=GNUM)?"GigaEthernet":"TenGigaEthernet", (portid<=GNUM)?portid:(portid-GNUM));
#endif 
	}
	
	/* port description */
	for(cnt = 1; cnt <= portid; cnt++)				//by zhangwei
	{
		p1=strchr(p,';');
		if(p1 == NULL)
			continue;
    	memset(descri,'\0',sizeof(descri));
    	memcpy(descri,p,p1-p);
    	p=p1+1;
	}
	
	//descri[12] = '\0';
	fprintf(fp,"Description: ");
	fprintf(fp, "%-s\n",descri);

    bcm_port_mtu_get(skfd, portid, &mtu);
	/* show MTU&BW&DLY*/
	if(portid<=FNUM)
		fprintf(fp,"MTU %d bytes, BW 100000 kbit, DLY 10 usec\n", (mtu<(13000-28))?(mtu-28):13000);
	else
		fprintf(fp,"MTU %d bytes, BW 1000000 kbit, DLY 10 usec\n", (mtu<(13000-28))?(mtu-28):13000);
	fprintf(fp,"Encapsulation ARPA\n");

	/*port speed set*/ 
	switch(*(port_speed+portid-1)-'0')
	{
		case PORT_SPEED_AUTO:
			s_speed  = "Auto_Speed";
			break;

		case PORT_SPEED_10:
			s_speed  = "10M";
			break;
			
		case PORT_SPEED_100:
			s_speed  = "100M";
			break;
		
		case PORT_SPEED_1000:
			s_speed  = "1000M";
			break;
			
		default:
			s_speed  ="100M";
			break;
	}

	/*port duplex set*/ 
	switch(*(port_duplex+portid-1)-'0')
	{
		case PORT_DUPLEX_AUTO:
			s_duplex = "Auto_Duplex";
			break;
			
		case PORT_DUPLEX_FULL:
			s_duplex ="FULL_Duplex";
			break;
			
		case PORT_DUPLEX_HALF:
			s_duplex ="HALF_Duplex";
			break;
			
		default:
			s_duplex ="FULL_Duplex";
			break;			
	}
	
	/*real port speed*/
    bcm_get_port_duplex(skfd, 0, portid, &m_duplex);
    bcm_get_port_speed(skfd, 0, portid, &m_speed);
 	
	if(((link>>phy[portid])&0x01ULL)==0x00ULL)
	{
		memset(r_speed, '\0', sizeof(r_speed));
		r_duplex= "";
	}
	else
	{
        memset(r_speed, '\0', sizeof(r_speed));
        if(m_speed != 0)
            sprintf(r_speed, "%dM", m_speed);
                		
		if(m_duplex == 0x00)
			r_duplex = "HALF";
		else
			r_duplex = "FULL";
	}
		
	fprintf(fp, "%s(%s),%s(%s)\n",s_duplex,r_duplex,s_speed,r_speed);

	/*set flow control*/
		if (*(port_flow+portid-1)=='1')
		    fprintf(fp, "flow_control on\n");
		else 
			fprintf(fp, "flow_control off\n");
	
	//fprintf(fp, "\n");
	
	free(port_enable);
	free(port_speed);
	free(port_duplex);
	free(port_flow);
	/* the statis of the ports */
	uint32 high_data1;
	uint32 low_data1;
	uint32 high_data2;
	uint32 low_data2;
	uint64_t tmp_total;
	uint32 total1,total2;
	uint32 tmp_good1,tmp_good2,tmp_good3,tmp_good4;
	uint32_t ucast_tx=0, ucast_rx=0, mcast_tx=0, mcast_rx=0, bcast_tx=0, bcast_rx=0;
	uint64_t t_tx=0,t_rx=0;
	int interval = 300;//s
	char *flow_interval = NULL;
	
	/* rx information */
	get_port_txrx_status(skfd, portid, RxOctets, &high_data1, &low_data1);
	get_port_txrx_status(skfd, portid, RxBroadcastPkts, &tmp_good4, &tmp_good1);
	get_port_txrx_status(skfd, portid, RxMulticastPkts, &tmp_good4, &tmp_good2);
	get_port_txrx_status(skfd, portid, RxUnicastPkts, &tmp_good4, &tmp_good3);
	
	bcm_get_port_txrx_average_rate_bps(portid,&t_tx,&t_rx);
	bcm_get_port_txrx_average_rate_pps(portid, &ucast_tx,  &ucast_rx, &mcast_tx, &mcast_rx, &bcast_tx, &bcast_rx);

    flow_interval = nvram_safe_get(NVRAM_STR_FLOW_INTERVAL);
    if(flow_interval != NULL) {
    	interval = atoi(flow_interval);
        free(flow_interval);
        flow_interval = NULL;
    }
    fprintf(fp, "     Last %d seconds input: %llu bytes/sec Ucast %lu pps Multicast %lu pps Broadcast %lu pps\n",interval,t_rx,ucast_rx,mcast_rx,bcast_rx);
    fprintf(fp, "     Last %d seconds output: %llu bytes/sec Ucast %lu pps Multicast %lu pps Broadcast %lu pps\n",interval,t_tx,ucast_tx,mcast_tx,bcast_tx);
	tmp_total=(uint64_t)(high_data1*4294967296+ low_data1);
	fprintf(fp, "     %s %lu %s, %llu %s\n","Received",tmp_good1+tmp_good2+tmp_good3,"packets",tmp_total,"bytes");
	#if 0
	total1=(uint32_t)tmp_total/10000000000;
	total2=(uint32_t)tmp_total%10000000000;
    if(0==total1){
		fprintf(fp, "     %s %lu %s, %lu %s\n","Received",tmp_good1+tmp_good2+tmp_good3,"packets",total2,"bytes");
    }
    else
    {
		fprintf(fp, "     %s %lu, %s %lu %lu %s\n","Received",tmp_good1+tmp_good2+tmp_good3,"packets",total1,total2," bytes");
    }
    #endif
	get_port_txrx_status(skfd, portid, RxBroadcastPkts, &high_data1, &low_data1);
	get_port_txrx_status(skfd, portid, RxMulticastPkts, &high_data2, &low_data2);
	fprintf(fp, "     %lu %s, %lu %s\n",low_data1,"broadcasts",low_data2,"multicasts");	

	get_port_txrx_status(skfd, portid, RxDropPkts, &high_data1, &low_data1);
	get_port_txrx_status(skfd, portid, RxPausePkts, &high_data2, &low_data2);
	fprintf(fp, "     %lu %s, %lu %s\n",low_data1,"discard",low_data2,"PAUSE");
	
	get_port_txrx_status(skfd, portid, RxAlignmentErrors, &high_data1, &low_data1);
	get_port_txrx_status(skfd, portid, RxFCSErrors, &high_data2, &low_data2);
	fprintf(fp, "     %lu %s, %lu %s\n",low_data1,"align",low_data2,"FCS");
	
	get_port_txrx_status(skfd, portid, RXSymbolError, &high_data1, &low_data1);
	get_port_txrx_status(skfd, portid, RxFragments, &high_data2, &low_data2);
	fprintf(fp, "     %lu %s, %lu %s\n",low_data1,"symbol",low_data2,"fragment");
	
	get_port_txrx_status(skfd, portid, RxJabbers, &high_data1, &low_data1);
	get_port_txrx_status(skfd, portid, RxOversizePkts, &high_data2, &low_data2);
	fprintf(fp, "     %lu %s, %lu %s\n",low_data1,"jabber",low_data2,"oversize");
	
	get_port_txrx_status(skfd, portid, RxUndersizePkts, &high_data1, &low_data1);
	get_port_txrx_status(skfd, portid, RxExcessSizeDisc, &high_data2, &low_data2);
	fprintf(fp, "     %lu %s, %lu %s\n",low_data1,"undersize",low_data2,"excesssize");
	
    /* tx information */
	get_port_txrx_status(skfd, portid, TxOctets, &high_data1, &low_data1);
	get_port_txrx_status(skfd, portid, TxBroadcastPkts, &tmp_good4, &tmp_good1);
	get_port_txrx_status(skfd, portid, TxMulticastPkts, &tmp_good4, &tmp_good2);
	get_port_txrx_status(skfd, portid, TxUnicastPkts, &tmp_good4, &tmp_good3);
	tmp_total=high_data1*4294967296+ low_data1;
	fprintf(fp, "     %s %lu %s, %llu %s\n","Transmited",tmp_good1+tmp_good2+tmp_good3,"packets",tmp_total,"bytes");
	#if 0
	total1=tmp_total/10000000000;
	total2=tmp_total%10000000000;
	if(0==total1){
	    fprintf(fp, "     %s %lu %s, %lu %s\n","Transmited",tmp_good1+tmp_good2+tmp_good3,"packets",total2,"bytes");
	}
	else
	{
	    fprintf(fp, "     %s %lu %s, %lu %lu %s\n","Transmited",tmp_good1+tmp_good2+tmp_good3,"packets",total1,total2," bytes");	    
	}
	#endif
    get_port_txrx_status(skfd, portid, TxBroadcastPkts, &high_data1, &low_data1);
	get_port_txrx_status(skfd, portid, TxMulticastPkts, &high_data2, &low_data2);
	fprintf(fp, "     %lu %s, %lu %s\n",low_data1,"broadcasts",low_data2,"multicasts");
	
	get_port_txrx_status(skfd, portid, TxDropPkts, &high_data1, &low_data1);
	get_port_txrx_status(skfd, portid, TxPausePkts, &high_data2, &low_data2);
	fprintf(fp, "     %lu %s, %lu %s\n",low_data1,"discard",low_data2,"PAUSE");

	get_port_txrx_status(skfd, portid, TxCollisions, &high_data1, &low_data1);
	get_port_txrx_status(skfd, portid, TxFrameInDisc, &high_data2, &low_data2);
	fprintf(fp, "     %lu %s, %lu %s\n",low_data1,"collision",low_data2,"indisc");
	
	get_port_txrx_status(skfd, portid, TxDeferredTransmit, &high_data1, &low_data1);
	get_port_txrx_status(skfd, portid, TxSingleCollision, &high_data2, &low_data2);
	fprintf(fp, "     %lu %s, %lu %s\n",low_data1,"deferred",low_data2,"single");
	
	get_port_txrx_status(skfd, portid, TxMultipleCollision, &high_data1, &low_data1);
	get_port_txrx_status(skfd, portid, TxExcessiveCollision, &high_data2, &low_data2);
	fprintf(fp, "     %lu %s, %lu %s\n",low_data1,"multiple",low_data2,"excessive");
	
	get_port_txrx_status(skfd, portid, TxLateCollision, &high_data1, &low_data2);
	fprintf(fp, "     %lu %s\n",low_data1,"late");

	fprintf(fp, "\n");
	close(skfd);
	free(port_description);
	
    return CLI_SUCCESS;
}

int func_show_inter()
{
	int portid;
	FILE * fp;
	
	fp = fopen(SHOW_INTERFACE,"w+");
    if(fp == NULL)
    return 0;
    for(portid = 1; portid<=PNUM; portid++) {
    	cli_show_interface(fp, portid);
    }
    fclose(fp);
	
    cli_read_config(SHOW_INTERFACE);
	
    return 0;
}

/*------------------------------------show_all_ip_acl--------------------------*/
int func_show_all_ip_acl()
{
	FILE *fp;
	IP_STANDARD_ACL_ENTRY entry1;
	IP_EXTENDED_ACL_ENTRY entry2;
	
	if(NULL == (fp = fopen(SHOW_ALL_IP_ACL, "w")))
		return 0;
	fclose(fp);
	
	memset(&entry1, '\0', sizeof(IP_STANDARD_ACL_ENTRY));
	memset(&entry2, '\0', sizeof(IP_EXTENDED_ACL_ENTRY));
	
	ip_std_acl_set("", &entry1, ARL_LIST_SHOW_ALL, -1, 0x00ULL);
	ip_ext_acl_set("", &entry2, ARL_LIST_SHOW_ALL, -1, 0x00ULL);
	
	cli_read_config(SHOW_ALL_IP_ACL);		
	return 0;
}

int func_show_one_ip_acl(struct users *u)
{
	int res, flag=0;
	IP_STANDARD_ACL_ENTRY entry1;
	IP_EXTENDED_ACL_ENTRY entry2;
	char acl_name[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_string(STATIC_PARAM, 0, acl_name, u);

	memset(&entry1, '\0', sizeof(IP_STANDARD_ACL_ENTRY));
	memset(&entry2, '\0', sizeof(IP_EXTENDED_ACL_ENTRY));

	res = ip_std_acl_set(acl_name, &entry1, ACL_NAME_CHECK, -1, 0x00ULL);
	/* ip standard acl name is not exist */
	if(res)
	{
		/* following is for extended  */
		res = ip_ext_acl_set(acl_name, &entry2, ACL_NAME_CHECK, -1, 0x00ULL);
		/* ip extended acl name is not exist */
		if(res)
		{
			printf("access-group %s not exist\n", acl_name);
			return -1;
		}
		else
			flag = 1;	/* extended */
	}
	else
		flag = 0;  /* standard */

	if(0 == flag)
		ip_std_acl_set(acl_name, &entry1, ARL_LIST_SHOW_ONE, -1, 0x00ULL);
	else
		ip_ext_acl_set(acl_name, &entry2, ARL_LIST_SHOW_ONE, -1, 0x00ULL);

	cli_read_config(SHOW_ONE_IP_ACL);
	return 0;
}

/*----------------------------------------show_ip_dhcp_snoopy---------------------------------*/
int func_ip_dhcp_snoopy()
{
	char *arp_enable = nvram_safe_get("arp_enable");
	char *snoop_enable = nvram_safe_get(NVRAM_STR_SNOOP_ENABLE);
	char *relay_enable = nvram_safe_get("relay_enable");

	if( ('1' == *arp_enable)||('1' == *snoop_enable)||('1' == *relay_enable) ) {
		SYSTEM("/usr/bin/killall -SIGUSR2 arp_inspection > /dev/null 2>&1");
		usleep(500000);
	} else {
		vty_output("  Please start dhcp snooping first\n");
	}

	free(arp_enable);
	free(snoop_enable);
	free(relay_enable);

	return 0;

}
void func_show_ip_dhcp_snoop_source_mac()
{
	char *ip_dhcp_snooping_source_mac = nvram_safe_get("ip_dhcp_snooping_source_mac");
	if (*ip_dhcp_snooping_source_mac == '1')
	{
		cli_read_config(DHCP_CONFIG_FILE);
	}
	free(ip_dhcp_snooping_source_mac);	
}
/*----------------------------------------func_show_ip_source_binding-----------------------------*/
int func_show_ip_source_binding()
{
	char tmp[32], str[8];
	cli_source_info_conf *p_source = NULL;

	memset(&cur_source_conf, 0, sizeof(cli_source_conf));
	cur_source_conf.cur_source_info = NULL;

	cli_nvram_conf_get(CLI_SOURCE_BINDING, (unsigned char *)&cur_source_conf);
	p_source = cur_source_conf.cur_source_info;

	printf("  %-22s%-20s%-8s%-6s%s\n", "mac address", "ip address", "port", "vlan", "type");
	while(NULL != p_source) {

			memset(tmp, '\0', sizeof(tmp));
			sprintf(tmp, "%02x:%02x:%02x:%02x:%02x:%02x", p_source->mac_addr[0],
				p_source->mac_addr[1],  p_source->mac_addr[2],  p_source->mac_addr[3],
					p_source->mac_addr[4],  p_source->mac_addr[5]);

			memset(str, '\0', 8);
			if(p_source->port <= FNUM)
			{
				sprintf(str, "%s0/%d", "F", p_source->port);
				printf("  %-22s%-20s%-8s%-6d%s\n", tmp, inet_ntoa(p_source->ip_addr), str, p_source->vlan, "static");
			}
			else
			{
				sprintf(str, "%s0/%d", "G", (p_source->port-FNUM));
				printf("  %-22s%-20s%-8s%-6d%s\n", tmp, inet_ntoa(p_source->ip_addr), str, p_source->vlan, "static");
			}

		p_source = p_source->next;
	}

	cli_nvram_conf_free(CLI_SOURCE_BINDING, (unsigned char *)&cur_source_conf);

	return;

}



/*----------------------------------------func_show_igmp_snooping---------------------------------*/
void func_show_igmp_snooping(void)
{
	char *igmp_enable = nvram_safe_get("igmp_enable");
	char *igmp_query_enable = nvram_safe_get("igmp_query_enable");
	char *igmp_querytime = nvram_safe_get("igmp_querytime");
	char *igmp_agetime = nvram_safe_get("igmp_agetime");

	vty_output("Global IGMP snooping configuration:\n");
	vty_output("-----------------------------------\n");
	vty_output("Globally enable      : %s\n", atoi(igmp_enable)?"Enabled":"Disabled");
	vty_output("Querier              : %s\n", atoi(igmp_query_enable)?"Enabled":"Disabled");
	vty_output("Querier time         : %s\n", igmp_querytime);
	vty_output("Member age time      : %s\n", igmp_agetime);

	free(igmp_enable);
	free(igmp_query_enable);
	free(igmp_querytime);
	free(igmp_agetime);
	return;	
}
/*----------------------------------------func_show_ip_interface---------------------------------*/

void func_show_ip_interface(void)
{
	char tmp[10], state[10];
	char *manage_vlan = nvram_safe_get("manage_vlan");
	char *manage_IMP = nvram_safe_get("manage_IMP");
    char *ip_staticip_enable=nvram_safe_get("ip_staticip_enable");

	int vlanid, flag = 0;
	uint64_t link = 0x0ULL;

	cli_vlan_info_conf *p_vlan = NULL;

	vty_output("%-27s%-16s%-8s%-s\n","Interface","IP Address","Method","Protocol-status");

	vlanid = atoi(manage_vlan);
	if(0 != vlanid) {
		sprintf(tmp, "VLAN%d", vlanid);
		if_info_t if_info;
  		bzero(&if_info,sizeof(if_info_t));
    	strcpy(if_info.ifname, IMP);
		getIFInfo(&if_info);

		if(*manage_IMP=='1') {

			memset(&cur_vlan_conf, 0, sizeof(cli_vlan_conf));
			memset(cur_port_conf, 0, sizeof(cli_port_conf)*PNUM);
			cur_vlan_conf.cur_vlan_info = NULL;

			GENERAL_MSG;
			cli_nvram_conf_get(CLI_VLAN_FOWD, (unsigned char *)&cur_vlan_conf);

			/* get management vlan portmap */
			p_vlan = cur_vlan_conf.cur_vlan_info;
			while(NULL != p_vlan) {
				if(vlanid == p_vlan->vlanid) {
					flag = 1;
					break;          
				}
				p_vlan = p_vlan->next;
			}

			if(1 == flag) {
				/* get current port link state */
				bcm_get_swlink_status(&link);
				if(link & p_vlan->forward)
					sprintf(state, "UP");
				else
					sprintf(state, "DOWN");
			} else
				sprintf(state, "DOWN");
		} else
			sprintf(state, "DOWN");

		vty_output("%-27s%-16s%-8s%-s\n",tmp,(strlen(if_info.ipaddr) > 0)?if_info.ipaddr:"no address",('1' == *ip_staticip_enable)?"Manual":"DHCP",state);
	}

	free(manage_vlan);
	free(manage_IMP);
	free(ip_staticip_enable);

	return;
}

void func_show_ip_interface_detail(void)
{
	char *manage_vlan = nvram_safe_get("manage_vlan");
	char *ip_staticip_enable = nvram_safe_get("ip_staticip_enable");

	if(atoi(ip_staticip_enable) == 0){
		if(0 != atoi(manage_vlan)) {
			char *lan_dhcp_ipaddr = nvram_safe_get("lan_dhcp_ipaddr");
			char *lan_dhcp_netmask = nvram_safe_get("lan_dhcp_netmask");
			char *lan_dhcp_gateway = nvram_safe_get("lan_dhcp_gateway");
			char *lan_dhcp_dns = nvram_safe_get("lan_dhcp_dns");

			vty_output("IP addr: %s for Interface:VLAN%s\n", lan_dhcp_ipaddr, manage_vlan);
			vty_output("Sub net mask: %s\n", lan_dhcp_netmask);
			vty_output("DNS server: %s\n", lan_dhcp_dns);
			vty_output("Default gateway addr: %s\n", lan_dhcp_gateway);

			free(lan_dhcp_ipaddr);
			free(lan_dhcp_netmask);
			free(lan_dhcp_gateway);
			free(lan_dhcp_dns);
		} else{
			vty_output("please set manage vlan first\n");
		}
	} else {
		vty_output("Set the IP address DHCP mode first\n");
	}

	free(manage_vlan);
	free(ip_staticip_enable);

	return;
}


/*--------------------show ip source----------------------------------*/
int func_show_ip_source()
{	
	char tmp[32], str[8];
	cli_source_info_conf *p_source = NULL;

	memset(&cur_source_conf, 0, sizeof(cli_source_conf));
	cur_source_conf.cur_source_info = NULL;

	cli_nvram_conf_get(CLI_SOURCE_BINDING, (unsigned char *)&cur_source_conf);
	p_source = cur_source_conf.cur_source_info;

	vty_output("  %-22s%-20s%-8s%-6s%s\n", "mac address", "ip address", "port", "vlan", "type");
	while(NULL != p_source) {
			
			memset(tmp, '\0', sizeof(tmp));
			sprintf(tmp, "%02x:%02x:%02x:%02x:%02x:%02x", p_source->mac_addr[0],
				p_source->mac_addr[1],  p_source->mac_addr[2],  p_source->mac_addr[3],
					p_source->mac_addr[4],  p_source->mac_addr[5]);

			memset(str, '\0', 8);			
			if(p_source->port <= FNUM)
			{
				sprintf(str, "%s0/%d", "F", p_source->port);
				vty_output("  %-22s%-20s%-8s%-6d%s\n", tmp, inet_ntoa(p_source->ip_addr), str, p_source->vlan, "static");
			}
			else
			{
				sprintf(str, "%s0/%d", "G", (p_source->port-FNUM));
				vty_output("  %-22s%-20s%-8s%-6d%s\n", tmp, inet_ntoa(p_source->ip_addr), str, p_source->vlan, "static");	
			}

		p_source = p_source->next;
	}
	
	cli_nvram_conf_free(CLI_SOURCE_BINDING, (unsigned char *)&cur_source_conf);
	
	return 0;

}
/*-----------------------------------------show lldp-------------*/
void func_show_lldp_neighbor(void)
{
	FILE *fp;
	char lldp_buf[128]={'\0'};
	char printf_info[1000]={'\0'};
	int  check_next = 0;
	show_lldp_neighbor lldp_neigh_list;
	show_lldp_neighbor_list *lldp_list = NULL;
	show_lldp_neighbor_list *t_lldp_list = NULL;
	show_lldp_neighbor_list *p_lldp_list = NULL;
	
	char *lldp_enable = nvram_safe_get("lldp_enable");
	
	lldp_list = malloc(sizeof(show_lldp_neighbor_list));
	lldp_neigh_list.lldp_neighbor_list = lldp_list;
	memset(lldp_list,'\0',sizeof(show_lldp_neighbor_list));
	t_lldp_list = lldp_list;
	p_lldp_list = lldp_list;
	if(*lldp_enable == '1')
	{
		system("killall -SIGUSR1 lldpd > /dev/null 2>&1");
		check_file("/tmp/lldp_status");
        
		if((fp = fopen("/tmp/lldp_status","r"))!=NULL)
		{	
			lldp_neigh_list.lldp_neighbor_count = 0;
			memset(lldp_buf,'\0',sizeof(lldp_buf));
			while(fgets(lldp_buf, 128, fp)!=NULL){
				if(strstr(lldp_buf,"Local_port:") != NULL){
					lldp_neigh_list.lldp_neighbor_count +=1;
					if(check_next){
						lldp_list->next = malloc(sizeof(show_lldp_neighbor_list));
						lldp_list = lldp_list->next;
						memset(lldp_list,'\0',sizeof(show_lldp_neighbor_list));
					}
					lldp_list->next = NULL;
					memcpy(lldp_list->local_port,lldp_buf+12,strlen(lldp_buf)-13);
				}
				
				if(strstr(lldp_buf,"Port-id:") != NULL){
					memcpy(lldp_list->port_id,lldp_buf+9,strlen(lldp_buf)-10);
				}
				
				if(strstr(lldp_buf,"Hold_time:") != NULL){
					memcpy(lldp_list->hold_time,lldp_buf+11,strlen(lldp_buf)-12);
				}
				
				if(strstr(lldp_buf,"Capability:") != NULL){
					memcpy(lldp_list->capability,lldp_buf+12,strlen(lldp_buf)-13);
				}
				
				if(strstr(lldp_buf,"System name:") != NULL){
					memcpy(lldp_list->system_name,lldp_buf+13,strlen(lldp_buf)-14);
				}
				
				check_next = 1;
				memset(lldp_buf,'\0',sizeof(lldp_buf));
			}
			lldp_list->next = NULL;
			fclose(fp);
			if(check_next == 0){
				vty_output("no neighbor now!\n");
				
				while(NULL != p_lldp_list) {
					t_lldp_list = p_lldp_list;
					p_lldp_list = p_lldp_list->next;
					free(t_lldp_list);
				}
				free(lldp_enable);
				return;
			}
			vty_output("Capability Codes:\n");
			vty_output("        (R)Router,(B)Bridge,(C)DOCSIS Cable Device,(T)Telephone\n");
			vty_output("        (W)WLAN Access Point, (P)Repeater,(S)Station,(O)Other\n\n");
			vty_output("%-15s%-15s%-15s%-15s%-15s\n","Device","Local_port","Holdtime","Port-ID","Capability");

			do{
				if(t_lldp_list->system_name[0] == '\0'){
					vty_output("%-15s","-----");
				}else{
					vty_output("%-15s",t_lldp_list->system_name);
				}
				
				if(t_lldp_list->local_port[0] == '\0'){
					vty_output("%-15s","-----");
				}else{
					vty_output("%-15s",t_lldp_list->local_port);
				}
				
				if(t_lldp_list->hold_time[0] == '\0'){
					vty_output("%-15s","-----");
				}else{
					vty_output("%-15s",t_lldp_list->hold_time);
				}
				
				if(t_lldp_list->port_id[0] == '\0'){
					vty_output("%-15s","-----");
				}else{
					vty_output("%-15s",t_lldp_list->port_id);
				}
				
				if(t_lldp_list->capability[0] == '\0'){
					vty_output("%-15s\n","-----");
				}else{
					vty_output("%-15s\n",t_lldp_list->capability);
				}
				t_lldp_list = t_lldp_list->next;
				
			}while(t_lldp_list != NULL);
			
			vty_output("\nTotal entries displayed: %d\n",lldp_neigh_list.lldp_neighbor_count);
		}
		
	}else{
		vty_output("lldp protocol is down!\n");
	}
	while(NULL != p_lldp_list) {
		t_lldp_list = p_lldp_list;
		p_lldp_list = p_lldp_list->next;
		free(t_lldp_list);
	}
	free(lldp_enable);
	return;
}
void func_show_lldp_neigh_det()
{
	FILE *fp;
	char lldp_buf[128]={'\0'};
	char printf_info[1000]={'\0'};
	char *lldp_enable = nvram_safe_get("lldp_enable");
	if(*lldp_enable == '1'){
		system("killall -SIGUSR1 lldpd > /dev/null 2>&1");
		check_file("/tmp/lldp_status");
	
		if((fp = fopen("/tmp/lldp_status","r"))!=NULL){
			while(fgets(lldp_buf, 128, fp)!=NULL){
				strcat(printf_info,lldp_buf);
			}
			fclose(fp);
			if(printf_info[0] == '\0'){
				vty_output("no neighbor now!\n");
				
				free(lldp_enable);
				return;
			}
			vty_output("%s",printf_info);
		}
	}else{
		vty_output("lldp protocol is down!\n");
	}
	free(lldp_enable);
	return;
}

/*-----------------------------show loggin----------------------------------*/
void func_show_loggin(char *file)
{
	char line[256];                                         
	FILE *fp;                                               
	//int cli_cnt = 0, cli_r = 0;                                                                                       
	if(access(file,F_OK) == 0)                              
    {                                                       
    	fp=fopen(file,"r");                                 
		if(fp == NULL)                                      
			return;                                                                                                     
		fseek(fp, 0, SEEK_SET);                             
   		memset(&line, '\0', 256);                               	                                                    
   		while(fgets(line, 256, fp)!=NULL)                   
			vty_output("%s", line);                                                                             
   		fclose(fp);	
   	}
}

/*-----------------------------func_show_loopback----------------------------------*/
void func_show_loopback(void)
{
	FILE *fp;
	int portid=0, skfd;
	char time_buf[3*PNUM];
	char line[256];
	char buff[3];
	char *stat,*time,*lo_port;
	uint64_t link_status;
	char *lo_config = nvram_safe_get("lo_config");
	char *lo_protect_enable = nvram_safe_get("lo_protect_enable");
	char *port_enable = nvram_safe_get("port_enable");
	uint64_t lo_port_down = 0x0ULL;
    uint8 r_stp_state;

	SYSTEM("/usr/bin/killall -SIGUSR2 loopback > /dev/null 2>&1");
	usleep(100000);

	if( (fp = fopen(SHOW_LOOPBACK,"r")) == NULL ){
		vty_output("%-16s%-16s\n","Interface ","Status");
		vty_output("%-16s%-16s\n","---------","--------");
		
		free(lo_config);
		free(lo_protect_enable);
		free(port_enable);
		return;
	}

	//vty_output("%-16s%-16s%-20s\n","Interface ","Status","Recovery Time");
	//vty_output("%-16s%-16s%-20s\n","---------","--------","---------------");
	vty_output("%-16s%-16s\n","Interface ","Status");
	vty_output("%-16s%-16s\n","---------","--------");
	fseek(fp, 0, SEEK_SET);
	memset(&line, '\0', 256);
	memset(&time_buf, '\0', sizeof(time_buf));
	fgets(line, sizeof(line), fp);
	stat=line;
	time=strchr(stat,';')+1;

	lo_port=strchr(time,';')+1;
	str2bit(lo_port, &lo_port_down);

    if((skfd = open(DEVICE_FILE_NAME, 0)) < 0){
		
		free(lo_config);
		free(lo_protect_enable);
		free(port_enable);
		fclose(fp);
		return CLI_FAILED;
    }
	bcm_get_swlink_status(&link_status);
    for(portid = 1; portid <= PNUM; portid++)
	{
		if(*(lo_config+portid-1) == '1')
		{
			if(portid <= FNUM)
				vty_output("F0/%-13d", portid);
			else
				vty_output("G0/%-13d", (portid-FNUM));

			if(*(port_enable+portid-1) == '0')
            {
				if(lo_port_down & (0x1ULL << phy[portid]))
				{
                    #if 0
					if(*lo_protect_enable == '1')
                    {
						if(*stat == '1')
                        {
							printf("%-10s", "Loop");
							printf("%-4ds\n", atoi(time));
						}
					}
                    else
                    {
						if(*stat == '1')
                        {
							printf("%-10s", "Loop");
							printf("%s\n", "Non-Recovery");
						}
					}
                    #endif
				}
                else
                {
					vty_output("%-16s\n", "ShutDown");
					//vty_output("%s\n", "None");
				}
			}
            else
            {
				if(link_status & (0x1ULL << phy[portid]))
                {
                    bcm_get_rstp_stp(skfd, 0, portid, &r_stp_state);/*shanming.ren 2011-11-9 9:42:13*/
                    if(((r_stp_state) & 0xe0) == 0x20)
                    {
                        vty_output("%-16s\n","err-disabled");/*shanming.ren 2011-11-9 9:42:17*/
                        //vty_output("%s\n", "None");
                    }
                    else
                    {
                        vty_output("%-16s\n", "Forward");
                        //vty_output("%s\n", "None");
                    }
				}
                else
                {
					vty_output("%-16s\n", "NoLink");
					//vty_output("%s\n", "Non-Recovery");
				}
			}
		}
		stat++;
		time=strchr(time,',')+1;
	}
    
    close(skfd);
    fclose(fp);
	free(lo_config);
	free(lo_protect_enable);
	free(port_enable);

	return;

}
/*---------------------show memery------------------------------*/
void func_show_memery()
{
	 SYSTEM("cat /proc/meminfo 2>/dev/null");

}
/*---------------------func_show_mirror_session------------------------------*/


void func_show_mirror_session(void)
{
	int i, flag=0;
	uint64_t egress_int,ingress_int,original_int, mask=0x00ULL;	//destination_int,
	char *mirror_enable = nvram_safe_get("mirror_enable");
	char *destination_config  = nvram_safe_get("destination_config");
	char *egress_config  = nvram_safe_get("egress_config");
	char *ingress_config = nvram_safe_get("ingress_config");	
	char *mirror_vlan = nvram_safe_get("mirror_vlan");
	str2bit(egress_config,&egress_int);
	str2bit(ingress_config,&ingress_int);
	original_int=(ingress_int&egress_int);
	vty_output("Session 1\n");
	vty_output("---------\n");
	if('1' == *mirror_enable) {
		/*  betty modified for giga port*/
		if(atoi(destination_config) <= FNUM)
			vty_output("Destination Ports:f0/%d\n",atoi(destination_config));	/* Here should show different type */
		else
			vty_output("Destination Ports:g0/%d\n",atoi(destination_config)-FNUM);	/* Here should show different type */
		vty_output("Source Ports:\n");

		original_int=(egress_int&ingress_int);
		egress_int=((~original_int)&egress_int);
		ingress_int=((~original_int)&ingress_int);
		
		/*betty modified for giga port*/
		for(i = 1; i <= FNUM; i++)
			mask |= (0x01ULL << phy[i]);
		if(ingress_int)
		{
			flag = 0;
			vty_output("        RX Only:        ");
			if(0x00ULL != (ingress_int & mask))
			{
				vty_output("f0/%s", bit2str(ingress_int&mask));
				flag = 1;
			}
			if(0x00ULL != (ingress_int & (~mask)))
			{
				if(flag)
					vty_output(",");
				ingress_int >>= (phy[FNUM+1]-phy[1]);
				vty_output("g0/%s", bit2str(ingress_int));
			}
			vty_output("\n");
		}
		else	
				vty_output("        RX Only:        None\n");
		if(egress_int)	
		{	
			flag = 0;
			vty_output("        TX Only:        ");
			if(0x00ULL != (egress_int & mask))
			{
				vty_output("f0/%s", bit2str(egress_int&mask));
				flag = 1;
			}
			
			if(0x00ULL != (egress_int & (~mask)))
			{
				if(flag)
					vty_output(",");
				egress_int >>= (phy[FNUM+1]-phy[1]);
				vty_output("g0/%s", bit2str(egress_int));
			}
			vty_output("\n");	
		}
		else	
				vty_output("        TX Only:        None\n");
		if(original_int)
		{
			flag = 0;
			vty_output("        Both:           ");
			if(0x00ULL != (original_int & mask))
			{
				flag = 1;
				vty_output("f0/%s", bit2str(original_int&mask));
			}
			if(0x00ULL != (original_int & (~mask)))
			{
				if(flag)
					vty_output(",");
				original_int >>= (phy[FNUM+1]-phy[1]);
				vty_output("g0/%s", bit2str(original_int));
				
			}
			vty_output("\n");
		}
		else
				vty_output("        Both:           None\n");
		
		if(strlen(mirror_vlan) >= 1)
		    vty_output("Source vlan: %s\n", mirror_vlan);		
	}
	else {
		vty_output("Destination Ports: None\n");
		vty_output("Source Ports:\n");
		vty_output("        RX Only:        None\n");
		vty_output("        TX Only:        None\n");
		vty_output("        Both:           None\n");
	}
	free(mirror_enable);
	free(destination_config);
	free(egress_config);
	free(ingress_config);
	free(mirror_vlan);
}

/*-------------------------------func_show_mstcfg-----------------------*/
void func_show_mstcfg(void)
{
	char *instance_vlan = nvram_safe_get("mstp_instance_vlan");
	char *name = nvram_safe_get("mstp_name");
	char *revision = nvram_safe_get("mstp_revision");
	char *p = instance_vlan;
	char *inTmp, *vlanTmp;

	vty_output("MST configuration\n");
	vty_output("%-12s[%s]\n", "Name", name);
	vty_output("%-12s%s\n", "Revision", revision);
	vty_output("%-12s%s\n","Instance", "Vlans mapped");
	vty_output("----------- --------------------------------------------\n");
	while (p && *p) {
		inTmp = strsep(&p, ":");
		vlanTmp = strsep(&p, ";");
		vty_output("%-12s%s\n", inTmp, vlanTmp);
	}
	vty_output("--------------------------------------------------------\n");

	free(instance_vlan);
	free(name);
	free(revision);
	return 0;
}


/*-------------------------------func_show_ntp--------------------------*/

void func_show_ntp()
{
	char *ntp_sleep = nvram_safe_get("ntp_sleeptime");
	char *time_ser = nvram_safe_get("time_server");
	vty_output("    Interval to Query NTP server: %s (Minutes)\n", ntp_sleep);
	vty_output("    Configured NTP server List : %s\n", time_ser);
	vty_output("    ");
	free(ntp_sleep);
	free(time_ser);
	func_show_clock();
}
/*-----------------------------func_show_pol------------------------------*/
int do_show_all_pol()
{
	POLICY_CLASSIFY classify;
	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));
	policy_set("", &classify, POLICY_SHOW_ALL, -1, 0x00ULL);
	cli_read_config(SHOW_ALL_POLICY);
	return 0;
}
int func_show_pol(struct users *u)
{
	int res;
	POLICY_CLASSIFY classify;
	char policy_name[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_string(STATIC_PARAM, 0, policy_name, u);
	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));	
	/* -1: not exist,  0: exist*/
	res = policy_set(policy_name, &classify, POLICY_NAME_CHECK, -1, 0x00ULL);
		
	/* ip standard acl name is not exist */
	if(res)
	{
		vty_output("policy-map %s does not exist\n", policy_name);
		return -1;
	}	
	policy_set(policy_name, &classify, POLICY_SHOW_ONE, -1, 0x00ULL);
	cli_read_config(SHOW_ONE_POLICY);
	
	return 0;

}

/*-----------------------------func_show_process_cpu------------------------------*/
void func_show_process_cpu(void)
{
	system("top > /tmp/cpu_info &");
	sleep(1);
	system("killall top >/dev/null 2>&1");
	cli_read_config("/tmp/cpu_info");
	vty_output("\n");	
	unlink("/tmp/cpu_info");
}

/*---------------------------------------show running----------------------------------*/
char *vlan2str(void)
{
	char *vlan_str = (char *)malloc(100*sizeof(char));
	cli_vlan_info_conf *p = NULL;
	int i, j=0, line_num = 0, created_vlan[VLAN_MAX_CNT];
	
	for(i=0; i<VLAN_MAX_CNT; i++)
		created_vlan[i] = 0;
		
	memset(vlan_str, '\0', 100*sizeof(char));
	memset(&cur_vlan_conf, '\0', sizeof(cli_vlan_conf));
	
	cli_nvram_conf_get(CLI_VLAN_FOWD, (unsigned char *)&cur_vlan_conf);
	
	p = cur_vlan_conf.cur_vlan_info;	
	while( NULL != p ){
		created_vlan[j++] = p->vlanid;
		p = p->next;
	}
		
	created_vlan[j] = 0;
	j = j-1;
	
	for(i=0; i<=j; i++){
		if( (i==0) && (created_vlan[i] >0) ){
			sprintf(vlan_str, "%s%d", vlan_str, created_vlan[i]);
			line_num = 0;
		}
		else if( (created_vlan[i] == (created_vlan[i-1]+1)) && (i!=j) ){
			if(line_num ==0){
				sprintf(vlan_str, "%s-", vlan_str);
				line_num = 1;
			}
		}
		else if( (created_vlan[i] > (created_vlan[i-1]+1)) && (line_num == 1)){
			sprintf(vlan_str, "%s%d,%d", vlan_str, created_vlan[i-1], created_vlan[i]);
			line_num = 0;
		}
		else if( (created_vlan[i] > (created_vlan[i-1]+1)) && (line_num == 0)){
			sprintf(vlan_str, "%s,%d", vlan_str, created_vlan[i]);
			line_num = 0;
		}
		else if((created_vlan[i] == (created_vlan[i-1]+1)) && (i==j) && (line_num == 0) )
			sprintf(vlan_str, "%s-%d", vlan_str, created_vlan[i]);
		else if((created_vlan[i] == (created_vlan[i-1]+1)) && (i==j) && (line_num == 1) )
			sprintf(vlan_str, "%s%d", vlan_str, created_vlan[i]);
	}

	cli_nvram_conf_free(CLI_VLAN_FOWD, (unsigned char *)&cur_vlan_conf);
	
	return vlan_str;
}

static void cli_show_running_hostname(void)
{
	char *hostname = nvram_safe_get("hostname");
    char *cluster_enable = nvram_safe_get("cluster_enable");
    char *cluster_id = nvram_safe_get("cluster_id");
    char *cluster_mac = nvram_safe_get("cluster_mac");
	
	if(strlen(hostname) > 0)
	{
		vty_output("hostname %s\n", hostname);
	}
	vty_output("!\n");
	
	if(*cluster_enable == '1')	
	{
		vty_output("cluster member %s mac-address %s\n", cluster_id, cluster_mac);
	}
	vty_output("!\n");
	
	free(hostname);
    free(cluster_enable);
    free(cluster_id);
    free(cluster_mac); 
}

static void __aaa_auth_list_foreach(const char *option, char *list_name)
{
	char *aaa_auth = nvram_safe_get(list_name);
	char *p = aaa_auth;
	char *entry, *name, *src;

	while (p && *p) {
		vty_output("aaa authentication %s", option);
		entry = strsep(&p, ";");
		name = strsep(&entry, "@");
		vty_output(" %s", name);

		while (entry && *entry) {
			src = strsep(&entry, "|");
			if (!strcmp(option, "login") || !strcmp(option, "dot1x")) {
				if (!strcmp(src, "local") || !strcmp(src, "none"))
					vty_output(" %s", src);
				else 
					vty_output(" group %s", src);
			} else if (!strcmp(option, "enable")) { 
				if (!strcmp(src, "enable") || !strcmp(src, "none"))
					vty_output(" %s", src);
				else 
					vty_output(" group %s", src);
			} 
		}

		vty_output("\n");
	}

	free(aaa_auth);
}


static void __aaa_acct_list_foreach(const char *option, char *list_name)
{
	char *aaa_acct = nvram_safe_get(list_name);
	char *p = aaa_acct;
	char *entry, *name, *action, *src;

	while (p && *p) {
		vty_output("aaa accounting %s", option);
		entry = strsep(&p, ";");
		name = strsep(&entry, "@");
		vty_output(" %s", name);
		action = strsep(&entry, ",");
		src = entry;

		switch (*action) {
		case '0':
			vty_output(" none");
			break;
		case 't':
			vty_output(" start-stop group %s", src);
			break;
		case 'p':
			vty_output(" stop group %s", src);
			break;
		}

		vty_output("\n");
	}

	free(aaa_acct);
}

#ifdef CLI_AAA_MODULE
static void cli_show_aaa(void)
{
	char *aaa_banner = nvram_safe_get("aaa_auth_banner");
	char *aaa_auth_fail_message = nvram_safe_get("aaa_auth_fail_message");
	char *aaa_auth_username_prompt = nvram_safe_get("aaa_auth_username_prompt");
	char *aaa_auth_password_prompt = nvram_safe_get("aaa_auth_password_prompt");
	
	if (*aaa_banner)
		vty_output("aaa authentication banner \"%s\"\n", aaa_banner);
	if (*aaa_auth_fail_message)
		vty_output("aaa authentication fail-message \"%s\"\n", aaa_auth_fail_message);
	if (*aaa_auth_username_prompt)
		vty_output("aaa authentication username-prompt %s\n", aaa_auth_username_prompt);
	if (*aaa_auth_password_prompt)
		vty_output("aaa authentication password-prompt %s\n", aaa_auth_password_prompt);

	__aaa_auth_list_foreach("login", "aaa_auth_login");
	__aaa_auth_list_foreach("enable", "aaa_auth_enable");
	__aaa_auth_list_foreach("dot1x", "aaa_auth_dot1x");
	__aaa_acct_list_foreach("exec", "aaa_acct_exec");
	__aaa_acct_list_foreach("connection", "aaa_acct_con");

	vty_output("!\n");	

	free(aaa_banner);
	free(aaa_auth_fail_message);
	free(aaa_auth_username_prompt);
	free(aaa_auth_password_prompt);
}
#endif

static void cli_show_running_username()
{
#ifdef CLI_AAA_MODULE
	char *ptr, *buf;
	char *user, *password, *level;
	int type;

	char *user_data = nvram_safe_get("user");
	if (user_data == NULL) {
		perror("alloc memory error");
		return;
	}

	buf = user_data;

	if (strlen(buf) < 3){
		free(user_data);
		return;
	}
	while (strlen(buf)) {
		ptr = strsep(&buf,"|");
		user = strsep(&ptr, "@");
		password = strsep(&ptr, "@");
		level = strsep(&ptr, "@");
		type = atoi(ptr);

		if (type == AAA_ENCRYPTED)
			level = 7;
		else
			level = 0;

		if (user != NULL){
			vty_output("username %s password %d %s\n", user, level, password);
			break;
		}
			
        if(buf == NULL)
            break;
	}

	free(user_data);
#endif
	vty_output("!\n");
}


static int cli_show_running_policy()
{
	POLICY_CLASSIFY classify;
	
	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));
	policy_set("", &classify, POLICY_LIST_PRINT, -1, 0x00ULL);
	cli_read_config(SHOW_RUNNING_POLICY);
	return 0;
}


static void cli_show_running_global()
{
	char *ptr, *current_config = NULL;
	char *default_config = NULL;
	int current_own = 0, stp = 0, mode;
	
	cli_global_param *current_param = NULL;
	char *rstp_enable = nvram_safe_get("rstp_enable");
	char *rstp_version = nvram_safe_get("rstp_version");
	char *mstp_enable = nvram_safe_get("mstp_enable");
	char *gvrp = nvram_safe_get("gvrp_enable");
	char *gmrp = nvram_safe_get("gmrp_enable");
	char *ring_ident = nvram_safe_get("ring_ident");
	char *ring_type = nvram_safe_get("ring_type");
	char *dhcp_relay = nvram_safe_get("dhcp_relay");
	char *ring_enable = nvram_safe_get("ring");

    if(*ring_enable == '1'){
        mode = atoi(ring_ident);
        if(mode > 0)
        {
            vty_output("ring %d mode single\n", mode);
            ptr = strchr(ring_ident, ':') + 1;
            if(atoi(ptr) > 0)
            {
                vty_output("ring %d mode %s\n", atoi(ptr), (*ring_type=='1')?"double":"coupling");
            }  
            vty_output("!\n");  
        }    
    }
    free(ring_enable);
    free(ring_ident);
    free(ring_type);

	if(*rstp_enable == '1') {
	    if(*rstp_version == '1')
	    {    
		    vty_output("spanning-tree mode stp\n");
		    stp = 1;
		}    
		else    
		{    
		    vty_output("spanning-tree mode rstp\n");
		    stp = 0;
		}    
	} else if (*mstp_enable == '1') {
		vty_output("spanning-tree mode mstp\n");
	} else {
		vty_output("no spanning-tree\n");
	}
	free(rstp_enable);
	free(mstp_enable);
    free(rstp_version);

	for(current_param = cli_current_param; current_param->name; current_param++)
	{
		if(current_param->own != current_own)
			vty_output("!\n");

		current_config = nvram_safe_get(current_param->name);
		default_config = nvram_safe_get_def(current_param->name);

		if(0 != strcmp(current_config, default_config)) {
			if(current_param->type)
				vty_output(current_param->command, current_config);
			else
				vty_output(current_param->command);
		}

		current_own = current_param->own;
		
		free(current_config);
		free(default_config);
	}
	/*fprintf(fp, "!\n");*/
	
	if(*gvrp == '1') 
	{    
		vty_output("gvrp\n");
		vty_output("!\n");
    }		
	free(gvrp);		
		
	if(*gmrp == '1') 
	{    
		vty_output("gmrp\n");
		vty_output("!\n");
    }
	free(gmrp);		
    
	if(*dhcp_relay == '1') 
	{    
		vty_output("ip forward-protocol udp bootps\n");
		vty_output("!\n");
    }	
	free(dhcp_relay);
}

/* luole begin */
static void cli_show_running_mstp_vlan2msti(void)
{
	char *vlan2msti = nvram_safe_get("mstp_instance_vlan");
	char *vlan2msti_def = nvram_safe_get_def("mstp_instance_vlan");
	char *p, *p1, *p2;

	if (0 != strcmp(vlan2msti, vlan2msti_def)) {
		p = vlan2msti;
		while (p && *p) {
			p1 = strsep(&p, ";");
			p2 = strchr(p1, ':') + 1;
			vty_output("instance %d vlan %s\n", atoi(p1), p2);
		}
	}
    
	free(vlan2msti);
	free(vlan2msti_def);
}
/* luole end */

/* add by jiangyaohui 20120307 */
static void cli_show_running_schedule_wrr()
{
	char *qos_wrr_current_config = nvram_safe_get("qos_wrr");
	char *qos_wrr_default_config = nvram_safe_get_def("qos_wrr");
	char *p1, *p;
	char print_wrr[4];
	
	if(0 != strcmp(qos_wrr_current_config, qos_wrr_default_config)) {
		vty_output("scheduler wrr bandwidth ");
		p1 = qos_wrr_current_config;
		while (p1){
			p = strchr(p1, ',');
			memset(print_wrr,'\0',sizeof(print_wrr));
			if(p != NULL){
				memcpy(print_wrr, p1, p-p1);
				vty_output("%s ", print_wrr);
				p1 = p + 1;
			}else{
				vty_output("%s \n", p1);
				break;
			}
		}
	}
	vty_output("!\n");
		
	free(qos_wrr_current_config);
	free(qos_wrr_default_config);
}
/* add by jiangyaohui 20120316 */
static void cli_show_running_qinq()
{
	char *qinq_enable = nvram_safe_get("qinq_enable");
	char *qinq_enable_def = nvram_safe_get_def("qinq_enable");
	char *qinq_tpid = nvram_safe_get("qinq_tpid");
	char *qinq_tpid_def = nvram_safe_get_def("qinq_tpid");
	uint32_t  tpid;
	char print_tpid[5]={'\0'};

	if(0 != strcmp(qinq_enable, qinq_enable_def)) {
		if(*qinq_enable == '1')
		{
			vty_output("dot1q-tunnel\n");
		}else{
			vty_output("no dot1q-tunnel\n");
		}
	}

	if(0 != strcmp(qinq_tpid, qinq_tpid_def)) {
		tpid = atoi(qinq_tpid);
		sprintf(print_tpid, "%04x", tpid);
		vty_output("dot1q-tunnel tpid %s\n", print_tpid);
	}
	vty_output("!\n");
		
	free(qinq_enable);
	free(qinq_enable_def);
	free(qinq_tpid);
	free(qinq_tpid_def);
}
static void cli_show_err_disable()
{
    //int i = 0;
    char *errdisable = cli_nvram_safe_get(CLI_ERR_DISABLE, "err_disable_cfg");
    if(errdisable)
    {
		if(*(errdisable+ERR_SRC_AGGREGATION) == '0')
		{
			vty_output("no errdisable detect cause aggregation\n");
		}
		
		if(*(errdisable+ERR_SRC_ARP) == '0')
		{
			//vty_output("no errdisable detect cause arp-inspection\n");
		}

		if(*(errdisable+ERR_SRC_BPDUGUARD) == '0')
		{
			vty_output("no errdisable detect cause bpduguard\n");
		}

		if(*(errdisable+ERR_SRC_LOOPBACK) == '0')
		{
			vty_output("no errdisable detect cause loopback\n");
		}

		if(*(errdisable+ERR_SRC_SECURITY) == '0')
		{
			//vty_output("no errdisable detect cause security-violation\n");
		}

		if(*(errdisable+ERR_SRC_SFP) == '0')
		{
			//vty_output("no errdisable detect cause sfp-config-mismatch\n");
		}

		if(*(errdisable+ERR_SRC_UDLD) == '0')
		{
			//vty_output("no errdisable detect cause udld\n");
		}
        
        free(errdisable);
    }
}

/*shanming.ren 2011-11-3*/
static void cli_show_err_recover()
{
    char *err_recover_cfg = cli_nvram_safe_get(CLI_ERR_RECOVER, "err_recover_cfg");
    char *err_recover_time;
    char *err_recover_time_def;

    if(err_recover_cfg)
    {
        if(strlen(err_recover_cfg)< ERR_SRC_ROOTGUARD){
            free(err_recover_cfg);
            return;
        }
        if(*(err_recover_cfg+ERR_SRC_AGGREGATION) == '1')
        {
            vty_output("errdisable recovery cause aggregation\n");
        }
        
        if(*(err_recover_cfg+ERR_SRC_ARP) == '1')
        {
            //vty_output("errdisable recovery cause arp-inspection\n");
        }
        
        if(*(err_recover_cfg+ERR_SRC_BPDUGUARD) == '1')
        {
            vty_output("errdisable recovery cause bpduguard\n");
        }
        
        if(*(err_recover_cfg+ERR_SRC_LOOPBACK) == '1')
        {
            vty_output("errdisable recovery cause loopback\n");
        }
        
        if(*(err_recover_cfg+ERR_SRC_SECURITY) == '1')
        {
            //vty_output("errdisable recovery cause security-violation\n");
        }
        
        if(*(err_recover_cfg+ERR_SRC_SFP) == '1')
        {
            //vty_output("errdisable recovery cause sfp-config-mismatch\n");
        }
        
        if(*(err_recover_cfg+ERR_SRC_UDLD) == '1')
        {
            //vty_output("errdisable recovery cause udld\n");
        }
        free(err_recover_cfg);
    }

    err_recover_time = nvram_safe_get("err_recover_time");
    err_recover_time_def = nvram_safe_get_def("err_recover_time");
    if(err_recover_time && err_recover_time_def)
    {
        if(0 != strcmp(err_recover_time, err_recover_time_def))
        {
            vty_output("errdisable recovery interval %s\n", err_recover_time);
        }
        free(err_recover_time);
        free(err_recover_time_def);
    }
}
static void cli_show_running_qos()
{
	int enable,priority,queue_id, j=0;
    char *qos_1p_enable,*qos_1p_config,*dscp_enable,*qos_dscp_config;
    char *qos_enable = nvram_safe_get("qos_enable");	
	
	enable = atoi(qos_enable);
    free(qos_enable);
    if(enable != 1)
        return;
	
	vty_output("qos enable\n");
	
	qos_1p_enable = nvram_safe_get("qos_8021p_enable");
	enable = atoi(qos_1p_enable);
    if(enable == 1)
	{
		vty_output("qos dot1p enable\n");
        qos_1p_config = cli_nvram_safe_get(CLI_COS_CONFIG, "qos_802_1p_config");
        if(strlen(qos_1p_config) == 8){
            for(priority = 0; priority < 8; priority++)
            {
                queue_id = *(qos_1p_config+priority)-'0';
                if(queue_id != priority){
                    j++;
                    vty_output("cos map %d %d\n", priority,queue_id);
                }
            }
    	}
        free(qos_1p_config);
        if(j != 0)
		    vty_output("!\n");
	}
    free(qos_1p_enable);

	dscp_enable = nvram_safe_get("tos_dscp_enable");
	enable = atoi(dscp_enable);
    free(dscp_enable);
	if(enable != 1)
        return;
	
	vty_output("qos dscp enable\n");
    qos_dscp_config = cli_nvram_safe_get(CLI_DSCP_CONFIG, "qos_dscp_config");

	vty_output("!\n");
	if(strlen(qos_dscp_config) == 64){
	    for(priority = 0; priority < 64; priority++)
	    {
		    queue_id = *(qos_dscp_config+priority)-'0';
		    if(queue_id != (priority>>3)){
			    vty_output("dscp map %d %d\n", priority,queue_id);
		    }
	    }
	    vty_output("!\n");
    }
	free(qos_dscp_config);
    return;
}

static void cli_show_running_ntp_querytime()
{
	char *ntp_querytime = nvram_safe_get("ntp_sleeptime");
	if (atoi(ntp_querytime) != 1 && strlen(ntp_querytime) > 0) {
		vty_output("ntp query-interval %s\n", ntp_querytime);
		vty_output("!\n");
	}
	free(ntp_querytime);
}

/*modify by wei.zhang 2012-5-23*/
static void cli_show_running_login()
{
	char *login_exec_timeout = nvram_safe_get("login_timeout");
	int i, time_out;
	char *p = login_exec_timeout;

	for(i = 0; i < 17; i++)
	{
		p = strchr( p, ':' );
		if(p == NULL)
			break;
		
		p++;
	}	
	
	if(p != NULL)
		time_out = atoi(p);
	else
		time_out = 0;
	
	if(0 == time_out) {
		vty_output("no exec_timeout\n");
		vty_output("!\n");
	} else if(300 != time_out) {
		vty_output("exec_timeout %d\n", time_out);
    	vty_output("!\n");
    }

	free(login_exec_timeout);
}

static void cli_show_running_snmp_server()
{
	int index;
	char tmp[32];
	cli_snmp_user *s_snmp = NULL;
	cli_snmp_user_info *p_snmp = NULL;
	char *snmp_enable = NULL;
	char *snmp_rcomm = NULL;
	char *snmp_rwcomm = NULL;
	char *p = NULL;
	char *p1 = NULL;

    snmp_enable = nvram_safe_get("snmp_enable");
    if(*snmp_enable == '1')
    {    
        vty_output("snmp-server view\n");   
    
    	snmp_rcomm = nvram_safe_get("snmp_rcomm");
    	snmp_rwcomm = nvram_safe_get("snmp_rwcomm");
    	p1 = snmp_rcomm;
    	while (*p1){
    		p = strchr(p1, '|');
    		if (NULL == p) {
    			vty_output("snmp-server community %s ro\n", p1);
    			break;
    		} else {
    			*p = '\0';
    			vty_output("snmp-server community %s ro\n", p1);
    			p1 = p + 1;
    		}
    	}
    	p1 = snmp_rwcomm;
    	while (*p1){
    		p = strchr(p1, '|');
    		if (NULL == p) {
    			vty_output("snmp-server community %s rw\n", p1);
    			break;
    		} else {
    			*p = '\0';
    			vty_output("snmp-server community %s rw\n", p1);
    			p1 = p + 1;
    		}
    	}
    
    	
    	memset(&cur_snmp_user, 0, sizeof(cli_snmp_user));
    	cli_nvram_conf_get(CLI_SNMP_USER, (unsigned char *)&cur_snmp_user);
    
    	s_snmp = &cur_snmp_user;
    	p_snmp = s_snmp->cur_snmp_user_info;
    
    	for(index = 1; index <= s_snmp->user_count; index++) {
    		if(0 == strcmp(p_snmp->priv, "3DES"))
    			sprintf(tmp, "3des");
    		else if(0 == strcmp(p_snmp->priv, "AES"))
    			sprintf(tmp, "aes");
    		else
    			sprintf(tmp, "des");
    		vty_output("snmp-server user %s auth %s %s priv %s %s %s\n", p_snmp->name, (0 == strcmp(p_snmp->auth, "MD5"))?"md5":"sha", p_snmp->auth_passwd, tmp, p_snmp->priv_passwd, (CLI_SNMP_RONLY == p_snmp->mode)?"ro":"rw");
    
    		p_snmp++;
    	}
    
    	vty_output("!\n");
    	cli_nvram_conf_free(CLI_SNMP_USER, (unsigned char *)&cur_snmp_user);
    	free(snmp_rcomm);
    	free(snmp_rwcomm);
    }
    else 
    {    
        vty_output("no snmp-server view\n");
    	vty_output("!\n");
    }
    
    free(snmp_enable);
    
    return;    
}
static void cli_show_running_arp()
{	
	
	cli_static_arp_list *arp_list = NULL;
	
	cli_nvram_conf_get(CLI_STATIC_ARP,(unsigned char *)&cur_static_arp_conf);
	arp_list = cur_static_arp_conf.static_arp_list;
	while(arp_list)
	{
	    if(arp_list->port <= FNUM)
		    vty_output("arp %s %s vlan %d interface f0/%d\n",arp_list->static_ip,arp_list->static_mac,arp_list->vlan,arp_list->port);
		else
		    vty_output("arp %s %s vlan %d interface g0/%d\n",arp_list->static_ip,arp_list->static_mac,arp_list->vlan,arp_list->port-FNUM);
		    
		arp_list=arp_list->next;
	}
	vty_output("!\n");
	cli_nvram_conf_free(CLI_STATIC_ARP,(unsigned char *)&cur_static_arp_conf);
}
/* changed by jiangyaohui 20120322.
 * fix bug:1.lldp enable, show all info,even the value is default;
 *         2.lldp disable,all info not be show,even the value is change.*/
static void cli_show_running_lldp()
{
	char *lldp_enable = nvram_safe_get("lldp_enable");
	char *lldp_holdtime = nvram_safe_get("lldp_holdtime");
	char *lldp_interval_time = nvram_safe_get("lldp_interval_time");
	char *lldp_enable_def = nvram_safe_get_def("lldp_enable");
	char *lldp_holdtime_def = nvram_safe_get_def("lldp_holdtime");
	char *lldp_interval_time_def = nvram_safe_get_def("lldp_interval_time");
	
	if(0 != strcmp(lldp_enable, lldp_enable_def)) {
		if(*lldp_enable == '1'){
			vty_output("lldp enable\n");
			
        	if(0 != strcmp(lldp_holdtime, lldp_holdtime_def)) {
        		vty_output("lldp holdtime %s\n",lldp_holdtime);
        	}
        	
        	if(0 != strcmp(lldp_interval_time, lldp_interval_time_def)) {
        		vty_output("lldp timer %s\n",lldp_interval_time);
        	}
		}
	}
	

	vty_output("!\n");
	
	free(lldp_enable);
	free(lldp_holdtime);
	free(lldp_interval_time);
	free(lldp_enable_def);
	free(lldp_holdtime_def);
	free(lldp_interval_time_def);
}

static void cli_show_running_garp()
{
	char *garp_hold = nvram_safe_get("garp_hold");
	char *garp_join = nvram_safe_get("garp_join");
	char *garp_leave = nvram_safe_get("garp_leave");
	char *garp_leaveall = nvram_safe_get("garp_leaveall");

	if(0 != atoi(garp_join)) {
		vty_output("garp timer join %s\n", garp_join);
	}
	
	if(0 != atoi(garp_hold)) {
		vty_output("garp timer hold %s\n", garp_hold);
	}
	
	if(0 != atoi(garp_leave)) {
		vty_output("garp timer leave %s\n", garp_leave);
	}
	
	if(0 != atoi(garp_leaveall)) {
		vty_output("garp timer leaveall %s\n", garp_leaveall);
	}

	vty_output("!\n");
	
	free(garp_hold);
	free(garp_join);
	free(garp_leave);
	free(garp_leaveall);
}

/*end*/
static void cli_show_running_logging_level(int level, char *command)
{
	switch(level) {
		case 3:
			vty_output("logging %s errors\n", command);
			break;
		case 6:
			vty_output("logging %s informational\n", command);
			break;
		case 1:
			vty_output("logging %s alerts\n", command);
			break;	
		case 2:
			vty_output("logging %s critical\n", command);
			break;			
		case 0:
			vty_output("logging %s emergencies\n", command);
			break;
		case 5:
			vty_output("logging %s notifications\n", command);
			break;
		case 7:
			vty_output("logging %s debugging\n", command);
			break;
		case 4:
			vty_output("logging %s warnings\n", command);
			break;
		default:
			break;
	}
}

/*modified by wuchunli 2012-3-19 14:18:52*/
static void cli_show_running_logging()
{
	/*global logging*/
	char *log_enable = nvram_safe_get("log_enable");
	if((strlen(log_enable) > 0) && (*log_enable != '1')) {
		vty_output("no logging on\n");
	}
	free(log_enable);
	/*logging console*/
	char *log_con_enable = nvram_safe_get("log_con_enable");
	if((strlen(log_con_enable) > 0) && (*log_con_enable != '1')) {
		vty_output("no logging console\n");
	}
	free(log_con_enable);
	/*logging buffer*/
	char *log_buf_enable = nvram_safe_get("log_buf_enable");
	if((strlen(log_buf_enable) > 0) && (*log_buf_enable != '1')) {
		vty_output("no logging buffered\n");
	}
	free(log_buf_enable);
	/*logging trap*/
	char *log_host_enable = nvram_safe_get("log_host_enable");
	if((strlen(log_host_enable) > 0) && (*log_host_enable != '1')) {
		vty_output("no logging trap\n");
	}
	free(log_host_enable);
	
	/*logging host*/
	char *log_host = nvram_safe_get("log_host");
	if (strlen(log_host) > 0) {
		vty_output("logging host %s\n", log_host);
	}
	free(log_host);

	char *log_buf_size = nvram_safe_get("log_buf_size");
	char *log_buf_size_def = nvram_safe_get_def("log_buf_size");
	if ((*log_con_enable == '1') && (atoi(log_buf_size) > 0) && (atoi(log_buf_size) != atoi(log_buf_size_def))) {
		vty_output("logging buffered %s\n", log_buf_size);
	}
	free(log_buf_size);
	free(log_buf_size_def);

	char *log_buf_type = nvram_safe_get("log_buf_type");
	char *log_buf_type_def = nvram_safe_get_def("log_buf_type");
	if ((*log_con_enable == '1') && (0 != strcmp(log_buf_type,log_buf_type_def))) {
		cli_show_running_logging_level(atoi(log_buf_type), "buffered");
	}
	free(log_buf_type);
	free(log_buf_type_def);
	
	char *log_con_type = nvram_safe_get("log_con_type");
	char *log_con_type_def = nvram_safe_get_def("log_con_type");
	if (0 != strcmp(log_con_type, log_con_type_def)) {
		cli_show_running_logging_level(atoi(log_con_type), "console");
	}
	free(log_con_type);
	free(log_con_type_def);
	
	char *log_host_type = nvram_safe_get("log_host_type");
	char *log_host_type_def = nvram_safe_get_def("log_host_type");
	if (0 != strcmp(log_host_type, log_host_type_def)) {
		cli_show_running_logging_level(atoi(log_host_type), "trap");
	}
	free(log_host_type);
	free(log_host_type_def);
	
	vty_output("!\n");
}
static void cli_show_running_ip_access()
{
		char *p3, *p;
		char tmp[32];
	
    char *access_enable = nvram_safe_get("access_enable");
    char *access_config = nvram_safe_get("access_config");
	
		p = access_config;
		if('1' == *access_enable) {
			while((p3=strchr(p, ';')) != NULL)
			{
				memset(tmp, '\0', sizeof(tmp));
				memcpy(tmp, p, p3-p);
				vty_output("ip access-list %s\n",tmp);
				p = p3+1;
			}
		}
		vty_output("!\n");

		free(access_config);
		free(access_enable);
}
static void cli_show_running_mirror()
{
	int i; 
	uint64_t egress_int,ingress_int,original_int,destination_int, mask=0x00ULL;	
	char *mirror_enable = nvram_safe_get("mirror_enable");
	char *destination_config  = nvram_safe_get("destination_config");
	char *egress_config  = nvram_safe_get("egress_config");
	char *ingress_config = nvram_safe_get("ingress_config");	
	char *mirror_vlan = nvram_safe_get("mirror_vlan");
	str2bit(egress_config,&egress_int);
	str2bit(ingress_config,&ingress_int);
	original_int=(ingress_int&egress_int);
	if('1' == *mirror_enable) {
		/*  betty modified to add giga port*/
		if(atoi(destination_config)!=0)
		{
#if (XPORT==0)			    
			if(atoi(destination_config) <= FNUM)
				vty_output("mirror session 1 destination interface FastEthernet 0/%d\n",atoi(destination_config));
			else
				vty_output("mirror session 1 destination interface GigaEthernet 0/%d\n",(atoi(destination_config)-FNUM));
#endif	
#if (XPORT==1)			    
			if(atoi(destination_config) <= GNUM)
				vty_output("mirror session 1 destination interface GigaEthernet 0/%d\n",atoi(destination_config));
			else
				vty_output("mirror session 1 destination interface TenGigaEthernet 0/%d\n",(atoi(destination_config)-GNUM));
#endif				
		}
		original_int=(egress_int&ingress_int);
		egress_int=((~original_int)&egress_int);
		ingress_int=((~original_int)&ingress_int);

#if (XPORT==0)	
		for(i = 1; i <= FNUM; i++)
			mask |= (0x01ULL << phy[i]);
		if(ingress_int)
		{			
			if(0x00ULL != (ingress_int&mask))
				vty_output("mirror session 1 source interface FastEthernet 0/%s rx\n", bit2str(ingress_int & mask));
				
			if(0x00ULL != (ingress_int&(~mask)))
			{
				ingress_int >>= (phy[FNUM+1] - phy[1]); 
				vty_output("mirror session 1 source interface GigaEthernet 0/%s rx\n", bit2str(ingress_int));
			}
			
		}
		if(egress_int)
		{
			if(0x00ULL != (egress_int&mask))
				vty_output("mirror session 1 source interface FastEthernet 0/%s tx\n", bit2str(egress_int & mask));	
				
			if(0x00ULL != (egress_int&(~mask)))
			{
				egress_int >>= (phy[FNUM+1] - phy[1]); 
				vty_output("mirror session 1 source interface GigaEthernet 0/%s tx\n", bit2str(egress_int));
			}
		}
		if(original_int)
		{
			if(0x00ULL != (original_int&mask))
				vty_output("mirror session 1 source interface FastEthernet 0/%s both\n", bit2str(original_int&mask));
				
			if(0x00ULL != (original_int&(~mask)))
			{
				original_int >>= (phy[FNUM+1] - phy[1]);
				vty_output("mirror session 1 source interface GigaEthernet 0/%s both\n", bit2str(original_int));	
			}
		}
#endif
#if (XPORT==1)	
		for(i = 1; i <= GNUM; i++)
			mask |= (0x01ULL << phy[i]);
		if(ingress_int)
		{			
			if(0x00ULL != (ingress_int&mask))
				vty_output("mirror session 1 source interface GigaEthernet 0/%s rx\n", bit2str(ingress_int & mask));
				
			if(0x00ULL != (ingress_int&(~mask)))
			{
				ingress_int >>= phy[GNUM+1]; 
				vty_output("mirror session 1 source interface TenGigaEthernet 0/%s rx\n", bit2str(ingress_int));
			}
			
		}
		if(egress_int)
		{
			if(0x00ULL != (egress_int&mask))
				vty_output("mirror session 1 source interface GigaEthernet 0/%s tx\n", bit2str(egress_int & mask));	
				
			if(0x00ULL != (egress_int&(~mask)))
			{
				egress_int >>= phy[GNUM+1]; 
				vty_output("mirror session 1 source interface TenGigaEthernet 0/%s tx\n", bit2str(egress_int));
			}
		}
		if(original_int)
		{
			if(0x00ULL != (original_int&mask))
				vty_output("mirror session 1 source interface GigaEthernet 0/%s both\n", bit2str(original_int&mask));
				
			if(0x00ULL != (original_int&(~mask)))
			{
				original_int >>= phy[GNUM+1];
				vty_output("mirror session 1 source interface TenGigaEthernet 0/%s both\n", bit2str(original_int));	
			}
		}	
#endif
		
		if(strlen(mirror_vlan) >= 1)
		{   
		    vty_output("mirror session 1 source vlan %s\n", mirror_vlan);
		}
    }
	vty_output("!\n");
	free(mirror_enable);
	free(destination_config);
	free(egress_config);
	free(ingress_config);
	free(mirror_vlan);
}
static void cli_show_running_mac()
{
	char *p1, *p3, *p;
	char buff[256], tmp[32];
	int vlanid, i, flag=0;
	uint64 bmaps, mask=0x00ULL;
	char *pstr;

	char *lock_mac  = nvram_safe_get("lock_mac_list");
	p = lock_mac;

	while((p3=strchr(p, ';')) != NULL)
	{
		memset(buff, '\0', sizeof(buff));
		memset(tmp, '\0', sizeof(tmp));
		p1 = strchr(p, '|');
		memcpy(tmp, p, p1-p);
		p = ++p1;

		vlanid = atoi(p);

		p1 = strchr(p, '|');
		p = ++p1;
		
		memcpy(buff, p, p3-p);

		/*  betty modified for giga port */  
#if (XPORT==0)	     
		if(atoi(buff) <= FNUM)
			vty_output("mac address-table static %c%c:%c%c:%c%c:%c%c:%c%c:%c%c vlan %d interface f0/%d\n", tmp[0],tmp[1],
			tmp[2],tmp[3],tmp[4],tmp[5],tmp[6],tmp[7],tmp[8],tmp[9],tmp[10],tmp[11], vlanid, atoi(buff));
		else
			vty_output("mac address-table static %c%c:%c%c:%c%c:%c%c:%c%c:%c%c vlan %d interface g0/%d\n", tmp[0],tmp[1],
			tmp[2],tmp[3],tmp[4],tmp[5],tmp[6],tmp[7],tmp[8],tmp[9],tmp[10],tmp[11], vlanid, atoi(buff)-FNUM);
#endif  
#if (XPORT==1)	   
		if(atoi(buff) <= GNUM)
			vty_output("mac address-table static %c%c:%c%c:%c%c:%c%c:%c%c:%c%c vlan %d interface g0/%d\n", tmp[0],tmp[1],
			tmp[2],tmp[3],tmp[4],tmp[5],tmp[6],tmp[7],tmp[8],tmp[9],tmp[10],tmp[11], vlanid, atoi(buff));
		else
			vty_output("mac address-table static %c%c:%c%c:%c%c:%c%c:%c%c:%c%c vlan %d interface t0/%d\n", tmp[0],tmp[1],
			tmp[2],tmp[3],tmp[4],tmp[5],tmp[6],tmp[7],tmp[8],tmp[9],tmp[10],tmp[11], vlanid, atoi(buff)-GNUM); 
#endif  

		p = p3+1;
	}
	
	char *mct_staticmac  = nvram_safe_get("mct_staticmac");
	p = mct_staticmac;

	while((p3=strchr(p, ';')) != NULL)
	{
		memset(tmp, '\0', sizeof(tmp));
		memset(buff, '\0', sizeof(buff));
		
		p1 = strchr(p, ':');
		memcpy(tmp, p, p1-p);
		p = ++p1;
		
		vlanid = atoi(p);

		p1 = strchr(p, ':');
		p = ++p1;
		memcpy(buff, p, p3-p);

		/* betty modified for giga port */
#if (XPORT==0)			
		for(i = 1; i <= FNUM; i++)
			mask |= (0x01ULL << i);
#endif  
#if (XPORT==1)	
		for(i = 1; i <= GNUM; i++)
			mask |= (0x01ULL << i);
#endif  	
		str2bit(buff, &bmaps);
		flag = 0;
		vty_output("mac address-table static %c%c:%c%c:%c%c:%c%c:%c%c:%c%c vlan %d interface ", tmp[0],tmp[1],
			tmp[2],tmp[3],tmp[4],tmp[5],tmp[6],tmp[7],tmp[8],tmp[9],tmp[10],tmp[11], vlanid);
		/* fast port */	
#if (XPORT==0)	     
		if(0x00ULL != (bmaps&mask))
		{
			pstr = bit2str(bmaps&mask);
			if(pstr){
				vty_output("f0/%s", pstr);
				flag = 1;
				free(pstr);
			}
		}
		/* giga port */	
		if(0x00ULL != (bmaps&(~mask)))
		{
			if(1 == flag)
				vty_output(",");
			bmaps >>= (phy[FNUM+1] - phy[1]);
			pstr = bit2str(bmaps);
			if(pstr){
				vty_output("g0/%s", pstr);
				free(pstr);
			}
		}
#endif  
#if (XPORT==1)
		if(0x00ULL != (bmaps&mask))
		{
			pstr = bit2str(bmaps&mask);
			if(pstr){
			vty_output("g0/%s", pstr);
			flag = 1;
			free(pstr);
			}
		}
		/* tengiga port */	
		if(0x00ULL != (bmaps&(~mask)))
		{
			if(2 == flag)
				vty_output(",");
			bmaps >>= (phy[GNUM+1] - phy[1]);
			pstr = bit2str(bmaps);
			if(pstr){
			vty_output("t0/%s", pstr);
			free(pstr);
			}
		}
#endif  	 
		vty_output("\n");
	
		p = p3+1;
	}
	
	vty_output("!\n");
	
	free(lock_mac);
	free(mct_staticmac);
}
/*wuchunli 2012-3-13 10:19:45*/
static void cli_show_running_ipv6_route()
{    
	cli_ipv6_route_list *route_list = NULL;

    cli_nvram_conf_get(CLI_IPV6_ROUTE,(unsigned char *)&cur_ipv6_route_conf);

    route_list = cur_ipv6_route_conf.ipv6_route_list;
    while(route_list)
    {
        vty_output("ipv6 route %s %s\n",route_list->prefix,route_list->nexthop);
        vty_output("!\n");
        route_list=route_list->next;
    }
    vty_output("!\n");
    cli_nvram_conf_free(CLI_IPV6_ROUTE,(unsigned char *)&cur_ipv6_route_conf);
	return 0;
}

/*added by wei.zhang 2012-4-20*/
static void cli_show_running_line_vty()
{
	typedef struct line_vty_info{
		int absolute_timeout;
		int login_timeout;
	}line_vty_info_t;
	
	int max_vty, i;
	char message_print[30] = "", buf[128] = "", *line_vty = NULL, *p1 = NULL, *p2 = NULL;
	char tmp[10];
	char *line_max_vty = NULL, *login_timeout = NULL;

	line_vty_info_t vty_infos[17];
	
	line_max_vty = nvram_safe_get("line_max_vty");
	max_vty = atoi( line_max_vty );
	free( line_max_vty );
	
	p1 = line_vty = nvram_safe_get("line_vty");
	p2 = login_timeout = nvram_safe_get("login_timeout");
	for( i = 0; i < max_vty; i++ ){
		strsep( &p1, ":" );
		strsep( &p2, ":" );
		vty_infos[i].absolute_timeout = atoi( strsep( &p1, ";" ) );
		vty_infos[i].login_timeout = atoi( strsep( &p2, ";" ) );
	}
	free( line_vty );
	free( login_timeout );
	
	if( 0 == memcmp(&vty_infos[0], &vty_infos[1], sizeof(vty_infos[0])) ){
		vty_output("line vty 1 ");
	}
	else{
		vty_output("line vty 1\n");
		if( vty_infos[0].absolute_timeout != ABSOLUTE_TIMEOUT_DEFAULT )
			vty_output(" absolute-timeout %d\n", vty_infos[0].absolute_timeout);
		if( vty_infos[0].login_timeout != LOGIN_TIMEOUT )
			vty_output(" login-timeout %d\n", vty_infos[0].login_timeout);
	}
	
	for( i = 1; i < (max_vty - 1); i++ ){
		if( 0 == memcmp( &vty_infos[i], &vty_infos[i-1], sizeof(vty_infos[0]) ) &&
			0 == memcmp( &vty_infos[i], &vty_infos[i+1], sizeof(vty_infos[0]) ) ){		
		}
		else if( 0 == memcmp( &vty_infos[i], &vty_infos[i-1], sizeof(vty_infos[0]) ) &&
				 0 != memcmp( &vty_infos[i], &vty_infos[i+1], sizeof(vty_infos[0]) ) ){	
			vty_output("%d\n", i+1);
			if( vty_infos[i].absolute_timeout != ABSOLUTE_TIMEOUT_DEFAULT )
				vty_output(" absolute-timeout %d\n", vty_infos[i].absolute_timeout);
			if( vty_infos[i].login_timeout != LOGIN_TIMEOUT )
				vty_output(" login-timeout %d\n", vty_infos[i].login_timeout);
		}
		else if( 0 != memcmp( &vty_infos[i], &vty_infos[i-1], sizeof(vty_infos[0]) ) &&
				 0 == memcmp( &vty_infos[i], &vty_infos[i+1], sizeof(vty_infos[0]) ) ){	
			vty_output("line vty %d ", i+1);
		}
		else if( 0 != memcmp( &vty_infos[i], &vty_infos[i-1], sizeof(vty_infos[0]) ) &&
				 0 != memcmp( &vty_infos[i], &vty_infos[i+1], sizeof(vty_infos[0]) ) ){	
			vty_output("line vty %d\n", i+1);
			if( vty_infos[i].absolute_timeout != ABSOLUTE_TIMEOUT_DEFAULT )
				vty_output(" absolute-timeout %d\n", vty_infos[i].absolute_timeout);
			if( vty_infos[i].login_timeout != LOGIN_TIMEOUT )
				vty_output(" login-timeout %d\n", vty_infos[i].login_timeout);
		}
		
	}
	
	if( 0 == memcmp(&vty_infos[max_vty-1], &vty_infos[max_vty-2], sizeof(vty_infos[0])) ){
		vty_output("%d\n", max_vty);
		if( vty_infos[max_vty-1].absolute_timeout != ABSOLUTE_TIMEOUT_DEFAULT )
			vty_output(" absolute-timeout %d\n", vty_infos[max_vty-1].absolute_timeout);
		if( vty_infos[max_vty-1].login_timeout != LOGIN_TIMEOUT )
			vty_output(" login-timeout %d\n", vty_infos[max_vty-1].login_timeout);
	}
	else{
		vty_output("line vty %d\n", max_vty);
		if( vty_infos[max_vty-1].absolute_timeout != ABSOLUTE_TIMEOUT_DEFAULT )
			vty_output(" absolute-timeout %d\n", vty_infos[max_vty-1].absolute_timeout);
		if( vty_infos[max_vty-1].login_timeout != LOGIN_TIMEOUT )
			vty_output(" login-timeout %d\n", vty_infos[max_vty-1].login_timeout);
	}
	return;	
}

static void cli_show_mac_blackhole(void)
{    
	char *mac_bloackhole = nvram_safe_get("mac_bloackhole"); 

	if(strlen(mac_bloackhole) != 0){
	  	vty_output("mac blackhole:\n");
	  	vty_output("%s\n",mac_bloackhole);
	    vty_output("!\n");
	}
	free(mac_bloackhole);
}

static void cli_show_mac_age(void)
{    
	char *age_time = nvram_safe_get("age_time"); 

	if((strlen(age_time) != 0)&&(atoi(age_time) != 300)){
	  	vty_output("mac age time: %s\n",age_time);
	    vty_output("!\n");
	}
	free(age_time);
}

static void cli_show_running_scheduler()
{    
    int  enable, priority, dscp, port;
    char *qos_schedule = nvram_safe_get("qos_schedule"); 
    char *p, *qos_wrr_config = nvram_safe_get("qos_wrr_config");  
    char *qos_port_config = nvram_safe_get("qos_port_config"); 
    char *qos_8021p_config = nvram_safe_get("qos_802_1p_config");
    char *qos_dscp_config = nvram_safe_get("qos_dscp_config"); 
    
    enable = 0;
    for(port = 1; port <= PNUM; port++)
    {
		if(strlen(qos_port_config) ==PNUM){
	        if(*(qos_port_config+port-1) != '0')
	        {
	            enable = 1;    
	            break;
	        }
		}
    }
    
    for(priority = 0; priority < 8; priority++)
    {
        if((*(qos_8021p_config+priority)-'0') != priority)
        {
            enable = 1;    
            break;
        }    
    }
    
    for(dscp = 0; dscp < 64; dscp++)
    {
        if((*(qos_dscp_config+dscp)-'0') != (dscp>>3))
        {
            enable = 1;    
            break;
        }    
    }

    //if(enable == 1)
    {    
    	if(strcmp(qos_schedule,"sp") == 0)
    		vty_output("scheduler policy sp\n");
    	else if(strcmp(qos_schedule,"wrr") == 0)
    	{
    		vty_output("scheduler policy wrr\n");
    		
    		p = qos_wrr_config;
    		vty_output("scheduler wrr bandwidth ");
    		while(NULL != strchr(p, ','))
    		{
    			vty_output("%d ", atoi(p));
    			p = strchr(p, ',')+1;
    		}
    	    vty_output("\n");
    	}
    	else if(strcmp(qos_schedule,"wfq") == 0)
    		vty_output("scheduler policy wfq\n");
    	else if(strcmp(qos_schedule,"drr") == 0)
    		vty_output("scheduler policy drr\n");
    	
    	vty_output("!\n");
    }
    
	free(qos_schedule);
	free(qos_wrr_config);
	free(qos_port_config);
	free(qos_8021p_config);
	free(qos_dscp_config);
}

static void cli_show_running_interface_aggregator()
{
	char *p3, *p, *p1, *p2;
    int aggregator_id[7] = {0};
	int i, j;
	char *trunk_list = nvram_safe_get("trunk_list");
	char *load_mode = nvram_safe_get("h_load_mode");
	char *port_description = cli_nvram_safe_get(CLI_ALL_DES, "agg_port_description");
	char *pvid_config = cli_nvram_safe_get(CLI_COMMA_ONE, "agg_pvid_config");
	char *vlan_link_type = cli_nvram_safe_get(CLI_ALL_ONE, "agg_vlan_link_type");
	char *trunk_vlan_allowed = cli_nvram_safe_get(CLI_TRUNK_VLAN, "agg_trunk_vlan_allowed");
	char *trunk_vlan_untagged = cli_nvram_safe_get(CLI_TRUNK_VLAN, "agg_trunk_vlan_untagged");
	char *lacp_mode = nvram_safe_get("lacp_mode");
	char *vlan_allowed_tmp, *vlan_untagged_tmp;
	char *allowed_value, *untagged_value;

	if('2' == *load_mode)
		vty_output("aggregator-group load-balance src-mac\n");
	else if('3' == *load_mode)	
		vty_output("aggregator-group load-balance dst-mac\n");
	else if('4' == *load_mode)
		vty_output("aggregator-group load-balance both-ip\n");
	else if('5' == *load_mode)
		vty_output("aggregator-group load-balance src-ip\n");
	else if('6' == *load_mode)	
		vty_output("aggregator-group load-balance dst-ip\n");

	vty_output("!\n");
	
	if('1' == *lacp_mode){
		vty_output("lacp mode fast\n");
		vty_output("!\n");
	}
	
	p = trunk_list;
	while((p3=strchr(p, ';')) != NULL)	{
		i = atoi(p+6); 
		aggregator_id[i] = i;
		
		p = p3+1;
	}

	p2 = port_description;
	//for (j = 0; j < PNUM; p1 = strchr(p2, ';'), p2 = p1 + 1, j++);

	p3 = pvid_config;
	//i = 0;
	//while (i++ < PNUM) 
	//	p = strsep(&p3, ",");

	vlan_allowed_tmp = trunk_vlan_allowed;
	//i = 0;
	//while (i++ < PNUM)
	//	allowed_value = strsep(&vlan_allowed_tmp, ";");

	vlan_untagged_tmp = trunk_vlan_untagged;
	//i = 0;
	//while (i++ < PNUM)
	//	untagged_value = strsep(&vlan_untagged_tmp, ";");

    for (i = 1; i < 7; i++) {
		if (aggregator_id[i]) 
			vty_output("interface port-aggregator %d\n", i);

			/* description */
			p1 = strchr(p2, ';');
			if (*p2 != ';') {
				*p1 = '\0';
				vty_output(" description %s\n", p2);
			} 
			p2 = p1 + 1;

			/* switchport pvid */
			p = strsep(&p3, ",");
			if (strcmp(p, "1"))
				vty_output(" switchport pvid %s\n", p);

			/* switchport mode */
			if (*(vlan_link_type+i-1) == '3') {
				vty_output(" switchport mode trunk\n");
			}

			/* switchport trunk_vlan_allowed */
			allowed_value = strsep(&vlan_allowed_tmp, ";");
			strsep(&allowed_value, ":");
			if (*allowed_value)
				vty_output(" switchport trunk vlan-allowed %s\n", allowed_value);
			vlan_allowed_tmp++;

			/* switchport trunk_vlan_untagged */
			untagged_value = strsep(&vlan_untagged_tmp, ";");
			strsep(&untagged_value, ":");
			if (*untagged_value)
				vty_output(" switchport trunk vlan-untagged %s\n", untagged_value);
			vlan_untagged_tmp++;

			vty_output("!\n");
	}
	free(trunk_list);
	free(load_mode);
	free(port_description);
	free(pvid_config);
	free(vlan_link_type);
	free(trunk_vlan_allowed);
	free(trunk_vlan_untagged);
	free(lacp_mode);

}

static int cli_check_port_aggregator(int portid)
{
	int i;

	for(i = 0; i < cur_trunk_conf.group_count; i++) {
		if( cur_trunk_conf.cur_trunk_list[i].port_int & (0x1ULL<<phy[portid]) )
			return i;
	}
	
	return -1;
}
static void cli_restore_port_aggregator_info(void)
{
	
	memset(&cur_trunk_conf, 0, sizeof(cli_trunk_conf));
	cli_nvram_conf_get(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);

}

static void port_mac_limit_print(int portid,int argvport)
{
	char *port_mac_limit = nvram_safe_get("port_mac_limit");
	char *pt = NULL,*pc = NULL;
	char buf[32] = {0};
	
	sprintf(buf, "P%d",portid);
	if(strlen(port_mac_limit) != 0){
		if((pt = strstr(port_mac_limit,buf)) != NULL){
			if((pc = strchr(pt,',')) != NULL){
				vty_output(" mac learn limit %d\n",atoi(++pc));
			}
		}
	}
	
	free(port_mac_limit);
}

static void cli_show_running_interface(int port_num)
{
    cli_ring_conf conf;
	int portid, index, guest_vlan, tmp_user, mstid, mstp_tmp, adminedge;
	char *p = NULL;
	char tmp[512], line[256], name[ACL_NAME_LEN+1];

	char *port_enable = cli_nvram_safe_get(CLI_ALL_ONE, "port_enable");
	char *port_speed = cli_nvram_safe_get(CLI_SPEED_ALL_AUTO, "port_speed");
	char *port_duplex = cli_nvram_safe_get(CLI_DUPLEX_ALL_AUTO, "port_duplex");
	char *port_description = cli_nvram_safe_get(CLI_ALL_DES, "port_description");
	char *port_flow = cli_nvram_safe_get(CLI_ALL_ZERO, "port_flow");
	char *vlan_link_type = cli_nvram_safe_get(CLI_ALL_ONE, "vlan_link_type");
	char *pvid_config = cli_nvram_safe_get(CLI_COMMA_ONE, "pvid_config");
	char *dot1x_config = cli_nvram_safe_get(CLI_DOT1X_CONFIG, "dot1x_config");
	char *protect_config = cli_nvram_safe_get(CLI_PROTECT_CONFIG,"port_protect_config");	
	char *qos_port_config = cli_nvram_safe_get(CLI_ALL_ZERO,"qos_port_config");
	char *port_learn = cli_nvram_safe_get(CLI_ALL_ONE,"port_learn");
	char *mac_advanced_config = cli_nvram_safe_get(CLI_MAC_ADVANCED,"mac_advanced_config");
	char *rstp_config = cli_nvram_safe_get(CLI_RSTP_CONFIG,"rstp_config");
	char *trunk_vlan_allowed = cli_nvram_safe_get(CLI_TRUNK_VLAN, "trunk_vlan_allowed");
	char *trunk_vlan_untagged = cli_nvram_safe_get(CLI_TRUNK_VLAN, "trunk_vlan_untagged");
	char *lo_config = cli_nvram_safe_get(CLI_ALL_ZERO, "lo_config");
	char *filter_arp = cli_nvram_safe_get(CLI_COMMA_ZERO, "filter_arp");
	char *port_mac_acl = cli_nvram_safe_get(CLI_PORT_ACL, "port_mac_acl");
	char *port_ip_acl = cli_nvram_safe_get(CLI_PORT_ACL, "port_ip_acl");
	char *port_ipv6_acl = cli_nvram_safe_get(CLI_PORT_ACL, "port_ipv6_acl");
	char *arp_trust_port = cli_nvram_safe_get(CLI_ALL_ZERO, "arp_trust_port");
	char *snoop_trust_port = cli_nvram_safe_get(CLI_ALL_ZERO, "snoop_trust_port");
	char *port_policy = cli_nvram_safe_get(CLI_PORT_POLICY, "port_policy");
	char *filter_dhcp_port = cli_nvram_safe_get(CLI_ALL_ZERO, "filter_dhcp_port");
	char *dhcp6_snoop_trust_port = cli_nvram_safe_get(CLI_ALL_ZERO, "dhcp6_snoop_trust_port");
	char *port_mtu  = cli_nvram_safe_get(CLI_COMMA,  "port_mtu");
	/* betty added on 2011/5/5 */
	char *storm_bro = cli_nvram_safe_get(CLI_RATE,"storm_bro");
	char *storm_mul = cli_nvram_safe_get(CLI_RATE,"storm_mul");
	char *storm_uni = cli_nvram_safe_get(CLI_RATE,"storm_uni");
	char *port_l2tp = cli_nvram_safe_get(CLI_ALL_ZERO,  "port_l2tp");
	char *gmrp_config = cli_nvram_safe_get(CLI_ALL_ZERO,  "gmrp_config");
	char *gvrp_config = cli_nvram_safe_get(CLI_ALL_ZERO,  "gvrp_config");
    char *qinq_enable = nvram_safe_get("qinq_enable");
	char *qinq_config = cli_nvram_safe_get(CLI_ALL_ONE,  "qinq_config");
	char *lldp_rx = cli_nvram_safe_get(CLI_ALL_ONE,  "lldp_rx");
	char *lldp_tx = cli_nvram_safe_get(CLI_ALL_ONE,  "lldp_tx");
	char *lldp_enable = nvram_safe_get("lldp_enable");
	char *vlantrans = nvram_safe_get("qinq_trans");    
	char *rate_ingress = cli_nvram_safe_get(CLI_RATE,"rate_ingress");
	char *rate_egress = cli_nvram_safe_get(CLI_RATE,"rate_egress");
	char *dot1x_enable = nvram_safe_get("dot1x_enable");	
    memset(&conf, '\0', sizeof(cli_ring_conf));
    cli_nvram_conf_get(CLI_RING_INFO, (unsigned char *)&conf);

	/* added by luole */
	char *mstp_port_cp = cli_nvram_safe_get(CLI_MSTP_PORT_CP_CONFIG, "mstp_port_cost_prio");
	char *mstp_port_config = cli_nvram_safe_get(CLI_MSTP_PORT_CONFIG, "mstp_port_config");


	char *storm_bro_tmp = storm_bro;
	char *storm_mul_tmp = storm_mul;
	char *storm_uni_tmp = storm_uni;
	/* betty added on 2011/5/5 */

	char *rate_ingress_tmp = rate_ingress;
	char *rate_egress_tmp = rate_egress;

	char *pvid_tmp = pvid_config;
	char *dot1x_tmp = dot1x_config;
	char *protect_tmp = protect_config;
	char *mac_advanced_tmp = mac_advanced_config;
	char *rstp_config_tmp = rstp_config;
	char *port_discribtion_tmp = port_description;
	char *port_discribtion_tmp_s = port_description;
	char *vlan_allowed_tmp = trunk_vlan_allowed;
	char *vlan_untagged_tmp = trunk_vlan_untagged;
	char *filter_arp_tmp = filter_arp;
	char *mtu_tmp = port_mtu;
	char *mac_acl_tmp1 = port_mac_acl, *mac_acl_tmp2;
	char *ip_acl_tmp1 = port_ip_acl, *ip_acl_tmp2;
	char *ipv6_acl_tmp1 = port_ipv6_acl, *ipv6_acl_tmp2;
	char *port_policy_tmp1 = port_policy, *port_policy_tmp2;
	char *vp1, *vp2, *vp3, *vp4, *vlan_translation = vlantrans;
	
	cli_restore_port_aggregator_info();
	/*cli_restore_static_mac();*/
	for(portid = 1; portid <= PNUM; portid++)
	{
		if( (portid == port_num)||(0 == port_num) )
		{
#if (XPORT==0)
			/*  betty modified to add giga port*/
			if(portid <= FNUM)
				vty_output("interface FastEthernet 0/%d\n", portid); 
			else
				vty_output("interface GigaEthernet 0/%d\n", (portid-FNUM));
#endif	
#if (XPORT==1)
			/*  betty modified to add giga port*/
			if(portid <= GNUM)
				vty_output("interface GigaEthernet 0/%d\n", portid); 
			else
				vty_output("interface TenGigaEthernet 0/%d\n", (portid-GNUM));
#endif				 
		} 
		
		if((1500 != atoi(mtu_tmp)) &&(0 != atoi(mtu_tmp))){
			if( (portid == port_num)||(0 == port_num) )
				vty_output(" mtu jumbo %d\n", atoi(mtu_tmp));
		}
		
		if((mtu_tmp = strchr(mtu_tmp, ',')) != NULL)
			mtu_tmp++;
		
		/* vlan link type */
		switch( *(vlan_link_type+portid-1) ) {
			case '2':
				if( (portid == port_num)||(0 == port_num) )
					vty_output(" switchport mode hybrid\n");
				break;
			case '3':
				if( (portid == port_num)||(0 == port_num) )
					vty_output(" switchport mode trunk\n");
				break;
			default:
				break;
		}
		
		/* port pvid */
		if(1 != atoi(pvid_tmp)){
			if( (portid == port_num)||(0 == port_num) )
				vty_output(" switchport pvid %d\n", atoi(pvid_tmp));
		}
		if((pvid_tmp = strchr(pvid_tmp, ',')) != NULL)
			pvid_tmp++;

		/* port mac limit */
		port_mac_limit_print(portid,port_num);
		
		
		/* trunk vlan allowed */
		if((p = strchr(vlan_allowed_tmp, ':')) != NULL)
			p++;
			
		vlan_allowed_tmp = strchr(vlan_allowed_tmp, ';');

		memset(tmp, '\0', sizeof(tmp));
		
		if(vlan_allowed_tmp != NULL)
			memcpy(tmp, p, vlan_allowed_tmp-p);
			
		if(0 != strlen(tmp)) {
			if( (portid == port_num)||(0 == port_num) )
				vty_output(" switchport trunk vlan-allowed %s\n", tmp);
		}
		if(vlan_allowed_tmp != NULL)
			vlan_allowed_tmp++;
			

		/* trunk vlan untagged */
		p = strchr(vlan_untagged_tmp, ':');
		vlan_untagged_tmp = strchr(vlan_untagged_tmp, ';');
		if(p != NULL)
			p++;

		memset(tmp, '\0', sizeof(tmp));
		memcpy(tmp, p, vlan_untagged_tmp-p);
		if(0 != strlen(tmp)) {
			if( (portid == port_num)||(0 == port_num) )
				vty_output(" switchport trunk vlan-untagged %s\n", tmp);
		}
		
		if(vlan_untagged_tmp != NULL)
			vlan_untagged_tmp++;

		#if 0
		/* qinq link type */
		if(*qinq_enable == '1')
		{    
    		switch( *(qinq_config+portid-1) ) {
    			case '1':
    				if( (portid == port_num)||(0 == port_num) )
    					vty_output(" switchport dot1q-translating-tunnel mode qinq\n");
    				break;
    			case '2':
    				if( (portid == port_num)||(0 == port_num) )
    				{    
    					vty_output(" switchport dot1q-translating-tunnel mode uplink\n");
    				}	
    				break;
    			case '3':
    				if( (portid == port_num)||(0 == port_num) )
    					vty_output(" switchport dot1q-translating-tunnel mode flat\n");
    				break;
    			default:
    				break;
    		}
		}
		#endif
		
		if((vp1 = strchr(vlan_translation, ';')) != NULL)
		{
    		memset(tmp, '\0', sizeof(tmp));
    		memcpy(tmp, vlan_translation, vp1-vlan_translation);
			if(((portid == port_num)||(0 == port_num))&&(strlen(tmp) > 0))
			{
			    vp2 = tmp;
			    while(strlen(vp2) > 0)
			    {
    		        memset(line, '\0', sizeof(line));
			        vp3 = strchr(vp2, '/');
			        if(vp3 == NULL)
			        {    
    		            strcat(line, vp2);
    		            vp2 += strlen(line);
    		        }else
    		        {    
    		            memcpy(line, vp2, vp3-vp2);
    		            vp2 = vp3+1;    
    		        }
    		        vp4 = strchr(line, ':');
    		        *vp4 = '\0'; 
					vty_output(" switchport dot1q-translating-tunnel translate %s %d\n", line, atoi(vp4+1));
			    }    
			}    
    		
    		vlan_translation = vp1+1;
    	}
		
		/* shutdown */
		switch( *(port_enable+portid-1) ) {
			case '0':
				if( (portid == port_num)||(0 == port_num) )
					vty_output(" shutdown\n");
				break;
			default:
				break;
		}

		/* port speed */
		switch( *(port_speed+portid-1)-'0')
        {
			case PORT_SPEED_10:
				if( (portid == port_num)||(0 == port_num) )
					vty_output(" speed 10\n");
				break;
				
			case PORT_SPEED_100:
				if( (portid == port_num)||(0 == port_num) )
					vty_output(" speed 100\n");
				break;
				
            case PORT_SPEED_1000:
				if( (portid == port_num)||(0 == port_num) )
					vty_output(" speed 1000\n");
			default:
				break;
		}

		/* port duplex */
		switch( *(port_duplex+portid-1)-'0' ) {
			case PORT_DUPLEX_FULL:
				if( (portid == port_num)||(0 == port_num) )
					vty_output(" duplex full\n");
				break;

			case PORT_DUPLEX_HALF:
				if( (portid == port_num)||(0 == port_num) )
					vty_output(" duplex half\n");
				break;
			default:
				break;
		}

		/* port flow-control */
		switch( *(port_flow+portid-1) ) {
			case '1':
				if( (portid == port_num)||(0 == port_num) )
					vty_output(" flow-control on\n");
				break;
			default:
				break;
		}

		/* port description */
		port_discribtion_tmp = strchr(port_discribtion_tmp,';');
		if(port_discribtion_tmp != NULL){
			memset(tmp,'\0',sizeof(tmp));

			if(portid==1)
			{
				strncpy(tmp,port_discribtion_tmp_s,port_discribtion_tmp-port_discribtion_tmp_s);
				if(port_discribtion_tmp-port_discribtion_tmp_s) {
					if( (portid == port_num)||(0 == port_num) )
						vty_output(" description %s\n",tmp);
				}
			} 
			else{
				strncpy(tmp,port_discribtion_tmp_s+1,port_discribtion_tmp-port_discribtion_tmp_s-1);
				if(port_discribtion_tmp-port_discribtion_tmp_s-1) {
					if( (portid == port_num)||(0 == port_num) )
						vty_output(" description %s\n",tmp);
				}
			}

			port_discribtion_tmp_s = strchr(port_discribtion_tmp,';');
			port_discribtion_tmp++;
		}

		/* port qos */
		if('0' != *(qos_port_config+portid-1) ) {
			if( (portid == port_num)||(0 == port_num) )
				vty_output(" cos default %c\n", *(qos_port_config+portid-1));
		}

		/* port rate limit ingress*/
		if(0 != atoi(rate_ingress_tmp)){
			if( (portid == port_num)||(0 == port_num) )
				vty_output(" switchport rate-limit %d ingress\n", atoi(rate_ingress_tmp));
		}
		if((rate_ingress_tmp = strchr(rate_ingress_tmp, ',')) != NULL)
			rate_ingress_tmp++;
			
		/* port rate limit egress*/
		if(0 != atoi(rate_egress_tmp)){
			if( (portid == port_num)||(0 == port_num) )
				vty_output(" switchport rate-limit %d egress\n", atoi(rate_egress_tmp));
		}
		
		if((rate_egress_tmp = strchr(rate_egress_tmp, ',')) != NULL)
			rate_egress_tmp++;
		
		/*storm control by betty 2011-5-5*/
		if(0 != atoi(storm_bro_tmp)){
			if( (portid == port_num)||(0 == port_num) )
			vty_output(" storm-control broadcast threshold %d\n", atoi(storm_bro_tmp));
		}
		if(0 != atoi(storm_mul_tmp)){
			if( (portid == port_num)||(0 == port_num) )
			vty_output(" storm-control multicast threshold %d\n", atoi(storm_mul_tmp));
		}
		if(0 != atoi(storm_uni_tmp)){
			if( (portid == port_num)||(0 == port_num) )
			vty_output(" storm-control unicast threshold %d\n", atoi(storm_uni_tmp));
		}
		
		if((storm_bro_tmp = strchr(storm_bro_tmp, ',')) != NULL)
			storm_bro_tmp++;
			
		if((storm_mul_tmp = strchr(storm_mul_tmp, ',')) != NULL)
			storm_mul_tmp++;
			
		if((storm_uni_tmp = strchr(storm_uni_tmp, ',')) != NULL)
			storm_uni_tmp++;
			

		/* port aggregator group */
		if( (index = cli_check_port_aggregator(portid)) != -1 ) {
			if(1 == cur_trunk_conf.cur_trunk_list[index].mode) {
				if( (portid == port_num)||(0 == port_num) )
					vty_output(" aggregator-group %d mode static\n", cur_trunk_conf.cur_trunk_list[index].group_no);
			} else if(2 == cur_trunk_conf.cur_trunk_list[index].mode) {
				if( (portid == port_num)||(0 == port_num) )
					vty_output(" aggregator-group %d mode static-lacp\n", cur_trunk_conf.cur_trunk_list[index].group_no);
			} else {
				if( (portid == port_num)||(0 == port_num) )
					vty_output(" aggregator-group %d mode lacp\n", cur_trunk_conf.cur_trunk_list[index].group_no);
			}
		}
		
		/* arp filter */
		if(0 != atoi(filter_arp_tmp)){
			if( (portid == port_num)||(0 == port_num) )
				vty_output(" ip arp inspection limit rate %d\n", atoi(filter_arp_tmp));
		}
		
		if((filter_arp_tmp = strchr(filter_arp_tmp, ',')) != NULL)
			filter_arp_tmp++;

		/* port lock mac */
		/*if( (index = cli_check_port_static_mac(portid)) != -1 ) {
			fprintf(fp, " switchport port-security static mac-address %s\n", cli_cur_mac.static_mac.[index].mac);
		}*/
		
        if(*dot1x_enable =='1')
        {   
    		/* port dot1x control */
    		switch(atoi(dot1x_tmp)) {
    			case 2:
    				if( (portid == port_num)||(0 == port_num) )
    					vty_output(" dot1x port-control auto\n");
    				break;
    				
    			case 3:
    				if( (portid == port_num)||(0 == port_num) )
    					vty_output(" dot1x port-control force-unauthorized\n");
    				break;
    				
    			default:
    				break;
    		}
         
    		if((dot1x_tmp = strchr(dot1x_tmp, ',')) != NULL){
	    		dot1x_tmp++;
	    		
	    		if((dot1x_tmp = strchr(dot1x_tmp, ',')) != NULL)
	    			dot1x_tmp++;
	    	}
    		/*guest_vlan = atoi(dot1x_tmp);
    		if(guest_vlan != 0)
    			vty_output(" dot1x guest-vlan %d\n", guest_vlan);
    		dot1x_tmp = strchr(dot1x_tmp, ',');
    		dot1x_tmp++;*/
    		tmp_user = atoi(dot1x_tmp);
    		if(tmp_user != 4096)
    			vty_output(" dot1x max_user %d\n", tmp_user);
    		
    		if(dot1x_tmp != NULL){
    			dot1x_tmp = strchr(dot1x_tmp, ';');
    			if(dot1x_tmp != NULL)
    				dot1x_tmp++;
    		}
    	}
    	
		/* port protect config*/
		protect_tmp = strchr(protect_tmp, ',');
		if(protect_tmp != NULL){
			protect_tmp++;
			if(1 == atoi(protect_tmp)) {
				if( (portid == port_num)||(0 == port_num) )
					vty_output(" switchport protected\n");
			}
			protect_tmp = strchr(protect_tmp, ';');
			protect_tmp++;
		}
		
		/* port learn mode */
		if('0' == *(port_learn+portid-1) ) {
			if( (portid == port_num)||(0 == port_num) )
				vty_output(" switchport port-security mode static accept\n");
		}
		
		/* port dynamic learn max num */
		if(8191 != atoi(mac_advanced_tmp)){
			if( (portid == port_num)||(0 == port_num) )
				vty_output(" switchport port-security dynamic maximum %d\n", atoi(mac_advanced_tmp));
		}
		if((mac_advanced_tmp = strchr(mac_advanced_tmp, ',')) != NULL)
			mac_advanced_tmp++;
		
		/* lldp mode */
	    if('1' == *lldp_enable)
	    {
    		if('1' == *(lldp_rx+portid-1) ) {
    			if( (portid == port_num)||(0 == port_num) )
    				vty_output(" lldp receive\n");
    		}
    		
    		if('1' == *(lldp_tx+portid-1) ) {
    			if( (portid == port_num)||(0 == port_num) )
    				vty_output(" lldp transmit\n");
    		}
    	}
    	
		/* bpdu forward setting */
		if('1' == *(port_l2tp+portid-1) ) {
			if( (portid == port_num)||(0 == port_num) )
				vty_output(" l2protocol-tunnel stp\n");
		}
		
		
		if('1' == *(gvrp_config+portid-1) ) {
			if( (portid == port_num)||(0 == port_num) )
				vty_output(" gvrp\n");
		}
		
		if('1' == *(gmrp_config+portid-1) ) {
			if( (portid == port_num)||(0 == port_num) )
				vty_output(" gmrp\n");
		}
		
#if 0	

		/* spanning-tree rstp port cost */
		if(0 != atoi(rstp_config_tmp)) {
			if( (portid == port_num)||(0 == port_num) )
				vty_output(" spanning-tree cost %d\n", atoi(rstp_config_tmp));
		}
		if((rstp_config_tmp = strchr(rstp_config_tmp, ',')) != NULL)
			rstp_config_tmp++;
		
		/* spanning-tree rstp port priority */
		if(128 != atoi(rstp_config_tmp)) {
			if( (portid == port_num)||(0 == port_num) )
				vty_output(" spanning-tree port-priority %d\n", atoi(rstp_config_tmp));
		}
		if((rstp_config_tmp = strchr(rstp_config_tmp, ',')) != NULL)
			rstp_config_tmp++;
		
		/* spanning-tree rstp port p2p */
		if(0 == atoi(rstp_config_tmp)) {
			if( (portid == port_num)||(0 == port_num) )
				vty_output(" spanning-tree link-type point-to-point\n");
		} else if(1 == atoi(rstp_config_tmp)) {
			if( (portid == port_num)||(0 == port_num) )
				vty_output(" spanning-tree link-type shared\n");
		}
		if((rstp_config_tmp = strchr(rstp_config_tmp, ',')) != NULL)
			rstp_config_tmp++;
		
		/* spanning-tree rstp port edge */
		if(0 != atoi(rstp_config_tmp)) {
			if( (portid == port_num)||(0 == port_num) )
				vty_output(" spanning-tree portfast\n");
		}
		if((rstp_config_tmp = strchr(rstp_config_tmp, ',')) != NULL)
			rstp_config_tmp++;	
		
		/* spanning-tree rstp port enable */
		/*if(1 != atoi(rstp_config_tmp)) {
			if( (portid == port_num)||(0 == port_num) )
				fprintf(fp, " spanning-tree rstp enable\n");
		}*/
		rstp_config_tmp = strchr(rstp_config_tmp, ',');
		rstp_config_tmp++;

        /*shanming.ren 2011-9-20 begin*/
        /* spanning-tree rstp port bpdu guard */
		if(0 != atoi(rstp_config_tmp)) 
        {
			if( (portid == port_num)||(0 == port_num) )
            {
                if(1 == atoi(rstp_config_tmp))
                {
                    vty_output(" spanning-tree bpduguard enable\n");
                }
                else if(2 == atoi(rstp_config_tmp))
                {
                    vty_output(" spanning-tree bpduguard disable\n");
                }
            }
		}
		rstp_config_tmp = strchr(rstp_config_tmp, ',');
		rstp_config_tmp++;

        /* spanning-tree rstp port bpdu filter */
		if(0 != atoi(rstp_config_tmp)) 
        {
			if( (portid == port_num)||(0 == port_num) )
            {
                if(1 == atoi(rstp_config_tmp))
                {
                    vty_output(" spanning-tree bpdufilter enable\n");
                }
                else if(2 == atoi(rstp_config_tmp))
                {
                    vty_output(" spanning-tree bpdufilter disable\n");
                }
            }
		}
		rstp_config_tmp = strchr(rstp_config_tmp, ',');
		rstp_config_tmp++;

        /* spanning-tree rstp port root guard */
		if(0 != atoi(rstp_config_tmp)) 
        {
			if( (portid == port_num)||(0 == port_num) )
            {
                if(1 == atoi(rstp_config_tmp))
                {
                    vty_output(" spanning-tree guard root\n");
                }
                else if(2 == atoi(rstp_config_tmp))
                {
                    vty_output(" spanning-tree guard loop\n");
                }
            }
		}


		if((rstp_config_tmp = strchr(rstp_config_tmp, ';') ) != NULL)
			rstp_config_tmp++;
        /*shanming.ren 2011-9-20 end*/
#endif

#if 0
    	char *mstp_cp_tmp = mstp_port_cp;
    	char *mstp_port_tmp = mstp_port_config;
	
		/* port path cost for each msti */
		/*for (mstid = 0; mstid < MSTI_NUM; mstid++)*/ {
			mstp_tmp = atoi(mstp_cp_tmp);
			if (0 != mstp_tmp) {
				if ((portid == port_num)||(0 == port_num)) {
					vty_output(" spanning-tree mst %d cost %d\n", mstid, mstp_tmp);
				}
			}
			mstp_cp_tmp = strchr(mstp_cp_tmp, ',');
			mstp_cp_tmp++;

			/* port priority for each msti */
			mstp_tmp = atoi(mstp_cp_tmp);
			if (128 != mstp_tmp) {
				if ((portid == port_num) || (0 == port_num)) {
					vty_output(" spanning-tree mst %d priority %d\n", mstid, mstp_tmp);
				}
			}
			mstp_cp_tmp = strchr(mstp_cp_tmp, ';');
			mstp_cp_tmp++;
		}
		
		/* p2p, mstp */
		mstp_tmp = atoi(mstp_port_tmp);
		if (2 != mstp_tmp) {
			if ((portid == port_num) || (0 == port_num)) {
				if (1 == mstp_tmp) {
					vty_output(" spanning-tree link-type shared\n");
				} else if (0 == mstp_tmp) {
					vty_output(" spanning-tree link-type point-to-point\n");
				}
			}
		}
		mstp_port_tmp = strchr(mstp_port_tmp, ',');
		mstp_port_tmp++;
	
		/* edge port */
		adminedge = atoi(mstp_port_tmp);
		mstp_port_tmp = strchr(mstp_port_tmp, ',');
		mstp_port_tmp++;
	
		mstp_tmp = atoi(mstp_port_tmp);
		if (1 != mstp_tmp) {
			if ((portid == port_num) || (0 == port_num)) {
				if (1 == adminedge)
				{
					vty_output(" spanning-tree portfast enable\n");
				}
				else if (0 == adminedge)
				{
					vty_output(" spanning-tree portfast disable\n");
				}
			}
		}
		mstp_port_tmp = strchr(mstp_port_tmp, ',');
		mstp_port_tmp++;

//		/* restrrole */
//		mstp_tmp = atoi(mstp_port_tmp);
//		if (0 != mstp_tmp) {
//			if ((portid == port_num) || (0 == port_num)) {
////				vty_output(" mstp restrrole\n");
//			}
//		}
//		mstp_port_tmp = strchr(mstp_port_tmp, ',');
//		mstp_port_tmp++;
//
//		/* restrtcn */
//		mstp_tmp = atoi(mstp_port_tmp);
//		if (0 != mstp_tmp) {
//			if ((portid == port_num) || (0 == port_num)) {
////				vty_output(" mstp restrtcn\n");
//			}
//		}
//		mstp_port_tmp = strchr(mstp_port_tmp, ',');
//		mstp_port_tmp ++;
//		
//		/* bpdufilter */
//		mstp_tmp = atoi(mstp_port_tmp);
//		if (0 != mstp_tmp)
//		{
//			if ((portid == port_num) || (0 == port_num)) {
//				vty_output(" spaning-tree bpdufilter\n");
//			}
//		}
//		mstp_port_tmp = strchr(mstp_port_tmp, ',');
//		mstp_port_tmp ++;
//		
//		/* bpduguard */
//		mstp_tmp = atoi(mstp_port_tmp);
//		if (0 != mstp_tmp)
//		{
//			if ((portid == port_num) || (0 == port_num)) {
//				vty_output(" spanning-tree bpduguard\n");
//			}
//		}
//		mstp_port_tmp = strchr(mstp_port_tmp, ',');
//		mstp_port_tmp ++;
//		
//		/* rootguard */
//		mstp_tmp = atoi(mstp_port_tmp);
//		if (0 != mstp_tmp)
//		{
//			if ((portid == port_num) || (0 == port_num)) {
//				vty_output(" spanning-tree rootguard\n");
//			}
//		}	
		mstp_port_tmp = strchr(mstp_port_tmp, ';');
		mstp_port_tmp++;
		/* mstp end Luo Le */
#endif

		/* loopback */
		if('1' == *(lo_config+portid-1) ) {
			if( (portid == port_num)||(0 == port_num) )
				vty_output(" switchport loopback-detected\n");
		}
		
		if((conf.ports[0] == portid) || (conf.ports[1] == portid)) {
			if(((portid == port_num)||(0 == port_num) )&&(conf.ident[0] != 0))
				vty_output(" switchport ring %d\n", conf.ident[0]);
		}
		
		if((conf.ports[2] == portid) || (conf.ports[3] == portid)) {
			if(((portid == port_num)||(0 == port_num)&&(conf.ident[1] != 0)))
				vty_output(" switchport ring %d\n", conf.ident[1]);
		}

		/* mac acl */
		memset(name, '\0', ACL_NAME_LEN+1);
		mac_acl_tmp2 = strchr(mac_acl_tmp1, ',');
		if(mac_acl_tmp2 != NULL){
			strncpy(name, mac_acl_tmp1, mac_acl_tmp2-mac_acl_tmp1);
			mac_acl_tmp1 = mac_acl_tmp2 + 1;
			if(strlen(name))
				if( (portid == port_num)||(0 == port_num) )
					vty_output(" mac access-group %s\n", name);
		}
		
		/* ip acl */
		memset(name, '\0', ACL_NAME_LEN+1);
		ip_acl_tmp2 = strchr(ip_acl_tmp1, ',');
		if(ip_acl_tmp2 != NULL){
			strncpy(name, ip_acl_tmp1, ip_acl_tmp2-ip_acl_tmp1);
			ip_acl_tmp1 = ip_acl_tmp2 + 1;
			if(strlen(name))
				if( (portid == port_num)||(0 == port_num) )
					vty_output(" ip access-group %s\n", name);
		}

		/* ipv6 acl */
		memset(name, '\0', ACL_NAME_LEN+1);
		ipv6_acl_tmp2 = strchr(ipv6_acl_tmp1, ',');
		if(ipv6_acl_tmp2 != NULL){
			strncpy(name, ipv6_acl_tmp1, ipv6_acl_tmp2-ipv6_acl_tmp1);
			ipv6_acl_tmp1 = ipv6_acl_tmp2 + 1;
			if(strlen(name))		
				if( (portid == port_num)||(0 == port_num) )			
					vty_output(" ipv6 access-group %s\n", name);
		}
		
		/* arp inspection trust port */
		if('0' != *(arp_trust_port+portid-1) ) {
			if( (portid == port_num)||(0 == port_num) )
				vty_output(" ip arp inspection trust\n");
		}

		/* arp inspection trust port */
		if('0' != *(snoop_trust_port+portid-1) ) {
			if( (portid == port_num)||(0 == port_num) )
				vty_output(" ip dhcp snooping trust\n");
		}
		/*ip dhcp port filter  */
		if('0' != *(filter_dhcp_port+portid-1) ) {
			if( (portid == port_num)||(0 == port_num) )
				vty_output(" enable port dhcp filter\n");
		}
		/* ipv6 snoop trust port */
		if('0' != *(dhcp6_snoop_trust_port+portid-1) ) {
			if( (portid == port_num)||(0 == port_num) )
				vty_output(" ipv6 dhcp snooping trust\n");
		}	
		/* policy_map */
		memset(name, '\0', ACL_NAME_LEN+1);
		port_policy_tmp2 = strchr(port_policy_tmp1, ',');
		if(port_policy_tmp2 != NULL){
			strncpy(name, port_policy_tmp1, port_policy_tmp2-port_policy_tmp1);
			port_policy_tmp1 = port_policy_tmp2 + 1;
			if(strlen(name))
				if( (portid == port_num)||(0 == port_num) )
				vty_output(" qos policy %s ingress\n", name);	
		}
		
		/* Done */
		if( (portid == port_num)||(0 == port_num) )
			vty_output("!\n");
	}

	/* free trunk_list struct */
	cli_nvram_conf_free(CLI_TRUNK_LIST, (unsigned char *)&cur_trunk_conf);

	CMD_FREE(dot1x_enable);
	CMD_FREE(port_enable);
	CMD_FREE(port_speed);
	CMD_FREE(port_duplex);
	CMD_FREE(port_flow);
	CMD_FREE(vlan_link_type);
	CMD_FREE(pvid_config);
	CMD_FREE(dot1x_config);
	CMD_FREE(protect_config);
	CMD_FREE(qos_port_config);
	CMD_FREE(port_learn);
	CMD_FREE(mac_advanced_config);
	CMD_FREE(rstp_config);
	CMD_FREE(trunk_vlan_allowed);
	CMD_FREE(trunk_vlan_untagged);
	CMD_FREE(port_mac_acl);
	CMD_FREE(port_ip_acl);
	CMD_FREE(port_policy);
	CMD_FREE(arp_trust_port);
	CMD_FREE(snoop_trust_port);
	CMD_FREE(filter_dhcp_port);
	CMD_FREE(storm_bro);
	CMD_FREE(storm_mul);
	CMD_FREE(storm_uni);
	CMD_FREE(rate_ingress);
	CMD_FREE(rate_egress);
	CMD_FREE(port_mtu);
	CMD_FREE(qinq_config);
	CMD_FREE(mstp_port_cp);
	CMD_FREE(mstp_port_config);
	CMD_FREE(port_l2tp);
	CMD_FREE(gmrp_config);
	CMD_FREE(gvrp_config);
	CMD_FREE(lldp_rx);
	CMD_FREE(lldp_tx);
	CMD_FREE(lldp_enable); 
	CMD_FREE(vlantrans);
	CMD_FREE(lo_config);
	CMD_FREE(filter_arp);
	CMD_FREE(port_ipv6_acl);
	CMD_FREE(dhcp6_snoop_trust_port);
	CMD_FREE(port_description);
	CMD_FREE(qinq_enable);
}
static void cli_show_running_interface_ipv6(void)
{
	char ethbuf[12];
	char *manage_vlan = nvram_safe_get("manage_vlan");
	char *manage_IMP = nvram_safe_get("manage_IMP");
	char *ip_staticip_enable=nvram_safe_get("dhcp6_client");
	if_ipv6_t *ipv6_info = NULL, *ipv6_info_tmp = NULL;
	int vlanid;

	memset(ethbuf,'\0',12);
	vlanid = atoi(manage_vlan);
	if(0 != vlanid) {
		sprintf(ethbuf,"eth2.%d",vlanid);
	}
	else {
		sprintf(ethbuf,"eth2.%d",1);
	}

	ipv6_info = get_ipv6_addr();
	ipv6_info_tmp = ipv6_info;
	while(ipv6_info_tmp!= NULL)
	{
		if(strcmp(ipv6_info_tmp->devname, ethbuf) == 0)
		{

			if(ipv6_info_tmp->scope_type == 0)
				vty_output("%s ipv6 address %s/%d\n",
				('1' == *ip_staticip_enable)?"DHCP":"Manual",ipv6_info_tmp->addr6, ipv6_info_tmp->plen);
			}
		ipv6_info_tmp = ipv6_info_tmp->next;
	}
	free_ipv6_addr(ipv6_info);

	free(manage_vlan);
	free(manage_IMP);
	free(ip_staticip_enable);
	return ;
}

static void cli_show_running_interface_ip()
{
	char *lan_ip = nvram_safe_get("lan_ipaddr");
	char *lan_mask = nvram_safe_get("lan_netmask");
	char *lan_gateway = nvram_safe_get("lan_gateway");
	char *manage_vlan = nvram_safe_get("manage_vlan");
	int vlanid;

	vlanid = atoi(manage_vlan);
	if(vlanid >0)
		vty_output("manage vlan %d\n",vlanid);
	else
		vty_output("manage vlan %d\n",1);
	
	vty_output("IP %s %s\n", lan_ip, lan_mask);
	vty_output("Gateway %s\n", lan_gateway);

	free(lan_ip);
	free(lan_mask);
	free(lan_gateway);
	free(manage_vlan);
	return;
}

static void cli_show_running_radius()
{
	char *radius_server = nvram_safe_get("radius_server");
	/*char *aaa_server = nvram_safe_get("aaa_server");*/
	char *radius_port = nvram_safe_get("radius_port");
	char *aaa_port = nvram_safe_get("aaa_port");
	char *radius_prekey = nvram_safe_get("radius_prekey");
    char *radius_defkey_ena = nvram_safe_get("radius_defkey_ena");
	/*char *aaa_prekey = nvram_safe_get("aaa_prekey");*/
	
	if( (0 != strlen(radius_server))&&(0 != strlen(radius_port))&&(0 != strlen(aaa_port)) ) {
		vty_output("radius-server host %s auth-port %s acct-port %s\n", radius_server, radius_port, aaa_port);
	}
	
	if(0 != strlen(radius_prekey)){
		vty_output("radius-server key %s\n", radius_prekey);
	}
	vty_output("!\n");
	
	free(radius_server);
	free(radius_port);
	free(aaa_port);
	free(radius_prekey);
    free(radius_defkey_ena);
}

void cli_show_running_vlan(int printtype)
{
	int  vid, iptype, pim_type, len; 
	char *p, *p1, *p2, *p3, *p4, *ip, *pim;
	char *l3_ip, *vlanname, *vlan_name, *bfd_enable, *bfd_intf, *bfd_str;
	char intf[8], key[8], line[256], subv[256], ipv4[32], ipv6[64], ipaddr[32];
	char isis[4096], substr[8192], arpstr[8192], freearp[8192], pim_str[8192], relay_str[8192];
	char *dhcp_relay_ip, *isis_intf_config, *subvlan, *arp_timeout, *free_arp, *ipmc_enable,*ipmc_type;
	
	vlanname = nvram_safe_get("vlan_name");
	len = strlen(vlanname)+2;
	vlan_name = malloc(len);
	if(NULL == vlan_name)
	{
		vty_output("Error: no enough memory for show vlan setting!\n");
		free(vlanname);
		return -1;
	} 
    memset(vlan_name, '\0', len);

    bfd_intf = nvram_safe_get("bfd_intf");
	len = strlen(bfd_intf)+2;
	bfd_str = malloc(len);
	if(NULL == bfd_str)
	{
		vty_output("Error: no enough memory for show vlan setting!\n");
		
		free(vlanname);
		free(vlan_name);
		free(bfd_intf);
		
		return -1;
	} 
    memset(bfd_str, '\0', len);
	
	sprintf(vlan_name, ";%s", vlanname);
	free(vlanname);
	
	sprintf(bfd_str, ";%s", bfd_intf);
	free(bfd_intf);
	
	isis_intf_config = nvram_safe_get("isis_intf_config");
    subvlan = nvram_safe_get("subvlan");
    arp_timeout = nvram_safe_get("arp_timeout");
    free_arp = nvram_safe_get("free_arp");
    ipmc_enable = nvram_safe_get("ipmc_enable");
    ipmc_type = nvram_safe_get("ipmc_type");
    dhcp_relay_ip = nvram_safe_get("dhcp_relay_ip");
    bfd_enable = nvram_safe_get("bfd_enable");
	
	memset(isis, '\0', sizeof(isis));
	sprintf(isis, ";%s", isis_intf_config);
	free(isis_intf_config);
	
	memset(substr, '\0', sizeof(substr));
	sprintf(substr, ";%s", subvlan);
	free(subvlan);
	
	memset(arpstr, '\0', sizeof(arpstr));
	sprintf(arpstr, ";%s", arp_timeout);
	free(arp_timeout);
	
	memset(freearp, '\0', sizeof(freearp));
	sprintf(freearp, ";%s", free_arp);
	free(free_arp);
	
	memset(relay_str, '\0', sizeof(relay_str));
	sprintf(relay_str, ";%s", dhcp_relay_ip);
	free(dhcp_relay_ip);
	
	memset(pim_str, '\0', sizeof(pim_str));
	if(*ipmc_enable == '1')
	{
	    if((strlen(ipmc_type) == 0) || (*ipmc_type == '0'))
	    {    
	        pim_type = 1;
	        pim = nvram_safe_get("pim_sm");
	        sprintf(pim_str, ";%s", pim);
	        free(pim);
	    }
	    else if(*ipmc_type == '1')
	    {    
	        pim_type = 2;
	        pim = nvram_safe_get("pim_dm");
	        sprintf(pim_str, ";%s", pim);
	        free(pim);
	    }
    }
    else
        pim_type = 0;
    free(ipmc_enable);
    free(ipmc_type);
    
    l3_ip = nvram_safe_get("lan_ipaddr");
	
	show_fun("l3_ip:%s \n",l3_ip);
    ip = l3_ip;
    while(strlen(ip) > 0)
    {   
        memset(line, '\0', sizeof(line));
        p1 = strchr(ip, ';'); 
        if(NULL == p1)
            break;    
        
        memcpy(line, ip, p1-ip);
        memset(ipv4, '\0', sizeof(ipv4));
        memset(ipv6, '\0', sizeof(ipv6));
        cli_interface_info_get(line, &vid, &iptype, ipv4, ipv6);
        ip = p1+1;
        
	    memset(intf, '\0', sizeof(intf));
	    sprintf(intf, ";%d,", vid);
    	    
        memset(key, '\0', sizeof(key));
        sprintf(key, ";%d:", vid);
        
        vty_output("interface vlan %d\n", vid);
        
        if((p3 = strstr(vlan_name, key)) != NULL)
        {
            memset(subv, '\0', sizeof(subv));
            p3 = strchr(p3, ':')+1;
            p4 = strchr(p3, ';');
            memcpy(subv, p3, p4-p3);
	        vty_output(" name %s\n", subv);
        }
          
        if(0 == (iptype%2))
        {
            if(strlen(ipv4) > 0)
            {    
                memset(ipaddr, '\0', sizeof(ipaddr));
                if((p = strchr(ipv4, '/')) == NULL)
                    strcpy(ipaddr, ipv4);
                else
                    memcpy(ipaddr, ipv4, p-ipv4);   
       
    			vty_output(" ip address %s %s\n", ipaddr, get_netmask_str(ipv4));
    		}
    		
            if(strlen(ipv6) > 0)
            {    
    			vty_output(" ipv6 address %s\n", ipv6);
    		}
		
			if(iptype & 0x02)
			{   
			    vty_output(" supervlan\n");
    	        if((p3 = strstr(substr, key)) != NULL)
    	        {
                    memset(subv, '\0', sizeof(subv));
                    p3 = strchr(p3, ':')+1;
    	            p4 = strchr(p3, ';');
    	            memcpy(subv, p3, p4-p3);
			        vty_output(" subvlan %s\n", subv);
    	        }
			}
			
			if(iptype & 0x04)
			{    
			    vty_output(" ip proxy-arp\n");
			}     
		}else if(1 == iptype)
		{    
			vty_output(" ip address dhcp\n");  
        } 
        
        //arp_timeout=20:300;1:600;30:500;
        if((p1 = strstr(arpstr, key)) != NULL)
        {
            p2 = strchr(p1+1, ':')+1;
            vty_output(" arp timeout %d\n", atoi(p2));
        } 
        
        if((p1 = strstr(freearp, key)) != NULL)
        {
            p2 = strchr(p1+1, ':')+1;
            vty_output(" arp send-gratuitous interval %d\n", atoi(p2));
        } 
        
        //isis_intf_config=2,1;3,1;4,1;
        if((p1 = strstr(isis, intf)) != NULL)
        {
            p2 = strchr(p1+1, ';');
            memset(line, '\0', sizeof(line));
            memcpy(line, p1+1, p2-p1-1);
            
            p2 = strchr(line, ',')+1;
            vty_output(" ip router isis %d\n", atoi(p2));
        }  
        
        //pim_sm=1:;2:;200:;2000:;
        if((p1 = strstr(pim_str, key)) != NULL)
        {
            if(pim_type == 1)
                vty_output(" ip pim-sm\n");
            else if(pim_type == 2) 
            {   
                char *pp2 = strchr(p1, ':')+1;
                int dr = atoi(pp2);
                  
                vty_output(" ip pim-dm\n");  
                if(dr > 0)
                    vty_output(" ip pim-dm dr-priority %d\n", dr);
            }    
        } 
        
        //dhcp_relay_ip=1:192.168.1.1,2000::1:2345:6789:abcd;
        if((p1 = strstr(relay_str, key)) != NULL)
        {
            char *pp1, *pp2, rline[256], list[3][64];
            memset(rline, '\0', sizeof(rline));
            memset(list, '\0', sizeof(list));
            pp1 = p1+1;
            pp2 = strchr(pp1, ';'); 
            memcpy(rline, pp1, pp2-pp1);
           
            sscanf(rline, "%[^:]:%[^,],%[^,],", list[0],list[1],list[2]); 
            
            if(strlen(list[1]) > 0)
                vty_output(" ip helper-address %s\n",list[1]);  
                
            if(strlen(list[2]) > 0)
                vty_output(" ip helper-address %s\n",list[2]);  
        } 
        
        if(*bfd_enable == '1')
        {
            //bfd_intf=1:3000,3000,3;2:2000,3000,5;5:200,400,8;
	        if((p1 = strstr(bfd_str, key)) != NULL)
	        {
	            char *pp1, *pp2, rline[256], list[4][8];
                memset(rline, '\0', sizeof(rline));
                memset(list, '\0', sizeof(list));
                pp1 = p1+1;
                pp2 = strchr(pp1, ';'); 
                memcpy(rline, pp1, pp2-pp1);
               
                sscanf(rline, "%[^:]:%[^,],%[^,],%[^,],", list[0],list[1],list[2],list[3]); 
                vty_output(" bfd interval %s min_rx %s multiplier %s\n",list[1],list[2],list[3]);  
	        } 
        }    
        
        if(1 == printtype)
            vty_output("\n"); 
        else    
            vty_output("!\n"); 
    } 
    free(l3_ip);
    free(vlan_name);  
    free(bfd_str);  
	free(bfd_enable);
    if(1 == printtype)
        vty_output("\n"); 
    else    
        vty_output("!\n"); 
      
	return;
}

static void cli_show_static_route()
{
    int metric, dev;
    char *l3_st, *st, *p1, *pend; 
    char dst[18], mask[18], gateway[18], line[128];
 
    //l3_st=0.0.0.0:192.168.10.2:255.255.255.0:20:eth1.1;192.168.11.0:192.168.16.2:255.255.255.0:20:eth1.3;
    l3_st = st = nvram_safe_get("l3_st");  
    while((*st != NULL) && (strlen(st) > 0))
    {
        memset(line, '\0', sizeof(line));
        memset(dst, '\0', sizeof(dst));
        memset(mask, '\0', sizeof(mask));
        memset(gateway, '\0', sizeof(gateway));
        
        p1 = st;// analysis this
        pend = strchr(st, ';'); 
        memcpy(line, p1, pend-p1);
        st = pend+1; //next one

        sscanf(line,"%[^:]:%[^:]:%[^:]:%d:eth1.%d", dst, gateway, mask, &metric, &dev);

        if(!strcmp(dst, "0.0.0.0"))
            vty_output(" ip route default %s\n", gateway);
        else
            vty_output(" ip route %s %s %s\n", dst, mask, gateway);
    } 
    free(l3_st);       
    
	vty_output("!\n");
	return;
}

static void cli_show_bfd()
{
    char *bfd_enable = nvram_safe_get("bfd_enable");
    
    if(*bfd_enable == '1') //no rip
    {
	    vty_output("bfd enable\n");
    }
    free(bfd_enable);    
	vty_output("!\n");
	return;
} 
  
static void cli_show_rip()
{
    int protocol;
    char *p1, *p2, *p3, tmp[128], ipaddr[32], *zebra = nvram_safe_get("zebra");
    
    protocol = atoi(zebra);
    if(protocol & 0x01) //no rip
    {
        int redistribute;
        char *config, *rip_config = nvram_safe_get("rip_ip_config");
        char * rebute = nvram_safe_get("rebute_rip"); 
        char *ripng_config = nvram_safe_get("ripng_config");
    
	    vty_output("router rip\n");
	    
        config = rip_config;  
        while((*config != NULL) && (strlen(config) > 0))
        {  
            p3 = strchr(config, ';');
            memset(tmp, '\0', sizeof(tmp));
            memcpy(tmp, config, p3-config);
            
            p1 = strchr(tmp, ',');
            if(p1 != NULL)
                *p1 = '\0';
            
            memset(ipaddr, '\0', sizeof(ipaddr));
            if((p2 = strchr(tmp, '/')) == NULL)
                strcpy(ipaddr, tmp);
            else
                memcpy(ipaddr, tmp, p2-tmp);   
   
			vty_output(" network %s %s\n", ipaddr, get_netmask_str(tmp));
            config = p3+1;
        } 
        
        config = ripng_config;  
        while((*config != NULL) && (strlen(config) > 0))
        {  
            p3 = strchr(config, ';');
            memset(tmp, '\0', sizeof(tmp));
            memcpy(tmp, config, p3-config);
            
            vty_output(" network %s\n", tmp); 
            config = p3+1;
        } 
        
        redistribute = atoi(rebute);
        if(redistribute & 0x01)
            vty_output(" redistribute static\n"); 
        if(redistribute & 0x02)
            vty_output(" redistribute ospf\n");  
        if(redistribute & 0x04)
            vty_output(" redistribute bgp\n");   
        if(redistribute & 0x08)
            vty_output(" redistribute connected\n");   
        
        free(rebute);
        free(rip_config);
        free(ripng_config);
    }
    
    free(zebra);    
	vty_output("!\n");
	return;
}
   
static void cli_show_ospf()
{
    struct in_addr addr;
    int vid, type, protocol, area;
    char *p1, *p2, *p3, *config, tmp[128], ipaddr[32], *zebra = nvram_safe_get("zebra");
    char area_mask[16], *p4, list[3][64];
    
    protocol = atoi(zebra);
    if(protocol & 0x02) //no rip
    {
        int vid, area, type, redistribute;
        char * ospfid = nvram_safe_get("ospfid");
        char * routerid = nvram_safe_get("route_id");
        char * ospf_config = nvram_safe_get("ospf_ip_config");
        char * rebute = nvram_safe_get("rebute_ospf"); 
        char * ospf6_config = nvram_safe_get("ospf6_config");
		char *ospf_bfd = nvram_safe_get("ospf_bfd");	
    
	    vty_output("router ospf %s\n", ospfid);
	    
	    if(strlen(routerid) > 4)
	        vty_output(" router-id %s\n", routerid);
	        
        config = ospf_config;  
        while((*config != NULL) && (strlen(config) > 0))
        {  
            p3 = strchr(config, ';');
            memset(tmp, '\0', sizeof(tmp));
            memset(ipaddr, '\0', sizeof(ipaddr));
            memcpy(tmp, config, p3-config);
            memset(list, '\0', sizeof(list));
            sscanf(tmp,"%[^,],%[^,],%[^,]", list[0],list[1],list[2]); 
            
            type = atoi(list[2]);
            p1 = strchr(list[0], '/');
            memcpy(ipaddr, list[0], p1-list[0]);
            
            if(0 == type)
            {
                vty_output(" network %s %s area %s\n", ipaddr, get_netmask_str(list[0]), list[1]); 
            }
            else if(1 == type)
            {
                vty_output(" network %s %s area %s advertise\n", ipaddr, get_netmask_str(list[0]), list[1]); 
            }
            else if(2 == type)
            {
                vty_output(" network %s %s area %s notadvertise\n", ipaddr, get_netmask_str(list[0]), list[1]); 
            }
                
            config = p3+1;
        } 
        
        config = ospf6_config;  
        while((*config != NULL) && (strlen(config) > 0))
        {  
            p3 = strchr(config, ';');
            memset(tmp, '\0', sizeof(tmp));
            memcpy(tmp, config, p3-config);
            p2 = strchr(tmp, ',');
            area = atoi(p2+1);
            *p2 = '\0';
            
            vty_output(" network  %s area %d\n", tmp, area); 
            config = p3+1;
        } 
        
        redistribute = atoi(rebute);
        if(redistribute & 0x01)
            vty_output(" redistribute static\n"); 
        if(redistribute & 0x02)
            vty_output(" redistribute ospf\n");  
        if(redistribute & 0x04)
            vty_output(" redistribute bgp\n");   
        if(redistribute & 0x08)
            vty_output(" redistribute connected\n");   
            
        if(*ospf_bfd == '1') //no rip
        {
    	    vty_output(" bfd all-interface\n");
        }
        free(ospf_bfd);   
        free(ospfid);
        free(routerid);
        free(ospf_config);
        free(ospf6_config);
        free(rebute);
    }
//    else
//	    vty_output("no router ospf\n");
            
    
    free(zebra);    
	vty_output("!\n");
	return;
}
    
static void cli_show_bgp()
{
    char *bgp = nvram_safe_get("bgp_enable");
    
    if(*bgp == '1')
    {    
        int id = 0;
        int vid, area, type, redistribute;
        char *pt, *p1, *p2, *p3, *ip, tmp[128], lanip[128], *config;
        char * bgp_as = nvram_safe_get("bgp_as");
        char * routerid = nvram_safe_get("bgp_route_id");
        char * bgp_remote = nvram_safe_get("bgp_remote");
        char * bgp_network = nvram_safe_get("bgp_network");
        char * rebute = nvram_safe_get("rebute_bgp"); 
    	char * bgp6_config = nvram_safe_get("bgp6_config");
    	char * bgp6_remote = nvram_safe_get("bgp6_remote");

        vty_output("router bgp %s\n", bgp_as);
        vty_output(" router-id %s\n", routerid); 
        
        if(strchr(bgp_remote, ';') != NULL)
        {    
            ip = bgp_remote;  
            while((ip != NULL) && (strlen(ip) > 0))
            { 
                pt = strchr(ip, ';');
                memset(tmp, '\0', sizeof(tmp));
                memcpy(tmp, ip, pt-ip);
                ip = pt+1;
                
                p1 = strrchr(tmp, ',');
                memset(lanip, '\0', sizeof(lanip));
                memcpy(lanip, tmp, p1-tmp);
                id = atoi(p1+1);      
                vty_output(" neighbor %s remote-as %d\n", lanip, id); 
            } 
        }   
        
        if(strchr(bgp6_remote, ';') != NULL)
        {    
            ip = bgp6_remote;  
            while((ip != NULL) && (strlen(ip) > 0))
            { 
                pt = strchr(ip, ';');
                memset(tmp, '\0', sizeof(tmp));
                memcpy(tmp, ip, pt-ip);
                ip = pt+1;
                
                p1 = strrchr(tmp, ',');
                memset(lanip, '\0', sizeof(lanip));
                memcpy(lanip, tmp, p1-tmp);
                id = atoi(p1+1);      
                vty_output(" neighbor %s remote-as %d\n", lanip, id); 
            } 
        }  
       
        if(strchr(bgp_network, ';') != NULL)
        {   
            ip = bgp_network;  
            while((ip != NULL) && (strlen(ip) > 0))
            {  
                pt = strchr(ip, ';');
                memset(tmp, '\0', sizeof(tmp));
                memcpy(tmp, ip, pt-ip);
                ip = pt+1;
                
                vty_output(" network %s\n", tmp); 
            } 
        } 
        
        if(strchr(bgp6_config, ';') != NULL)
        {   
            ip = bgp6_config;  
            while((ip != NULL) && (strlen(ip) > 0))
            {  
                pt = strchr(ip, ';');
                memset(tmp, '\0', sizeof(tmp));
                memcpy(tmp, ip, pt-ip);
                ip = pt+1;
                
                vty_output(" network %s\n", tmp); 
            } 
        } 
        
        redistribute = atoi(rebute);
        if(redistribute & 0x01)
            vty_output(" redistribute static\n"); 
        if(redistribute & 0x02)
            vty_output(" redistribute rip\n");  
        if(redistribute & 0x04)
            vty_output(" redistribute ospf\n");  
        if(redistribute & 0x08)
            vty_output(" redistribute connected\n");   
            
        free(bgp_as);  
        free(bgp_remote); 
        free(bgp_network); 
        free(rebute);    
        free(bgp6_remote);
        free(bgp6_config);
        free(routerid);
    }
    
    free(bgp);
	vty_output("!\n");
	return;
}

static void cli_show_isis()
{
    char *isis = nvram_safe_get("isis_enable");
    int vid, id, type, net[32], isisd;
    char *pt, *p1, *ip, *p3, *p, *p4,tmp[64];
    char *config, *isis_config = nvram_safe_get("isis_config");
    
    if(*isis == '1')
    {  
        if(strlen(isis_config) > 0)
        {    
            config = isis_config;  
            while((*config != NULL) && (strlen(config) > 0))
            {  
                p3 = strchr(config, ';');
                memset(tmp, '\0', sizeof(tmp));
                memcpy(tmp, config, p3-config);
                
                id = atoi(tmp);
                p1 = strchr(tmp, ':')+1; 
                pt = strrchr(tmp, ':');
                type = atoi(pt+1);
                memset(net, '\0', sizeof(net));
                memcpy(net, p1, pt-p1);
                
                vty_output("router isis %d\n", id);
                vty_output(" net %s\n", net);
                if(0 == type)
                    vty_output(" is-type level-1\n");
                else if(1 == type)
                    vty_output(" is-type level-2\n");
                else
                    vty_output(" is-type level-1-2\n");
    
                config = p3+1;
            }  
        }
    }
    
    free(isis);
    free(isis_config);
	vty_output("!\n");
	return;
}

static void cli_show_running_mroute()
{    
    char *ipmc_enable = nvram_safe_get("ipmc_enable"); 
    char *ipmc_type = nvram_safe_get("ipmc_type");
    
    if(*ipmc_enable == '1')
    {     
	    vty_output("ip multicast-routing\n");
	    
	    if((strlen(ipmc_type) == 0) || (*ipmc_type == '0'))
	    {
	        char *ip, *p1, *p2, line[256], ipaddr[3][32];
            char *pimsm_pri = nvram_safe_get("pimsm_pri");
            char *pimsm_rpc = nvram_safe_get("pimsm_rpc"); 
            char *pimsm_rp = nvram_safe_get("pimsm_rp");
               
	        vty_output("!\nrouter pim-sm\n"); 
	        
	        if(atoi(pimsm_pri) != 0)
                vty_output(" ip pim-sm bsr-candidate priority %s\n", pimsm_pri);   
                
	        if(atoi(pimsm_rpc) != 0)
	        {    
	            p1 = strchr(pimsm_rpc, ':')+1;
                vty_output(" ip pim-sm rp-candidate time %d priority %d\n", atoi(pimsm_rpc), atoi(p1)); 
            }    
            
            ip = pimsm_rp;
		    while(strlen(ip) > 0)
		    {
		        memset(line, '\0', sizeof(line));
		        memset(ipaddr, '\0', sizeof(ipaddr));
		        p1 = strchr(ip, ';');
		        memcpy(line, ip, p1-ip);
		        
		        sscanf(line, "%[^:]:%[^:]:%[^:]", ipaddr[0], ipaddr[1], ipaddr[2]);

		        if((!strcmp("224.0.0.0", ipaddr[1])) && (!strcmp("240.0.0.0", ipaddr[2])))
		            vty_output(" ip pim-sm rp-address %s\n", ipaddr[0]);
		        else    
                    vty_output(" ip pim-sm rp-address %s %s %s\n", ipaddr[0], ipaddr[1], ipaddr[2]);

		        
		        ip = p1+1;
		    } 
            
            free(pimsm_pri);   
            free(pimsm_rpc);    
            free(pimsm_rp); 
	    }     
	    else
	        vty_output("!\nrouter pim-dm\n");  
    }
 
    free(ipmc_enable); 
    free(ipmc_type);
	vty_output("!\n");
	return;
}  

static void cli_show_static_mroute()
{    
    char line[128], intf[8], sip[16], gip[16];
    char *ipmc = nvram_safe_get("ipmc_slist"); 
    char *buf, *p1, *p2, *ipmc_enable = nvram_safe_get("ipmc_enable"); 
    
    if(*ipmc_enable == '1')
    { 
        p1 = ipmc;
        while((p1 != NULL) && (strlen(p1) > 0))
        {   
            memset(line, '\0', sizeof(line));
            memset(intf, '\0', sizeof(intf));
            memset(sip, '\0', sizeof(sip));
            memset(gip, '\0', sizeof(gip));
            
            p2 = strchr(p1, ';'); 
            memcpy(line, p1, p2-p1);
            p1 = p2+1;
            
            sscanf(line, "%[^,],%[^,],%s", intf, gip, sip); 
            vty_output(" ip mroute %s %s interface vlan %s\n", sip, gip, intf); 
        }
    }
 
    free(ipmc_enable); 
    free(ipmc); 
	vty_output("!\n");
	return;
}  
 
static void cli_show_igmp()
{
    int i, igmp_number = 0;
    IPMC_ENTRY  igmp_config[VLAN_MAX_CNT]; 
    char *igmp = nvram_safe_get("igmp_config");

    igmp_number = bcm_get_ipmc_number(igmp); 
    memset(igmp_config, '\0', sizeof(igmp_config));
    bcm_get_ipmc_entry(igmp, igmp_config); 
    free(igmp);
    
    for(i = 0; i < igmp_number; i++)
    {  
		vty_output("interface vlan %d\n", igmp_config[i].vlanid);
		vty_output(" ip igmp\n");
		vty_output(" ip igmp version %d\n", igmp_config[i].version);
		vty_output(" ip igmp query-interval %d\n", igmp_config[i].query);
		vty_output(" ip igmp query-max-response-time %d\n", igmp_config[i].timeout);
	    vty_output("!\n");
    }  
    
	vty_output("!\n");
	return;
}   

static void cli_show_vrrp()
{
    char line[128], list[8][64], intf[32];
    char *p1, *vrrp, * vrrp_list = nvram_safe_get("vrrp_list"); 
    
    //vrrp_list=1,22,192.168.10.254,100,0,1,1,0;
    vrrp = vrrp_list;
    while((*vrrp != NULL) && (strlen(vrrp) > 0))
    {   
        memset(line, '\0', sizeof(line));
        memset(list, '\0', sizeof(list));
        memset(intf, '\0', sizeof(intf));
        
        p1 = strchr(vrrp, ';'); 
        memcpy(line, vrrp, p1-vrrp);
        
        sscanf(line,"%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,]", 
            list[0],list[1],list[2],list[3],list[4],list[5],list[6],list[7]); 

		vty_output("interface vlan %s\n", list[0]);
		vty_output(" vrrp %s associate %s\n", list[1], list[2]);
		vty_output(" vrrp %s timer %s\n", list[1], list[5]);
		vty_output(" vrrp %s priority %s\n", list[1], list[3]);
		if(list[4][0] == '1')
		    vty_output(" vrrp %s preempt\n", list[1]);
		
		if((list[6][0] != '0') && (strlen(list[7]) > 4))
		    vty_output(" vrrp %s authentication %s\n", list[1], list[7]);
	    vty_output("!\n");
        vrrp = p1+1;       
    } 

    free(vrrp_list);
	vty_output("!\n");
	return;
}   

static void cli_show_dhcp_config()
{
	uint32 netmask;
    struct in_addr addr;
	int i, j, intfno = 0, netid, lease_time;
	char *p1, *p2, *p3, *pt, *dhcpd, *l3_dhcp, line[256], server[18], subnet[18],name[32];

    //dhcp_pool1=192.168.10.254/24,192.168.10.254,192.168.10.100-192.168.10.150,86400,192.168.1.1,
   for(j=1; j<32; j++)
   {
        memset(name, '\0', sizeof(name));
        sprintf(name, "dhcp_pool%d", j);
        
        dhcpd = l3_dhcp = nvram_safe_get(name);  
        if(strlen(dhcpd) > 17)
        {         
//            vty_output(" name %s=%s\n", name, dhcpd);   
            vty_output("ip dhcp pool %d\n", j);
         
            //gateway/subnet 192.168.19.2/24
            memset(line, '\0', sizeof(line)); 
            p2 = strchr(dhcpd, ',');
            pt = strchr(dhcpd, '/');
            netid = atoi(pt+1);
            memset(server, '\0', 18);
            memcpy(server, dhcpd, pt-dhcpd);  
            netmask = 0x00;
            for(i = 0; i < 32; i++)
            {
                if(i < netid)
                    netmask |= 1<<(31-i); 
            }
            memset(subnet, '\0', 18);
        	addr.s_addr = htonl(netmask);
            strcpy(subnet, inet_ntoa(addr));
            vty_output(" network %s %s\n", server, subnet);
            
            //default-router
            p3 = strchr(p2+1, ',');;
            memset(line, '\0', sizeof(line)); 
            memcpy(line, p2+1, p3-p2-1);
            vty_output(" default-router %s\n", line);
        
            //start ip
            p1 = p3+1;
            memset(line, '\0', sizeof(line));
            p2 = strchr(p1, '-');
            memcpy(line, p1, p2-p1);
            vty_output(" rang %s ", line);
            
            //end ip
            p1 = p2+1;
            memset(line, '\0', sizeof(line));
            p2 = strchr(p1, ',');
            memcpy(line, p1, p2-p1);
            vty_output(" %s\n", line);

            //lease time 
            p1 = p2+1;
            lease_time = atoi(p1);

            if (lease_time == 0) 
                lease_time = 86400; 
   
            memset(line, '\0', sizeof(line));  
            if(31622400 == lease_time) 
                vty_output(" lease_time infinite\n");
            else            
                vty_output(" lease_time %d %d %d %d\n", lease_time/86400, (lease_time%86400)/3600, (lease_time%3600)/60, lease_time%60); 
            
            //dns 
            p1 = strchr(p1, ',') + 1; 
            memset(line, '\0', sizeof(line));  
            p2 = strchr(p1, ',');
            memcpy(line, p1, p2-p1);
            pt = strchr(line, '/');
            if(NULL != pt)
                *pt = ' '; 
            vty_output(" dns-server %s\n", line);
            
            vty_output("!\n");
        } 
        free(l3_dhcp);
    }
    
    return;
}
    
static void cli_show_ip_config()
{
	cli_show_dhcp_config();
    cli_show_static_route();  
    cli_show_bfd(); 
    cli_show_rip(); 
    cli_show_ospf();  
    cli_show_bgp();   
    cli_show_isis(); 
    
    cli_show_static_mroute();  
	cli_show_igmp();
	cli_show_vrrp();

	vty_output("!\n");
	return;
}

static void cli_show_running_http_server()
{
	char *http_enable = nvram_safe_get("http_enable");

	if(strlen(http_enable) == 0)
		return;
		
	if(*http_enable == '1')
		vty_output("ip http server\n");
	
	free(http_enable);
	vty_output("!\n");	
}

static void cli_show_mstp()
{
	char *mstp_fwd_delay = nvram_safe_get("mstp_fwd_delay");
	char *mstp_hello_time = nvram_safe_get("mstp_hello_time");
	char *mstp_max_age = nvram_safe_get("mstp_max_age");
	char *mstp_max_hops = nvram_safe_get("mstp_max_hops");
	char *mstp_fwd_delay_def = nvram_safe_get_def("mstp_fwd_delay");
	char *mstp_hello_time_def = nvram_safe_get_def("mstp_hello_time");
	char *mstp_max_age_def = nvram_safe_get_def("mstp_max_age");
	char *mstp_max_hops_def = nvram_safe_get_def("mstp_max_hops");
	if(0 != strcmp(mstp_fwd_delay, mstp_fwd_delay_def)) {
		vty_output("spanning-tree mst forward-time %s\n", mstp_fwd_delay);
	}
	if(0 != strcmp(mstp_hello_time, mstp_hello_time_def)) {
		vty_output("spanning-tree mst hello-time %s\n", mstp_hello_time);
	}
	if(0 != strcmp(mstp_max_age, mstp_max_age_def)) {
		vty_output("spanning-tree mst max-age %s\n", mstp_max_age);
	}
	if(0 != strcmp(mstp_max_hops, mstp_max_hops_def)) {
		vty_output("spanning-tree mst max-hops %s\n", mstp_max_hops);
	}
	free(mstp_fwd_delay);
	free(mstp_hello_time);
	free(mstp_max_age);
	free(mstp_max_hops);
	free(mstp_fwd_delay_def);
	free(mstp_hello_time_def);
	free(mstp_max_age_def);
	free(mstp_max_hops_def);
	char *mstp_instance_priority = nvram_safe_get("mstp_instance_priority");
	int mstid = 0, prio;
	char *entry;
	char *p_str = mstp_instance_priority;
	while(p_str && *p_str) {
		entry = strsep(&p_str, ";");
		prio = atoi(entry);
		if (prio != 32768) {
			vty_output("spanning-tree mst %d priority %d\n", mstid, prio);
		}
		mstid++;
	}
	free(mstp_instance_priority);

	char *mstp_name = nvram_safe_get("mstp_name");
	char *mstp_revision = nvram_safe_get("mstp_revision");
	char *vlan2msti = nvram_safe_get("mstp_instance_vlan");
	char *mstp_name_def = nvram_safe_get_def("mstp_name");
	char *mstp_revision_def = nvram_safe_get_def("mstp_revision");
	char *vlan2msti_def = nvram_safe_get_def("mstp_instance_vlan");

	if ((0 != strcmp(mstp_name, mstp_name_def)) || (0 != strcmp(mstp_revision, mstp_revision_def))
		|| (0 != strcmp(vlan2msti, vlan2msti_def))) {
		vty_output("spanning-tree mst configuration\n");
	}
	
	if(0 != strcmp(mstp_name, mstp_name_def)) {
		vty_output("name %s\n", mstp_name);
	}
	if(0 != strcmp(mstp_revision, mstp_revision_def)) {
		vty_output("revision %s\n", mstp_revision);
	}
	
	char *p, *p1, *p2;
	if (0 != strcmp(vlan2msti, vlan2msti_def)) {
		p = vlan2msti;
		while (p && *p) {
			p1 = strsep(&p, ";");
			p2 = strchr(p1, ':') + 1;
			vty_output("instance %d vlan %s\n", atoi(p1), p2);
		}
	}

	free(vlan2msti);
	free(vlan2msti_def);
	free(mstp_name);
	free(mstp_revision);
	free(mstp_name_def);
	free(mstp_revision_def);
	
	vty_output("!\n");
}


static void cli_show_running_mstp()
{
	char *mstp_fwd_delay = nvram_safe_get("mstp_fwd_delay");
	char *mstp_hello_time = nvram_safe_get("mstp_hello_time");
	char *mstp_max_age = nvram_safe_get("mstp_max_age");
	char *mstp_max_hops = nvram_safe_get("mstp_max_hops");
	char *mstp_fwd_delay_def = nvram_safe_get_def("mstp_fwd_delay");
	char *mstp_hello_time_def = nvram_safe_get_def("mstp_hello_time");
	char *mstp_max_age_def = nvram_safe_get_def("mstp_max_age");
	char *mstp_max_hops_def = nvram_safe_get_def("mstp_max_hops");
	if(0 != strcmp(mstp_fwd_delay, mstp_fwd_delay_def)) {
		vty_output(" spanning-tree mst forward-time %s\n", mstp_fwd_delay);
	}
	if(0 != strcmp(mstp_hello_time, mstp_hello_time_def)) {
		vty_output(" spanning-tree mst hello-time %s\n", mstp_hello_time);
	}
	if(0 != strcmp(mstp_max_age, mstp_max_age_def)) {
		vty_output(" spanning-tree mst max-age %s\n", mstp_max_age);
	}
	if(0 != strcmp(mstp_max_hops, mstp_max_hops_def)) {
		vty_output(" spanning-tree mst max-hops %s\n", mstp_max_hops);
	}
	free(mstp_fwd_delay);
	free(mstp_hello_time);
	free(mstp_max_age);
	free(mstp_max_hops);
	free(mstp_fwd_delay_def);
	free(mstp_hello_time_def);
	free(mstp_max_age_def);
	free(mstp_max_hops_def);
	char *mstp_instance_priority = nvram_safe_get("mstp_instance_priority");
	int mstid = 0, prio;
	char *entry;
	char *p_str = mstp_instance_priority;
	while(p_str && *p_str) {
		entry = strsep(&p_str, ";");
		prio = atoi(entry);
		if (prio != 32768) {
			vty_output(" spanning-tree mst %d priority %d\n", mstid, prio);
		} 
		mstid++;
	}
	free(mstp_instance_priority);

	char *mstp_name = nvram_safe_get("mstp_name");
	char *mstp_revision = nvram_safe_get("mstp_revision");
	char *vlan2msti = nvram_safe_get("mstp_instance_vlan");
	char *mstp_name_def = nvram_safe_get_def("mstp_name");
	char *mstp_revision_def = nvram_safe_get_def("mstp_revision");
	char *vlan2msti_def = nvram_safe_get_def("mstp_instance_vlan");

	if ((0 != strcmp(mstp_name, mstp_name_def)) || (0 != strcmp(mstp_revision, mstp_revision_def))
		|| (0 != strcmp(vlan2msti, vlan2msti_def))) {
		vty_output("!\nspanning-tree mst configuration\n");
	}
	
	if(0 != strcmp(mstp_name, mstp_name_def)) {
		vty_output(" name %s\n", mstp_name);
	}
	if(0 != strcmp(mstp_revision, mstp_revision_def)) {
		vty_output(" revision %s\n", mstp_revision);
	}
	
	char *p, *p1, *p2;
	if (0 != strcmp(vlan2msti, vlan2msti_def)) {
		p = vlan2msti;
		while (p && *p) {
			p1 = strsep(&p, ";");
			p2 = strchr(p1, ':') + 1;
			if(atoi(p1) != 0)
			    vty_output(" instance %d vlan %s\n", atoi(p1), p2);
		}
	}

	free(vlan2msti);
	free(vlan2msti_def);
	free(mstp_name);
	free(mstp_revision);
	free(mstp_name_def);
	free(mstp_revision_def);
	
	vty_output("!\n");
}

void func_show_running(int type, int portid)
 {   
	vty_output("Building configuration...\n");
	vty_output("\n"); 
	vty_output("\n");
	vty_output("\n");
	vty_output("Current Configuration:\n");
	/* create current configuration file */
	switch(type) {
		case CLI_SHOW_ALL:
			vty_output("!\n");
			vty_output("!version %s\n", FVERSION);
			vty_output("!\n");
			cli_show_running_hostname();	
			cli_show_running_username();

#ifdef CLI_AAA_MODULE			
			/* aaa */
			cli_show_aaa();
#endif

			/* acl */
			func_show_access_list();
			cli_show_mac_blackhole();
			cli_show_mac_age();
/* 			if(NULL == (fp=fopen(SHOW_RUNNING_ACL, "w")))
 * 				return;
 * 			fclose(fp);
 * 			cli_show_running_mac_acl();
 * 			cli_show_running_ip_std_acl();
 * 			cli_show_running_ip_ext_acl();
 * 			SYSTEM("cat %s >> %s", SHOW_RUNNING_ACL, SHOW_RUNNING_FILE);
 */

			/* policy_map */
			cli_show_running_policy();
			//SYSTEM("cat %s >> %s", SHOW_RUNNING_POLICY, SHOW_RUNNING_FILE);
			cli_show_running_global();
			cli_show_running_mroute();
			cli_show_running_qinq();	
//			cli_show_err_disable();	
			cli_show_err_recover();
			cli_show_running_qos();
			cli_show_running_scheduler();
			cli_show_running_ntp_querytime();
			cli_show_running_login();
			cli_show_running_snmp_server();
			cli_show_running_arp();
			cli_show_running_lldp();
			cli_show_running_garp();
			cli_show_running_logging();
			cli_show_running_ip_access();
			cli_show_running_mirror();		
			cli_show_running_mac();
			cli_show_running_ipv6_route();/*wuchunli 2012-3-13 10:14:21*/
//			cli_show_running_schedule_wrr();		
			cli_show_running_interface_aggregator();
			cli_show_running_interface(0);
			cli_show_running_mstp();
			//cli_show_running_interface_vlan();
			cli_show_running_interface_ip();
			cli_show_running_interface_ipv6();

			cli_show_running_radius();	
			cli_show_running_interface_loop();	
			cli_show_running_vlan(0);
			cli_show_ip_config();

			cli_show_running_http_server();
//			cli_show_running_line_vty();	/*wei.zhang 2012-4-20*/
			break;

		case CLI_SHOW_INTER:
			vty_output("!\n");
			vty_output("!\n");
			vty_output("!\n");
			cli_show_running_interface(portid);
			break;
			
		default:
			break;
	}
	
    vty_output("!\n");
	return;
 }
 
static void cli_show_running_interface_loop()
{
	int vlanid; 
	char lanip[64], intf[128], ipaddr[64];
	char *p, *p1, *ip, *lo_ip = nvram_safe_get("lo_ip");

    ip = lo_ip;
    while((*ip != NULL) && (strlen(ip) > 0))
    {   
        memset(intf, '\0', sizeof(intf));
        memset(lanip, '\0', sizeof(lanip));
        memset(ipaddr, '\0', sizeof(ipaddr));
      
        p1 = strchr(ip, ';'); 
        memcpy(intf, ip, p1-ip);

        sscanf(intf, "%d,%s", &vlanid, lanip);
  
        if((p = strchr(lanip, '/')) == NULL)
            strcpy(ipaddr, lanip);
        else
            memcpy(ipaddr, lanip, p-lanip);   
   
		vty_output("interface loopback %d %s %s\n", vlanid, ipaddr, get_netmask_str(lanip));
        ip = p1+1;  
    } 
	vty_output("!\n");
    
    free(lo_ip);
	return;
} 

static void cli_show_running_interface_vlan_n(int vlan_id)
{
	int vlanid, iptype; 
	char *p, *p1, *p2, *ip, lanip[64], intf[128], key[8], ipaddr[64], *l3_ip = nvram_safe_get("lan_ipaddr");
	char *p3, *p4, ipv4[32], ipv6[64];

    vty_output("interface vlan %d\n", vlan_id);

    ip = l3_ip;
	
	show_fun("l3_ip:%s \n",l3_ip);
    while((*ip != NULL) && (strlen(ip) > 0))
    {   
        memset(intf, '\0', sizeof(intf));
        memset(lanip, '\0', sizeof(lanip));
        p1 = strchr(ip, ';'); 
		
		if(p1 == NULL)
			break;
		
        memcpy(intf, ip, p1-ip);
        
        memset(ipv4, '\0', sizeof(ipv4));
        memset(ipv6, '\0', sizeof(ipv6));
        
        cli_interface_info_get(intf, &vlanid, &iptype, ipv4, ipv6);
 
        if(vlan_id == vlanid)
        {    
            if(0 == (iptype%2))
            {
                if(strlen(ipv4) > 0)
                {    
                    memset(ipaddr, '\0', sizeof(ipaddr));
                    if((p = strchr(ipv4, '/')) == NULL)
                        strcpy(ipaddr, ipv4);
                    else
                        memcpy(ipaddr, ipv4, p-ipv4);   
           
        			vty_output(" ip address %s %s\n", ipaddr, get_netmask_str(ipv4));
        		}
        		
                if(strlen(ipv6) > 0)
                {    
        			vty_output(" ipv6 address %s\n", ipv6);
        		}
    			
    		}
    		else if(1 == iptype)
    		{    
    			vty_output(" ip address dhcp\n");  
            }  
        }  
        ip = p1+1;  
    } 
    free(l3_ip);

	return;
}	
/*----------------------------------------func_show_spanning-------------------------*/
static void cli_show_spanning_tree(FILE *fp)
{
	FILE *fp_status;
	char *p, line[512];
    char bri_prio[5],bri_add[13];
    char root_prio[32],root_add[32];
    int root_cost = 0, root_port = 0, root_max_age = 0, root_hello_time = 0, root_fwd_delay = 0;
    int index, portid, port_prio, port_cost;
    char *hello_time, *fwd_delay, *max_age;
    int tmp_root_pri, tmp_bri_pri;
  	char cli_priority[256], cli_cost[512], cli_link[PNUM+32], cli_trunk[PNUM+32], cli_p2p[PNUM+32], cli_edge[PNUM+32];
  	char cli_neigb[PNUM+32], cli_role[PNUM+32], cli_state[PNUM+32], cli_root_guard[PNUM+32];
    char *cli_priority_tmp, *cli_cost_tmp;
    char role_tmp[32], state_tmp[32], type_tmp[32], prio_tmp[32];
    char trunk_group[CLI_TRUNK_GROUP];
	char *rstp_version;

	memset(root_prio, '\0', sizeof(root_prio));
	memset(bri_prio, '\0', sizeof(bri_prio));	
	memset(bri_add, '\0', sizeof(bri_add));
	memset(root_add, '\0', sizeof(root_add));	

	memset(cli_priority, '\0', sizeof(cli_priority));
	memset(cli_cost, '\0', sizeof(cli_cost));
	memset(cli_link, '\0', sizeof(cli_link));
	memset(cli_trunk, '\0', sizeof(cli_trunk));
	memset(cli_p2p, '\0', sizeof(cli_p2p));
	memset(cli_edge, '\0', sizeof(cli_edge));
	memset(cli_neigb, '\0', sizeof(cli_neigb));
	memset(cli_role, '\0', sizeof(cli_role));
	memset(cli_state, '\0', sizeof(cli_state));
	memset(cli_root_guard, '\0', sizeof(cli_root_guard));

	memset(trunk_group, '0', sizeof(trunk_group));

	system("/usr/bin/killall -SIGUSR1 rstp > /dev/null 2>&1");
	usleep(500000);
	if(access("/tmp/rstp_status",F_OK) == 0)
    {
    	fp_status=fopen("/tmp/rstp_status","r");
		if(fp_status != NULL)
		{
			fseek(fp_status,0,SEEK_SET); 
    		memset(&line, '\0', 512);

    		while(fgets(line, 512, fp_status) != NULL)
    		{
    			p = strchr(line, ':');				
				if(NULL == p)
					continue;
			    if (strstr(line,"BridgeId"))
				{
				    p=p+2;
				    memcpy(bri_prio,p,4);
				    p=p+5;
				    memcpy(bri_add,p,12);
				}
				else if (strstr(line,"RootId"))
				{
				    p=p+2;
				    memcpy(root_prio,p,4);
				    p=p+5;
				    memcpy(root_add,p,12);
				}
	            else if(strstr(line,"RootPathCost"))
	            {
	                p=p+2;
	                root_cost = atoi(p);
	            }
	            else if(strstr(line,"RootPort"))
	            {
	                p=p+2;
	                root_port = atoi(p);
	            }
				else if(strstr(line,"RootMaxAge"))
	            {
	                p=p+2;
	                root_max_age = atoi(p);
	            }
				else if(strstr(line,"RootHelloTime"))
	            {
	                p=p+2;
	                root_hello_time = atoi(p);
	            }
				else if(strstr(line,"RootForwardDelay"))
	            {
	                p=p+2;
	                root_fwd_delay = atoi(p);
	            }
	            /* port config */
	            else if(strstr(line,"PortPriority"))
	            {
	                p=p+2;
	                strcpy(cli_priority, p);
	            }
	            else if(strstr(line,"PortCost"))
	            {
	                p=p+2;
	                strcpy(cli_cost, p);
	            }
	            else if(strstr(line,"Portlink"))
	            {
	                p=p+2;
	                strcpy(cli_link, p);
	            }
	            else if(strstr(line,"Porttrunk"))
	            {
	                p=p+2;
	                strcpy(cli_trunk, p);
	            }
	            else if(strstr(line,"PortP2p"))
	            {
	                p=p+2;
	                strcpy(cli_p2p, p);
	            }
	            else if(strstr(line,"PortEdge"))
	            {
	                p=p+2;
	                strcpy(cli_edge, p);
	            }
	            else if(strstr(line,"PortNeigb"))
	            {
	                p=p+2;
	                strcpy(cli_neigb, p);
	            }
	            else if(strstr(line,"PortRole"))
	            {
	                p=p+2;
	                strcpy(cli_role, p);
	            }
	            else if(strstr(line,"PortState"))
	            {
	                p=p+2;
	                strcpy(cli_state, p);
	            }
				else if(strstr(line,"PortRootGuard"))
	            {
	                p=p+2;
	                strcpy(cli_root_guard, p);
	            }
	            /* end */
    		}
    		
    		sscanf(root_prio,"%x",&tmp_root_pri);
    		sscanf(bri_prio,"%x",&tmp_bri_pri);
    		
    		hello_time = nvram_safe_get("rstp_hello_time");
    	    fwd_delay = nvram_safe_get("rstp_fwd_delay");
    	    max_age = nvram_safe_get("rstp_max_age");
    	    rstp_version = nvram_safe_get("rstp_version");
			
			fprintf(fp, "\n");
			fprintf(fp, "Spanning tree enabled protocol %s\n", ((strlen(rstp_version) == 1)&&(*rstp_version == '1'))?"STP":"RSTP");
			fprintf(fp, "\n");
			fprintf(fp, "%s\n", ((strlen(rstp_version) == 1)&&(*rstp_version == '1'))?"STP":"RSTP");
			
			if(0 == root_port) {
				fprintf(fp, "  %-15s%-20s%-10d\n","Root ID:","Priority",tmp_bri_pri);
			    fprintf(fp, "  %-15s%-20s%-c%-c%-c%-c.%-c%-c%-c%-c.%-c%-c%-c%-c\n"," ","Address",bri_add[0],bri_add[1],bri_add[2],bri_add[3],bri_add[4],bri_add[5],bri_add[6],bri_add[7],bri_add[8],bri_add[9],bri_add[10],bri_add[11]);
				fprintf(fp, "  %-15s%-s\n", " ", "This bridge is the root");
				fprintf(fp, "  %-15s%-20s%-s/%-s/%-s(s)\n\n"," ","Hello/Max/FwdDly",hello_time,max_age,fwd_delay);
			} else {
	    	    fprintf(fp, "  %-15s%-20s%-10d\n","Root Id:","Priority",tmp_root_pri);
			    fprintf(fp, "  %-15s%-20s%-c%-c%-c%-c.%-c%-c%-c%-c.%-c%-c%-c%-c\n"," ","Address",root_add[0],root_add[1],root_add[2],root_add[3],root_add[4],root_add[5],root_add[6],root_add[7],root_add[8],root_add[9],root_add[10],root_add[11]);
				fprintf(fp, "  %-15s%-20s%-10d\n"," ","Cost",root_cost);
#if (XPORT==0)
				fprintf(fp, "  %-15s%-20s%s0/%d\n"," ","Port",(root_port<=FNUM)?"FastEthernet":"GigaEthernet",(root_port<=FNUM)?root_port:(root_port-FNUM));
#endif
#if (XPORT==1)
				fprintf(fp, "  %-15s%-20s%s0/%d\n"," ","Port",(root_port<=GNUM)?"GigaEthernet":"TenGigaEthernet",(root_port<=GNUM)?root_port:(root_port-GNUM));
#endif
				fprintf(fp, "  %-15s%-20s%-d/%-d/%-d(s)\n\n"," ","Hello/Max/FwdDly",root_hello_time,root_max_age,root_fwd_delay);
			}
    	    fprintf(fp, "  %-15s%-20s%-10d\n","Bridge Id:","Priority",tmp_bri_pri);
		    fprintf(fp, "  %-15s%-20s%-c%-c%-c%-c.%-c%-c%-c%-c.%-c%-c%-c%-c\n"," ","Address",bri_add[0],bri_add[1],bri_add[2],bri_add[3],bri_add[4],bri_add[5],bri_add[6],bri_add[7],bri_add[8],bri_add[9],bri_add[10],bri_add[11]);
			fprintf(fp, "  %-15s%-20s%-s/%-s/%-s(s)\n"," ","Hello/Max/FwdDly",hello_time,max_age,fwd_delay);

			fprintf(fp, "\n");

			fprintf(fp, "%-17s%-5s%-4s%-10s%-9s%-s\n", 
				"Interface", "Role", "Sts", "Cost", "Prio.Nbr", "Type");
			fprintf(fp, "%-17s%-5s%-4s%-10s%-9s%-s\n", 
				"----------------", "----", "---", "---------", "--------", "--------------------------------");

			cli_priority_tmp = cli_priority;
			cli_cost_tmp = cli_cost;
			for(portid = 1; portid <= PNUM; portid++) {
				port_prio = atoi(cli_priority_tmp);
				cli_priority_tmp = strchr(cli_priority_tmp, ',');
				cli_priority_tmp++;

				port_cost = atoi(cli_cost_tmp);
				cli_cost_tmp = strchr(cli_cost_tmp, ',');
				cli_cost_tmp++;

				memset(role_tmp, '\0', sizeof(role_tmp));
				memset(state_tmp, '\0', sizeof(state_tmp));
				memset(type_tmp, '\0', sizeof(type_tmp));
				memset(prio_tmp, '\0', sizeof(prio_tmp));

			    switch (cli_role[portid-1]) {
					case 'A': sprintf(role_tmp, "Altn"); break;
					case 'B': sprintf(role_tmp, "Back"); break;
					case 'R': sprintf(role_tmp, "Root"); break;
					case 'D': sprintf(role_tmp, "Desg"); break;
					case '-': sprintf(role_tmp, "NStp"); break;
					default:  sprintf(role_tmp, "Desg"); break;
			    }
			    
			    switch (cli_state[portid-1]) {
					case '0':  sprintf(state_tmp, "DIB");break;
					case '1':  sprintf(state_tmp, "BLK");break;
					case '2':  sprintf(state_tmp, "LRN");break;
					case '3':  sprintf(state_tmp, "FWD");break;
					case '4':  sprintf(state_tmp, "UKN");break;
					default:   sprintf(state_tmp, "DIB");break;
				}

				if(cli_p2p[portid-1] == '1')
					sprintf(type_tmp, "P2p");
				else if(cli_p2p[portid-1] == '0')
					sprintf(type_tmp, "Shr");

				if(cli_edge[portid-1] == '1')
					strcat(type_tmp, " Edge");

				if (cli_root_guard[portid-1] == '1') {
					strcat(type_tmp, " *Root_Inc");
				}
				if(cli_link[portid-1] == '1') {
					if(cli_trunk[portid-1] != '0') {
						for(index = 0; index < CLI_TRUNK_GROUP; index++) {
							if(cli_trunk[portid-1] == trunk_group[index]) {
								break;
							} else if(trunk_group[index] == '0'){
								trunk_group[index] = cli_trunk[portid-1];
								sprintf(prio_tmp, "%d.%d", port_prio, 192 + cli_trunk[portid-1] - '0');
								fprintf(fp, "po%-15c%-5s%-4s%-10d%-9s%-s\n", cli_trunk[portid-1], role_tmp, state_tmp,
									port_cost, prio_tmp, type_tmp);
								break;
							}
						}
					} else {
						sprintf(prio_tmp, "%d.%d", port_prio, portid);
#if (XPORT==0)						
						fprintf(fp, "%s0/%-14d%-5s%-4s%-10d%-9s%-s\n", (portid<=FNUM)?"F":"G", (portid<=FNUM)?portid:(portid-FNUM), role_tmp, state_tmp,
							port_cost, prio_tmp, type_tmp);
#endif
#if (XPORT==1)							
						fprintf(fp, "%s0/%-14d%-5s%-4s%-10d%-9s%-s\n", (portid<=GNUM)?"G":"T", (portid<=GNUM)?portid:(portid-GNUM), role_tmp, state_tmp,
							port_cost, prio_tmp, type_tmp);
#endif						
					}
				}
    		}
    	    free(hello_time); 
    	    free(fwd_delay); 
    	    free(max_age);
    	    free(rstp_version);

		    fclose(fp_status);
    	}
 	} 
    return;
}
void func_show_spanning()
{
	FILE * fp;
	char *rstp_enable = NULL;
	rstp_enable = nvram_safe_get("rstp_enable");
	char *mstp_enable = nvram_safe_get("mstp_enable");

    if('1'==*rstp_enable) 
      {
        fp = fopen(SHOW_SPANNING_TREE,"w+");
        if(fp == NULL)
           return;
        cli_show_spanning_tree(fp);
                
        fclose(fp);
        cli_read_config(SHOW_SPANNING_TREE);
     }
	else if('1' == *mstp_enable) 
	{
		SYSTEM("/usr/sbin/mstpctl showmstp >/dev/null 2>&1");
		usleep(100000);
		cli_read_config(SHOW_SPANNING_TREE);
	}
    else
	{
    vty_output("No spanning tree instances exist\n");
	}
    free(mstp_enable);
    free(rstp_enable);

}

void func_show_spanning_msti(struct users *u)
{
	char *mstp_enable = nvram_safe_get("mstp_enable");
	int mstid;
	cli_param_get_int(STATIC_PARAM, 0, &mstid, u);
	if ('1' == *mstp_enable) {
		SYSTEM("/usr/sbin/mstpctl showmsti %d 2>&1", mstid);
		check_file("/tmp/mstp_msti_state");
		cli_read_config(SHOW_MSTI);
	} else {
		vty_output("This switch is not in mst mode.\n");
	}

	free(mstp_enable);
}

/*-----------------------------------------func_show_startup----------------------*/
int  create_startup_config()
{

	int fd;
	char *ptr;

	extern char vty_path[];

	func_show_running(CLI_SHOW_ALL, 0);

	fd = open(vty_path, O_RDONLY);
	if (fd < 0) {
		perror("vty_path");
		return -1;
	}
	
	size_t len = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
	char *buf = calloc(1, len + 1);
	read(fd, buf, len);
	close(fd);

	fd = open(SHOW_STARTUP_FILE, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR |S_IWUSR);
	if (fd < 0) {
		perror("show startup");
		return -1;
	}

	ptr = strstr(buf, "Current");
	memcpy(ptr, "Startup", 7);

	write(fd, buf, len);
	close(fd);

	unlink(vty_path);
	free(buf);
	
	return 0;
}

int func_show_startup()
{   
	if (access(SHOW_STARTUP_FILE, F_OK))
	{
	    system("cp /tmp/nvram /tmp/nvram.bak");
	    nvram_load();
	    create_startup_config();
	    system("mv /tmp/nvram.bak /tmp/nvram");
	}
	     	
	if (!access(SHOW_STARTUP_FILE, F_OK)) 
	{
		FILE *fp = fopen(SHOW_STARTUP_FILE, "r+");
		char buf[256] = {'\0'};
		if (fp == NULL) {
			perror("open file");
			return -1;
		}

		while (fgets(buf, 255, fp)) {
			vty_output("%s", buf);
		}
		fclose(fp);
	}
	
	return 0;
}

/*-----------------------------------func_show_ssh---------------------------------*/
#ifdef CLI_AAA_MODULE
#define	MAX_VTY 	16

void func_show_ssh()
{
	struct aaa_line_vty_info *vty_info = get_aaa_line_vty_info();
	int i, j, max_line_id = 0, matched = 0;
	
	vty_output("%-4s%-22s%-13s%-13s\n","No","Remote Address","Remote Port", "Local Port");
	vty_output("%-4s%-22s%-13s%-13s\n","--","--------------","-----------", "----------");
	
	if (NULL == vty_info)
		return 0;
		
	for (i = 0; i < MAX_VTY; i++) {
		if ((max_line_id < vty_info[i].line_id) && (22 == vty_info[i].local_port))
			max_line_id = vty_info[i].line_id;
	}

	for (i = 0; i <= max_line_id; i++) {
		matched = 0;
		for (j = 0; j <= MAX_VTY; j++) {
			if ((i == vty_info[j].line_id) && (22 == vty_info[j].local_port)) {
				vty_output("%-4d%-22s%-13d%-13d\n", vty_info[j].line_id, 
				vty_info[j].remote_ip, vty_info[j].remote_port,
				vty_info[j].local_port);
				matched = 1;
			}
		}
/* 		if (0 == matched && max_line_id != 0)
 * 			vty_output("%-4d\n", i);
 */
	}
	free(vty_info);
	return 0;
}
/*-----------------------------------func_show_telnet---------------------------------*/
void func_show_telnet()
{
	struct aaa_line_vty_info *vty_info = get_aaa_line_vty_info();
	int i, j, max_line_id = 0, matched = 0;
	
	vty_output("%-4s%-22s%-13s%-13s\n","No","Remote Address","Remote Port", "Local Port");
	vty_output("%-4s%-22s%-13s%-13s\n","--","--------------","-----------", "----------");
	
	if (NULL == vty_info)
		return 0;
		
	for (i = 0; i < MAX_VTY; i++) {
		if ((max_line_id < vty_info[i].line_id) && (23 == vty_info[i].local_port))
			max_line_id = vty_info[i].line_id;
	}

	for (i = 0; i <= max_line_id; i++) {
		matched = 0;
		for (j = 0; j <= max_line_id; j++) {
			if ((i == vty_info[j].line_id) && (23 == vty_info[j].local_port)) {
				vty_output("%-4d%-22s%-13d%-13d\n", vty_info[j].line_id, 
				vty_info[j].remote_ip, vty_info[j].remote_port,
				vty_info[j].local_port);
				matched = 1;
			}
		}
/* 		if (0 == matched && max_line_id != 0)
 * 			vty_output("%-4d\n", i);
 */
	}
	free(vty_info);	

	return 0;
}
#endif

#define PATH_SVN_VERSION		"/usr/etc/svn_info"
static void get_svn_version(char *str_p)
{
	FILE *fp = NULL;
	
	fp = fopen(PATH_SVN_VERSION,"r");
	if(NULL == fp){
		*str_p = 0;	
		return ;
	}
	fread(str_p,32,32,fp);
	fclose(fp);
}


/*---------------------------------func_show_version-------------------------------------*/
void func_show_version()
{
	FILE *fp1;
	char *timezone = nvram_safe_get("time_zone");
	char buf[256]	= {0};
	char date[50] = {0};
	char *p1, *p;
	int uptime;
	/* add by gujiajie start 05/14/2012 */
	time_t now;
	struct tm *nowtime;
	struct timeval tv;
	struct timezone tz;
	char buftime[12] = {'\0'};
	char day[30] = {'\0'};
	char svn_ver[32] = {0};
	/* add by gujiajie end */

	//by liujh
	get_svn_version(svn_ver);
	svn_ver[sizeof(svn_ver) - 1] = '\0';
	vty_output("Svn Version:%s  \r",svn_ver);
	vty_output("Version Compile Time %s,%s\n",__TIME__,__DATE__);
	
	MAC_INFO sw_info;
	getSWInfo(&sw_info);

	vty_output("Base ethernet MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
			(unsigned char)(sw_info.mac>>40),(unsigned char)(sw_info.mac>>32),
					(unsigned char)(sw_info.mac>>24),(unsigned char)(sw_info.mac>>16),
						(unsigned char)(sw_info.mac>>8), (unsigned char)sw_info.mac);

	//modified by xuanyunchang 110907					
	memset(buf , 0 , sizeof(buf) );
	//memset(name , 0 , sizeof(name) );
	memset(date , 0 , sizeof(date) );  
	
	uptime = 0;
	if ((fp1 = fopen("/proc/uptime", "r")) != NULL) { 
		if (fgets(buf, 256, fp1) != NULL) {
			uptime = atoi(buf);
		}	
	    fclose(fp1);
	}
	nowtime = gmtime(&uptime);
	strftime(buftime, 12, "%T", nowtime);
	vty_output("Switch uptime total %s, ", buftime);

	/* add by gujiajie start 05/14/2012 */
	now = time(NULL);
	now += time_adjust(timezone)*60;  
	nowtime = gmtime(&now);
	gettimeofday(&tv, &tz);
	nowtime->tm_hour -= tz.tz_minuteswest/60;

	strftime(buftime, 12, "%T", nowtime);
	strftime(date, 30, "%a %b %d %Y", nowtime);

	vty_output("The current time %s %s %s\n", buftime, timezone, day);

	/* add by gujiajie end */

	free(timezone);

}
/*-------------------------------------func_show_vlan---------------------------------*/
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  cli_show_vlan_interface
 *  Description:  show vlan interface port
 * 		 Author:  gujiajie
 *		   Date:  05/24/2012
 * =====================================================================================
 */
static int cli_show_vlan_interface(struct users *u, int port_num)
{	
	memset(cur_port_conf, 0, sizeof(cli_port_conf)*PNUM);
	cli_nvram_conf_get(CLI_VLAN_PORT, (unsigned char *)&cur_port_conf);
	char mode[8];
		
	/* show vlan title  */
	vty_output("\n");
	vty_output("%-25s%-12s\n","Interface", "VLAN");
	vty_output("%-25s%-12s%-8s%-16s%-s\n", "Name", "Property", "PVID", "Vlan-allowed", "Vlan-untagged");
	vty_output("%-25s%-12s%-8s%-16s%-s\n", "------------------", "--------", "----", "------------", "-------------");		
	
	memset(mode, '\0', 8);
	if (cur_port_conf[port_num-1].mode == '1') 
		strcpy(mode, "access");
	else if (cur_port_conf[port_num-1].mode == '3')
		strcpy(mode, "trunk");

#if (XPORT==0)	 
	if(port_num <= FNUM) {
		vty_output("FastEthernet0/%-11d%-12s%-8d%-16s%s\n",port_num, mode, cur_port_conf[port_num-1].pvid, 
					cur_port_conf[port_num-1].allow, cur_port_conf[port_num-1].untag);
	} else {
		vty_output("GigaEthernet0/%-11d%-12s%-8d%-16s%s\n", (port_num-FNUM), mode, cur_port_conf[port_num-1].pvid, 
					cur_port_conf[port_num-1].allow, cur_port_conf[port_num-1].untag);
	}
#endif  
#if (XPORT==1)	 
	if(port_num <= GNUM) {
		vty_output("GigaEthernet0/%-11d%-12s%-8d%-16s%s\n",port_num, mode, cur_port_conf[port_num-1].pvid, 
					cur_port_conf[port_num-1].allow, cur_port_conf[port_num-1].untag);
	} else {
		vty_output("TenGigaEthernet0/%-11d%-12s%-8d%-16s%s\n", (port_num-GNUM), mode, cur_port_conf[port_num-1].pvid, 
					cur_port_conf[port_num-1].allow, cur_port_conf[port_num-1].untag);
	}
#endif          

	return 0;	
}

void func_show_vlan(int showvlanid)
{
    FILE *fp;
    uint64 fwd, untag;
    PORT_CONF_ENTRY port_conf[PNUM];
    char *vlan_fwd_config, buf[128], *p;
    int vlanid, forward[PNUM][4096], total[4096];
    int flag = 0, portid, i, k=0, j=0, number, count = 0, skfd;
	char *gvrp_vlan,*p0;

    //port vlan info
    vlan_port_get(port_conf);
    for(portid = 1; portid<=PNUM; portid++) 
	{
		if(1 == port_conf[portid-1].mode) //fwd = untag = vpid
		{
		    forward[portid-1][port_conf[portid-1].pvid] = total[port_conf[portid-1].pvid] = 1; 
		}
		else
		{
		    str2vlan(port_conf[portid-1].allow, forward[portid-1], total);
		}        
	}
    gvrp_vlan = cli_nvram_safe_get(CLI_ALL_ZERO,  "gvrp_vlan");
	p0 = gvrp_vlan;
	while(0 != p0)
	{  
		total[atoi(p0)] = 2;
		p0 = strchr(p0, ';');
		if(p0 != 0)
		{
		    p0++;
		}
	}	
	free(gvrp_vlan);
    unlink("/var/vlanshow");
	if((skfd = open(DEVICE_FILE_NAME, 0)) >= 0)
	{     
        bcm_get_all_vlan(skfd, 1, &count);
        close(skfd);
    }

	if(0 == showvlanid) 
	{
		/* show vlan title  */
		vty_output("%-5s%-8s%-33s%-33s\n","VLAN","Status","Name","Ports");
		vty_output("%-5s%-8s%-33s%-33s\n","----","-------","-------------------------------","-------------------------------");

        if ((fp = fopen("/var/vlanshow","r")) != NULL) 
        {
        	while(fgets(buf, 128, fp)!=NULL) 
        	{    
			    k = 0, j = 0;
			
        	    vlanid = atoi(buf);
    			p = strchr(buf, ',')+1;
    			input_num(p, 1, 8, &fwd);
    			fwd &= 0x1ffffffeULL;
    			p = strchr(p, ',')+1;
    			input_num(p, 1, 8, &untag);
    			untag &= 0x1ffffffeULL;
    			
    			if(1 == total[vlanid])
    			{
    				vty_output("%-5d%-8s%-33s", vlanid, "Static", "Default");
    			}
				else if(2 == total[vlanid])
				{
    				vty_output("%-5d%-8s%-33s", vlanid, "Dynamic", "GVRP");
				}
    			else
    			{
    				vty_output("%-5d%-8s%-33s", vlanid, "Dynamic", "");
    			}
    			    	
    			
    			for(portid = 1; portid<=PNUM; portid++) 
    			{
            		if(fwd & (0x01ULL << phy[portid]) ){
            		    if(4==k){
                		    vty_output("\n");
                		    vty_output("%-5s%-8s%-33s"," "," "," ");
                		    k=0;
                		    j=0;
            		    }
                        if(0==j){
#if (XPORT==0)                            
                        	/*betty modified for giga port*/
                        	if(portid <= FNUM)
                            	vty_output("F0/%-2d",portid);
                            else
                            	vty_output("G0/%-2d",portid-FNUM);
#endif                          
#if (XPORT==1)             
                        	if(portid <= GNUM)
                            	vty_output("G0/%-2d",portid);
                            else
                            	vty_output("T0/%-2d",portid-GNUM); 
#endif             	
                            k++;
                            j++;
                        }
                        else{
#if (XPORT==0)
                        	if(portid <= FNUM)
                            	vty_output(", F0/%-2d",portid);
    						else
    	                       	vty_output(", G0/%-2d",portid-FNUM);
#endif      	                      
#if (XPORT==1)           
                        	if(portid <= GNUM)
                            	vty_output(", G0/%-2d",portid);
    						else
    	                       	vty_output(", T0/%-2d",portid-GNUM);    
#endif             	    	
    						k=k+1;
    						j=j+1;
    					}
    				}
    			}	
			    vty_output("\n");
    	    }	
    	    fclose(fp);
    	}    
	}
	
	return;
}

void func_show_vlan_id(struct users *u)
{
    FILE *fp;
    uint64 fwd, untag;
	int showvlanid = 0;
    PORT_CONF_ENTRY port_conf[PNUM];
    char *vlan_fwd_config, buf[128], *p;
    int vlanid, forward[PNUM][4096], total[4096];
    int flag = 0, portid, i, k=0, j=0, number, count = 0, skfd;
    

	cli_param_get_int(DYNAMIC_PARAM,0,&showvlanid,u);
	
    //port vlan info
    vlan_port_get(port_conf);
    for(portid = 1; portid<=PNUM; portid++) 
	{
		if(1 == port_conf[portid-1].mode) //fwd = untag = vpid
		{
		    forward[portid-1][port_conf[portid-1].pvid] = total[port_conf[portid-1].pvid] = 1; 
		}
		else
		{
		    str2vlan(port_conf[portid-1].allow, forward[portid-1], total);
		}        
	}
    
    unlink("/var/vlanshow");
	if((skfd = open(DEVICE_FILE_NAME, 0)) >= 0)
	{     
        bcm_get_all_vlan(skfd, 1, &count);
        close(skfd);
    }

    if ((fp = fopen("/var/vlanshow","r")) != NULL) 
    {
    	while(fgets(buf, 128, fp)!=NULL) 
    	{    
		    k = 0, j = 0;
    	    vlanid = atoi(buf);
    	    
    	    if(showvlanid == vlanid)
    	    {    
    			p = strchr(buf, ',')+1;
    			input_num(p, 1, 8, &fwd);
    			fwd &= 0x1ffffffeULL;
    			p = strchr(p, ',')+1;
    			input_num(p, 1, 8, &untag);
    			untag &= 0x1ffffffeULL;
    			flag = 1;
    			
        		vty_output("%-5s%-8s%-33s%-33s\n","VLAN","Status","Name","Ports");
        		vty_output("%-5s%-8s%-33s%-33s\n","----","-------","-------------------------------","-------------------------------");
    			
    			if(1 == total[vlanid])
    			    vty_output("%-5d%-8s%-33s", vlanid,"Static", "Default");
    			else
    				vty_output("%-5d%-8s%-33s", vlanid,"Dynamic", "");
    			    	
    			
    			for(portid = 1; portid<=PNUM; portid++) 
    			{
            		if(fwd & (0x01ULL << phy[portid]) ){
            		    if(4==k){
                		    vty_output("\n");
                		    vty_output("%-5s%-8s%-33s"," "," "," ");
                		    k=0;
                		    j=0;
            		    }
                        if(0==j){
#if (XPORT==0)                            
                        	/*betty modified for giga port*/
                        	if(portid <= FNUM)
                            	vty_output("F0/%-2d",portid);
                            else
                            	vty_output("G0/%-2d",portid-FNUM);
#endif                          
#if (XPORT==1)             
                        	if(portid <= GNUM)
                            	vty_output("G0/%-2d",portid);
                            else
                            	vty_output("T0/%-2d",portid-GNUM); 
#endif             	
                            k++;
                            j++;
                        }
                        else{
#if (XPORT==0)
                        	if(portid <= FNUM)
                            	vty_output(", F0/%-2d",portid);
    						else
    	                       	vty_output(", G0/%-2d",portid-FNUM);
#endif      	                      
#if (XPORT==1)           
                        	if(portid <= GNUM)
                            	vty_output(", G0/%-2d",portid);
    						else
    	                       	vty_output(", T0/%-2d",portid-GNUM);    
#endif             	    	
    						k=k+1;
    						j=j+1;
    					}
    				}
    			}	
    		}
	    }	
	    fclose(fp);
	}  

	if(0 == flag) {
		vty_output("VLAN id %d not found in current VLAN database\n", showvlanid);
	}else
	    vty_output("\n");

	return;
}


static void cli_show_ipv6_interface(void)
{
	char tmp[10], state[10],ethbuf[12];
	char *manage_vlan = nvram_safe_get("manage_vlan");
	char *manage_IMP = nvram_safe_get("manage_IMP");
	char *ip_staticip_enable=nvram_safe_get("dhcp6_client");
	int vlanid, flag = 0;
	/*wuchunli 2012-4-19 15:13:37*/
	int flag1 = 0;
	uint64_t link = 0x0ULL;
	cli_vlan_info_conf *p_vlan = NULL;
	if_ipv6_t *ipv6_info = NULL, *ipv6_info_tmp = NULL;

	//printf("%-16s%-28s%-16s%-8s%-s\n","Interface","IP Address","Scope","Method","Protocol-status");
	vlanid = atoi(manage_vlan);
	if(0 != vlanid) {
		sprintf(tmp, "VLAN%d", vlanid);

		sprintf(ethbuf,"eth2.%d",vlanid);

		if(*manage_IMP=='1') {
			memset(&cur_vlan_conf, 0, sizeof(cli_vlan_conf));
			memset(cur_port_conf, 0, sizeof(cli_port_conf)*PNUM);
			cur_vlan_conf.cur_vlan_info = NULL;

			cli_nvram_conf_get(CLI_VLAN_FOWD, (unsigned char *)&cur_vlan_conf);

			/* get management vlan portmap */
			p_vlan = cur_vlan_conf.cur_vlan_info;
			while(NULL != p_vlan) {
				if(vlanid == p_vlan->vlanid) {
					flag = 1;
					break;
				}
				p_vlan = p_vlan->next;
			}

			if(1 == flag) {
				/* get current port link state */
				bcm_get_swlink_status(&link);
				if(link & p_vlan->forward)
					sprintf(state, "UP");
				else
					sprintf(state, "DOWN");
			}
			else
				sprintf(state, "DOWN");
			cli_nvram_conf_free(CLI_VLAN_FOWD, (unsigned char *)&cur_vlan_conf);


		}
	else
		sprintf(state, "DOWN");
	}
	/*wuchunli 2012-4-19 15:13:46 begin*/
	else {
		flag1 = 1;
	}
	/*wuchunli 2012-4-19 15:13:58 end*/
	ipv6_info = get_ipv6_addr();
	ipv6_info_tmp = ipv6_info;
	while(ipv6_info_tmp!= NULL)
	{
		if(strcmp(ipv6_info_tmp->devname, ethbuf) == 0)
		{
			/*wuchunli 2012-4-19 15:14:11*/
			if(flag1) {

			} else {
			if(ipv6_info_tmp->scope_type == 0)
				vty_output("manage vlan%d %s ipv6 address %s/%d\n", vlanid,
				('1' == *ip_staticip_enable)?"DHCP":"Manual",ipv6_info_tmp->addr6, ipv6_info_tmp->plen);
				/*printf("%-16s%-28s%-16s%-8s%-s\n", tmp ,ipv6_info_tmp->addr6, ipv6_info_tmp->scope,
				(ipv6_info_tmp->scope_type != 0)?"  -  ":(('0' == *ip_staticip_enable)?"Manual":"DHCP"),state);*/
			}
		}
		//printf("%s, %d, %s, %s\n",
		//	ipv6_info_tmp->addr6, ipv6_info_tmp->plen, ipv6_info_tmp->scope, ipv6_info_tmp->devname);
		ipv6_info_tmp = ipv6_info_tmp->next;
	}
	free_ipv6_addr(ipv6_info);

	free(manage_vlan);
	free(manage_IMP);
	free(ip_staticip_enable);
	return ;
}


int func_show_ipv6_brief(struct users *u)
{
	cli_show_ipv6_interface();

	return 0;
}
int func_show_ipv6_dhcp_snooping_binding_all()
{
	char *manage_vlan = nvram_safe_get("manage_vlan");
	char *dhcp6_snoop_enable = nvram_safe_get("dhcp6_snoop_enable");
	FILE * fp;
	char line_buf[512] = {'\0'};
	char mac[32], ipv6_addr[64], lease_time[16];
	char *ptr, *ptr0;

	if('1' == *dhcp6_snoop_enable) {
		system("/usr/bin/killall -SIGUSR2 dhcp6snoop > /dev/null 2>&1");
		usleep(500000);

		vty_output("\n%-18s%-40s%-12s%-5s\n", "mac address", "ip address", "lease(sec)", "vlan");
		vty_output("%-18s%-40s%-12s%-5s\n", "-------------", "------------", "----------", "-----");

		if(access("/tmp/dhcp6_snooping", F_OK) < 0)		
			goto failed;	
		if((fp = fopen("/tmp/dhcp6_snooping", "r")) == NULL)
			goto failed;			
		while(fgets(line_buf, sizeof(line_buf), fp) != NULL) {
			ptr0 = ptr = line_buf;
			if((ptr0 = strchr(ptr, ',')) == NULL)
				goto parse_continue;
			memcpy(mac, ptr, (ptr0-ptr)<(sizeof(mac)-1)? (ptr0-ptr):(sizeof(mac)-1));

			ptr = ptr0 + 1;
			if((ptr0 = strchr(ptr, ',')) == NULL)
				goto parse_continue;
			memcpy(ipv6_addr, ptr, (ptr0-ptr)<(sizeof(ipv6_addr)-1)? (ptr0-ptr):(sizeof(ipv6_addr)-1));

			ptr = ptr0 + 1;
			if((ptr0 = strchr(ptr, '\n')) == NULL)
				goto parse_continue;
			memcpy(lease_time, ptr, (ptr0-ptr)<(sizeof(lease_time)-1)? (ptr0-ptr):(sizeof(lease_time)-1));

			if(atoi(lease_time) == 0)
				goto parse_continue;

			vty_output("%-18s%-40s%-12s%-5s\n", mac, ipv6_addr, lease_time, manage_vlan);

			parse_continue:
			memset(mac, '\0', sizeof(mac));
			memset(ipv6_addr, '\0', sizeof(ipv6_addr));
			memset(lease_time, '\0', sizeof(lease_time));
			memset(line_buf, '\0', sizeof(line_buf));
		}

		fclose(fp);
		unlink("/tmp/dhcp6_snooping");
	} else {
		vty_output("  Please start dhcpv6 snooping first\n");
	}

failed:
	free(manage_vlan);
	free(dhcp6_snoop_enable);

	return;
}

/*
 *  Function:  func_show_ipv6_vlan
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ipv6_vlan(struct users *u)
{
	int vlanid, iptype, vlan_id; 
	char *p, *p1, *p2, *ip, lanip[64], intf[128], key[8], ipaddr[64], *l3_ip = nvram_safe_get("lan_ipaddr");
	char *p3, *p4, ipv4[32], ipv6[64];

	cli_param_get_int(STATIC_PARAM, 0, &vlan_id, u);
    vty_output("interface vlan %d\n", vlan_id);

    ip = l3_ip;
    while((*ip != NULL) && (strlen(ip) > 0))
    {   
        memset(intf, '\0', sizeof(intf));
        memset(lanip, '\0', sizeof(lanip));
        p1 = strchr(ip, ';'); 
        memcpy(intf, ip, p1-ip);
        
        memset(ipv4, '\0', sizeof(ipv4));
        memset(ipv6, '\0', sizeof(ipv6));
        
        cli_interface_info_get(intf, &vlanid, &iptype, ipv4, ipv6);
 
        if(vlan_id == vlanid)
        {    
            if(0 == (iptype%2))
            {
                if(strlen(ipv6) > 0)
                {    
        			vty_output(" ipv6 address %s\n", ipv6);
        		}
    		}
    		else if(1 == iptype)
    		{    
    			vty_output(" ip address dhcp\n");  
            }  
        }  
        ip = p1+1;  
    } 
    free(l3_ip);

	return;
}

/*
 *  Function:  func_show_ipv6_neighbors
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ipv6_neighbors(struct users *u)
{
    FILE *fp;
    int vlan;
    char line[128], *p, *p1;

//   	system("killall -SIGUSR2 ospf6d > /dev/null 2>&1");
//	check_file("/var/ipv6_ospf");
//	 
//    fp=fopen("/var/ipv6_ospf", "r+");
//    if( fp == NULL) return 0;
//    
//    fseek(fp,0,SEEK_SET);
//    memset(line, '\0', 128); 
//    while(fgets(line,128,fp)!=NULL)
//    {     
//        vty_output(" %s", line);
//    }
//    
//    fclose(fp);    		  
//    unlink("/var/ipv6_ospf");    
    
	return 0;
}

/*
 *  Function:  func_show_ipv6_ospf_neighbor
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ipv6_ospf_neighbor(struct users *u)
{
    FILE *fp;
    int vlan;
    char line[128], *p, *p1;

   	system("killall -SIGUSR2 ospf6d > /dev/null 2>&1");
	check_file("/var/ipv6_ospf");
	 
    fp=fopen("/var/ipv6_ospf", "r+");
    if( fp == NULL) return 0;
    
    fseek(fp,0,SEEK_SET);
    memset(line, '\0', 128); 
    while(fgets(line,128,fp)!=NULL)
    {     
        vty_output(" %s", line);
    }
    
    fclose(fp);    		  
    unlink("/var/ipv6_ospf");    

	return 0;
}

/*
 *  Function:  func_show_ipv6_rip_hops
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ipv6_rip_hops(struct users *u)
{
	printf("do func_show_ipv6_rip_hops here\n");

	return 0;
}

/*
 *  Function:  func_show_ipv6_route
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ipv6_route(struct users *u)
{
    FILE *fp;
    int vlan;
    char line[128], *p, *p1, *p2;
    
    vty_output("Codes: K - kernel route, C - connected, S - static, R - RIPng, O - OSPFv3,\n       I - ISIS, B - BGP, * - FIB route.\n");

   	system("killall -SIGUSR2 zebra > /dev/null 2>&1");
	check_file("/var/ipv6_status");
	 
    fp=fopen("/var/ipv6_status","r+");
    if( fp == NULL) return 0;
    
    fseek(fp,0,SEEK_SET);
    memset(line, '\0', 128); 
    while(fgets(line,128,fp)!=NULL)
    {     
        if(!memcmp(line, "C>* ::1/128", sizeof("C>* ::1/128")))
            continue;
            
        if(strstr(line, "fe80::/64") != NULL)
            continue;
            
        p = strstr(line, IMP);
        p2 = strstr(line, "br");
        if((p == NULL)&&(p2 == NULL))
        {    
            if((p1 = strstr(line, "inactive")) != NULL)
    		    vty_output(" %s", line);
            else
                continue;
        }
        else if(p != NULL)    
        {
            p1 = strchr(p, '.')+1;
            vlan = atoi(p1);
            *p = '\0';
                   
    		vty_output(" %s vlan %d\n", line, vlan);
    		memset(line, '\0', 128);
    	}
    	else if(p2 != NULL)    
        {
            p1 = strstr(p2, "br")+2;
            vlan = atoi(p1);
            *p2 = '\0';
                   
    		vty_output(" %s vlan %d\n", line, vlan);
    		memset(line, '\0', 128);
    	} 
    }
    
    fclose(fp);    		  
    unlink("/var/ipv6_status");    

	return 0;
}

/*
 *  Function:  func_show_vrrp_brief
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_vrrp_brief(struct users *u)
{
    FILE *fp;
	MAC_INFO sw_info;
    char line[128], list[8][64], intf[32], buffer[128];	
	char *p1, *vrrp, * vrrp_list = nvram_safe_get("vrrp_list");
		
	bzero(&sw_info,sizeof(sw_info));
	getSWInfo(&sw_info);
	
    vrrp = vrrp_list;
    //vrrp_list=1,1,192.168.10.254,100,1,10,0,;10,2,192.168.20.254,99,0,22,1,123456;
    while((*vrrp != NULL) && (strlen(vrrp) > 0))
    {   
        memset(line, '\0', sizeof(line));
        memset(list, '\0', sizeof(list));
        memset(intf, '\0', sizeof(intf));
        
        p1 = strchr(vrrp, ';'); 
        memcpy(line, vrrp, p1-vrrp);
        
        sscanf(line,"%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,]", 
            list[0],list[1],list[2],list[3],list[4],list[5],list[6],list[7]); 

	    vty_output("\nVLAN%s (%s\t%04X%08X)\n", list[0], list[2], (uint16)(sw_info.mac >> 32), (uint32)sw_info.mac);
	    vty_output("-----------------------------------------\n" );
	    vty_output("group id: %s\n", list[1]);  
	    
	    sprintf(intf, "/var/vrrp.status.%s", list[1]);
	    
	    if((fp=fopen(intf,"r"))==NULL)
        {
            vty_output("state: this vlan interface no ip\n" ); 
        }
	    else
	    {
	        memset(buffer, '\0', sizeof(buffer));
	        fgets(buffer,256,fp);
	        
	        if(strstr(buffer, "master") != NULL)
	            vty_output("state: Master\n" );   
	        else if(strstr(buffer, "backup") != NULL)
	            vty_output("state: Backup\n" );   
	        else
	            vty_output("state: Init mode\n" );          
	        fclose(fp);
	    }    
	     
	    vty_output("priority : %s\n", list[3]);
	    vty_output("preempt: %s\n", (list[4][0] == '0')?"off":"on"); 
	    vty_output("authentication: %s\n", (list[6][0] == '0')?"no-authen":"auth");  
	    vty_output("advertisement interval: 1\n" );  
//	    vty_output("associate IP address: 192.168.20.110\n" ); 
	    vty_output("advertisement timer expiry : %s\n", list[5]); 
            
        vrrp = p1+1;       
    } 
    free(vrrp_list);

	return 0;
}

/*
 *  Function:  func_show_ipv6_mld_int
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ipv6_mld_int(struct users *u)
{
	printf("do func_show_ipv6_mld_int here\n");

	return 0;
}

int func_show_ipv6_mld_group(struct users *u)
{
	printf("do func_show_ipv6_mld_group here\n");

	return 0;
}

int func_show_ipv6_mld_detail(struct users *u)
{
	printf("do func_show_ipv6_mld_detail here\n");

	return 0;
}

/*
 *  Function:  func_show_vrrp_int
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_vrrp_int(struct users *u)
{
    FILE *fp;
	MAC_INFO sw_info;
	int vlan, found = 0;
    char line[128], list[8][64], intf[32], buffer[128];	
	char *p, *p1, *vrrp, * vrrp_list = nvram_safe_get("vrrp_list");
		
    p = strstr(u->linebuf, "interface") + strlen("interface");
    while(*p == ' ')
        p++;
	vlan = atoi(p);
//	vty_output("vlan %d\n", vlan); 	
		
	bzero(&sw_info,sizeof(sw_info));
	getSWInfo(&sw_info);
	
    vrrp = vrrp_list;
    //vrrp_list=1,1,192.168.10.254,100,1,10,0,;10,2,192.168.20.254,99,0,22,1,123456;
    while((*vrrp != NULL) && (strlen(vrrp) > 0))
    {   
        memset(line, '\0', sizeof(line));
        memset(list, '\0', sizeof(list));
        memset(intf, '\0', sizeof(intf));
        
        p1 = strchr(vrrp, ';'); 
        memcpy(line, vrrp, p1-vrrp);
        
        sscanf(line,"%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,],%[^,]", 
            list[0],list[1],list[2],list[3],list[4],list[5],list[6],list[7]); 

        if(vlan == atoi(list[0]))
        {    
            found = 1;
    	    vty_output("\nVLAN%s (%s\t%04X%08X)\n", list[0], list[2], (uint16)(sw_info.mac >> 32), (uint32)sw_info.mac);
    	    vty_output("-----------------------------------------\n" );
    	    vty_output("group id: %s\n", list[1]);  
    	    
    	    sprintf(intf, "/var/vrrp.status.%s", list[1]);
    	    
    	    if((fp=fopen(intf,"r"))==NULL)
            {
                vty_output("state: this vlan interface no ip\n" ); 
            }
    	    else
    	    {
    	        memset(buffer, '\0', sizeof(buffer));
    	        fgets(buffer,256,fp);
    	        
    	        if(strstr(buffer, "master") != NULL)
    	            vty_output("state: Master\n" );   
    	        else if(strstr(buffer, "backup") != NULL)
    	            vty_output("state: Backup\n" );   
    	        else
    	            vty_output("state: Init mode\n" );          
    	        fclose(fp);
    	    }    
    	     
    	    vty_output("priority : %s\n", list[3]);
    	    vty_output("preempt: %s\n", (list[4][0] == '0')?"off":"on"); 
    	    vty_output("authentication: %s\n", (list[6][0] == '0')?"no-authen":"auth");  
    	    vty_output("advertisement interval: 1\n" );  
    //	    vty_output("associate IP address: 192.168.20.110\n" ); 
    	    vty_output("advertisement timer expiry : %s\n", list[5]); 
        }
         
        vrrp = p1+1;       
    } 
    free(vrrp_list);
    
    if(found == 0)
        vty_output("\nVLAN%d no vrrp\n", vlan);

	return 0;
}

/*
 *  Function:  func_show_bgp_ipv6_unicast
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_bgp_ipv6_unicast(struct users *u)
{
	printf("do func_show_bgp_ipv6_unicast here\n");

	return 0;
}

/*
 *  Function:  func_show_isis_beighbors
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_isis_beighbors(struct users *u)
{
	printf("do func_show_isis_beighbors here\n");

	return 0;
}

int func_show_edr_disable_state(void)
{
    int skfd,retval;
    struct sockaddr_un edr_sock_addr, cli_sock_addr;
	IPC_SK tx, rx;
	int i, iPort;
	fd_set rfds;
	if(creat_sk_client(&skfd, &edr_sock_addr, SOCK_PATH_EDR, &cli_sock_addr, SOCK_PATH_CONSOLE, 0))
	{
		return -1;
	}

	/*operate data for sending*/
	
	tx.stHead.enCmd = IPC_CMD_GET;
	tx.stHead.cOpt = 0;
	tx.stHead.cBack = IPC_SK_BACK;
	
	/*send data to server*/
	if(ipc_send(skfd, &tx, &edr_sock_addr) == -1)
	{
		return -1;
	}
	//printf("%s.%s.%d\n", __FILE__, __FUNCTION__, __LINE__);
	if(ipc_recv(skfd, &rx, &edr_sock_addr) == -1)
	{
		return -1;
	}
	//printf("%s.%s.%d\n", __FILE__, __FUNCTION__, __LINE__);
	if((rx.stHead.enCmd == IPC_CMD_GET) && (rx.stHead.cOpt == 1))
	{
		EDR_PORT *pstEdrPort = (EDR_PORT *)rx.acData;
		for(i = 0; i < PORT_MAX; i++)
		{
			iPort = i+1;
			//printf("port%d, state=%d, ErrSrc=%d, RecSrc=%d\n", iPort, (pstEdrPort+i)->cPortState, (pstEdrPort+i)->enErrSrc, (pstEdrPort+i)->enRecSrc);
			
			if((pstEdrPort+i)->enErrSrc == ERR_SRC_BPDUGUARD)
			{
				printf("%s0/%d              bpduguard\n", (iPort<=FNUM)?"F":"G", (iPort<=FNUM)?iPort:(iPort-FNUM));
			}
			else if((pstEdrPort+i)->enErrSrc == ERR_SRC_AGGREGATION)
			{
				printf("%s0/%d              aggregation-flap\n", (iPort<=FNUM)?"F":"G", (iPort<=FNUM)?iPort:(iPort-FNUM));
			}
			else if((pstEdrPort+i)->enErrSrc == ERR_SRC_LOOPBACK)
			{
				//printf("---------       -----------------       --------------\n");
				printf("%s0/%d              loopback\n", (iPort<=FNUM)?"F":"G", (iPort<=FNUM)?iPort:(iPort-FNUM));
			}
			else if((pstEdrPort+i)->enErrSrc == ERR_SRC_ROOTGUARD)
			{
				//printf("---------       -----------------       --------------\n");
				printf("%s0/%d              rootguard\n", (iPort<=FNUM)?"F":"G", (iPort<=FNUM)?iPort:(iPort-FNUM));
			}
		}
	}

	unlink(cli_sock_addr.sun_path);
	return 0;
}
int func_show_error_detect()
{
	int i = 0;
	char *errdisable = cli_nvram_safe_get(CLI_ERR_DISABLE, "err_disable_cfg");
	printf("ErrDisable Reason               Detection\n");
	printf("-----------------               ---------\n");
	if(errdisable)
	{
		if(*(errdisable+ERR_SRC_AGGREGATION) == '1')
		{
			printf("aggregation                     Enabled\n");
		}
		else if(*(errdisable+ERR_SRC_AGGREGATION) == '0')
		{
			printf("aggregation                     Disabled\n");
		}
		/*
		if(*(errdisable+ERR_SRC_ARP) == '1')
		{
			printf("arp-inspection                  Enabled\n");
		}
		else if(*(errdisable+ERR_SRC_ARP) == '0')
		{
			printf("arp-inspection                  Disabled\n");
		}
		*/

		if(*(errdisable+ERR_SRC_BPDUGUARD) == '1')
		{
			printf("bpduguard                       Enabled\n");
		}
		else if(*(errdisable+ERR_SRC_BPDUGUARD) == '0')
		{
			printf("bpduguard                       Disabled\n");
		}

		if(*(errdisable+ERR_SRC_LOOPBACK) == '1')
		{
			printf("loopback                        Enabled\n");
		}
		else if(*(errdisable+ERR_SRC_LOOPBACK) == '0')
		{
			printf("loopback                        Disabled\n");
		}
		/*
		if(*(errdisable+ERR_SRC_ROOTGUARD) == '1')
		{
			printf("rootguard                       Enabled\n");
		}
		else if(*(errdisable+ERR_SRC_ROOTGUARD) == '0')
		{
			printf("rootguard                       Disabled\n");
		} 
		*/ 
		/*
		if(*(errdisable+ERR_SRC_SECURITY) == '1')
		{
			printf("security-violation              Enabled\n");
		}
		else if(*(errdisable+ERR_SRC_SECURITY) == '0')
		{
			printf("security-violation              Disabled\n");
		}
		i++;

		if(*(errdisable+ERR_SRC_SFP) == '1')
		{
			printf("sfp-config-mismatch             Enabled\n");
		}
		else if(*(errdisable+ERR_SRC_SFP) == '0')
		{
			printf("sfp-config-mismatch             Disabled\n");
		}
		i++;

		if(*(errdisable+ERR_SRC_UDLD) == '1')
		{
			printf("udld                            Enabled\n");
		}
		else if(*(errdisable+ERR_SRC_UDLD) == '0')
		{
			printf("udld                            Disabled\n");
		}
		*/
		free(errdisable);
	}
	
	printf("\n");
	printf("Interface       Errdisable reason\n");
	printf("---------       -----------------\n");
	func_show_edr_disable_state();
	return 0;
}

int func_show_edr_recover_state(void)
{
    int skfd,retval;
    struct sockaddr_un edr_sock_addr, cli_sock_addr;
	IPC_SK tx, rx;
	int i, iPort;
	fd_set rfds;
	if(creat_sk_client(&skfd, &edr_sock_addr, SOCK_PATH_EDR, &cli_sock_addr, SOCK_PATH_CONSOLE, 0))
	{
		return -1;
	}

	/*operate data for sending*/
	
	tx.stHead.enCmd = IPC_CMD_GET;
	tx.stHead.cOpt = 0;
	tx.stHead.cBack = IPC_SK_BACK;
	
	/*send data to server*/
	if(ipc_send(skfd, &tx, &edr_sock_addr) == -1)
	{
		return -1;
	}
	//printf("%s.%s.%d\n", __FILE__, __FUNCTION__, __LINE__);
	if(ipc_recv(skfd, &rx, &edr_sock_addr) == -1)
	{
		return -1;
	}
	//printf("%s.%s.%d\n", __FILE__, __FUNCTION__, __LINE__);
	if((rx.stHead.enCmd == IPC_CMD_GET) && (rx.stHead.cOpt == 1))
	{
		EDR_PORT *pstEdrPort = (EDR_PORT *)rx.acData;
		for(i = 0; i < PORT_MAX; i++)
		{
			iPort = i+1;
			//printf("port%d, state=%d, ErrSrc=%d, RecSrc=%d\n", iPort, (pstEdrPort+i)->cPortState, (pstEdrPort+i)->enErrSrc, (pstEdrPort+i)->enRecSrc);
			
			if((pstEdrPort+i)->enRecSrc == ERR_SRC_BPDUGUARD)
			{
				printf("%s0/%d              bpduguard                 %d\n", (iPort<=FNUM)?"F":"G", (iPort<=FNUM)?iPort:(iPort-FNUM),
				    (pstEdrPort+i)->lRecTimer);
			}
			else if((pstEdrPort+i)->enRecSrc == ERR_SRC_AGGREGATION)
			{
				printf("%s0/%d              aggregation-flap          %d\n", (iPort<=FNUM)?"F":"G", (iPort<=FNUM)?iPort:(iPort-FNUM),
				    (pstEdrPort+i)->lRecTimer);
			}
			else if((pstEdrPort+i)->enRecSrc == ERR_SRC_LOOPBACK)
			{
				//printf("---------       -----------------       --------------\n");
				printf("%s0/%d              loopback                  %d\n", (iPort<=FNUM)?"F":"G", (iPort<=FNUM)?iPort:(iPort-FNUM),
				    (pstEdrPort+i)->lRecTimer);
			}
		}
	}

	unlink(cli_sock_addr.sun_path);
	return 0;
}
int func_show_error_recovery()
{
	char *err_recover_cfg = cli_nvram_safe_get(CLI_ERR_RECOVER, "err_recover_cfg");
	char *err_recover_time = nvram_safe_get("err_recover_time");
	printf("ErrDisable Reason         Timer Status\n");
	printf("-----------------         ------------\n");
	if(err_recover_cfg)
	{

		if(*(err_recover_cfg+ERR_SRC_AGGREGATION) == '1')
		{
			printf("aggregation               Enabled\n");
		}
		else if(*(err_recover_cfg+ERR_SRC_AGGREGATION) == '0')
		{
			printf("aggregation               Disabled\n");
		}
		/*
		if(*(err_recover_cfg+ERR_SRC_ARP) == '1')
		{
			printf("arp-inspection            Enabled\n");
		}
		else if(*(err_recover_cfg+ERR_SRC_ARP) == '0')
		{
			printf("arp-inspection            Disabled\n");
		}
		*/

		if(*(err_recover_cfg+ERR_SRC_BPDUGUARD) == '1')
		{
			printf("bpduguard                 Enabled\n");
		}
		else if(*(err_recover_cfg+ERR_SRC_BPDUGUARD) == '0')
		{
			printf("bpduguard                 Disabled\n");
		}

		if(*(err_recover_cfg+ERR_SRC_LOOPBACK) == '1')
		{
			printf("loopback                  Enabled\n");
		}
		else if(*(err_recover_cfg+ERR_SRC_LOOPBACK) == '0')
		{
			printf("loopback                  Disabled\n");
		}
		/*
		if(*(err_recover_cfg+ERR_SRC_SECURITY) == '1')
		{
			printf("security-violation        Enabled\n");
		}
		else if(*(err_recover_cfg+ERR_SRC_SECURITY) == '0')
		{
			printf("security-violation        Disabled\n");
		}

		if(*(err_recover_cfg+ERR_SRC_SFP) == '1')
		{
			printf("sfp-config-mismatch       Enabled\n");
		}
		else if(*(err_recover_cfg+ERR_SRC_SFP) == '0')
		{
			printf("sfp-config-mismatch       Disabled\n");
		}

		if(*(err_recover_cfg+ERR_SRC_UDLD) == '1')
		{
			printf("udld                      Enabled\n");
		}
		else if(*(err_recover_cfg+ERR_SRC_UDLD) == '0')
		{
			printf("udld                      Disabled\n");
		}
		*/
		free(err_recover_cfg);
	}
	printf("\n");
	if(err_recover_time)
	{
		printf("Timer interval: %s seconds\n", err_recover_time);
	}
	free(err_recover_time);
	printf("\n");
	printf("Interfaces that will be enabled at the next timeout:\n");
	printf("\n");
	printf("Interface       Errdisable reason       Time left(sec)\n");
	printf("---------       -----------------       --------------\n");
	func_show_edr_recover_state();
	return 0;
}

/*
 *  Function:  func_show_line_vty
 *  Purpose:  show line vty list(include ssh and telnet)
 *  Parameters:
 *     void
 *  Returns:
 *     retval 
 *  Author:   wei.zhang
 *  Date:    2012/4/19
 */
int func_show_line_vty(int vty_first, int vty_last)
{
	vty_output("%-4s%-22s%-13s%-12s\n","No","Remote Address","Remote Port","Local Port");
	vty_output("%-4s%-22s%-13s%-12s\n","--","--------------","-----------","----------");
	
	FILE *fp;
	int id = 0;
	char buf[256];
	char remote_ip[64];	//remote_port[8],local_ip[64],local_port[8],line_id[3];	//line_id[3] add by zhangwei
	int remote_port;
	int local_port;
	int line_id;
	char *p=NULL, *local_ip_from_nvram = NULL;
	char print_msg[16][128], k;	
	

	memset(buf, 0, sizeof(buf));
	memset(print_msg, 0, sizeof(print_msg));

	if ((fp = fopen("/tmp/telnet_sessions","r")) != NULL) {
    	while(fgets(buf, 128, fp)!=NULL) {
			p = buf;
			memset( remote_ip, 0, sizeof(remote_ip) );
			strcpy( remote_ip, strsep( &p, "," ) );
			remote_port = atoi( strsep( &p, ",") );
			strsep( &p, "," );
			local_port = atoi( strsep( &p, ",") );
			line_id = atoi( strsep( &p, ";") );
			sprintf(print_msg[(line_id-1)%16], "%-4d%-22s%-13d%-12d\n", line_id, remote_ip, remote_port, local_port);
			memset(buf, 0, sizeof(buf));
    	}
		fclose( fp );
	}
			
	memset(buf, 0, sizeof(buf));
	if ( (fp = fopen("/tmp/ssh_sessions", "r")) != NULL ){
		while( fgets(buf, 128, fp) != NULL ){
			p = buf;
			memset( remote_ip, 0, sizeof(remote_ip) );
			strcpy( remote_ip, strsep( &p, "," ) );
			remote_port = atoi( strsep( &p, ",") );
			local_port = 22;
			strsep( &p, ",");
			line_id = atoi( strsep( &p, ";") );
			sprintf(print_msg[(line_id-1)%16], "%-4d%-22s%-13d%-12d\n", line_id, remote_ip, remote_port, local_port);

		}
		fclose( fp );
	}
	
	for( k=vty_first-1; k<=vty_last-1; k++){
		if( 0 == print_msg[k][0] )
			vty_output("%d\n", k+1);
		else
			vty_output("%s", print_msg[k]);
	}
}

/*
 *  Function:  func_show_ip_dhcp_binding_addr
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ip_dhcp_binding_addr(struct users *u)
{
	printf("do func_show_ip_dhcp_binding_addr here\n");

	return 0;
}

/*
 *  Function:  func_show_ip_dhcp_binding_all
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ip_dhcp_binding_all(struct users *u)
{
	printf("do func_show_ip_dhcp_binding_all here\n");

	return 0;
}

/*
 *  Function:  func_show_ip_dhcp_binding_manual
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ip_dhcp_binding_manual(struct users *u)
{
	printf("do func_show_ip_dhcp_binding_manual here\n");

	return 0;
}

/*
 *  Function:  func_show_ip_dhcp_binding_dynamic
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ip_dhcp_binding_dynamic(struct users *u)
{
	printf("do func_show_ip_dhcp_binding_dynamic here\n");

	return 0;
}

/*
 *  Function:  func_show_ip_dhcp_server_stats
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ip_dhcp_server_stats(struct users *u)
{
	printf("do func_show_ip_dhcp_server_stats here\n");

	return 0;
}

/*
 *  Function:  func_show_ipv6_dhcp
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ipv6_dhcp(struct users *u)
{
	printf("do func_show_ipv6_dhcp here\n");

	return 0;
}

/*
 *  Function:  func_show_ipv6_dhcp_binding
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ipv6_dhcp_binding(struct users *u)
{
	printf("do func_show_ipv6_dhcp_binding here\n");

	return 0;
}

/*
 *  Function:  func_show_ipv6_dhcp_inter_all
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ipv6_dhcp_inter_all(struct users *u)
{
	printf("do func_show_ipv6_dhcp_inter_all here\n");

	return 0;
}

/*
 *  Function:  func_show_ipv6_dhcp_pool_all
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ipv6_dhcp_pool_all(struct users *u)
{
	printf("do func_show_ipv6_dhcp_pool_all here\n");

	return 0;
}

/*
 *  Function:  func_show_ipv6_dhcp_pool_name
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ipv6_dhcp_pool_name(struct users *u)
{
	printf("do func_show_ipv6_dhcp_pool_name here\n");

	return 0;
}

/*
 *  Function:  cli_show_gvrp_interface
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int cli_show_gvrp_interface(struct users *u, int port_num)
{
	char *gvrp_config = cli_nvram_safe_get(CLI_ALL_ZERO,  "gvrp_config");
	if(port_num <= FNUM)
		vty_output("GMRP statistics on port FastEthernet 0/%d\n", port_num); 
	else
		vty_output("GMRP statistics on port GigaEthernet 0/%d\n", (port_num-GNUM)); 
				
	vty_output("GVRP Status: %s\n", ('1' == *(gvrp_config+port_num-1))?"Enabled":"Disable"); 
	vty_output("GVRP Failed Registrations: 0\n"); 
	vty_output("GVRP Registration Type: Normal\n");

    free(gvrp_config);
	return 0;
}

/*
 *  Function:  cli_show_garp_interface
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int cli_show_garp_interface(struct users *u, int port_num)
{
	printf("do cli_show_garp_interface here\n");

	return 0;
}

/*
 *  Function:  cli_show_gmrp_interface
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int cli_show_gmrp_interface(struct users *u, int port_num)
{
	char *gmrp_config = cli_nvram_safe_get(CLI_ALL_ZERO,  "gmrp_config");
	if(port_num <= FNUM)
		vty_output("GMRP statistics on port FastEthernet 0/%d\n", port_num); 
	else
		vty_output("GMRP statistics on port GigaEthernet 0/%d\n", (port_num-GNUM)); 
				
	vty_output("GMRP Status: %s\n", ('1' == *(gmrp_config+port_num-1))?"Enabled":"Disable"); 
	vty_output("GMRP Frames Received: 54\n");  
	vty_output("GMRP Frames Transmitted: 27\n"); 
	vty_output("GMRP Frames Discarded: 0\n");  

    free(gmrp_config);
	return 0;
}

/*
 *  Function:  func_show_ip_route
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
typedef struct routelist
{	
    int  vid;
	unsigned int destip; 
	unsigned int netmask;
	unsigned int gateway;
	int  metric;	
    int  flage;
}ROUTETable;


typedef struct strlist
{	
    char dst[18];
    char mask[18];
    char gateway[18];
	unsigned int subnet; 
	int netmask;
	int  metric;	
    int  dev;
}STRTable;
 
int func_show_ip_route(struct users *u)
{
    FILE *fp;
    int vlan;
    char line[128], *p, *p1, *p2, *p3;
	
    vty_output("\nCodes: K - kernel, C - connected, S - static, R - RIP, B - BGP\n");  
    vty_output("\tO - OSPF, IA - OSPF inter area\n");    
    vty_output("\tN1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2\n");    
    vty_output("\tE1 - OSPF external type 1, E2 - OSPF external type 2\n");    
    vty_output("\ti - IS-IS, L1 - IS-IS level-1, L2 - IS-IS level-2, ia - IS-IS inter area\n");    
    vty_output("\t* - candidate default\n");	

   	system("killall -SIGUSR1 zebra > /dev/null 2>&1");
	check_file("/var/ipv4_status");
	 
    fp=fopen("/var/ipv4_status","r+");
    if( fp == NULL) return 0;
    
    fseek(fp,0,SEEK_SET);
    memset(line, '\0', 128); 
    while(fgets(line,128,fp)!=NULL)
    {     
        if(!memcmp(line, "127.0.0.0", sizeof("127.0.0.0")))
            continue;
       
        p = strstr(line, IMP);
        if(p == NULL) 
        {    
            if((p1 = strstr(line, "inactive")) != NULL)
    		    vty_output(" %s", line);
            else if((p2 = strstr(line, "eth0")) != NULL) 
            {
                *p2 = '\0';
                vty_output(" %s loopback\n", line, vlan);
            }
            else    
                continue;
        }else    
        {
            p1 = strchr(p, '.')+1;
            vlan = atoi(p1);
            *p = '\0';
                   
    		vty_output(" %s vlan %d\n", line, vlan);
    	} 
    	memset(line, '\0', 128);
    }
    
    fclose(fp);    		  
    unlink("/var/ipv4_status");    
    
	return 0;
}

/*
 *  Function:  func_show_ip_ospf_neighbor
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ip_ospf_neighbor(struct users *u)
{
    FILE *fp;
    int vlan;
    char line[128], *p, *p1;

   	system("killall -SIGUSR2 ospfd > /dev/null 2>&1");
	check_file("/var/ipv4_ospf");
	 
    fp=fopen("/var/ipv4_ospf", "r+");
    if( fp == NULL) return 0;
    
    fseek(fp,0,SEEK_SET);
    memset(line, '\0', 128); 
    while(fgets(line,128,fp)!=NULL)
    {     
        vty_output(" %s", line);
    }
    
    fclose(fp);    		  
    unlink("/var/ipv4_ospf");   
	return 0;
}

/*
 *  Function:  func_show_ip_rip
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ip_rip(struct users *u)
{
	int rip;
    char * rip_enable = nvram_safe_get("zebra");
    
	rip = atoi(rip_enable);
	free(rip_enable);
	
    vty_output("\n RIP protocol:   %s\n", (rip&0x01)?"Enabled":"Disable");    
    vty_output("  Decided on the interface version control\n");    
    vty_output("  AUTO-SUMMAR Y:    Yes\n");    
    vty_output("  Update: 30,  Expire:  180,  Holddown: 120\n");    
    vty_output("  Distance:    120\n");    
    vty_output("  default-metric: 1\n");

	return 0;
}

/*
 *  Function:  func_show_clns_neighbor
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_clns_neighbor(struct users *u)
{
    FILE *fp;
    int vlan;
    char line[128], *p, *p1;

   	system("killall -SIGUSR2 isisd > /dev/null 2>&1");
	check_file("/var/isis_status");
	 
    fp=fopen("/var/isis_status", "r+");
    if( fp == NULL) return 0;
    
    fseek(fp,0,SEEK_SET);
    memset(line, '\0', 128); 
    while(fgets(line,128,fp)!=NULL)
    {     
        vty_output(" %s", line);
    }
    
    fclose(fp);    		  
    unlink("/var/isis_status");    
    
	return 0;
}

/*
 *  Function:  func_show_ip_bgp_summary
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ip_bgp_summary(struct users *u)
{
    FILE *fp;
    int vlan;
    char line[128], *p, *p1;

   	system("killall -SIGUSR2 bgpd > /dev/null 2>&1");
	check_file("/var/ip_bgp");
	 
    fp=fopen("/var/ip_bgp", "r+");
    if( fp == NULL) return 0;
    
    fseek(fp,0,SEEK_SET);
    memset(line, '\0', 128); 
    while(fgets(line,128,fp)!=NULL)
    {     
        vty_output(" %s", line);
    }
    
    fclose(fp);    		  
    unlink("/var/ip_bgp");    
    
	return 0;
}

/*
 *  Function:  func_show_ip_mroute
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ip_mroute(struct users *u)
{
    FILE *fp;
    int vlan, count = 0;
    char line[128], *p, *p1;
    char *ipmc_enable = nvram_safe_get("ipmc_enable");
    char *ipmc_type = nvram_safe_get("ipmc_type");
    
    vty_output("IP Multicast Route:\n"); 
    
    if(*ipmc_enable == '1') 
    {    
        if((strlen(ipmc_type) == 0) || (*ipmc_type == '0'))
        {
        	unlink("/var/mrt.status");  
           	system("killall -SIGUSR1 pimd > /dev/null 2>&1");
        	check_file("/var/mrt.status");
        	 
            fp=fopen("/var/mrt.status","r+");
            if( fp != NULL)
            {    
                while(fgets(line,128,fp)!=NULL)
        	        vty_output(" %s", line);
        	    fclose(fp); 
        	}      
    	}
    	else if(*ipmc_type == '1')
        {
            unlink("/tmp/ipmc.data");
            system("killall -SIGUSR2 ipmc > /dev/null 2>&1");
            check_file("/tmp/ipmc.data");
        
            if((fp=fopen("/tmp/ipmc.data","r")) != NULL)
            { 
                memset(line, '\0', sizeof(line));
            	while(fgets(line, sizeof(line), fp)!=NULL)
            	{		
                    vty_output("%s", line); 
            	}
            	fclose(fp);   
            } 
            vty_output("\n"); 
        }
    }
    else
    {
        vty_output("Warning: multi-routing is disabled on the devices\n"); 
    }    

    free(ipmc_enable);
    free(ipmc_type);
	return 0;
    
	return 0;
}

/*
 *  Function:  func_show_ip_mroute_static
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ip_mroute_static(struct users *u)
{
    FILE * fp;
    char line[128], intf[8], sip[16], gip[16];
    
    vty_output("Static IP Multicast Routing Table\n"); 
    vty_output("Flags: D - Dense, S - Sparse, B - Bidir Group, s - SSM Group, C - Connected,\n"); 
    vty_output("       L - Local, P - Pruned, R - RP-bit set, F - Register flag,\n"); 
    vty_output("       T - SPT-bit set, J - Join SPT, M - MSDP created entry,\n"); 
    vty_output("       X - Proxy Join Timer Running, A - Candidate for MSDP Advertisement,\n"); 
    vty_output("       U - URD, I - Received Source Specific Host Report, Z - Multicast Tunnel\n"); 
    vty_output("       Y - Joined MDT-data group, y - Sending to MDT-data group\n"); 
    vty_output("Outgoing interface flags: H - Hardware switched, A - Assert winner\n"); 
    vty_output("Timers: Uptime/Expires\n"); 
    vty_output("Interface state: Interface, Next-Hop or VCD, State/Mode\n"); 
    
    if((fp=fopen("/etc/ipmc","r")) != NULL)
    { 
        memset(line, '\0', sizeof(line));
    	while(fgets(line, sizeof(line), fp)!=NULL)
    	{		
            memset(intf, '\0', sizeof(intf));
            memset(sip, '\0', sizeof(sip));
            memset(gip, '\0', sizeof(gip));				
    		
            sscanf(line, "%[^,],%[^,],%s", intf, gip, sip); 
            vty_output("\n(%s, %s), flags: \n", sip, gip); 
            vty_output("Incoming interface: vlan%s, RPF nbr 0.0.0.0\n", intf); 
            vty_output("Outgoing interface list: null\n");     
    	}
    	fclose(fp);   
    } 
    vty_output("\n"); 
    
	return 0;
}

/*
 *  Function:  func_show_ip_mroute_pim
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ip_mroute_pim(struct users *u)
{
    FILE *fp;
    int vlan;
    char line[128], *p, *p1;
    char *ipmc_enable = nvram_safe_get("ipmc_enable");
    char *ipmc_type = nvram_safe_get("ipmc_type");

    if(((*ipmc_enable == '1')) && ((strlen(ipmc_type) == 0) || (*ipmc_type == '0')))
    {
    	unlink("/var/mrt.status");   
       	system("killall -SIGUSR1 pimd > /dev/null 2>&1");
    	check_file("/var/mrt.status");
    	 
        fp=fopen("/var/mrt.status","r+");
        if( fp != NULL)
        {    
            while(fgets(line,128,fp)!=NULL)
    	        vty_output(" %s", line);
    	    fclose(fp); 
    	}        
    }
    else
    {
        vty_output("Warning: PIM-SM is disabled on the devices\n"); 
    }    

    free(ipmc_enable);
    free(ipmc_type);
	return 0;
}

/*
 *  Function:  func_show_ip_mroute_pim_group
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ip_mroute_pim_group(struct users *u)
{
	printf("do func_show_ip_mroute_pim_group here\n");

	return 0;
}

/*
 *  Function:  func_show_ip_mroute_pim_group_src
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ip_mroute_pim_group_src(struct users *u)
{
	printf("do func_show_ip_mroute_pim_group_src here\n");

	return 0;
}

/*
 *  Function:  func_show_ip_pim_neighbor
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ip_pim_neighbor(struct users *u)
{
    FILE *fp;
    int vlan;
    char line[128], *p, *p1;
    char *ipmc_enable = nvram_safe_get("ipmc_enable");
    char *ipmc_type = nvram_safe_get("ipmc_type");

	printf("ipmc_type %s, len %d\n", ipmc_type, strlen(ipmc_type));
    if(((*ipmc_enable == '1')) && ((strlen(ipmc_type) == 0) || (*ipmc_type == '0')))
    {
    	unlink("/var/neighbors.status");  
       	system("killall -SIGUSR1 pimd > /dev/null 2>&1");
    	check_file("/var/neighbors.status");
    	 
        fp=fopen("/var/neighbors.status","r+");
        if( fp != NULL)
        {    
            while(fgets(line,128,fp)!=NULL)
    	        vty_output(" %s", line);
    	    fclose(fp); 
    	}       
    }
    else
    {
        vty_output("Warning: PIM-SM is disabled on the devices\n"); 
    }    

    free(ipmc_enable);
    free(ipmc_type);
	return 0;
}

/*
 *  Function:  func_show_ip_pim_neighbor_int
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ip_pim_neighbor_int(struct users *u)
{
	printf("do func_show_ip_pim_neighbor_int here\n");

	return 0;
}

/*
 *  Function:  func_show_ip_pim_interface
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ip_pim_interface(struct users *u)
{
	printf("do func_show_ip_pim_interface here\n");

	return 0;
}

/*
 *  Function:  func_show_ip_pim_interface_int
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ip_pim_interface_int(struct users *u)
{
	printf("do func_show_ip_pim_interface_int here\n");

	return 0;
}

/*
 *  Function:  func_show_garp_timer
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_garp_timer(struct users *u)
{
	char *garp_hold = nvram_safe_get("garp_hold");
	char *garp_join = nvram_safe_get("garp_join");
	char *garp_leave = nvram_safe_get("garp_leave");
	char *garp_leaveall = nvram_safe_get("garp_leaveall");

    vty_output("GARP timers on all ports:\n"); 

	if(0 != atoi(garp_join)) {
		vty_output("Garp Join Time: %s seconds\n", garp_join);
	}else
        vty_output("Garp Join Time: 2 seconds\n");  
	    
	
	if(0 != atoi(garp_hold)) {
		vty_output("Garp Hold Time: %s seconds\n", garp_hold);
	}else
        vty_output("Garp Hold Time: 1 seconds\n"); 
	
	if(0 != atoi(garp_leave)) {
		vty_output("Garp Leave Time: %s seconds\n", garp_leave);
	}else
        vty_output("Garp Leave Time: 6 seconds\n"); 
	
	if(0 != atoi(garp_leaveall)) {
		vty_output("Garp LeaveAll Time: %s seconds\n", garp_leaveall);
	}else
        vty_output("Garp LeaveAll Time: 10 seconds\n"); 

	free(garp_hold);
	free(garp_join);
	free(garp_leave);
	free(garp_leaveall);

	return 0;
}

int func_show_multicast_vlan(struct users *u)
{
	char *multicast_vlan = nvram_safe_get("multicast_vlan");
	char *multicast_vlan_enable = nvram_safe_get("multicast_vlan_enable");
	char *str;

    vty_output("multicast_vlan infomation\n"); 

	if(0 != atoi(multicast_vlan_enable)) {
		vty_output("multicast_vlan: enable\n");
	}else
        vty_output("multicast_vlan: disable\n");  
	    
	
	vty_output("multicast_vlan:%d\n",atoi(multicast_vlan));
	str = strchr(multicast_vlan,',')+1;
	if(str != NULL )
	{
       vty_output("sub_vlan:%s\n",str);
	}
	else
	{
	   vty_output("sub_vlan:none\n");
	}
	free(multicast_vlan);
	free(multicast_vlan_enable);
	
	return 0;
}

/*
 *  Function:  func_show_gmrp_status
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_gmrp_status(struct users *u)
{
	char *gmrp = nvram_safe_get("gmrp_enable");
	
	if(*gmrp == '1') 
	{    
		vty_output("GMRP is enabled\n");
    }else 
	{    
		vty_output("GMRP is disabled\n");
    }	

	free(gmrp);	
	return 0;
}

/*
 *  Function:  func_show_ip_igmp_int
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ip_igmp_allint(struct users *u)
{
    uint32 ipaddr;
    struct in_addr addr;
    int i = 0, vlan, ret;
    IPMC_ENTRY ipmc_entry;
    char *p, *p1, *p2, *p3, *p4;
	char *ipmc_config = nvram_safe_get("igmp_config");
    
    p = ipmc_config;
    while((p4=strchr(p, ';')) != NULL)
    {    
        ipmc_entry.vlanid = atoi(p);      
        p1 = strchr(p, ',');
        p1++;
        ipmc_entry.version = atoi(p1);
        p2 = strchr(p1, ',');      
        p2++;
        ipmc_entry.query = atoi(p2);      
        p3 = strchr(p2, ',');      
        p3++;
        ipmc_entry.timeout = atoi(p3);      
        p = p4 + 1;
        
        vlan = find_vlan_intf_exit(ipmc_entry.vlanid);
        if(0 == vlan)
        {
            vty_output("vlan%d is down, all protocol is down\n\n", ipmc_entry.vlanid);  

        }else
        {
            ret = get_interface_ip(IMP, ipmc_entry.vlanid, &ipaddr);
            vty_output("vlan%d is up, line protocol is up\n", ipmc_entry.vlanid);  
            
            if(ret < 0) 
                vty_output("Internet address is 0.0.0.0, please check!\n"); 
            else
            {    
	            addr.s_addr = ipaddr;
                vty_output("Internet address is %s\n", inet_ntoa(addr));  
	        }    
            vty_output("Current IGMP router version is %d\n", ipmc_entry.version);   
            vty_output("Router plays role of querier on the interface now\n");   
            vty_output("IGMP is enable on the interface\n"); 
            vty_output("IGMP query-interval is %d seconds\n", ipmc_entry.query);  
            vty_output("IGMP max query response time is %d seconds\n", ipmc_entry.timeout);  
            vty_output("Multicast routing is enabled on the interface\n\n");  
        }    
    }
    
    free(ipmc_config);
	return 0;
}

/*
 *  Function:  func_show_ip_igmp_int
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ip_igmp_int(struct users *u)
{
    uint32 ipaddr;
    struct in_addr addr;
    int i = 0, vlan, ret, found = 0, vlanid;
    IPMC_ENTRY ipmc_entry;
    char *p, *p1, *p2, *p3, *p4;
	char *ipmc_config = nvram_safe_get("igmp_config");
    
	cli_param_get_int(STATIC_PARAM,0,&vlanid,u);
	
    p = ipmc_config;
    while((p4=strchr(p, ';')) != NULL)
    {    
        ipmc_entry.vlanid = atoi(p);      
        p1 = strchr(p, ',');
        p1++;
        ipmc_entry.version = atoi(p1);
        p2 = strchr(p1, ',');      
        p2++;
        ipmc_entry.query = atoi(p2);      
        p3 = strchr(p2, ',');      
        p3++;
        ipmc_entry.timeout = atoi(p3);      
        p = p4 + 1;
        
        if(ipmc_entry.vlanid == vlanid)
        {    
            found = 1;
            break;
        }    
    }
    
    if(found == 0)
    {
        vty_output("vlan%d is unconfigure, all protocol is down\n\n", vlanid);  
    }
    else
    {    
        vlan = find_vlan_intf_exit(vlanid);
        if(0 == vlan)
        {
            vty_output("vlan%d is down, all protocol is down\n\n", vlanid);  

        }else
        {
            ret = get_interface_ip(IMP, ipmc_entry.vlanid, &ipaddr);
            vty_output("vlan%d is up, line protocol is up\n", ipmc_entry.vlanid);  
            
            if(ret < 0) 
                vty_output("Internet address is 0.0.0.0, please check!\n"); 
            else
            {    
	            addr.s_addr = ipaddr;
                vty_output("Internet address is %s\n", inet_ntoa(addr));  
	        }    
            vty_output("Current IGMP router version is %d\n", ipmc_entry.version);   
            vty_output("Router plays role of querier on the interface now\n");   
            vty_output("IGMP is enable on the interface\n"); 
            vty_output("IGMP query-interval is %d seconds\n", ipmc_entry.query);  
            vty_output("IGMP max query response time is %d seconds\n", ipmc_entry.timeout);  
            vty_output("Multicast routing is enabled on the interface\n\n");  
        }    
    }
    free(ipmc_config);
    
	return 0;
}

/*
 *  Function:  func_show_ip_igmp_group
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ip_igmp_group(struct users *u)
{
	printf("do func_show_ip_igmp_group here\n");

	return 0;
}

/*
 *  Function:  func_show_ip_igmp_detail
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ip_igmp_detail(struct users *u)
{
	printf("do func_show_ip_igmp_detail here\n");

	return 0;
}

/*
 *  Function:  func_show_ip_mroute_sm
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ip_mroute_sm(struct users *u)
{
    FILE *fp;
    int vlan;
    char line[128], *p, *p1;
    char *ipmc_enable = nvram_safe_get("ipmc_enable");
    char *ipmc_type = nvram_safe_get("ipmc_type");

    if(((*ipmc_enable == '1')) && ((strlen(ipmc_type) == 0) || (*ipmc_type == '0')))
    {
    	unlink("/var/mrt.status");  
       	system("killall -SIGUSR1 pimd > /dev/null 2>&1");
    	check_file("/var/mrt.status");
    	 
        fp=fopen("/var/mrt.status","r+");
        if( fp != NULL)
        {    
            while(fgets(line,128,fp)!=NULL)
    	        vty_output(" %s", line);
    	    fclose(fp); 
    	}       
    }
    else
    {
        vty_output("Warning: PIM-SM is disabled on the devices\n"); 
    }    

    free(ipmc_enable);
    free(ipmc_type);
	return 0;
}

/*
 *  Function:  func_show_ip_sm_neighbor
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ip_sm_neighbor(struct users *u)
{
    FILE *fp;
    int vlan;
    char line[128], *p, *p1;
    char *ipmc_enable = nvram_safe_get("ipmc_enable");
    char *ipmc_type = nvram_safe_get("ipmc_type");

    if(((*ipmc_enable == '1')) && ((strlen(ipmc_type) == 0) || (*ipmc_type == '0')))
    {
    	unlink("/var/neighbors.status");   
       	system("killall -SIGUSR1 pimd > /dev/null 2>&1");
    	check_file("/var/neighbors.status");
    	 
        fp=fopen("/var/neighbors.status","r+");
        if( fp != NULL)
        {    
            while(fgets(line,128,fp)!=NULL)
    	        vty_output(" %s", line);
    	    fclose(fp); 
    	}         
    }
    else
    {
        vty_output("Warning: PIM-SM is disabled on the devices\n"); 
    }    

    free(ipmc_enable);
    free(ipmc_type);
	return 0;
}

/*
 *  Function:  func_show_ip_sm_neighbor_int
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ip_sm_neighbor_int(struct users *u)
{
	printf("do func_show_ip_sm_neighbor_int here\n");

	return 0;
}

/*
 *  Function:  func_show_ip_sm_rp
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ip_sm_rp(struct users *u)
{
    FILE *fp;
    int vlan;
    char line[128], *p, *p1;
    char *ipmc_enable = nvram_safe_get("ipmc_enable");
    char *ipmc_type = nvram_safe_get("ipmc_type");

    if(((*ipmc_enable == '1')) && ((strlen(ipmc_type) == 0) || (*ipmc_type == '0')))
    {
    	unlink("/var/rp.status");  
       	system("killall -SIGUSR1 pimd > /dev/null 2>&1");
    	check_file("/var/rp.status");
    	 
        fp=fopen("/var/rp.status","r+");
        if( fp != NULL)
        {    
            while(fgets(line,128,fp)!=NULL)
    	        vty_output(" %s", line);
    	    fclose(fp); 
    	}      
    }
    else
    {
        vty_output("Warning: PIM-SM is disabled on the devices\n"); 
    }    

    free(ipmc_enable);
    free(ipmc_type);
	return 0;
}

/*
 *  Function:  func_show_ip_sm_rp_map
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ip_sm_rp_map(struct users *u)
{
	printf("do func_show_ip_sm_rp_map here\n");

	return 0;
}


/*
 *  Function:  func_show_ip_sm_rp_met
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ip_sm_rp_met(struct users *u)
{
	printf("do func_show_ip_sm_rp_met here\n");

	return 0;
}

/*
 *  Function:  func_show_ipv6_mroute_pim
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ipv6_mroute_pim(struct users *u)
{
	printf("do func_show_ipv6_mroute_pim here\n");

	return 0;
}

/*
 *  Function:  func_show_ipv6_mroute_pim_group
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ipv6_mroute_pim_group(struct users *u)
{
	printf("do func_show_ipv6_mroute_pim_group here\n");

	return 0;
}

/*
 *  Function:  func_show_ipv6_mroute_pim_group_src
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ipv6_mroute_pim_group_src(struct users *u)
{
	printf("do func_show_ipv6_mroute_pim_group_src here\n");

	return 0;
}

/*
 *  Function:  cli_show_lldp_interface
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int cli_show_lldp_interface(struct users *u, int port_num)
{
	char *lldp_enable = nvram_safe_get("lldp_enable");

	if(port_num <= GNUM) {
		vty_output("GigaEthernet0/%d:\n",port_num);
	} else {
		vty_output("TenGigaEthernet0/%d:\n", (port_num-GNUM));
	}
	
	if(atoi(lldp_enable) == 1)
	{    
		vty_output(" Rx: enabled\n");
		vty_output(" Tx: enabled\n");
    }else
	{    
		vty_output(" Rx: disabled\n");
		vty_output(" Tx: disabled\n");
    }
	free(lldp_enable);
	return 0;
}

/*
 *  Function:  func_show_ipv6_mroute
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ipv6_mroute(struct users *u)
{
	printf("do func_show_ipv6_mroute here\n");

	return 0;
}

/*
 *  Function:  func_show_bfd_neighbors_details
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_bfd_neighbors_details(struct users *u)
{
    FILE *fp;
    int vlan;
    char line[128], *p, *p1;

   	system("killall -SIGUSR2 bfdd > /dev/null 2>&1");
	check_file("/var/ipv4_bfd");
	 
    fp=fopen("/var/ipv4_bfd", "r+");
    if( fp == NULL) return 0;
    
    fseek(fp,0,SEEK_SET);
    memset(line, '\0', 128); 
    while(fgets(line,128,fp)!=NULL)
    {     
        vty_output(" %s", line);
    }
    
    fclose(fp);    		  
    unlink("/var/ipv4_bfd");   
    
	return 0;
}

/*
 *  Function:  func_show_filter
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_filter(struct users *u)
{
	char *filter_enable = nvram_safe_get("filter_enable");
	char *filter_arp = nvram_safe_get("filter_arp_enable");
	char *filter_igmp = nvram_safe_get("filter_igmp_enable");
	char *filter_ip_source = nvram_safe_get("filter_ip_source_enable");
	char *filter_period_time = nvram_safe_get("filter_period_time");
	char *filter_threshold_value = nvram_safe_get("filter_threshold_value");
	char *filter_block_value = nvram_safe_get("filter_block_value");

	vty_output("filter configuration:\n");
	vty_output("-----------------------------------\n");
	vty_output("filter_enable          : %s\n", atoi(filter_enable)?"Enabled":"Disabled");
	vty_output("filter_arp             : %s\n", atoi(filter_arp)?"Enabled":"Disabled");	
	vty_output("filter_igmp            : %s\n", atoi(filter_igmp)?"Enabled":"Disabled");
	vty_output("filter_ip_source       : %s\n", atoi(filter_ip_source)?"Enabled":"Disabled");
	vty_output("filter_period_time     : %s\n", filter_period_time);
	vty_output("filter_threshold_value : %s\n", filter_threshold_value);
	vty_output("filter_block_value     : %s\n", filter_block_value);

	free(filter_enable);
	free(filter_arp);
	free(filter_igmp);
	free(filter_ip_source);
	free(filter_period_time);
	free(filter_threshold_value);
    free(filter_block_value);

	return;	
}

/*
 *  Function:  func_show_tunnel
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_tunnel(struct users *u)
{
	printf("do func_show_tunnel here\n");

	return 0;
}

/*
 *  Function:  func_show_cluster
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_cluster(struct users *u)
{
	FILE *fp;
	int enable, link, status, pkts, portid = 1;
	char *p1, *p2, *p3;
	char line[32], system_name[32], lldp_buf[1000]={'\0'};

	system("killall -SIGUSR1 stacking > /dev/null 2>&1");
	check_file("/tmp/stack.status");
        
	if((fp = fopen("/tmp/stack.status","r"))!=NULL)
	{	
        int id = 0;
        char buf[128], list[4][32];
        
        vty_output("%-4s%-18s%-26s%-8s\n","ID","IP ADRRESS","MAC ADRRESS","LiveTime");
        vty_output("%-4s%-18s%-26s%-8s\n","---","------------------","-------------------","---------");
        
        memset(buf, 0, sizeof(buf));
        while(fgets(buf, 128, fp)!=NULL)
        {
            memset(list, 0, sizeof(list));
            sscanf(buf,"%[^,],%[^,],%[^,],%[^,]", list[0],list[1],list[2],list[3]); 
            vty_output("%-4s%-18s%-26s%-8d\n", list[0], list[1], list[2], atoi(list[3]));    
        	
            memset(buf, 0, sizeof(buf));
        }
        fclose(fp);  
	}else
		vty_output("cluster protocol is down!\n");
		
	return 0;
}

/*
 *  Function:  func_show_ring_id
 *  Purpose:
 *  Parameters:
 *  						struct users *u
 *  Returns:
 *  
 *  Author:   xi.chen
 *  Date:    2011/11/26
 */
int func_show_ring_id(struct users *u)
{
	char *ring_enable= nvram_safe_get("ring");
	char *ring_type= nvram_safe_get("ring_type");
	char *ring_config= nvram_safe_get("ring_config");
	char *ring_ident= nvram_safe_get("ring_ident");
	
	char *ptr,*pt,*por;
	int group[2],ident[2],status[2];
	char *mode[2];
	int i,skfd,number;
	int portid[4];
	ptr = strchr(ring_ident, ':') + 1;
	cli_param_get_int(STATIC_PARAM, 0, &number, u);
  
	if((number!=atoi(ring_ident))&&(number!=atoi(ptr)))
	{
		vty_output("RING does not exist, Creating ring %d!\n",number);
		free(ring_enable);
		free(ring_type);
		free(ring_config);
		free(ring_ident);
		return -1;
	}
	pt = ring_config;
	for(i = 0; i < 4; i++) 
    {      	
    	portid[i] = atoi(pt);
    	pt = strchr(pt, ':') + 1;
	}	
		if((*ring_enable == '1')&&(*ring_type > '0'))
				{status[0]=1;status[1]=1;}
		else if(*ring_enable == '1')
			  {status[0]=1;status[1]=0;}
		else if(*ring_enable != '1')
				{status[0]=0;status[1]=0;}	  
		if(*ring_type == '1')
			mode[1]="double";
		else if(*ring_type == '2')
			mode[1]="coupling";				
		group[0]=1;group[1]=2;ident[0]=atoi(ring_ident);ident[1]=atoi(ptr);mode[0]="single";
		vty_output("%-10s%-10s%-10s%-20s%-33s\n","group","status","mode","ident","ports");
		vty_output("%-10s%-10s%-10s%-20s%-33s\n","------","------","------","------","-------------------------------");
		if(number==atoi(ring_ident)){		
				vty_output("%-10d%-10d%-10s%-20d",group[0],status[0],mode[0],ident[0],portid[0],portid[1]);
					if(portid[0]<= FNUM)
             				 vty_output("F0/%-2d,",portid[0]);
              else
               			vty_output("G0/%-2d,",portid-FNUM);
           if(portid[1]<= FNUM)
             				 vty_output("F0/%-2d\n",portid[0]);
              else
               			vty_output("G0/%-2d\n",portid-FNUM);    			
           
      }     		
		if(number==atoi(ptr)){
				vty_output("%-10d%-10d%-10s%-20d",group[1],status[1],mode[1],ident[1],portid[2],portid[3]);
				if(portid[2]<= FNUM)
             				 vty_output("F0/%-2d,",portid[2]);
              else
               			vty_output("G0/%-2d,",portid-FNUM);
           if(portid[3]<= FNUM)
             				 vty_output("F0/%-2d\n",portid[3]);
              else
               			vty_output("G0/%-2d\n",portid-FNUM);  
       }   

	free(ring_enable);
	free(ring_type);
	free(ring_config);
	free(ring_ident);

	return 0;     			  		              			
}			
	
void func_show_ring(int id)
{
	FILE *fp;
	char tmp[8];
    int state = 0;
    cli_ring_conf conf;
	
    memset(&conf, '\0', sizeof(cli_ring_conf));
    cli_nvram_conf_get(CLI_RING_INFO, (unsigned char *)&conf);
    
    memset(tmp, '\0', 8);
    fp=fopen("/tmp/complete","r");
    if(fp!=NULL)
    {	
        fgets(tmp,8,fp);
        fclose(fp);	
        state = atoi(tmp);		
    }

    vty_output("Ring Status: %s\n", (conf.enable == 1)?"Enable":"Disable");
    vty_output("%-10s%-10s%-10s%-20s%-33s\n","group","status","mode","ident","ports");
    vty_output("%-10s%-10s%-10s%-20s%-33s\n","------","------","------","------","-------------------------------");

    if(conf.enable == 1)
    {    
        vty_output("%-10d%-10s%-10s%-20d", 1, (state>10)?"success":"trying", "single", conf.ident[0]);
            
        if(conf.ports[0] != 0)
        {        
            if(conf.ports[0]<= FNUM)
                vty_output("F0/%-2d,",conf.ports[0]);
            else
                vty_output("G0/%-2d,",conf.ports[0]-FNUM);
        }    
          
        if(conf.ports[1] != 0)
        {        
            if(conf.ports[1]<= FNUM)
                vty_output("F0/%-2d",conf.ports[1]);
            else
                vty_output("G0/%-2d",conf.ports[1]-FNUM);    			
        }
        vty_output("\n");
        
        if(conf.type > 0)
        {    
            vty_output("%-10d%-10s%-10s%-20d", 2, (state%2)?"success":"trying", (conf.type == 1)?"double":"coupling", conf.ident[1]);
                 
            if(conf.ports[2] != 0)
            {      
                if(conf.ports[2]<= FNUM)
                    vty_output("F0/%-2d,",conf.ports[2]);
                else
                    vty_output("G0/%-2d,",conf.ports[2]-FNUM);
            }  
             
            if((conf.type == 1)&&(conf.ports[3] != 0))
            {        
                if(conf.ports[3]<= FNUM)
                    vty_output("F0/%-2d",conf.ports[3]);
                else
                    vty_output("G0/%-2d",conf.ports[3]-FNUM);
            }  
            vty_output("\n");      
        }     
    } 
          
	return 0;
}											
int func_show_erps_ring_id(struct users *u)
{   
    int number;
	char szBuf[256];
    cli_param_get_int(STATIC_PARAM, 0, &number, u);
	printf("rint number:%d\r\n",number);

	memset(szBuf,0,sizeof(szBuf));
	sprintf(szBuf,"nvram set erps_cmd=\"show_ring;%d\"",number);
	system(szBuf);
}
int func_show_erps_instance_id(struct users *u)
{

    int number;
	char szBuf[256];
    cli_param_get_int(STATIC_PARAM, 0, &number, u);
	//printf("instance number:%d\r\n",number);
	memset(szBuf,0,sizeof(szBuf));
	sprintf(szBuf,"nvram set erps_cmd=\"show_inst;%d\"",number);
    system(szBuf);
}


