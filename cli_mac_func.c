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

#include "cli_mac_func.h"
#include "acl_utils.h"
#include "bcmutils.h"

#define db_mac(fmt,arg...)		//printf("%s %d "fmt,__FUNCTION__,__LINE__,##arg)
/*--------------------------------------do_port do_gport-------------------------------*/

static int cli_add_static_mct_mac(uint64 mac,  uint16 vid,  uint64_t bmap)
{
    uint64_t smac = mac, bitmap = bmap;
    uint16 s_vid = vid;
    
    smac |= (((uint64_t)s_vid)<<48);
    
    multiaddr_set(smac, bitmap, 256, 0);

	system("/usr/bin/killall -SIGUSR1 snoop > /dev/null 2>&1");
        
    return 0;
}
static int cli_write_mct_to_nvram(char *entry_mac, char *entry_vid, char *entry_port)
{
    int vid=0, flag=0;
    char *p, *ptr;
    char mac[20];
    char * maclist = nvram_safe_get("mct_staticmac");
    char *buff;
    
    buff = malloc(strlen(maclist) + 512);
    if(buff == NULL)
        return -1;        
    memset(buff, '\0', strlen(maclist) + 512);    
                  
    if(strlen(maclist))
    {        
        p = maclist;
        
        while(strchr(p, ';') != NULL)
        {
            memset(mac, '\0', 20);
            ptr = strchr(p, ':');   
            memcpy(mac, p, ptr-p);
            
            if(strcmp(mac, entry_mac))
            {
                flag = 0;
                ptr = strchr(p, ';');
                p = ptr+1; 
                continue;    
            }   
                
            p = ptr + 1;
            vid = atoi(p);
            
            if(vid != atoi(entry_vid))
            {
                flag = 0;
                ptr = strchr(p, ';');
                p = ptr+1;
                continue; 
            }           
            
            //had the entry, modified port range
            flag = 1;                               
            
            ptr = strchr(p , ':');
            p = ptr + 1;
            strncat(buff, maclist, p-maclist);
            strcat(buff, entry_port);
            
            ptr= strchr(p, ';');
            p = ptr;
            strcat(buff, p);                       
                       
            break;
        }       
    }
    
    //append entry
    if(0 == flag)
    {
        memcpy(buff, maclist, strlen(maclist));
        strcat(buff, entry_mac);
        strcat(buff, ":");
        strcat(buff, entry_vid);
        strcat(buff, ":");
        strcat(buff, entry_port);
        strcat(buff, ";");
    }
             
    nvram_set("mct_staticmac", buff);
    
    free(buff);
    free(maclist);
    return 0;
}
//******muticast end******
static int cli_write_uct_to_nvram(char *entry_mac, char *entry_vid, char *entry_port)
{
    char * maclist = nvram_safe_get("lock_mac_list");
    char *buff, *p;
    
    buff = malloc(strlen(maclist) + 512);
    if(buff == NULL){
		free(maclist);
		return -1;
	}
    memset(buff, '\0', strlen(maclist) + 512); 
    
    p = strstr(maclist, entry_mac);
    
    if(NULL == p)
    {
        memcpy(buff, maclist, strlen(maclist));
        strcat(buff, entry_mac);
        strcat(buff, "|");
        strcat(buff, entry_vid);
        strcat(buff, "|");
        strcat(buff, entry_port);
        strcat(buff, ";");        
    }
    else
    {
        strncat(buff, maclist, p - maclist);
        strcat(buff, entry_mac);
        strcat(buff, "|");
        strcat(buff, entry_vid);
        strcat(buff, "|");
        strcat(buff, entry_port);
        strcat(buff, ";");
        
        p = strchr(p, ';')+1;
        strcat(buff, p);        
    }
    
    nvram_set("lock_mac_list", buff);
    nvram_set("lock_enable", "1");
    
    free(buff);
    free(maclist);
    return 0;
}


/*----------------------------------------set mac addr-----------------------*/                               
int func_set_mac_static_address(int flag, char *mac_str, char *vid_str, char *port_str)
{
    char mac[13], temp[3];
    char *p, *ptr, *entry_mac, *entry_port, *entry_vid=vid_str;
    int port=0;
    uint64_t mac64=0x00ULL, bmap=0x00ULL;
    uint16 vid;
    
    //convert MAC
    memset(mac, '\0', 13);
    p = mac_str;
      
    while(strchr(p, ':') != NULL)
    {
        ptr = strchr(p , ':');
        strncat(mac, p, ptr-p);      
        p= ptr+1;
    }
    strcat(mac, p);     
    input_num(mac, 1, 8, &mac64);

    memset(mac, '\0', 13);
    sprintf(mac, "%04x%08x", (uint16)(mac64>>32), (uint32)(mac64));        
    entry_mac = mac;
    
    //convert vid
    vid = (uint16)(atoi(vid_str));
    
    //multicast mac address        
    if((mac64>>40)%2)   
    {
        //convert port range
        p = port_str;       
        str2bit(p, &bmap);

#if (XPORT==0)	        
        //Giga port
        if(1 == flag)
        {
        	bmap <<= (phy[FNUM+1]-phy[1]);     //move to left (phy[25]-phy[1])
        	entry_port = bit2str(bmap);
        }
        //FastEthernet port
        else
            entry_port = p;
#endif  
#if (XPORT==1)	        
        //Giga port
        if(1 == flag)
            entry_port = p;
        //FastEthernet port
        else
        {
        	bmap <<= phy[GNUM+1];     //move to left (phy[25]-phy[1])
        	entry_port = bit2str(bmap);
        }
#endif              
        cli_add_static_mct_mac(mac64, vid, bmap);                
        cli_write_mct_to_nvram(entry_mac, entry_vid, entry_port);
    }
    //unicast mac address    
    else   
    {
        //convert port
        p = port_str;         
        memset(temp, '\0', 3);    
        port = atoi(p);   
#if (XPORT==0)	     
        //Giga port
        if(1 == flag)
        	port += FNUM;
#endif  
#if (XPORT==1)	    
        if(2 == flag)
        	port += GNUM;
#endif      
        sprintf(temp, "%d", port);
        entry_port = temp;
                                      
        cli_write_uct_to_nvram(entry_mac, entry_vid, entry_port);
        system("rc lock restart > /dev/null 2>&1");
    }
    syslog(LOG_NOTICE, "[CONFIG-5-MAC]: Set the MAC address of the port %s in vlan %s to %s, %s\n", port_str, vid_str, mac_str, getenv("LOGIN_LOG_MESSAGE"));
    
    return CLI_SUCCESS;
}



int cli_set_acl_nvram(char *name_str)
{
	char *mac_acl  = nvram_safe_get("mac_acl");
	char *str;
	MAC_ACL_ENTRY entry;
	IP_STANDARD_ACL_ENTRY entry1;
	IP_EXTENDED_ACL_ENTRY entry2;
	int res;
	
	memset(&entry, '\0', sizeof(MAC_ACL_ENTRY));
	memset(&entry1, '\0', sizeof(IP_STANDARD_ACL_ENTRY));
	memset(&entry2, '\0', sizeof(IP_EXTENDED_ACL_ENTRY));
	
	/* check if name exists in extended acl list, -1:not exist, 0:exist */
	res = ip_ext_acl_set(name_str, &entry2, ACL_NAME_CHECK, -1, 0x00ULL);
	/* exist */
	if(0 == res)
	{
		free(mac_acl);
		printf("A named Extended IP access list with this name already exists\n");
		return -2;
	}
	
	/* check if name exists in standard acl list, -1:not exist, 0:exist */
	res = ip_std_acl_set(name_str, &entry1, ACL_NAME_CHECK, -1, 0x00ULL);
	/* exist */
	if(0 == res)
	{
		free(mac_acl);
		printf("A named Standard IP access list with this name already exists\n");
		return -2;
	}
	
	res = mac_acl_set(name_str, &entry, ACL_LIST_ADD, -1, 0x00ULL);
	/* this name has be exist or malloc space fail for new node */
	if(res == -1){
		free(mac_acl);
		return -1;
	}
	/* name is not exist */
	str = malloc(strlen(mac_acl) + 64);
	if(NULL == str)
	{
		free(mac_acl);
		return -1;
	}
	memset(str, '\0', strlen(mac_acl) + 64);
	strcpy(str, mac_acl);
	strcat(str, name_str);
	strcat(str, "|;");
	
	nvram_set("mac_acl", str);
	
	free(str);
	free(mac_acl);
	return CLI_SUCCESS;
}

/*-------------------------------------------no mac------------------------*/
/* delete mac acl list with specific name */
static int cli_delete_mac_acl_list(char *name)
{
	int res, i, flag=0;
	MAC_ACL_ENTRY entry;
	char *acl_name, *mac_acl, *port_acl, *buff, *p, *ptr;
	char temp[ACL_NAME_LEN+3], port_acl_name[1024];
	POLICY_CLASSIFY classify;
	
	memset(&classify, '\0', sizeof(POLICY_CLASSIFY));
	memset(&entry, '\0', sizeof(MAC_ACL_ENTRY));
	res = mac_acl_set(name, &entry, ACL_NAME_CHECK, -1, 0x00ULL);
	if(res)
	{
		vty_output("Can not find MAC Access-List %s\n", name);
		return -1;
	}
	
	/* write policy start*/
//	classify.type_flag = CLASSIFY_TYPE_MAC;
//	strcpy(classify.name, name);
//	/* get policy classify num based on acl with the name */
//	res = policy_set("", &classify, POLICY_ACL_NUM, 0, 0x00ULL);
//	if(res)
//	{
//		vty_output("MAC Access-List %s is included in policy-map, please delete it from policy-map first!\n", name);
//		return -1;
//	}
		
	/* delete mac Access-List*/
	mac_acl_set(name, &entry, ACL_LIST_DEL, -1, 0x00ULL);
		
	/* following is to modify nvram value */	
	acl_name = nvram_safe_get("acl_name");
	mac_acl  = nvram_safe_get("mac_acl");
	//port_acl = nvram_safe_get("port_mac_acl");
	port_acl = cli_nvram_safe_get(CLI_PORT_ACL, "port_mac_acl");
	
	/* set acl_name */
	if(0 == strcmp(acl_name, name))
		nvram_set("acl_name","");     
	
	/* set mac_acl */	
	memset(temp, '\0', ACL_NAME_LEN+3);
	strcpy(temp, name);
	strcat(temp, "|");
	p = strstr(mac_acl, temp);
	
	if(NULL == p)
	{
		free(mac_acl);
		free(acl_name);
		free(port_acl);
		return -1;
	}
	
	if(p != mac_acl)
	{
		memset(temp, '\0', ACL_NAME_LEN+3);
		strcat(temp, ";");
		strcat(temp, name);
		strcat(temp, "|");
		p = strstr(mac_acl, temp);
		
		if(NULL == p)
		{
			free(mac_acl);
			free(acl_name);
			free(port_acl);
			return -1;
		}
		p++;
	}
	
	buff = malloc(strlen(mac_acl));
	if(NULL == buff)
	{
		free(mac_acl);
		free(acl_name);
		free(port_acl);
		return -1;
	}
	memset(buff, '\0', strlen(mac_acl));
	
	strncpy(buff, mac_acl, p-mac_acl);
	p = strchr(p, ';');
	p++;
	strcat(buff, p);
	
	nvram_set("mac_acl", buff);  
	
	/* set port_mac_acl */
	p = port_acl;
	memset(port_acl_name, '\0', 1024);
	for(i = 0; i < PNUM; i++)
	{
		memset(temp, '\0', ACL_NAME_LEN+3);
		ptr = strchr(p, ',');
		strncpy(temp, p, ptr-p);
		
		if(0 == strcmp(temp, name))
		{
			flag = 1;
			strcat(port_acl_name, ",");
		}
		else
		{
			strcat(port_acl_name, temp);
			strcat(port_acl_name, ",");	
		}		
		p = ptr+1;
	}
	
	if(flag)
		nvram_set("port_mac_acl", port_acl_name);
	
	free(buff);
	free(mac_acl);
	free(acl_name);
	free(port_acl);
	syslog(LOG_NOTICE, "[CONFIG-5-NO]: Deleted the MAC address by name %s, %s\n", name, getenv("LOGIN_LOG_MESSAGE"));
	return 0;
}

int func_mac_acl_name(struct users *u)
{
	char acl_name[MAX_ARGV_LEN] = {'\0'};

	cli_param_get_string(STATIC_PARAM, 0, acl_name, u);

	//cli_set_acl_nvram(acl_name);
	if(cli_set_acl_nvram(acl_name) == -2)
		return -1;
	
	nvram_set("acl_name", acl_name);
	syslog(LOG_NOTICE, "[CONFIG-5-MAC]: The access list name was set to %s, %s\n", acl_name, getenv("LOGIN_LOG_MESSAGE"));

	return 0;
}

int nfunc_mac_acl_name(struct users *u)
{
	char acl_name[MAX_ARGV_LEN] = {'\0'};

	cli_param_get_string(STATIC_PARAM, 0, acl_name, u);

	cli_delete_mac_acl_list(acl_name);
	
	return 0;
}
static int cli_del_mct_from_nvram(char *entry_mac, char *entry_vid)
{
    char * maclist = nvram_safe_get("mct_staticmac");
    char *buff, *p;    
    int vid;
    
    buff = malloc(strlen(maclist));
    if(buff == NULL){
		free(maclist);
        return -1;
	}
    memset(buff, '\0', strlen(maclist));
    
    p = strstr(maclist, entry_mac);
    
    if(p != NULL)
    {
        strncat(buff, maclist, p - maclist);  
        p = strchr(p, ':') + 1;
        vid = atoi(p);
        if(vid == atoi(entry_vid))  
        {           
            p = strchr(p, ';') + 1;
            strcat(buff, p); 
            
            nvram_set("mct_staticmac", buff);
        }
    }
        
    free(buff);
    free(maclist);
    return 0;
}
static int cli_del_static_mct_mac(uint64 mac,  uint16 vid,  uint64_t bmap)
{
    uint64_t smac = mac, bitmap = bmap;
    uint16 s_vid = vid;
    
    smac |= (((uint64_t)s_vid)<<48);
    
    multiaddr_set(smac, bitmap, 256, 0);

	system("/usr/bin/killall -SIGUSR1 snoop > /dev/null 2>&1");
        
    return 0;
}
static int cli_del_uct_from_nvram(char *entry_mac, char *entry_vid)
{
    char * maclist = nvram_safe_get("lock_mac_list");
    char *buff, *p;    
    int vid;
    
    buff = malloc(strlen(maclist)+1);
    if(buff == NULL){
		free(maclist);
        return -1;        
	}
    
    p = strstr(maclist, entry_mac);
    if(p != NULL)
    {                
    	memset(buff, '\0', strlen(maclist)+1);
        strncat(buff, maclist, p - maclist);  
        p = strchr(p, '|') + 1;
        vid = atoi(p);
        if(vid == atoi(entry_vid))  
        {           
            p = strchr(p, ';') + 1;
            strcat(buff, p); 
            
            nvram_set("lock_mac_list", buff);
            if(strlen(buff) < 10)
                nvram_set("lock_enable", "0");
        }
    }
        
    free(buff);
    free(maclist);
    return 0;
}
static int cli_del_static_mac_by_mac_vid(char *mac_str, char *vid_str)
{
    char mac[13];
    char *p, *ptr, *entry_mac, *entry_vid = vid_str;
    uint64_t mac64=0x00ULL;
    
    //convert MAC
    memset(mac, '\0', 13);
    p = mac_str;
        
    while(strchr(p, ':') != NULL)
    {
        ptr = strchr(p , ':');
        strncat(mac, p, ptr-p);      
        p= ptr+1;
    }
    strcat(mac, p); 
    input_num(mac, 1, 8, &mac64);
    memset(mac, '\0', 13);
    sprintf(mac, "%04x%08x", (uint16)(mac64>>32), (uint32)(mac64));
    entry_mac = mac;
    
    //multicast mac address        
    if((mac64>>40)%2) 
    {
        /*
        *
        *  add multicast mac deleting action
        *
        */
        
        cli_del_mct_from_nvram(entry_mac, entry_vid);
        cli_del_static_mct_mac(mac64, atoi(entry_vid), 0x00ULL);
        
    }
    //unicast mac address
    else
    {
        cli_del_uct_from_nvram(entry_mac, entry_vid);
        system("rc lock restart > /dev/null 2>&1");
    }
    
    syslog(LOG_NOTICE, "[CONFIG-5-NO]: Delete static MAC address by MAC %s and vid %s, %s\n", mac_str, vid_str, getenv("LOGIN_LOG_MESSAGE"));
    return CLI_SUCCESS;
}
int nfunc_mac_by_mac_vid(struct users *u)
{
	int vlan = 0;
	char vlan_num[MAX_ARGV_LEN] = {'\0'};
	char mac_add[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_int(STATIC_PARAM, 0, &vlan, u);
	sprintf(vlan_num,"%d",vlan);
	cli_param_get_string(STATIC_PARAM, 0, mac_add, u);
	cli_del_static_mac_by_mac_vid(mac_add,vlan_num);
	
	return 0;
}

/*---------------------------------- func_cli_set_aging_time-------------------------------*/


//set aging time
int func_set_aging_time(char *age)
{    
    int skfd, time = atoi(age);
    if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
        return -1;
        
    bcm_set_age_time(skfd, time);
    nvram_set("age_time", age); 
    close(skfd);   
    syslog(LOG_NOTICE, "[CONFIG-5-MAC]: The age time was set to %d, %s\n", time, getenv("LOGIN_LOG_MESSAGE")); 
    return CLI_SUCCESS;
}

/*----------------------------------------------no aging time----------------------*/
int func_set_mac_blackhole(char *macstr,int vid)
{    
    int skfd;
    uint64_t mac = 0;
    char *bk = NULL;  
    char *pt = NULL;
    
    if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
        return -1;
    
    mac = str2mac_blackhole(macstr);
    bcm_l2_addr_blackhole(skfd,vid,&mac);
    close(skfd);
    
    bk = nvram_safe_get("mac_bloackhole");    
    pt = calloc(strlen(bk)+strlen("11:22:33:44:55:66,_vid;")+1,sizeof(char));
    if(pt == NULL){
    	perror("callos fail\n");
		free(bk);
    	return -1;
    }
    
    memcpy(pt,bk,strlen(bk));
    sprintf(&pt[strlen(pt)],"%s,%d;",macstr,vid);
    nvram_set("mac_bloackhole", pt);
    
    syslog(LOG_NOTICE, "[CONFIG-5-MAC]: The mac blackhole set to %d, %s\n", time, getenv("LOGIN_LOG_MESSAGE")); 
    
    free(pt);
    free(bk);
    
    return CLI_SUCCESS;
}

/*
	É¾³ýMacºÚ¶´Ê±£¬Í¬Ê±É¾³ýÏàÓ¦macºÚ¶´ÅäÖÃ by liujh
*/

int func_del_mac_blackhole(char *macstr,int vid)
{    
	uint64_t mac = 0;
    int skfd;
    char *pbk = NULL;
    char *p = NULL,*pstr = NULL,*pchr = NULL,*pvid = NULL;
	char tbuf[64] = {0};
    
    if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
        return -1;

	pbk = nvram_safe_get("mac_bloackhole");
	if(strlen(pbk) == 0){
		close(skfd);   
	    return CLI_FAILED;
	}
	    
	sprintf(tbuf,"%s,%d;",macstr,vid);
	
    db_mac("pbk %s tbuf %s\n",pbk,tbuf);
    if((p = strcasestr(pbk,tbuf,strlen(tbuf))) == NULL){
    	printf("Max not exist!\n");
		free(pbk);
		close(skfd);   
    	return CLI_FAILED;
    }
   
    pchr = strchr(p,';');
    db_mac("pchr %s\n",pchr);
    
    if(NULL == pchr){
    	perror("strche don't find ; ");
		free(pbk);
		close(skfd);
    	return -1;
    }
    
	pstr = calloc(strlen(pbk),sizeof(char));
	if(NULL == pstr){
    	perror("calloc fail");
		free(pbk);
		close(skfd);
		return -1;
	}
	
	memcpy(pstr,pchr+1,strlen(pchr));
    strcpy(p,pstr);
    
    db_mac("macstr:%s pbk:%s\n",macstr,pbk);
    nvram_set("mac_bloackhole", pbk);
    
    mac = str2mac_blackhole(macstr);
    bcm_l2_addr_del(skfd,0,vid,&mac);
    close(skfd);   
    syslog(LOG_NOTICE, "[CONFIG-5-MAC]: The mac blackhole delete to %d, %s\n", time, getenv("LOGIN_LOG_MESSAGE")); 

    free(pstr);
    free(pbk);
    
    return CLI_SUCCESS;
}

int nfunc_set_aging_time_default()
{
    int skfd;
    char *age = nvram_safe_get_def("age_time");
    
    if((skfd = open(DEVICE_FILE_NAME, 0)) < 0) 
        return -1;
    
    nvram_set("age_time", age);
    
    bcm_set_age_time(skfd, atoi(age));
    
    free(age);
    close(skfd);
    syslog(LOG_NOTICE, "[CONFIG-5-NO]: Set the aging time to default, %s\n", getenv("LOGIN_LOG_MESSAGE"));
    return CLI_SUCCESS;
}






