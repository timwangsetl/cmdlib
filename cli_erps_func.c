/*
 * Copyright 2016 by Kuaipao Corporation
 * 
 * All Rights Reserved
 * 
 * File name  : cli_clock_func.c
 * Function   : show command function
 * Auther     : dawei.hu
 * Version    : 1.0
 * Date       : 2011/11/21
 *                                         
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

#include <arpa/inet.h>

#include "console.h"
#include "cmdparse.h"
#include "parameter.h"

#include "cli_erps_func.h"
#include "bcmutils.h"

static int strsplit(char *str, char separator, char **p, int max) // str will be modified
{
    int i, j, len;

	if(NULL == str)
	{
	    return 0;
	}
	if( atoi(str) <= 0)
	{
	    return 0;
	}
    for (i = 0; i < max; i++) {
        p[i] = "";
    }
    len = strlen(str);
    p[0] = str;
    j = 1;
    for (i = 0; i < len; i++) {
        if (str[i] == separator) {
            str[i] = 0;
            if (j < max) {
                p[j++] = &str[i + 1];
            }
        }
    }
    return j;
}

static int erps_default_config(int inst,char **p,int len)
{
   int i = 0;
   static char erps_default[CONFIG_NUM][32];

   memset(erps_default,0,sizeof(erps_default));
   if(len > CONFIG_NUM)
   {
      return 0;
   }
   for (i = 0; i < len; i++)
   {
        p[i] = "";
   }
   //mst id
   sprintf(erps_default[1],"%d",0);
   //ring id
   sprintf(erps_default[2],"%d",1);
   //level 
   sprintf(erps_default[3],"%d",0);
   // profile default
   sprintf(erps_default[4],"%s","Default");
   //
   sprintf(erps_default[5],"%s","none");

   sprintf(erps_default[6],"%d" ,1000+inst);

   for(i = 0 ; i < len;i++)
   {
       p[i] = erps_default[i];     
   }
   return 0;
  
   
}


int func_erps_no_ring_config(struct users *u)
{    
    int ring_id = 0;
	int port_east = 0;
	int port_west = 0;
    char szbuff[1024] = {'\0'},*pszBuf; 
	char *rings[40];
    char *str = nvram_safe_get("erps_ring");
    if (!str || !str[0])
		return;
    int ringnum = strsplit(str, '|', rings, 40);
    char *cfg[4];
    int i,len,flag = 0;
    

	//printf("config:%s\r\n",erps_ring);
    cli_param_get_int(STATIC_PARAM, 0, &ring_id, u);

	cli_param_get_int(STATIC_PARAM, 1, &port_east, u);
	
	cli_param_get_int(STATIC_PARAM, 2, &port_west, u);


     pszBuf = szbuff;
    for (i = 0;i < ringnum;i++)
	{
        strsplit(rings[i], ';', cfg, 4);
        //printf("id=%s, east=%s, west=%s\r\n", cfg[0], cfg[1], cfg[2]);
		if(ring_id == atoi(cfg[0]))
		{
			flag = 1;
		}
		else if( atoi(cfg[0]) > 0)
		{
		    sprintf(pszBuf,"%s;%s;%s|",cfg[0], cfg[1], cfg[2]);
		}
		pszBuf =szbuff+strlen(szbuff); 
    }
    //printf("ring:%d port_west:%d,%d ,buf:%s\r\n",ring_id,port_east,port_west,szbuff);
    
	if(ringnum  > 1 )
	{
	    szbuff[strlen(szbuff)-1] = 0;
	}
	free(str);
    nvram_set("erps_ring",szbuff);
    //printf("ring:%d port_west:%d,%d ,buf:%s\r\n",ring_id,port_east,port_west,szbuff);
	//system("cat dfd > /tmp/tmp.txt");
	 // vty_output("Set the forward-delay to default(15s) failed!\n");
	return 0;
}

int func_erps_ring_config(struct users *u)
{
    int ring_id = 0;
	int port_east = 0;
	int port_west = 0;
    char szbuff[1024] = {'\0'},*pszBuf; 
	char *rings[40];
    char *str = nvram_safe_get("erps_ring");
    if (!str || !str[0]) return;
    int ringnum = strsplit(str, '|', rings, 40);
    char *cfg[4];
    int i,len,flag = 0;
    

	//printf("config:%s\r\n",erps_ring);
    cli_param_get_int(STATIC_PARAM, 0, &ring_id, u);

	cli_param_get_int(STATIC_PARAM, 1, &port_east, u);
	
	cli_param_get_int(STATIC_PARAM, 2, &port_west, u);


     pszBuf = szbuff;
    for (i = 0;i < ringnum;i++)
	{
        strsplit(rings[i], ';', cfg, 4);
        //printf("id=%s, east=%s, west=%s\r\n", cfg[0], cfg[1], cfg[2]);
		if(ring_id == atoi(cfg[0]))
		{
		    sprintf(pszBuf,"%d;%d;%d|",ring_id,port_east,port_west);
			flag = 1;
		}
		else
		{
		    sprintf(pszBuf,"%s;%s;%s|",cfg[0], cfg[1], cfg[2]);
		}
		pszBuf =szbuff+strlen(szbuff); 
    }
    //printf("ring:%d port_west:%d,%d ,buf:%s\r\n",ring_id,port_east,port_west,szbuff);
    if(0 == flag)
    {
	   sprintf(pszBuf,"%d;%d;%d",ring_id,port_east,port_west);	    
	}
	else
	{
	    szbuff[strlen(szbuff)-1] = 0;
	}
	
    nvram_set("erps_ring",szbuff);
    //printf("ring:%d port_west:%d,%d ,buf:%s\r\n",ring_id,port_east,port_west,szbuff);
	free(str);
	return 0;
}


int func_erps_inst_raps_vlan_config(struct users *u)
{
	char *str = nvram_safe_get("erps_inst");
	char *insts[40];    
    int instan_id = 0,i;
	int para1 = 0,flag = 0;
	char szbuff[MAX_ARGV_LEN] = {'\0'},*pszBuf; 
    int instnum = strsplit(str, '|', insts, 40);
    char *cfg[CONFIG_NUM];

	instan_id = atoi(u->promptbuf);
    cli_param_get_int(STATIC_PARAM, 0, &para1, u);  

    pszBuf = szbuff;
    for (i = 0; i < instnum; i++)
	{
        strsplit(insts[i], ';', cfg, CONFIG_NUM);
	    if(instan_id == atoi(cfg[0]))
	    {
	         flag = 1;
	         sprintf(pszBuf,"%d;%s;%s;%s;%s;%s;%d;%s;%s;|",instan_id,cfg[1],cfg[2],cfg[3],cfg[4],cfg[5],para1,cfg[7],cfg[8]);
	    }
	    else
	    {
		     sprintf(pszBuf,"%s;%s;%s;%s;%s;%s;%s;%s;%s;|",cfg[0],cfg[1],cfg[2],cfg[3],cfg[4],cfg[5],cfg[6],cfg[7],cfg[8]);
	    }
		pszBuf =szbuff+strlen(szbuff); 
	   
    } 
	if(0 == flag)
    {
        erps_default_config(instan_id,cfg,CONFIG_NUM);
	    sprintf(pszBuf,"%d;%s;%s;%s;%s;%s;%d;%s;%s;",instan_id,cfg[1],cfg[2],cfg[3],cfg[4],cfg[5],para1,cfg[7],cfg[8]);  
	}
	else
	{
	    szbuff[strlen(szbuff)-1] = 0;
	}	
	
	nvram_set("erps_inst",szbuff);
    free(str);
	return 0;
}

int func_erps_inst_profile_config(struct users *u)
{
	char *str = nvram_safe_get("erps_inst");
	char *insts[40];    
    int instan_id = 0,i;
	int para1 = 0,flag = 0;
	char szbuff[MAX_ARGV_LEN] = {'\0'},*pszBuf; 
    int instnum = strsplit(str, '|', insts, 40);
    char *cfg[CONFIG_NUM];
	char profileName[32];

	instan_id = atoi(u->promptbuf);
    memset(profileName,0,sizeof(profileName));
	cli_param_get_string(STATIC_PARAM, 0, profileName, u);
   
    pszBuf = szbuff;
    for (i = 0; i < instnum; i++)
	{
	    //printf("inst:%s\r\n",insts[i]);
        strsplit(insts[i], ';', cfg, CONFIG_NUM);
	    if(instan_id == atoi(cfg[0]))
	    {
	         flag = 1;
	         sprintf(pszBuf,"%d;%s;%s;%s;%s;%s;%s;%s;%s;|",instan_id,cfg[1],cfg[2],cfg[3],profileName,cfg[5],cfg[6],cfg[7],cfg[8]);
	    }
	    else
	    {
		     sprintf(pszBuf,"%s;%s;%s;%s;%s;%s;%s;%s;%s;|",cfg[0],cfg[1],cfg[2],cfg[3],cfg[4],cfg[5],cfg[6],cfg[7],cfg[8]);
	    }
		pszBuf =szbuff+strlen(szbuff); 
	   
    } 
	if(0 == flag)
    {
        erps_default_config(instan_id,cfg,CONFIG_NUM);
	    sprintf(pszBuf,"%d;%s;%s;%s;%s;%s;%s;%s;%s;",instan_id,cfg[1],cfg[2],cfg[3],profileName,cfg[5],cfg[6],cfg[7],cfg[8]);  
	}
	else
	{
	    szbuff[strlen(szbuff)-1] = 0;
	}	
	
	nvram_set("erps_inst",szbuff);
	free(str);
	return 0;
}

int func_erps_inst_profile_default_config(struct users *u)
{
	char *str = nvram_safe_get("erps_inst");
	char *insts[40];    
    int instan_id = 0,i;
	int para1 = 0,flag = 0;
	char szbuff[MAX_ARGV_LEN] = {'\0'},*pszBuf; 
    int instnum = strsplit(str, '|', insts, 40);
    char *cfg[CONFIG_NUM];
	char profileName[32];

	instan_id = atoi(u->promptbuf);
    memset(profileName,0,sizeof(profileName));
	cli_param_get_string(STATIC_PARAM, 0, profileName, u);
   
    pszBuf = szbuff;
    for (i = 0; i < instnum; i++)
	{
	    //printf("inst:%s\r\n",insts[i]);
        strsplit(insts[i], ';', cfg, CONFIG_NUM);
	    if(instan_id == atoi(cfg[0]))
	    {
	         flag = 1;
	         sprintf(pszBuf,"%d;%s;%s;%s;%s;%s;%s;%s;%s;|",instan_id,cfg[1],cfg[2],cfg[3],"Default",cfg[5],cfg[6],cfg[7],cfg[8]);
	    }
	    else
	    {
		     sprintf(pszBuf,"%s;%s;%s;%s;%s;%s;%s;%s;%s;|",cfg[0],cfg[1],cfg[2],cfg[3],cfg[4],cfg[5],cfg[6],cfg[7],cfg[8]);
	    }
		pszBuf =szbuff+strlen(szbuff); 
	   
    } 
	if(0 == flag)
    {
         erps_default_config(instan_id,cfg,CONFIG_NUM);
	    sprintf(pszBuf,"%d;%s;%s;%s;%s;%s;%s;%s;%s;",instan_id,cfg[1],cfg[2],cfg[3],"Default",cfg[5],cfg[6],cfg[7],cfg[8]);  
	}
	else
	{
	    szbuff[strlen(szbuff)-1] = 0;
	}	
	
	nvram_set("erps_inst",szbuff);
    free(str);
	return 0;
}

int func_erps_inst_level_config(struct users *u)
{
	char *str = nvram_safe_get("erps_inst");
	char *insts[40];    
    int instan_id = 0,i;
	int para1 = 0,flag = 0;
	char szbuff[MAX_ARGV_LEN] = {'\0'},*pszBuf; 
    int instnum = strsplit(str, '|', insts, 40);
    char *cfg[CONFIG_NUM];

	instan_id = atoi(u->promptbuf);
    cli_param_get_int(STATIC_PARAM, 0, &para1, u);  

    pszBuf = szbuff;
    for (i = 0; i < instnum; i++)
	{
	    strsplit(insts[i], ';', cfg, CONFIG_NUM);
	    if(instan_id == atoi(cfg[0]))
	    {
	         flag = 1;
	         sprintf(pszBuf,"%d;%s;%s;%d;%s;%s;%s;%s;%s;|",instan_id,cfg[1],cfg[2],para1,cfg[4],cfg[5],cfg[6],cfg[7],cfg[8]);
	    }
	    else
	    {
		     sprintf(pszBuf,"%s;%s;%s;%s;%s;%s;%s;%s;%s;|",cfg[0],cfg[1],cfg[2],cfg[3],cfg[4],cfg[5],cfg[6],cfg[7],cfg[8]);
	    }
		pszBuf =szbuff+strlen(szbuff); 
	   
    } 
	if(0 == flag)
    {
        erps_default_config(instan_id,cfg,CONFIG_NUM);
	    sprintf(pszBuf,"%d;%s;%s;%d;%s;%s;%s;%s;%s;",instan_id,cfg[1],cfg[2],para1,cfg[4],cfg[5],cfg[6],cfg[7],cfg[8]);  
	}
	else
	{
	    szbuff[strlen(szbuff)-1] = 0;
	}	
	//printf("\r\nconfig:%s\r\n",szbuff);
	free(str);	
    nvram_set("erps_inst",szbuff);
    //printf("inst:%d vlan%d\r\n",instan_id,para1);
	//system("cat dfd > /tmp/tmp.txt");
	 // vty_output("Set the forward-delay to default(15s) failed!\n");
	return 0;
}


int func_erps_inst_rpl_owner_east_config(struct users *u)
{
	char *str = nvram_safe_get("erps_inst");
	char *insts[40];    
    int instan_id = 0,i;
	int para1 = 0,flag = 0;
	char szbuff[MAX_ARGV_LEN] = {'\0'},*pszBuf; 
    int instnum = strsplit(str, '|', insts, 40);
    char *cfg[CONFIG_NUM];

	instan_id = atoi(u->promptbuf);
    cli_param_get_int(STATIC_PARAM, 0, &para1, u);  

      pszBuf = szbuff;
    for (i = 0; i < instnum; i++)
	{
	    //printf("inst:%s\r\n",insts[i]);
        strsplit(insts[i], ';', cfg, CONFIG_NUM);
	    if(instan_id == atoi(cfg[0]))
	    {
	         flag = 1;
	         sprintf(pszBuf,"%d;%s;%s;%s;%s;%s;%s;%s;%s;|",instan_id,cfg[1],cfg[2],cfg[3],cfg[4],"east",cfg[6],cfg[7],cfg[8]);
	    }
	    else
	    {
		     sprintf(pszBuf,"%s;%s;%s;%s;%s;%s;%s;%s;%s;|",cfg[0],cfg[1],cfg[2],cfg[3],cfg[4],cfg[5],cfg[6],cfg[7],cfg[8]);
	    }
		pszBuf =szbuff+strlen(szbuff); 
	   
    } 
	if(0 == flag)
    {
        erps_default_config(instan_id,cfg,CONFIG_NUM);
	    sprintf(pszBuf,"%d;%s;%s;%s;%s;%s;%s;%s;%s;",instan_id,cfg[1],cfg[2],"east",cfg[4],"east",cfg[6],cfg[7],cfg[8]);  
	}
	else
	{
	    szbuff[strlen(szbuff)-1] = 0;
	}	
	//printf("\r\nconfig:%s\r\n",szbuff);
	free(str);
    nvram_set("erps_inst",szbuff);
    //printf("inst:%d vlan%d\r\n",instan_id,para1);
	//system("cat dfd > /tmp/tmp.txt");
	 // vty_output("Set the forward-delay to default(15s) failed!\n");
	return 0;
}
int func_erps_inst_rpl_owner_west_config(struct users *u)
{
	char *str = nvram_safe_get("erps_inst");
	char *insts[40];    
    int instan_id = 0,i;
	int para1 = 0,flag = 0;
	char szbuff[MAX_ARGV_LEN] = {'\0'},*pszBuf; 
    int instnum = strsplit(str, '|', insts, 40);
    char *cfg[CONFIG_NUM];

	instan_id = atoi(u->promptbuf);
    cli_param_get_int(STATIC_PARAM, 0, &para1, u);  

      pszBuf = szbuff;
    for (i = 0; i < instnum; i++)
	{
	    //printf("inst:%s\r\n",insts[i]);
        strsplit(insts[i], ';', cfg, CONFIG_NUM);
	    if(instan_id == atoi(cfg[0]))
	    {
	         flag = 1;
	         sprintf(pszBuf,"%d;%s;%s;%s;%s;%s;%s;%s;%s;|",instan_id,cfg[1],cfg[2],cfg[3],cfg[4],"west",cfg[6],cfg[7],cfg[8]);
	    }
	    else
	    {
		     sprintf(pszBuf,"%s;%s;%s;%s;%s;%s;%s;%s;%s;|",cfg[0],cfg[1],cfg[2],cfg[3],cfg[4],cfg[5],cfg[6],cfg[7],cfg[8]);
	    }
		pszBuf =szbuff+strlen(szbuff); 
	   
    } 
	if(0 == flag)
    {
        erps_default_config(instan_id,cfg,CONFIG_NUM); 
	    sprintf(pszBuf,"%d;%s;%s;%s;%s;%s;%s;%s;%s;",instan_id,cfg[1],cfg[2],cfg[3],cfg[4],"west",cfg[6],cfg[7],cfg[8]);  
	}
	else
	{
	    szbuff[strlen(szbuff)-1] = 0;
	}	
	//printf("\r\nconfig:%s\r\n",szbuff);
	free(str);
    nvram_set("erps_inst",szbuff);
    //printf("inst:%d vlan%d\r\n",instan_id,para1);
	//system("cat dfd > /tmp/tmp.txt");
	 // vty_output("Set the forward-delay to default(15s) failed!\n");
	return 0;
}

int func_erps_inst_rpl_none_owner_config(struct users *u)
{
	char *str = nvram_safe_get("erps_inst");
	char *insts[40];    
    int instan_id = 0,i;
	int para1 = 0,flag = 0;
	char szbuff[MAX_ARGV_LEN] = {'\0'},*pszBuf; 
    int instnum = strsplit(str, '|', insts, 40);
    char *cfg[CONFIG_NUM];

	instan_id = atoi(u->promptbuf);
    cli_param_get_int(STATIC_PARAM, 0, &para1, u);  

    pszBuf = szbuff;
    for (i = 0; i < instnum; i++)
	{
	    strsplit(insts[i], ';', cfg, CONFIG_NUM);
	    if(instan_id == atoi(cfg[0]))
	    {
	         flag = 1;
	         sprintf(pszBuf,"%d;%s;%s;%s;%s;%s;%s;%s;%s;|",instan_id,cfg[1],cfg[2],cfg[3],cfg[4],"none",cfg[6],cfg[7],cfg[8]);
	    }
	    else
	    {
		     sprintf(pszBuf,"%s;%s;%s;%s;%s;%s;%s;%s;%s;|",cfg[0],cfg[1],cfg[2],cfg[3],cfg[4],cfg[5],cfg[6],cfg[7],cfg[8]);
	    }
		pszBuf =szbuff+strlen(szbuff); 
	   
    } 
	if(0 == flag)
    {
         erps_default_config(instan_id,cfg,CONFIG_NUM);
	    sprintf(pszBuf,"%d;%s;%s;%s;%s;%s;%s;%s;%s;",instan_id,cfg[1],cfg[2],cfg[3],cfg[4],"none",cfg[6],cfg[7],cfg[8]);  
	}
	else
	{
	    szbuff[strlen(szbuff)-1] = 0;
	}	
	free(str);	
    nvram_set("erps_inst",szbuff);    
	return 0;
}
int func_erps_inst_rpl_neighbor_east_config(struct users *u)
{
	char *str = nvram_safe_get("erps_inst");
	char *insts[40];    
    int instan_id = 0,i;
	int para1 = 0,flag = 0;
	char szbuff[MAX_ARGV_LEN] = {'\0'},*pszBuf; 
    int instnum = strsplit(str, '|', insts, 40);
    char *cfg[CONFIG_NUM];

	instan_id = atoi(u->promptbuf);
    cli_param_get_int(STATIC_PARAM, 0, &para1, u);  

      pszBuf = szbuff;
    for (i = 0; i < instnum; i++)
	{
	    strsplit(insts[i], ';', cfg, CONFIG_NUM);
	    if(instan_id == atoi(cfg[0]))
	    {
	         flag = 1;
	         sprintf(pszBuf,"%d;%s;%s;%s;%s;%s;%s;%s;%s;|",instan_id,cfg[1],cfg[2],cfg[3],cfg[4],"neib",cfg[6],cfg[7],cfg[8]);
	    }
	    else
	    {
		     sprintf(pszBuf,"%s;%s;%s;%s;%s;%s;%s;%s;%s;|",cfg[0],cfg[1],cfg[2],cfg[3],cfg[4],cfg[5],cfg[6],cfg[7],cfg[8]);
	    }
		pszBuf =szbuff+strlen(szbuff); 
	   
    } 
	if(0 == flag)
    {
         erps_default_config(instan_id,cfg,CONFIG_NUM); 
	    sprintf(pszBuf,"%d;%s;%s;%s;%s;%s;%s;%s;%s;",instan_id,cfg[1],cfg[2],cfg[3],cfg[4],"neib",cfg[6],cfg[7],cfg[8]);  
	}
	else
	{
	    szbuff[strlen(szbuff)-1] = 0;
	}	
	free(str);	
    nvram_set("erps_inst",szbuff);
    
	return 0;
}
int func_erps_inst_rpl_neighbor_west_config(struct users *u)
{
	char *str = nvram_safe_get("erps_inst");
	char *insts[40];    
    int instan_id = 0,i;
	int para1 = 0,flag = 0;
	char szbuff[MAX_ARGV_LEN] = {'\0'},*pszBuf; 
    int instnum = strsplit(str, '|', insts, 40);
    char *cfg[CONFIG_NUM];

	instan_id = atoi(u->promptbuf);
    cli_param_get_int(STATIC_PARAM, 0, &para1, u);  

    pszBuf = szbuff;
    for (i = 0; i < instnum; i++)
	{
	    //printf("inst:%s\r\n",insts[i]);
        strsplit(insts[i], ';', cfg, CONFIG_NUM);
	    if(instan_id == atoi(cfg[0]))
	    {
	         flag = 1;
	         sprintf(pszBuf,"%d;%s;%s;%s;%s;%s;%s;%s;%s;|",instan_id,cfg[1],cfg[2],cfg[3],cfg[4],"next",cfg[6],cfg[7],cfg[8]);
	    }
	    else
	    {
		     sprintf(pszBuf,"%s;%s;%s;%s;%s;%s;%s;%s;%s;|",cfg[0],cfg[1],cfg[2],cfg[3],cfg[4],cfg[5],cfg[6],cfg[7],cfg[8]);
	    }
		pszBuf =szbuff+strlen(szbuff); 
	   
    } 
	if(0 == flag)
    {
         erps_default_config(instan_id,cfg,CONFIG_NUM);
	    sprintf(pszBuf,"%d;%s;%s;%s;%s;%s;%s;%s;%s;",instan_id,cfg[1],cfg[2],cfg[3],cfg[4],"next",cfg[6],cfg[7],cfg[8]);  
	}
	else
	{
	    szbuff[strlen(szbuff)-1] = 0;
	}	
	nvram_set("erps_inst",szbuff);    
	free(str);

	return 0;
}

int func_erps_inst_rpl_next_neighbor_east_config(struct users *u)
{
	char *str = nvram_safe_get("erps_inst");
	char *insts[40];    
    int instan_id = 0,i;
	int para1 = 0,flag = 0;
	char szbuff[MAX_ARGV_LEN] = {'\0'},*pszBuf; 
    int instnum = strsplit(str, '|', insts, 40);
    char *cfg[CONFIG_NUM];

	instan_id = atoi(u->promptbuf);
    cli_param_get_int(STATIC_PARAM, 0, &para1, u);  

    pszBuf = szbuff;
    for (i = 0; i < instnum; i++)
	{
	    //printf("inst:%s\r\n",insts[i]);
        strsplit(insts[i], ';', cfg, CONFIG_NUM);
	    if(instan_id == atoi(cfg[0]))
	    {
	         flag = 1;
	         sprintf(pszBuf,"%d;%s;%s;%s;%d;%s;%s;%s;%s;|",instan_id,cfg[1],cfg[2],cfg[3],para1,cfg[5],cfg[6],cfg[7],cfg[8]);
	    }
	    else
	    {
		     sprintf(pszBuf,"%s;%s;%s;%s;%s;%s;%s;%s;%s;|",cfg[0],cfg[1],cfg[2],cfg[3],cfg[4],cfg[5],cfg[6],cfg[7],cfg[8]);
	    }
		pszBuf =szbuff+strlen(szbuff); 
	   
    } 
	if(0 == flag)
    {
         erps_default_config(instan_id,cfg,CONFIG_NUM);
	    sprintf(pszBuf,"%d;%s;%s;%s;%d;%s;%s;%s;%s;",instan_id,cfg[1],cfg[2],cfg[3],para1,cfg[5],cfg[6],cfg[7],cfg[8]);  
	}
	else
	{
	    szbuff[strlen(szbuff)-1] = 0;
	}	
	
    nvram_set("erps_inst",szbuff);
	free(str);    
	return 0;
}
int func_erps_inst_rpl_next_neighbor_west_config(struct users *u)
{
	char *str = nvram_safe_get("erps_inst");
	char *insts[40];    
    int instan_id = 0,i;
	int para1 = 0,flag = 0;
	char szbuff[MAX_ARGV_LEN] = {'\0'},*pszBuf; 
    int instnum = strsplit(str, '|', insts, 40);
    char *cfg[CONFIG_NUM];

	instan_id = atoi(u->promptbuf);
    cli_param_get_int(STATIC_PARAM, 0, &para1, u);  

      pszBuf = szbuff;
    for (i = 0; i < instnum; i++)
	{
	    //printf("inst:%s\r\n",insts[i]);
        strsplit(insts[i], ';', cfg, CONFIG_NUM);
	    if(instan_id == atoi(cfg[0]))
	    {
	         flag = 1;
	         sprintf(pszBuf,"%d;%s;%s;%s;%d;%s;%s;%s;%s;|",instan_id,cfg[1],cfg[2],cfg[3],para1,cfg[5],cfg[6],cfg[7],cfg[8]);
	    }
	    else
	    {
		     sprintf(pszBuf,"%s;%s;%s;%s;%s;%s;%s;%s;%s;|",cfg[0],cfg[1],cfg[2],cfg[3],cfg[4],cfg[5],cfg[6],cfg[7],cfg[8]);
	    }
		pszBuf =szbuff+strlen(szbuff); 
	   
    } 
	if(0 == flag)
    {
         erps_default_config(instan_id,cfg,CONFIG_NUM);
	    sprintf(pszBuf,"%d;%s;%s;%s;%d;%s;%s;%s;%s;",instan_id,cfg[1],cfg[2],cfg[3],para1,cfg[5],cfg[6],cfg[7],cfg[8]);  
	}
	else
	{
	    szbuff[strlen(szbuff)-1] = 0;
	}	
	//printf("\r\nconfig:%s\r\n",szbuff);
	
    nvram_set("erps_inst",szbuff);
 	free(str); 
	return 0;
}



int func_erps_inst_mst_id_config(struct users *u)
{
	char *str = nvram_safe_get("erps_inst");
	char *insts[40];    
    int instan_id = 0,i;
	int para1 = 0,flag = 0;
	char szbuff[MAX_ARGV_LEN] = {'\0'},*pszBuf; 
    int instnum = strsplit(str, '|', insts, 40);
    char *cfg[CONFIG_NUM];

	instan_id = atoi(u->promptbuf);
    cli_param_get_int(STATIC_PARAM, 0, &para1, u);  

      pszBuf = szbuff;
    for (i = 0; i < instnum; i++)
	{
	    //printf("inst:%s\r\n",insts[i]);
        strsplit(insts[i], ';', cfg, CONFIG_NUM);
	    if(instan_id == atoi(cfg[0]))
	    {
	         flag = 1;
	         sprintf(pszBuf,"%d;%d;%s;%s;%s;%s;%s;%s;%s;|",instan_id,para1,cfg[2],cfg[3],cfg[4],cfg[5],cfg[6],cfg[7],cfg[8]);
	    }
	    else
	    {
		     sprintf(pszBuf,"%s;%s;%s;%s;%s;%s;%s;%s;%s;|",cfg[0],cfg[1],cfg[2],cfg[3],cfg[4],cfg[5],cfg[6],cfg[7],cfg[8]);
	    }
		pszBuf =szbuff+strlen(szbuff); 
	   
    } 
	if(0 == flag)
    {
        erps_default_config(instan_id,cfg,CONFIG_NUM);
	    sprintf(pszBuf,"%d;%d;%s;%s;%d;%s;%s;%s;%s;",instan_id,para1,cfg[2],cfg[3],cfg[4],cfg[5],cfg[6],cfg[7],cfg[8]);  
	}
	else
	{
	    szbuff[strlen(szbuff)-1] = 0;
	}

	//printf("\r\nconfig:%s,ne:%s\r\n",str,szbuff);
	
    nvram_set("erps_inst",szbuff);
  	free(str); 
	return 0;
}

int func_erps_inst_ring_id_config(struct users *u)
{
	char *str = nvram_safe_get("erps_inst");
	char *insts[40];    
    int instan_id = 0,i;
	int para1 = 0,flag = 0;
	char szbuff[MAX_ARGV_LEN] = {'\0'},*pszBuf; 
    int instnum = strsplit(str, '|', insts, 40);
    char *cfg[CONFIG_NUM];

	instan_id = atoi(u->promptbuf);
    cli_param_get_int(STATIC_PARAM, 0, &para1, u);  

    pszBuf = szbuff;
    for (i = 0; i < instnum; i++)
	{
	    //printf("inst:%s\r\n",insts[i]);
        strsplit(insts[i], ';', cfg, CONFIG_NUM);
	    if(instan_id == atoi(cfg[0]))
	    {
	         flag = 1;
	         sprintf(pszBuf,"%d;%s;%d;%s;%s;%s;%s;%s;%s;|",instan_id,cfg[1],para1,cfg[3],cfg[4],cfg[5],cfg[6],cfg[7],cfg[8]);
	    }
	    else
	    {
		     sprintf(pszBuf,"%s;%s;%s;%s;%s;%s;%s;%s;%s;|",cfg[0],cfg[1],cfg[2],cfg[3],cfg[4],cfg[5],cfg[6],cfg[7],cfg[8]);
	    }
		pszBuf =szbuff+strlen(szbuff); 
	   
    } 
	if(0 == flag)
    {
         erps_default_config(instan_id,cfg,CONFIG_NUM);
	    sprintf(pszBuf,"%d;%s;%d;%s;%d;%s;%s;%s;%s;",instan_id,cfg[1],para1,cfg[3],cfg[4],cfg[5],cfg[6],cfg[7],cfg[8]);  
	}
	else
	{
	    szbuff[strlen(szbuff)-1] = 0;
	}	
	//printf("\r\nconfig:%s,ne:%s\r\n",str,szbuff);
	
    nvram_set("erps_inst",szbuff);
  	free(str);
	return 0;
}

int func_erps_inst_time_wait_to_config(struct users *u)
{
	char *erps_time = nvram_safe_get("erps_prof");
	char *insts[40];    
    int instan_id = 0,i;
	int para1 = 0,flag = 0;
	char szbuff[MAX_ARGV_LEN] = {'\0'},*pszBuf;	
	int ring_time = 0;
	int instnum;
	char *cfg[CONFIG_NUM];
    char *str_inst = nvram_safe_get("erps_inst");
	char *file_name[40];    
	
	//printf("config:%s\r\n",erps_time);
	cli_param_get_int(STATIC_PARAM, 0, &ring_time, u);


    instnum = strsplit(str_inst, '|', insts, 40);
	instan_id = atoi(u->promptbuf);
    for(i = 0 ; i < instnum;i++)
    {
        strsplit(insts[i], ';', cfg, 6);
        if(instan_id == atoi(cfg[0]))
        {
           memset(file_name,0,sizeof(file_name));
		   strcpy(file_name,cfg[4]);
        }		
    }

	//printf("wtb:%s\r\n",file_name); 
    instnum = strsplit(erps_time, '|', insts, 40);
    pszBuf = szbuff;
	memset(szbuff,0,sizeof(szbuff));
     
    for(i = 0 ; i < instnum;i++)
    {
        strsplit(insts[i], ';', cfg, CONFIG_NUM);
        if(0 == strcmp(file_name,cfg[0]))
		{
		    flag = 1;
		    sprintf(pszBuf,"%s;%d;%s;%s;%s;%s;|",cfg[0],ring_time*60,cfg[2],cfg[3],cfg[4],cfg[5]);
		}
		else
		{
		    sprintf(pszBuf,"%s;%s;%s;%s;%s;%s;|",cfg[0],cfg[1],cfg[2],cfg[3],cfg[4],cfg[5]);
		}
		pszBuf =szbuff+strlen(szbuff); 
    }
	
	if(0 == flag)
    {
	     sprintf(pszBuf,"%s;%d;%d;%s;%s;%s;",file_name,ring_time*60,5500,cfg[3],cfg[4],cfg[5]);  
	}
	else
	{
	    szbuff[strlen(szbuff)-1] = 0;
	}	
	//printf("wtb:%s\r\n",szbuff);
    nvram_set("erps_prof",szbuff);
	free(str_inst);
	free(erps_time);
	return 0;
}
int func_erps_inst_time_wait_to_default_config(struct users *u)
{
	char *erps_time = nvram_safe_get("erps_prof");
	char *insts[40];    
    int instan_id = 0,i;
	int para1 = 0,flag = 0;
	char szbuff[MAX_ARGV_LEN] = {'\0'},*pszBuf;	
	int ring_time = 0;
	int instnum;
	char *cfg[CONFIG_NUM];
	char *str_inst = nvram_safe_get("erps_inst");
	char *file_name[40];
	
	cli_param_get_int(STATIC_PARAM,0, &ring_time, u);
	instnum = strsplit(str_inst, '|', insts, 40);
	instan_id = atoi(u->promptbuf);
    for(i = 0 ; i < instnum;i++)
    {
        strsplit(insts[i], ';', cfg, 6);
        if(instan_id == atoi(cfg[0]))
        {
           memset(file_name,0,sizeof(file_name));
		   strcpy(file_name,cfg[4]);
        }		
    }
    
    instnum = strsplit(erps_time, '|', insts, 40);

    pszBuf = szbuff;
	memset(szbuff,0,sizeof(szbuff));
    //printf("instnum:%d\r\n",instnum);
	 
    for(i = 0 ; i < instnum;i++)
    {
        strsplit(insts[i], ';', cfg, CONFIG_NUM);
		if(0 == strcmp(file_name,cfg[0]))
		{
		    flag = 1;
		   sprintf(pszBuf,"%s;%d;%s;%s;%s;%s;|",cfg[0],300,cfg[2],cfg[3],cfg[4],cfg[5]);
		}
		else
		{
		    sprintf(pszBuf,"%s;%s;%s;%s;%s;%s;|",cfg[0],cfg[1],cfg[2],cfg[3],cfg[4],cfg[5]);
		}
		pszBuf =szbuff+strlen(szbuff); 
    }
	if(0 == flag)
    {
	     sprintf(pszBuf,"%s;%d;%d;%s;%s;%s;",file_name,300,5500,cfg[3],cfg[4],cfg[5]);  
	}
	else
	{
	    szbuff[strlen(szbuff)-1] = 0;
	}	
    nvram_set("erps_prof",szbuff);
	free(str_inst);
	free(erps_time);

	return 0;
}

int func_erps_inst_time_hold_off_config(struct users *u)
{
	char *erps_time = nvram_safe_get("erps_prof");
	char *insts[40];    
    int instan_id = 0,i;
	int para1 = 0,flag = 0;
	char szbuff[MAX_ARGV_LEN] = {'\0'},*pszBuf;	
	int ring_time = 0;
	int instnum;
	char *cfg[CONFIG_NUM];
	char *str_inst = nvram_safe_get("erps_inst");
	char *file_name[40];
	
	
	cli_param_get_int(STATIC_PARAM, 0, &ring_time, u);
    
    instan_id = atoi(u->promptbuf);
    instnum = strsplit(str_inst, '|', insts, 40);
    for(i = 0 ; i < instnum;i++)
    {
        strsplit(insts[i], ';', cfg, 6);
        if(instan_id == atoi(cfg[0]))
        {
           memset(file_name,0,sizeof(file_name));
		   strcpy(file_name,cfg[4]);
        }		
    }
	 
    instnum = strsplit(erps_time, '|', insts, 40);
    pszBuf = szbuff;
	memset(szbuff,0,sizeof(szbuff)); 
    for(i = 0 ; i < instnum;i++)
    {
        strsplit(insts[i], ';', cfg, CONFIG_NUM);
        if(0 == strcmp(file_name,cfg[0]))
		{
		    flag = 1;
		    sprintf(pszBuf,"%s;%s;%s;%s;%d;%s;|",cfg[0],cfg[1],cfg[2],cfg[3],ring_time,cfg[5]);
        }
		else
		{
		    sprintf(pszBuf,"%s;%s;%s;%s;%s;%s;|",cfg[0],cfg[1],cfg[2],cfg[3],cfg[4],cfg[5]);
		}
		pszBuf =szbuff+strlen(szbuff); 
    }
	if(0 == flag)
    {
	     sprintf(pszBuf,"%s;%s;%d;%s;%d;%s;",file_name,cfg[1],5500,cfg[3],ring_time,cfg[5]);  
	}
	else
	{
	    szbuff[strlen(szbuff)-1] = 0;
	}	
    nvram_set("erps_prof",szbuff);
	free(str_inst);
	free(erps_time);

	return 0;
}

int func_erps_inst_time_hold_off_default_config(struct users *u)
{
	char *erps_time = nvram_safe_get("erps_prof");
	char *insts[40];    
    int instan_id = 0,i;
	int para1 = 0,flag = 0;
	char szbuff[MAX_ARGV_LEN] = {'\0'},*pszBuf;	
	int ring_time = 0;
	int instnum;
	char *cfg[CONFIG_NUM];
	char *str_inst = nvram_safe_get("erps_inst");
	char *file_name[40];
	
	
	cli_param_get_int(STATIC_PARAM, 0, &ring_time, u);
    
    instan_id = atoi(u->promptbuf);
    instnum = strsplit(str_inst, '|', insts, 40);
    for(i = 0 ; i < instnum;i++)
    {
        strsplit(insts[i], ';', cfg, 6);
        if(instan_id == atoi(cfg[0]))
        {
           memset(file_name,0,sizeof(file_name));
		   strcpy(file_name,cfg[4]);
        }		
    }
	 
    instnum = strsplit(erps_time, '|', insts, 40);
   
	pszBuf = szbuff;
	memset(szbuff,0,sizeof(szbuff)); 
    for(i = 0 ; i < instnum;i++)
    {
        strsplit(insts[i], ';', cfg, CONFIG_NUM);
        if(0 == strcmp(file_name,cfg[0]))
		{
		    flag = 1;
		    sprintf(pszBuf,"%s;%s;%s;%s;%d;%s;|",cfg[0],cfg[1],cfg[2],cfg[3],0,cfg[5]);
        }
		else
		{
		    sprintf(pszBuf,"%s;%s;%s;%s;%s;%s;|",cfg[0],cfg[1],cfg[2],cfg[3],cfg[4],cfg[5]);
		}
		pszBuf =szbuff+strlen(szbuff); 
    }
	if(0 == flag)
    {
	     sprintf(pszBuf,"%s;%s;%d;%s;%d;%s;",file_name,cfg[1],5500,cfg[3],0,cfg[5]);  
	}
	else
	{
	    szbuff[strlen(szbuff)-1] = 0;
	}	
    nvram_set("erps_prof",szbuff);
	free(str_inst);
	free(erps_time);

	return 0;
}

int func_erps_inst_time_guand_time_config(struct users *u)
{
	char *erps_time = nvram_safe_get("erps_prof");
	char *insts[40];    
    int instan_id = 0,i;
	int para1 = 0,flag = 0;
	char szbuff[MAX_ARGV_LEN] = {'\0'},*pszBuf;	
	int ring_time = 0;
	int instnum;
	char *cfg[CONFIG_NUM];
	char *str_inst = nvram_safe_get("erps_inst");
	char *file_name[40];
	
	cli_param_get_int(STATIC_PARAM, 0, &ring_time, u);
     instnum = strsplit(str_inst, '|', insts, 40);
	 instan_id = atoi(u->promptbuf);
    for(i = 0 ; i < instnum;i++)
    {
        strsplit(insts[i], ';', cfg, 6);
        if(instan_id == atoi(cfg[0]))
        {
           memset(file_name,0,sizeof(file_name));
		   strcpy(file_name,cfg[4]);
        }		
    } 

	instnum = strsplit(erps_time, '|', insts, 40);

    pszBuf = szbuff;
	memset(szbuff,0,sizeof(szbuff)); 
    for(i = 0 ; i < instnum;i++)
    {
        strsplit(insts[i], ';', cfg, CONFIG_NUM);
		if(0 == strcmp(file_name,cfg[0]))
		{
		    flag = 1;
		    sprintf(pszBuf,"%s;%s;%s;%d;%s;%s;|",cfg[0],cfg[1],cfg[2],ring_time,cfg[4],cfg[5]);
		}
		else
		{
		    sprintf(pszBuf,"%s;%s;%s;%s;%s;%s;|",cfg[0],cfg[1],cfg[2],cfg[3],cfg[4],cfg[5]);
		}
		pszBuf =szbuff+strlen(szbuff); 
    }
	if(0 == flag)
    {
	     sprintf(pszBuf,"%s;%s;%d;%d;%s;%s;",file_name,cfg[1],5500,ring_time,cfg[4],cfg[5]);  
	}
	else
	{
	    szbuff[strlen(szbuff)-1] = 0;
	}	
    nvram_set("erps_prof",szbuff);
	free(str_inst);
	free(erps_time);

	return 0;
}

int func_erps_inst_time_guand_time_default_config(struct users *u)
{
	char *erps_time = nvram_safe_get("erps_prof");
	char *insts[40];    
    int instan_id = 0,i;
	int para1 = 0,flag = 0;
	char szbuff[MAX_ARGV_LEN] = {'\0'},*pszBuf;	
	int ring_time = 0;
	int instnum;
	char *cfg[CONFIG_NUM];
	char *str_inst = nvram_safe_get("erps_inst");
	char *file_name[40];
	
	cli_param_get_int(STATIC_PARAM, 0, &ring_time, u);

    instnum = strsplit(str_inst, '|', insts, 40);
	instan_id = atoi(u->promptbuf);
    for(i = 0 ; i < instnum;i++)
    {
        strsplit(insts[i], ';', cfg, 6);
        if(instan_id == atoi(cfg[0]))
        {
           memset(file_name,0,sizeof(file_name));
		   strcpy(file_name,cfg[4]);
        }		
    } 
	
    instnum = strsplit(erps_time, '|', insts, 40);
    pszBuf = szbuff;
	memset(szbuff,0,sizeof(szbuff)); 
    for(i = 0 ; i < instnum;i++)
    {
        strsplit(insts[i], ';', cfg, CONFIG_NUM);
		if(0 == strcmp(file_name,cfg[0]))
		{
		    flag = 1;
		    sprintf(pszBuf,"%s;%s;%s;%d;%s;%s;|",cfg[0],cfg[1],cfg[2],500,cfg[4],cfg[5]);
		}
		else
		{
		    sprintf(pszBuf,"%s;%s;%s;%s;%s;%s;|",cfg[0],cfg[1],cfg[2],cfg[3],cfg[4],cfg[5]);
		}
		pszBuf =szbuff+strlen(szbuff); 
    }

	if(0 == flag)
    {
	     sprintf(pszBuf,"%s;%s;%d;%d;%s;%s;",file_name,cfg[1],5500,500,cfg[4],cfg[5]);  
	}
	else
	{
	    szbuff[strlen(szbuff)-1] = 0;
	}	
    nvram_set("erps_prof",szbuff);
	free(str_inst);
	free(erps_time);

	return 0;
}


int func_erps_inst_revert_config(struct users *u)
{
	char *erps_time = nvram_safe_get("erps_prof");
	char *insts[40];
	char *file_name[40];    
    int instan_id = 0,i;
	int para1 = 0,flag = 0;
	char szbuff[MAX_ARGV_LEN] = {'\0'},*pszBuf;	
	int ring_time = 0;
	int instnum;
	char *cfg[CONFIG_NUM];
	char *str_inst = nvram_safe_get("erps_inst");
	
	cli_param_get_int(STATIC_PARAM, 0, &ring_time, u);

    instan_id = atoi(u->promptbuf); 
	
    instnum = strsplit(str_inst, '|', insts, 40);
    for(i = 0 ; i < instnum;i++)
    {
        strsplit(insts[i], ';', cfg, 6);
        if(instan_id == atoi(cfg[0]))
        {
           memset(file_name,0,sizeof(file_name));
		   strcpy(file_name,cfg[4]);
        }		
    }
	//printf("func_erps_inst_revert_config:%s,file:%s\r\n",erps_time,file_name);
    instnum = strsplit(erps_time, '|', insts, 40);

    pszBuf = szbuff;
	memset(szbuff,0,sizeof(szbuff));  
    for(i = 0 ; i < instnum;i++)
    {
        strsplit(insts[i], ';', cfg, 6);
		if(0 == strcmp(file_name,cfg[0]))
		{
		    flag = 1;
		    sprintf(pszBuf,"%s;%s;%s;%s;%s;%d;|",cfg[0],cfg[1],cfg[2],cfg[3],cfg[4],1);
		}
		else
		{
		    sprintf(pszBuf,"%s;%s;%s;%s;%s;%s;|",cfg[0],cfg[1],cfg[2],cfg[3],cfg[4],cfg[5]);
		}
		pszBuf =szbuff+strlen(szbuff); 
    }
	if(0 == flag)
    {
	     sprintf(pszBuf,"%s;%s;%d;%s;%s;%d;",file_name,cfg[1],5500,cfg[3],cfg[4],1);  
	}
	else
	{
	    szbuff[strlen(szbuff)-1] = 0;
	}	
    nvram_set("erps_prof",szbuff);
	free(str_inst);
	free(erps_time);

	return 0;
}

int func_erps_inst_none_revert_config(struct users *u)
{
	char *erps_time = nvram_safe_get("erps_prof");
	char *insts[40];    
    int instan_id = 0,i;
	int para1 = 0,flag = 0;
	char szbuff[MAX_ARGV_LEN] = {'\0'},*pszBuf;	
	int instnum;
	char *cfg[CONFIG_NUM];
	char *str_inst = nvram_safe_get("erps_inst");
	char *file_name[40];
	
	//printf("func_erps_inst_none_revert_config:%s\r\n",erps_time);

	instnum = strsplit(str_inst, '|', insts, 40);
	instan_id = atoi(u->promptbuf);
    for(i = 0 ; i < instnum;i++)
    {
        strsplit(insts[i], ';', cfg, 6);
        if(instan_id == atoi(cfg[0]))
        {
           memset(file_name,0,sizeof(file_name));
		   strcpy(file_name,cfg[4]);
        }		
    }
	
    instnum = strsplit(erps_time, '|', insts, 40);
	pszBuf = szbuff;
	memset(szbuff,0,sizeof(szbuff));  
    for(i = 0 ; i < instnum;i++)
    {
        strsplit(insts[i], ';', cfg, CONFIG_NUM);
		if(0 == strcmp(file_name,cfg[0]))
		{
		    flag = 1;
    	    sprintf(pszBuf,"%s;%s;%s;%s;%s;%d;|",cfg[0],cfg[1],cfg[2],cfg[3],cfg[4],0);
		}
		else
		{
		    sprintf(pszBuf,"%s;%s;%s;%s;%s;%s;|",cfg[0],cfg[1],cfg[2],cfg[3],cfg[4],cfg[5]);
		}
		pszBuf =szbuff+strlen(szbuff); 
    }

	if(0 == flag)
    {
	     sprintf(pszBuf,"%s;%s;%d;%s;%s;%d;",file_name,cfg[1],5500,cfg[3],cfg[4],0);  
	}
	else
	{
	    szbuff[strlen(szbuff)-1] = 0;
	}	
    nvram_set("erps_prof",szbuff);
	free(str_inst);
	free(erps_time);

	return 0;
}


int func_erps_inst_instance_id_config(struct users *u)
{
	//char *erps_ring = nvram_safe_get("erps_inst");
		
	int ring_id = 0;
	//int port_east = 0;
	//int port_west = 0;
	//char szbuff[MAX_ARGV_LEN] = {'\0'}; 

	//printf("instan id:%s\r\n",erps_ring);
	cli_param_get_int(STATIC_PARAM, 0, &ring_id, u);

	return 0;
}
int func_erps_inst_instance_ring_id_config(struct users *u)
{
	//char *erps_ring = nvram_safe_get("erps_inst");
		
	int ring_id = 0;
	int para1 = 0;
	//int para2 = 0;
	//char szbuff[MAX_ARGV_LEN] = {'\0'}; 

	//printf("ring:%s\r\n",erps_ring);
	cli_param_get_int(STATIC_PARAM, 0, &ring_id, u);

	cli_param_get_int(STATIC_PARAM, 1, &para1, u);
    //printf("ring id:%d,%d\r\n",ring_id,para1);

	return 0;
}


int func_erps_inst_sub_ring_east_config(struct users *u)
{
	char *str = nvram_safe_get("erps_inst");
	char *insts[40];    
    int instan_id = 0,i;
	int para1 = 0,flag = 0;
	char szbuff[MAX_ARGV_LEN] = {'\0'},*pszBuf; 
    int instnum = strsplit(str, '|', insts, 40);
    char *cfg[CONFIG_NUM];

	instan_id = atoi(u->promptbuf);
    cli_param_get_int(STATIC_PARAM, 0, &para1, u);  

    pszBuf = szbuff;
    for (i = 0; i < instnum; i++)
	{
	    //printf("inst:%s\r\n",insts[i]);
        strsplit(insts[i], ';', cfg, CONFIG_NUM);
	    if(instan_id == atoi(cfg[0]))
	    {
	         flag = 1;
	         sprintf(pszBuf,"%d;%s;%s;%s;%s;%s;%s;%s;%s;|",instan_id,cfg[1],cfg[2],cfg[3],cfg[4],cfg[5],cfg[6],cfg[7],"east");
	    }
	    else
	    {
		     sprintf(pszBuf,"%s;%s;%s;%s;%s;%s;%s;%s;%s;|",cfg[0],cfg[1],cfg[2],cfg[3],cfg[4],cfg[5],cfg[6],cfg[7],cfg[8]);
	    }
		pszBuf =szbuff+strlen(szbuff); 
	   
    } 
	if(0 == flag)
    {
	     erps_default_config(instan_id,cfg,CONFIG_NUM);
	    sprintf(pszBuf,"%d;%s;%s;%s;%s;%s;%s;%s;%s;",instan_id,cfg[1],cfg[2],cfg[3],cfg[4],cfg[5],cfg[6],cfg[7],"east");  
	}
	else
	{
	    szbuff[strlen(szbuff)-1] = 0;
	}	
	//printf("\r\nconfig:%s\r\n",szbuff);
	
    nvram_set("erps_inst",szbuff);
	free(str);
	return 0;
}

int func_erps_inst_sub_ring_west_config(struct users *u)
{
	char *str = nvram_safe_get("erps_inst");
	char *insts[40];    
    int instan_id = 0,i;
	int para1 = 0,flag = 0;
	char szbuff[MAX_ARGV_LEN] = {'\0'},*pszBuf; 
    int instnum = strsplit(str, '|', insts, 40);
    char *cfg[CONFIG_NUM];

	instan_id = atoi(u->promptbuf);
    cli_param_get_int(STATIC_PARAM, 0, &para1, u);  

    pszBuf = szbuff;
    for (i = 0; i < instnum; i++)
	{
	    //printf("inst:%s\r\n",insts[i]);
        strsplit(insts[i], ';', cfg, CONFIG_NUM);
	    if(instan_id == atoi(cfg[0]))
	    {
	         flag = 1;
	         sprintf(pszBuf,"%d;%s;%s;%s;%s;%s;%s;%s;%s;|",instan_id,cfg[1],cfg[2],cfg[3],cfg[4],cfg[5],cfg[6],cfg[7],"west");
	    }
	    else
	    {
		     sprintf(pszBuf,"%s;%s;%s;%s;%s;%s;%s;%s;%s;|",cfg[0],cfg[1],cfg[2],cfg[3],cfg[4],cfg[5],cfg[6],cfg[7],cfg[8]);
	    }
		pszBuf =szbuff+strlen(szbuff); 
	   
    } 
	if(0 == flag)
    {
	     erps_default_config(instan_id,cfg,CONFIG_NUM);
	    sprintf(pszBuf,"%d;%s;%s;%s;%s;%s;%s;%s;%s;",instan_id,cfg[1],cfg[2],cfg[3],cfg[4],cfg[5],cfg[6],cfg[7],"west");  
	}
	else
	{
	    szbuff[strlen(szbuff)-1] = 0;
	}	
	
	free(str);	
    nvram_set("erps_inst",szbuff);
   
	return 0;
}

int func_erps_inst_virtual_instance_config(struct users *u)
{
	char *str = nvram_safe_get("erps_inst");
	char *insts[40];    
    int instan_id = 0,i;
	int para1 = 0,flag = 0;
	char szbuff[MAX_ARGV_LEN] = {'\0'},*pszBuf; 
    int instnum = strsplit(str, '|', insts, 40);
    char *cfg[8];

	instan_id = atoi(u->promptbuf);
    cli_param_get_int(STATIC_PARAM, 0, &para1, u);  

    pszBuf = szbuff;
    for (i = 0; i < instnum; i++)
	{
	    //printf("inst:%s\r\n",insts[i]);
        strsplit(insts[i], ';', cfg, 8);
	    if(instan_id == atoi(cfg[0]))
	    {
	         flag = 1;
	         sprintf(pszBuf,"%d;%s;%s;%s;%s;%s;%s;%d;%s;|",instan_id,cfg[1],cfg[2],cfg[3],cfg[4],cfg[5],cfg[6],para1,cfg[8]);
	    }
	    else
	    {
		     sprintf(pszBuf,"%s;%s;%s;%s;%s;%s;%s;%s;%s;|",cfg[0],cfg[1],cfg[2],cfg[3],cfg[4],cfg[5],cfg[6],cfg[7],cfg[8]);
	    }
		pszBuf =szbuff+strlen(szbuff); 
	   
    } 
	if(0 == flag)
    {
	     erps_default_config(instan_id,cfg,CONFIG_NUM);
	    sprintf(pszBuf,"%d;%s;%s;%s;%s;%s;%s;%d;%s;",instan_id,cfg[1],cfg[2],cfg[3],cfg[4],cfg[5],cfg[6],para1,cfg[8]);  
	}
	else
	{
	    szbuff[strlen(szbuff)-1] = 0;
	}	
	free(str);	
    nvram_set("erps_inst",szbuff);
  
	return 0;
}

int func_erps_inst_delete_config(struct users *u)
{
	char *str = nvram_safe_get("erps_inst");
	char *insts[40];    
    int instan_id = 0,i;
	int para1 = 0,flag = 0;
	char szbuff[MAX_ARGV_LEN] = {'\0'},*pszBuf; 
    int instnum = strsplit(str, '|', insts, 40);
    char *cfg[8];

	instan_id = atoi(u->promptbuf);
    cli_param_get_int(STATIC_PARAM, 0, &para1, u);  

    pszBuf = szbuff;
    for (i = 0; i < instnum; i++)
	{
	    strsplit(insts[i], ';', cfg, 8);
	    if(para1 == atoi(cfg[0]))
	    {
	         flag = 1;	        
	    }
	    else
	    {
		     sprintf(pszBuf,"%s;%s;%s;%s;%s;%s;%s;|",cfg[0],cfg[1],cfg[2],cfg[3],cfg[4],cfg[5],cfg[6]);
	    }
		pszBuf =szbuff+strlen(szbuff); 
	   
    }
	
	szbuff[strlen(szbuff)-1] = 0;
	free(str);	
    nvram_set("erps_inst",szbuff);
  
	return 0;
}
int func_show_erps_profile(struct users *u)
{

    int number;
	char szBuf[256];
	char *insts[40];    
    int instan_id = 0,i;
	
	int instnum;
	char *cfg[CONFIG_NUM];
	char *str = nvram_safe_get("erps_prof");
    cli_param_get_int(STATIC_PARAM, 0, &number, u);
	//printf("instance number:%d\r\n",number);
	memset(szBuf,0,sizeof(szBuf));
	sprintf(szBuf,"nvram set erps_cmd=\"show_prof;Default\"");

    system(szBuf);
	instnum = strsplit(str, '|', insts, 40);

    sleep(1);
    for(i = 0 ; i < instnum;i++)
    {
        strsplit(insts[i], ';', cfg, 6);
		if(0 == strcmp("Default",cfg[0]))
		{
		    continue;
		}
        memset(szBuf,0,sizeof(szBuf));
	    sprintf(szBuf,"nvram set erps_cmd=\"show_prof;%s\"",cfg[0]);
		//printf("shoe profile:%s\r\n",szBuf);
        system(szBuf); 
		sleep(1);
    }
	free(str);
	return 0;
}


