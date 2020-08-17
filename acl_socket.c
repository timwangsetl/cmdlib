#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>

#include "bcmutils.h"
#include "acl_utils.h"

int acl_memsocket_read(acl_memmgr_hdr **header,char **data,int infd)
{
	int len=0;
	int total=0;
	char *pt;
	acl_memmgr_hdr hdr;
	
	*header=malloc(sizeof(acl_memmgr_hdr));
	if(*header==NULL)
		return -1;
	
	memset(&hdr, '\0', sizeof(acl_memmgr_hdr));
	memset(*header, '\0', sizeof(acl_memmgr_hdr));
		
	if(read(infd, &hdr, sizeof(acl_memmgr_hdr))<0){
		free(*header);
		return -1;
	}
	
	(*header)->magic = hdr.magic;
	(*header)->method = hdr.method;	
	strcpy((*header)->name, hdr.name);
	(*header)->bmaps = hdr.bmaps;
	(*header)->location = hdr.location;
	(*header)->len = hdr.len;
		
	if((*header)->magic != ONET_MAGIC ){
		free(*header);
		return -1;
	}
	
	if((*header)->len>0){
		if(!(*data=malloc((*header)->len))){
			free(*header);
		    return -1;
		}
		memset(*data, '\0', (*header)->len);
		pt=*data;
		while(total< (*header)->len){
			if((len=read(infd,pt,(*header)->len))<0){
				free(*header);
				free(*data);
				return -1;
			}
			total+=len;	
			pt+=len;
		}	
	}
	return 0;			
}

int acl_memsocket_write(acl_memmgr_hdr *header,char *data,int infd)
{
    acl_memmgr_hdr hdr;
	
	memset(&hdr, '\0', sizeof(acl_memmgr_hdr));
	hdr.magic = header->magic;
	hdr.method = header->method;
	strcpy(hdr.name, header->name);
	hdr.bmaps = header->bmaps;
	hdr.location = header->location;
	hdr.len = header->len;
		
	if(write(infd, &hdr, sizeof(acl_memmgr_hdr))<0) 
	    return -1;

	if(header->len > 0){
		if(write(infd,data,header->len)<0) 
		    return -1;
	}
	return 0;
}

/* flag=0-->mac   flag=1--->ip std  flag=2--->ip exd   flag=3--->policy  flag=4--->ipv6 std*/
int acl_memsocket_connect(int flag)
{
	int sockfd;
	struct sockaddr_in cli;
		
	if((sockfd=socket(PF_INET,SOCK_STREAM,0))<0)
		return -1;
	
	memset(&cli,0,sizeof(cli));
	cli.sin_family = AF_INET;
	if(0 == flag)
		cli.sin_port = htons(MAC_DEFAULT_REMOTE_PORT);
	else if(1 == flag)
		cli.sin_port = htons(SIP_DEFAULT_REMOTE_PORT);
	else if(2 == flag)
		cli.sin_port = htons(EIP_DEFAULT_REMOTE_PORT);
	else if(3 == flag)
		cli.sin_port = htons(POLICY_DEFAULT_REMOTE_PORT);
	else if(4 == flag)
		cli.sin_port = htons(SIPV6_DEFAULT_REMOTE_PORT);
	
	cli.sin_addr.s_addr=inet_addr("127.0.0.1");	
	if(connect(sockfd,(struct sockaddr *)&cli,sizeof(cli)))
		return -1;
	
	return sockfd;
}

int acl_memmgr_connect(acl_memmgr_hdr *shd,char *sdata, acl_memmgr_hdr **rhd,char **rdata, int flag)
{
	int sockfd;
	if((sockfd=acl_memsocket_connect(flag))<0) 
	    return -1;

	if(acl_memsocket_write(shd,sdata,sockfd)<0) 
	    return -1;

	if(acl_memsocket_read(rhd,rdata,sockfd)<0) 
	    return -1;

	close(sockfd);
	return 0;	
}

/**************************************************************************
 * FUNCTION NAME : mac_acl_set
 **************************************************************************
 * find a mindex for new portmaps
 *   
 * NOTES:
 *  return >= 0 means notmal index
 *  return = -1 means too many entry
 ***************************************************************************/ 
int mac_acl_set(char *name, MAC_ACL_ENTRY *entry, int method, int location, uint64_t bmaps)
{	
	int res=0;
	acl_memmgr_hdr shd;
	acl_memmgr_hdr *rhd;
	
	memset(&shd, '\0', sizeof(acl_memmgr_hdr));
	
	shd.magic=ONET_MAGIC;
	shd.method=method;
	strncpy(shd.name, name, strlen(name));
	shd.bmaps = bmaps;
	shd.location=location;
	shd.len=sizeof(MAC_ACL_ENTRY);
				
	if(acl_memmgr_connect(&shd, (char *)entry, &rhd, NULL, 0)<0) return -1;
	res=rhd->method;
	free(rhd);
	return res;	
}

/**************************************************************************
 * FUNCTION NAME : ip_std_acl_set
 **************************************************************************
 * find a mindex for new portmaps
 *   
 * NOTES:
 *  return >= 0 means notmal index
 *  return = -1 means too many entry
 ***************************************************************************/ 
int ip_std_acl_set(char *name, IP_STANDARD_ACL_ENTRY *entry, int method, int location, uint64_t bmaps)
{	
	int res=0;
	acl_memmgr_hdr shd;
	acl_memmgr_hdr *rhd;
	
	memset(&shd, '\0', sizeof(acl_memmgr_hdr));
	
	shd.magic=ONET_MAGIC;
	shd.method=method;
	strncpy(shd.name, name, strlen(name));
	shd.bmaps = bmaps;
	shd.location=location;
	shd.len=sizeof(IP_STANDARD_ACL_ENTRY);
				
	if(acl_memmgr_connect(&shd, (char *)entry, &rhd, NULL, 1)<0) 
		return -1;
	res=rhd->method;
	free(rhd);
	return res;	
}

/**************************************************************************
 * FUNCTION NAME : ipv6_std_acl_set
 **************************************************************************
 * find a mindex for new portmaps
 *   
 * NOTES:
 *  return >= 0 means notmal index
 *  return = -1 means too many entry
 ***************************************************************************/ 
int ipv6_std_acl_set(char *name, IPV6_STANDARD_ACL_ENTRY *entry, int method, int location, uint64_t bmaps)
{	
	int res=0;
	acl_memmgr_hdr shd;
	acl_memmgr_hdr *rhd;
	
	memset(&shd, '\0', sizeof(acl_memmgr_hdr));
	
	shd.magic=ONET_MAGIC;
	shd.method=method;
	strncpy(shd.name, name, strlen(name));
	shd.bmaps = bmaps;
	shd.location=location;
	shd.len=sizeof(IPV6_STANDARD_ACL_ENTRY);
				
	if(acl_memmgr_connect(&shd, entry, &rhd, NULL, 4)<0) return -1;
	res=rhd->method;
	free(rhd);
	return res;	
}


/**************************************************************************
 * FUNCTION NAME : ip_ext_acl_set
 **************************************************************************
 * find a mindex for new portmaps
 *   
 * NOTES:
 *  return >= 0 means notmal index
 *  return = -1 means too many entry
 ***************************************************************************/ 
int ip_ext_acl_set(char *name, IP_EXTENDED_ACL_ENTRY *entry, int method, int location, uint64_t bmaps)
{	
	int res=0;
	acl_memmgr_hdr shd;
	acl_memmgr_hdr *rhd;
	
	memset(&shd, '\0', sizeof(acl_memmgr_hdr));
	
	shd.magic=ONET_MAGIC;
	shd.method=method;
	strncpy(shd.name, name, strlen(name));
	shd.bmaps = bmaps;
	shd.location=location;
	shd.len=sizeof(IP_EXTENDED_ACL_ENTRY);
				
	if(acl_memmgr_connect(&shd, (char *)entry, &rhd, NULL, 2)<0) return -1;
	res=rhd->method;
	free(rhd);
	return res;	
}

/**************************************************************************
 * FUNCTION NAME : policy_set
 **************************************************************************
 * find a mindex for new portmaps
 *   
 * NOTES:
 *  return >= 0 means notmal index
 *  return = -1 means too many entry
 ***************************************************************************/ 
int policy_set(char *name, POLICY_CLASSIFY *entry, int method, int location, uint64_t bmaps)
{	
	int res=0;
	acl_memmgr_hdr shd;
	acl_memmgr_hdr *rhd;
	
	memset(&shd, '\0', sizeof(acl_memmgr_hdr));
	
	shd.magic=ONET_MAGIC;
	shd.method=method;
	strncpy(shd.name, name, strlen(name));
	shd.bmaps = bmaps;
	shd.location=location;
	shd.len=sizeof(POLICY_CLASSIFY);
				
	if(acl_memmgr_connect(&shd, (char *)entry, &rhd, NULL, 3)<0) return -1;
	res=rhd->method;
	free(rhd);
	return res;	
}
