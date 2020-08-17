#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>

#include "memutils.h"

int memsocket_read(memmgr_hdr **header,char **data,int infd)
{
	int len=0;
	int total=0;
	char *pt;
	memmgr_hdr hdr;
	
	*header=malloc(sizeof(memmgr_hdr));
	if(*header==NULL)
		return -1;
		
	if(read(infd, &hdr, sizeof(memmgr_hdr))<0){
		free(*header);
		return -1;
	}

	(*header)->magic = hdr.magic;
	(*header)->len = hdr.len;
	(*header)->cmd = hdr.cmd;	

	if((*header)->magic != ONET_MAGIC ){
		free(*header);
		return -1;
	}
	
	if((*header)->len>0){
		if(!(*data=malloc((*header)->len))){
			free(*header);
		    return -1;
		}
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


int memsocket_write(memmgr_hdr *header,char *data,int infd)
{
    memmgr_hdr hdr;

	hdr.magic = header->magic;
	hdr.len = header->len;
	hdr.cmd = header->cmd;

	if(write(infd, &hdr, sizeof(memmgr_hdr))<0) 
	    return -1;

	if(header->len > 0){
		if(write(infd,data,header->len)<0) 
		    return -1;
	}
	return 0;
}

int memsocket_connect()
{
	int sockfd;
	struct sockaddr_in cli;
		
	if((sockfd=socket(PF_INET,SOCK_STREAM,0))<0)
		return -1;
	
	memset(&cli,0,sizeof(cli));
	cli.sin_family = AF_INET;
	cli.sin_port = htons(DEFAULT_REMOTE_PORT_M);
	cli.sin_addr.s_addr=inet_addr("127.0.0.1");	
	if(connect(sockfd,(struct sockaddr *)&cli,sizeof(cli)))
		return -1;
	
	return sockfd;
}

int memmgr_connect(memmgr_hdr *shd,char *sdata, memmgr_hdr **rhd,char **rdata)
{
	int sockfd;
	if((sockfd=memsocket_connect())<0) 
	    return -1;
	if(memsocket_write(shd,sdata,sockfd)<0) 
	    return -1;
	if(memsocket_read(rhd,rdata,sockfd)<0) 
	    return -1;
	close(sockfd);
	return 0;	
}

/**************************************************************************
 * FUNCTION NAME : multiaddr_set
 **************************************************************************
 * find a mindex for new portmaps
 *   
 * NOTES:
 *  return >= 0 means notmal index
 *  return = -1 means too many entry
 ***************************************************************************/ 
int multiaddr_set(uint64_t addr, uint64_t portmaps, int maxindex, int learn)
{	
	int res=0;
	MultiAddrEntry entry;
	memmgr_hdr shd;
	memmgr_hdr *rhd;
	
	shd.magic=ONET_MAGIC;
	shd.cmd=MultiAddr;
	shd.len=sizeof(MultiAddrEntry);
	
	entry.type = learn;
	entry.pmap = portmaps;
	entry.maxindex = maxindex; 
	entry.mac = addr;

	if(memmgr_connect(&shd,(char *)&entry,&rhd,NULL)<0) return -1;
	res=rhd->cmd;
	free(rhd);
	return res;	
}

int multiaddr_find(uint64_t addr)
{	
	int res=0;
	MultiAddrEntry entry;
	memmgr_hdr shd;
	memmgr_hdr *rhd;
	
	shd.magic=ONET_MAGIC;
	shd.cmd=MultiFindType;
	shd.len=sizeof(MultiAddrEntry);
	
	entry.type = 1;
	entry.pmap = 0;
	entry.maxindex = 0; 
	entry.mac = addr;

	if(memmgr_connect(&shd,(char *)&entry,&rhd,NULL)<0) return -1;
	res=rhd->cmd;
	free(rhd);
	return res;	
}
