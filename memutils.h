/*	our socket communcation is similar packet
 *	
 *	+--------+--------------------------------+
 *	| header |	      payload		          |	 		
 *  +--------+--------------------------------+
 *      
 *      header format
 *      +-------------+----------------+
 *      | packet type | payload length |	
 *      +-------------+----------------+
 *      
 *      payload format 
 *      +-------+------+-------+------+--- ---+-------+-----------+
 *      | data1 | 0x00 | data2 | 0x00 | ----- | dataN | 0x00 0x00 |
 *      +-------+------+-------+------+--- ---+-------+-----------+
 *      data divide by 0x00
 *      data end by 0x00 0x00
 */
//#include "bcmutils.h"
 
/* ONet */
#define ONET_MAGIC 0x4F4E6574

#define DEFAULT_REMOTE_PORT_M 32732 

#define SOCKET_WAIT_TIME 10

/* header struct*/
typedef struct{
	int magic;
	int cmd;
	int	len;
} memmgr_hdr;

enum {
	MEM_WARNING=-2,
	MEM_ERR,
	MEM_OK,
	MultiAddr,
	MultiFindType,
}cmd_type_t;

/* portmaps struct*/
typedef struct index_pamps{
	int index;
	int maps;
    struct index_pamps *next;
} PMAPS;

/* address struct*/
/*
typedef struct addr_maps{
	int type;
	int pmap;
    uint64_t mac;
    struct addr_maps *next;
} MADDRTab;
*/

/* address struct*/
typedef struct{
	int type;
	uint64_t pmap;
	int maxindex;
    uint64_t mac;
} MultiAddrEntry;

extern int debug;
extern PMAPS *IndexTab;
//extern MADDRTab *AddrTab;

/* Share functions */
int memsocket_read(memmgr_hdr **header,char **data,int infd);
int memsocket_write(memmgr_hdr *header,char *data,int infd);
int memsocket_connect(void);
int memmgr_connect(memmgr_hdr *shd,char *sdata, memmgr_hdr **rhd,char **rdata);

/*
 * Save configuration data to scfgmgr
 * @param       data     data ,you want save
 * @param       value    value
 * @return      0 success -1 error
 */
int multiaddr_set(uint64_t addr, uint64_t portmaps, int maxindex, int learn);
int multiaddr_find(uint64_t addr);


