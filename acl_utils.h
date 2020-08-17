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
 
/* ONet */
#define ONET_MAGIC 0x4F4E6574

#define MAC_DEFAULT_REMOTE_PORT 32758 
#define SIP_DEFAULT_REMOTE_PORT 32759
#define EIP_DEFAULT_REMOTE_PORT 32760
#define POLICY_DEFAULT_REMOTE_PORT 32761
#define SIPV6_DEFAULT_REMOTE_PORT 32762

#define SOCKET_WAIT_TIME 10

#define ACL_NAME_LEN 20
#define TIME_NAME_LEN 20

enum {
    ACL_ACT_DENY,
    ACL_ACT_PERMIT,
}acl_action;

enum {
    ACL_IN,
    ACL_OUT,
    ACL_ALL,
}acl_direction;

enum {
	FLAG_SRC_IP=0,
	FLAG_DST_IP,
	FLAG_TIME_RANGE,
	FLAG_TOS,
	FLAG_VLAN,
	FLAG_PRECEDENCE,
	FLAG_SRC_PORT_RANGE,
	FLAG_DST_PORT_RANGE=FLAG_SRC_PORT_RANGE+3,
}acl_flag;

enum {
	PORT_EQ=1,
	PORT_GT,
	PORT_LT,
	PORT_NEQ,
	PORT_RANGE
}acl_port_range;

enum {
	OPTION_SRC_PORT,
	OPTION_DST_PORT,
	OPTION_TIME_RANGE,
	OPTION_TOS,
	OPTION_PRECEDENCE,
	OPTION_VLAN,
	OPTION_LOCATION
}ext_option;	

enum {
	CLASSIFY_ACTION_BANDWIDTH,
	CLASSIFY_ACTION_DROP,
	CLASSIFY_ACTION_MONITOR,
	CLASSIFY_ACTION_REDIRECT,
	CLASSIFY_ACTION_COS,
	CLASSIFY_ACTION_DSCP,
	CLASSIFY_ACTION_VLANID,	
}classify_action;

enum {
	CLASSIFY_TYPE_MAC,
	CLASSIFY_TYPE_IP,
	CLASSIFY_TYPE_DSCP,
	CLASSIFY_TYPE_VLAN,
	CLASSIFY_TYPE_COS,
	CLASSIFY_TYPE_ANY,
}classify_type;	

/* header struct for mac acl*/
typedef struct{
	int magic;
	int method;
	char name[ACL_NAME_LEN+1];
	uint64_t bmaps; 
	int location;  
	int	len;
} acl_memmgr_hdr;

enum {
	ACL_ERROR=-1,
	ACL_OK,
	ACL_ENTRY_APPEND,
	ACL_ENTRY_DELETE,
	ACL_ENTRY_INSERT,
	ACL_NAME_CHECK,
	ACL_LIST_ADD,
	ACL_LIST_DEL,
	ACL_PORT_DEL,
	ACL_PORT_ADD,
	ACL_WRITE_REGS,
	ACL_CHECK_ENTRY_NUM,
	ACL_ENTRY_NUM,
	ACL_CPU_OUT_SET,
	ACL_CPU_OUT_CLEAR,
	ACL_LIST_PRINT,
	ARL_LIST_SHOW_ONE,
	ARL_LIST_SHOW_ALL,
	ACL_POLICY_SET,
    ACL_ALL_ENTRY_NUM,
    ACL_COUNTERS_CLEAR_ONE,
    ACL_COUNTERS_CLEAR_ALL,
}acl_method;

enum {
	POLICY_ERROR=-1,
	POLICY_OK,
	POLICY_CLASSIFY_ADD,
	POLICY_CLASSIFY_DEL,
	POLICY_CLASSIFY_MODIFY,
	POLICY_ADD,
	POLICY_DEL,
	POLICY_NAME_CHECK,
	POLICY_PORT_DEL,
	POLICY_PORT_ADD,
	POLICY_CHECK_ENTRY_NUM,
	POLICY_CLASSIFY_CHECK,	
	POLICY_WRITE_REGS,
	POLICY_ACL_NUM,
	POLICY_ACL_DEL,
	POLICY_ACL_ENTRY_NUM,
	POLICY_SHOW_ONE,
	POLICY_SHOW_ALL,
	POLICY_LIST_PRINT,
	POLICY_CHECK_VLANID,
	POLICY_CLASSIFY_ELEMENT_DEL,	//add by gujiajie
}policy_method;

enum {
	ACL_IP=0x0800,
	ACL_TCP=6,
	ACL_UDP=17,	
}acl_protocol;


typedef struct number_str {
	int number;
	char *str;
}NUMBER_STR;

/* mac struct*/
typedef struct mac_acl_entry{
	int action;
    uint64_t src_mac;
    uint64_t dst_mac;
    uint16_t   ether_type;
    struct mac_acl_entry * next;
} MAC_ACL_ENTRY;

typedef struct ip_standard_acl_entry {
    int action;    /*bit 7:0 is for action (0:deny or 1:permit), bit 15:8 is for direction (0:in or 1:out)*/
    uint32_t src_ip;
    uint32_t src_subnet;
    int flag;  /* 1 is any, 0 is other */
    struct ip_standard_acl_entry * next;
}IP_STANDARD_ACL_ENTRY;

typedef struct ipv6_standard_acl_entry {
    int action;    /*bit 7:0 is for action (0:deny or 1:permit), bit 15:8 is for direction (0:in or 1:out)*/
    struct in6_addr src_ipv6;  /* ipv6 ip */
    int src_subnet_v6;         /* ipv6 subnet */
    int flag;  /* 1 is any, 0 is other */
    struct ipv6_standard_acl_entry * next;
}IPV6_STANDARD_ACL_ENTRY;

typedef struct ip_extended_acl_entry {
    int action;
    int protocol;
    uint32_t src_ip;
    uint32_t src_subnet;
    uint32_t dst_ip;
    uint32_t dst_subnet;
    uint16_t src_port1;   //source port begin
    uint16_t src_port2;   //source port end
    uint16_t dst_port1;   //destination port begin
    uint16_t dst_port2;   //destination port end  
    char time_range[TIME_NAME_LEN+1];
    uint8_t tos;
    uint8_t precedence;
    uint16_t vlan;
    int flag;  /* 1: set 0:not set, bit0:src_ip, bit1:dst_ip, bit2:time_range, bit3:tos, bit4:precedence, bit5-bit7:port range */
    struct ip_extended_acl_entry * next;
}IP_EXTENDED_ACL_ENTRY;

typedef struct policy_classify {
	int type_flag;	
	char name[ACL_NAME_LEN+1];
	int val;
	uint32_t action_flag;
	int bandwidth;
	int monitor;
	uint32_t redirect;
	int cos;
	int dscp;
	int vlanId;
	struct policy_classify *next;
}POLICY_CLASSIFY;

/* Share functions */
int acl_memsocket_read(acl_memmgr_hdr **header,char **data,int infd);
int acl_memsocket_write(acl_memmgr_hdr *header,char *data,int infd);
int acl_memsocket_connect(int flag);
int acl_memmgr_connect(acl_memmgr_hdr *shd,char *sdata, acl_memmgr_hdr **rhd,char **rdata, int flag);

/*
 * Save configuration data to scfgmgr
 * @param       data     data ,you want save
 * @param       value    value
 * @return      0 success -1 error
 */
int mac_acl_set(char *name, MAC_ACL_ENTRY *entry, int method, int location, uint64_t bmaps);
int ip_std_acl_set(char *name, IP_STANDARD_ACL_ENTRY *entry, int method, int location, uint64_t bmaps);
int ip_ext_acl_set(char *name, IP_EXTENDED_ACL_ENTRY *entry, int method, int location, uint64_t bmaps);
int policy_set(char *name, POLICY_CLASSIFY *entry, int method, int location, uint64_t bmaps);
int ipv6_std_acl_set(char *name, IPV6_STANDARD_ACL_ENTRY *entry, int method, int location, uint64_t bmaps);

