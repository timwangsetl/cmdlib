#ifndef __FUNC_SHOW__
#define __FUNC_SHOW__

// by liujh
#define CMD_FREE(p)	do{				\
						if(NULL != p) 	\ 
							free(p);		\
					}while(0)


#define SHOW_IF_FAST_PORT	0x08000000
#define SHOW_IF_GIGA_PORT	0x10000000
#define SHOW_IF_XE_PORT	    0x20000000
#define SHOW_IF_VLAN_PORT	0x40000000

#define SHOW_IF_PORT					0x00000001
#define SHOW_DOT1X_IF_PORT				0x00000002
#define SHOW_MAC_DYNAMIC_IF_PORT		0x00000004
#define SHOW_MAC_IF_PORT				0x00000008
#define SHOW_RUN_IF_PORT				0x00000010
#define SHOW_VLAN_IF_PORT				0x00000020
#define SHOW_GVRP_IF_PORT				0x00000040
#define SHOW_GARP_IF_PORT				0x00000080
#define SHOW_GMRP_IF_PORT				0x00000100
#define SHOW_LLDP_IF_PORT				0x00000200

#define ABSOLUTE_TIMEOUT_DEFAULT		30		//min
#define LOGIN_TIMEOUT					300		//sec

#define SHOW_RUNNING_FILE "/tmp/current_config"
#define SHOW_STARTUP_FILE "/tmp/vfs_root/startup_config"
#define SHOW_INTERFACE "/tmp/current_interface"
#define SHOW_SPANNING_TREE "/tmp/current_spanning"
#define SHOW_MSTI "/tmp/mstp_msti_state"
#define SHOW_LOGGING "/var/log/messages"
#define SHOW_LOOPBACK "/tmp/port_loop_status"
#define SHOW_DOT1X "/tmp/hostapd.dump"
#define DHCP_CONFIG_FILE "/tmp/dhcp_config"


#define ACL_NAME_LEN 20           
#define TIME_NAME_LEN 20  
typedef enum CLI_SHOW_RUNNING{
	CLI_SHOW_ALL,
	CLI_SHOW_INTER,
}CLI_SHOW_RUNNING;

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
typedef struct ip_standard_acl_entry {
    int action;    /*bit 7:0 is for action (0:deny or 1:permit), bit 15:8 is for direction (0:in or 1:out)*/
    uint32_t src_ip;
    uint32_t src_subnet;
    int flag;  /* 1 is any, 0 is other */
    struct ip_standard_acl_entry * next;
}IP_STANDARD_ACL_ENTRY;
typedef struct mac_acl_entry{
	int action;
    uint64_t src_mac;
    uint64_t dst_mac;
    uint16_t   ether_type;
    struct mac_acl_entry * next;
} MAC_ACL_ENTRY;
typedef enum CLI_SHOW_DOT1X{
	CLI_SHOW_GLOABAL,
	CLI_SHOW_INTERFACE,
}CLI_SHOW_DOT1X;

typedef struct show_lldp_neighbor_t{
	int lldp_neighbor_count;
	struct show_lldp_neighbor_list_t *lldp_neighbor_list;
}show_lldp_neighbor;

typedef struct show_lldp_neighbor_list_t{
	char local_port[128];
	char port_id[128];
	char hold_time[128];
	char system_name[128];
	char capability[128];
	struct show_lldp_neighbor_list_t *next;
}show_lldp_neighbor_list;

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
    int flag;  /* 1: set 0:not set, bit0:src_ip, bit1:dst_ip, bit2:time_range, bit3:tos, bit4:precedence, bit5-bit7:port range */
    struct ip_extended_acl_entry * next;
}IP_EXTENDED_ACL_ENTRY;

typedef struct ipv6_standard_acl_entry {
    int action;    /*bit 7:0 is for action (0:deny or 1:permit), bit 15:8 is for direction (0:in or 1:out)*/
    struct in6_addr src_ipv6;  /* ipv6 ip */
    int src_subnet_v6;         /* ipv6 subnet */
    int flag;  /* 1 is any, 0 is other */
    struct ipv6_standard_acl_entry * next;
}IPV6_STANDARD_ACL_ENTRY;

typedef struct policy_classify {
	int type_flag;	
	char name[ACL_NAME_LEN+1];
	int val;
	uint32_t action_flag;
	int bandwidth;
	int monitor;
	int redirect;
	int cos;
	int dscp;
	int vlanId;
	struct policy_classify *next;
}POLICY_CLASSIFY;

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
	POLICY_CLASSIFY_ELEMENT_DEL,	
}policy_method;
#if 0
typedef struct if_info_s{
	char ifname[16];
	char ipaddr[16];
	unsigned hexip;
	char mac[18];
    char hexmac[6];
    char bcask[16];
	char mask[16];
	char gateway[16];
	int  mtu;
	
}if_info_t;
#endif
#define SHOW_RUNNING_ACL       "/tmp/acl_cfg"        /* show running */
#define SHOW_RUNNING_POLICY    "/tmp/policy_cfg"     /* show running */

#define SHOW_ONE_IP_ACL        "/tmp/ip_acl_one"	/* show ip access-lists xx*/
#define SHOW_ALL_IP_ACL        "/tmp/ip_acl_all"    /* show ip access-lists*/

#define SHOW_ONE_POLICY        "/tmp/policy_one"	/* show policy xx*/
#define SHOW_ALL_POLICY        "/tmp/policy_all"	/* show policy*/


typedef struct cli_global_param_t{
    char *name;		/* nvram vlaue name */
    char *command;  /* command */
    int  type;      /* show param or not, 0 means no param, 1 means show it */
    int  own;       /* the same function level */
}cli_global_param;
static int convert_mac_address(char *mac)
{
	char *param = mac;
	
	*(param+2) = *(param+3);
	*(param+3) = *(param+4);
	
	*(param+4) = *(param+6);
	*(param+5) = *(param+7);
	
	*(param+6) = *(param+9);
	*(param+7) = *(param+10);
	
	*(param+8) = *(param+12);
	*(param+9) = *(param+13);
	
	*(param+10) = *(param+15);
	*(param+11) = *(param+16);
	
	*(param+12) = '\0';
	
	return 0;
}

static cli_global_param cli_current_param[]=
{
    /* show spanning-tree */
    /*{"rstp_enable", "no spanning-tree\n", 0, 1},*/
    {"rstp_priority", "spanning-tree rstp priority %s\n", 1, 1},
    {"rstp_hello_time", "spanning-tree rstp hello-time %s\n", 1, 1},
    {"rstp_max_age", "spanning-tree rstp max-age %s\n", 1, 1},
    {"rstp_fwd_delay", "spanning-tree rstp forward-time %s\n", 1, 1},
    {"rstp_bpdufilter_default", "spanning-tree portfast bpdufilter default\n", 0, 1},/*shanming.ren 2011-9-19*/
    {"rstp_uplinkfast", "spanning-tree uplinkfast\n", 0, 1},/*shanming.ren 2011-9-21*/
    {"rstp_uplinkfast_max_update_rate", "spanning-tree uplinkfast max-update-rate %s\n", 1, 1},/*shanming.ren 2011-9-21*/
    {"rstp_backbonefast", "spanning-tree backbonefast\n", 0, 1},/*shanming.ren 2011-9-21*/

    /* show snmp-server */
//    {"snmp_rcomm", "snmp-server community %s ro\n", 1, 2},
//    {"snmp_rwcomm", "snmp-server community %s rw\n", 1, 2},
    {"snmp_gateway", "snmp-server host %s\n", 1, 2},
    {"snmp_contact", "snmp-server contact %s\n", 1, 2},
    {"snmp_location", "snmp-server location %s\n", 1, 2},
    
    /* show storm control */
    {"control_speed_broad", "storm-control broadcast threshold %s\n", 1, 3},
    {"control_speed_multi", "storm-control multicast threshold %s\n", 1, 3},
    {"control_speed_uni", "storm-control unicast threshold %s\n", 1, 3},
    /* show dot1x */
    {"dot1x_enable", "dot1x enable\n", 0, 4},
    {"guest_vlan_enable", "dot1x guest-vlan\n", 0, 4},
    {"reauth_time", "dot1x timeout re-authperiod %s\n", 1, 4},
    
    /* show igmp */
    {"igmp_enable", "ip igmp-snooping\n", 0, 5},
    {"igmp_query_enable", "ip igmp-snooping querier\n", 0, 5},
    {"igmp_querytime", "ip igmp-snooping timer querier %s\n", 1, 5},
    {"igmp_agetime", "ip igmp-snooping timer survival %s\n", 1, 5},
    {"mld_enable", "ipv6 mld snooping\n", 0, 5},
    
    /* show qos */
    /* {"qos_enable", "scheduler enable\n", 0, 6}, */
    /* {"schedule_mode", "scheduler policy sp\n", 0, 6},*/
    /* {"qos_8021p_enable", "cos enable\n", 0, 6}, */
    
    /* show age time */
    {"age_time", "mac address-table aging-time %s\n", 1, 6},
    
    /* show ssh enable */
    {"ssh_enable", "ssh enable\n", 0, 7},
    
    /* show ip & ipv6 DNS / Gateway */
    {"lan_dns", "ip dns server %s\n", 1, 8},
    {"lan_ipv6dns", "ipv6 name-server %s\n", 1, 8},
    {"dns_proxy", "ip dns proxy\n", 0, 8},
    {"lan_gateway", "ip default-gateway %s\n", 1, 8},
    {"lan_ipv6gateway", "ipv6 default-gateway %s\n", 1, 8},
    
    /* show ip DNS / Gateway */
    /*{"qinq_enable", "dot1q-tunnel\n", 0, 9},*/
    
    /* show loopback */
    {"lo_protect_enable", "error-disable-recovery enable\n", 0, 11},
    {"lo_protect_time", "error-disable-recovery recovery-time %s\n", 1, 10},
    
    /* show timezone*/   //by zhangwei
    {"time_offset", "clock time-zone gmt %s\n", 1, 11},
    
    /* show timezone*/
    {"arp_enable", "ip arp inspection\n", 0, 12},
    {NVRAM_STR_SNOOP_ENABLE, "ip dhcp snooping\n", 0, 12},
    {"relay_enable", "ip dhcp relay\n", 0, 12},
    {"dhcp6_snoop_enable", "ipv6 dhcp snooping\n", 0, 12},
	{"dhcp6_relay_enable", "ipv6 dhcp relay\n", 0, 12},
    /* show ntp */
    {"time_server", "ntp server %s\n", 1, 13},
    /* show dscp */
    {"tos_dscp_enable", "dscp enable\n", 0, 14},
    /* none */
    {NULL, NULL, 0, 0},
};
#if 0
typedef struct{
	uint64_t   mac;
	unsigned int 	crc;
}MAC_INFO;
#endif
int func_show_interface_port(struct users *u);
int func_show_interface_vlan(struct users *u);

int func_show_interface(struct users *u);
int func_show_aaa_user();
int func_show_aggregator_group(int group);
void func_show_aggregator_load_balance();
int func_show_arp();
int func_show_clock();
void func_show_dot1x(int type, int portid);
void func_show_mac_add();
void func_show_mac_add_dy();
int cli_check_interface_include_trunk(int skfd, int group, int portid);
void func_show_mac_addr_value(struct users *u);
int func_show_interface_mac(struct users *u);

int func_show_inter();
static int cli_show_interface(FILE * fp, int portid);
int get_port_link_status(uint64_t *link);
int func_show_interface_f(struct users *u);
int check_port_include(int portid, char *port_str);
void show_dot1x_info();
int func_show_all_ip_acl();
int func_show_one_ip_acl(struct users *u);
void func_show_ip_interface(void);
void func_show_igmp_snooping(void);
int func_ip_dhcp_snoopy();
int func_show_ip_source();
int func_show_ip_source_binding();
void cli_show_ip_dhcp_snoopy_bind_vlan();


void func_show_lldp_neighbor(void);
void func_show_lldp_neigh_det();
void func_show_loggin(char *file);
void func_show_loopback(void);
void func_show_memery();
void func_show_mirror_session(void);
void func_show_ntp();
static void cli_show_running_ntp_querytime();
int do_show_all_pol();
int func_show_pol(struct users *u);
void func_show_process_cpu();
static void cli_show_running_hostname();
static void cli_show_running_username();
static int cli_show_running_policy();
static void cli_show_running_global();
static void cli_show_running_qinq();
static void cli_show_running_schedule_wrr();
static void cli_show_err_disable();
static void cli_show_err_recover();
static void cli_show_running_qos();
static void cli_show_running_login();
static void cli_show_running_snmp_server();
static void cli_show_running_arp();
static void cli_show_running_lldp();
static void cli_show_running_logging();
static void cli_show_running_logging_level(int level, char *command);
 static void cli_show_running_interface_vlan_n(int vlan_id);

static void cli_show_running_ip_access();
static void cli_show_running_mirror();
static void cli_show_running_mac();
static void cli_show_running_ipv6_route();
static void cli_show_running_scheduler();
static void cli_show_running_interface_aggregator();
static void cli_show_running_interface(int port_num);
static void cli_show_running_interface_vlan();
static void cli_show_running_interface_vlan_n(int vlan_id);
static void cli_show_running_radius();
static void cli_show_running_mac();
static void cli_show_ip_http_server();
void cli_show_running_vlan(int type);
static void cli_show_running_line_vty();

static void cli_show_running_mstp_vlan2msti(void);
static int cli_check_port_aggregator(int portid);
static void cli_restore_port_aggregator_info(void);
void func_show_running(int type, int portid);
char *vlan2str(void);
void func_show_spanning(void);
void func_show_spanning_msti(struct users *u);
static void cli_show_spanning_tree();
int  create_startup_config();
int func_show_startup();
void func_show_telnet();
void func_show_ssh();
void func_show_version();
void func_show_vlan(int vlanid);
void func_show_vlan_id(struct users *u);
int func_show_inter_agg(struct users *u);
void func_show_mac_addr_mul();
void func_show_mac_addr_static();
void func_show_inter_ddm();
static int cli_show_interface_ddm();
void func_show_inter_bri();
static int cli_show_interface_brief();
static int cli_show_vlan_interface(struct users *u, int port_num);
int func_show_ipv6_brief(struct users *u);
int func_show_ipv6_dhcp_snooping_binding_all();
static int cli_show_running_ipv6_std_acl();                  
int func_show_error_detect();
int func_show_error_recovery();
void func_show_ip_interface_detail(void);
int func_show_line_vty(int vty_first, int vty_last);

int func_show_ipv6_vlan(struct users *u);
int func_show_ipv6_neighbors(struct users *u);
int func_show_ipv6_ospf_neighbor(struct users *u);
int func_show_ipv6_rip_hops(struct users *u);
int func_show_ipv6_route(struct users *u);

int func_show_ipv6_mld_int(struct users *u);
int func_show_ipv6_mld_group(struct users *u);
int func_show_ipv6_mld_detail(struct users *u);

int func_show_vrrp_brief(struct users *u);
int func_show_vrrp_int(struct users *u);

int func_show_bgp_ipv6_unicast(struct users *u);
int func_show_isis_beighbors(struct users *u);

int func_show_ip_dhcp_binding_addr(struct users *u);
int func_show_ip_dhcp_binding_all(struct users *u);
int func_show_ip_dhcp_binding_manual(struct users *u);
int func_show_ip_dhcp_binding_dynamic(struct users *u);
int func_show_ip_dhcp_server_stats(struct users *u);
int func_show_ipv6_dhcp(struct users *u);
int func_show_ipv6_dhcp_binding(struct users *u);
int func_show_ipv6_dhcp_inter_all(struct users *u);
int func_show_ipv6_dhcp_pool_all(struct users *u);
int func_show_ipv6_dhcp_pool_name(struct users *u);

int cli_show_gvrp_interface(struct users *u, int port_num);

int cli_show_garp_interface(struct users *u, int port_num);

int cli_show_gmrp_interface(struct users *u, int port_num);

int func_show_ip_route(struct users *u);

int func_show_ip_ospf_neighbor(struct users *u);

int func_show_ip_rip(struct users *u);

int func_show_clns_neighbor(struct users *u);

int func_show_ip_bgp_summary(struct users *u);

int func_show_ip_mroute(struct users *u);
int func_show_ip_mroute_static(struct users *u);
int func_show_ip_mroute_pim(struct users *u);
int func_show_ip_mroute_pim_group(struct users *u);
int func_show_ip_mroute_pim_group_src(struct users *u);
int func_show_ip_pim_neighbor(struct users *u);
int func_show_ip_pim_neighbor_int(struct users *u);
int func_show_ip_pim_interface(struct users *u);
int func_show_ip_pim_interface_int(struct users *u);

int func_show_ip_mroute_sm(struct users *u);
int func_show_ip_sm_neighbor(struct users *u);
int func_show_ip_sm_neighbor_int(struct users *u);

int func_show_ip_sm_rp(struct users *u);
int func_show_ip_sm_rp_map(struct users *u);
int func_show_ip_sm_rp_met(struct users *u);

int func_show_garp_timer(struct users *u);
int func_show_gmrp_status(struct users *u);

int func_show_ip_igmp_int(struct users *u);
int func_show_ip_igmp_group(struct users *u);
int func_show_ip_igmp_detail(struct users *u);

int func_show_ipv6_mroute_pim(struct users *u);
int func_show_ipv6_mroute_pim_group(struct users *u);
int func_show_ipv6_mroute_pim_group_src(struct users *u);

int cli_show_lldp_interface(struct users *u, int port_num);

int func_show_ipv6_mroute(struct users *u);

int func_show_bfd_neighbors_details(struct users *u);

int func_show_filter(struct users *u);

int func_show_tunnel(struct users *u);

int func_show_cluster(struct users *u);

int func_show_ring_id(struct users *u);

static void cli_show_running_interface_loop();
int func_show_multicast_vlan(struct users *u);

#endif

