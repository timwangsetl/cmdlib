#ifndef __FUNC_IP__
#define __FUNC_IP__

#define IP_IF_FAST_PORT	0x08000000
#define IP_IF_GIGA_PORT	0x10000000
#define IP_IF_XE_PORT	0x20000000

int func_ip_acl_ext_name(struct users *u);
int func_ip_acl_std_name(struct users *u);
void func_set_arp_inspection(void);
static void cli_create_config(int first_start);
void func_set_dhcp_snooping(void);
void nfunc_dhcp_snooping(void);
void nfunc_dhcp_binding(void);

void func_http_server();
void nfunc_http_server();

int func_ip_name_server(struct users *u);
void nfunc_name_server(void);

int func_ipv6_name(struct users *u);
int nfunc_ipv6_name_server();
int func_ipv6_default_g(struct users *u);
int nfunc_ipv6_default_gateway();
int func_ipv6_dhcp_snooping();
int func_ipv6_addr(struct users *u);
int nfunc_ipv6_addr(struct users *u);


int func_ipv6_nd(struct users *u);
int nfunc_ipv6_nd(struct users *u);
int func_ipv6_router_ospf(struct users *u);
int func_ipv6_router_rip(struct users *u);
int func_ipv6_router_isis(struct users *u);
int nfunc_ipv6_router_ospf(struct users *u);
int nfunc_ipv6_router_rip(struct users *u);
int nfunc_ipv6_router_isis(struct users *u);
int func_ipv6_unicast(struct users *u);
int nfunc_ipv6_unicast(struct users *u);

int func_set_igmp_snooping_enable();
void nfunc_igmp_snooping();

int func_set_igmp_snooping_querier();
int nfunc_igmp_snooping_querier();

int func_igmp_snooping_timer_querier(struct users *u);
int nfunc_igmp_snooping_querier_timer();

int func_igmp_snooping_timer_survival(struct users *u);
int nfunc_igmp_snooping_survival_timer();

static int cli_stop_igmp_snooping(void);
static int cli_start_igmp_snooping(void);

int nfunc_ip_acl_ext_name(struct users *u);
int nfunc_ip_acl_std_name(struct users *u);

void nfunc_arp_inspection(void);

void func_set_default_gateway(struct users *u);
int nfunc_default_gateway();

int func_add_ip_source_binding(struct users*u);
int nfunc_mac_source_binding(struct users *u);
int nfunc_ip_source_binding(struct users *u);
void func_ip_dhcp_snooping_vlan(struct users *u);
void nfunc_ip_dhcp_snooping_vlan_all();
void nfunc_ip_dhcp_snooping_vlan_number(struct users *u);
static void cli_read_config(char *file);                     
static int check_vlan_range_format(char *vlan_str, int limit);

int func_cos_num(struct users *u);
int nfunc_cos_map();
int nfunc_cos();
static int cli_stop_dscp(void);
static int cli_start_dscp(void);
static int cli_new_start_dscp(void);
int func_dscp_enable();
int func_dscp_value(struct users *u);
int nfunc_dscp();
int nfunc_dscp_map();

int func_ipv6_mld_snooping(struct users *u);
int nfunc_ipv6_route_ipv6(struct users *u);
int nfunc_ipv6_route_all(struct users *u);
int func_ipv6_route_ipv6_next(struct users *u);
int nfunc_ipv6_mld_snooping(struct users *u);

/*    igmp snooping   */

int func_igmp_snooping_vlan(struct users *u);


int func_ip_dhcp_pool_name(struct users *u);
int nfunc_ip_dhcp_pool_name(struct users *u);
int func_ipv6_dhcp_pool_name(struct users *u);
int nfunc_ipv6_dhcp_pool_name(struct users *u);

int func_ip_forward_udp_bootps(struct users *u);
int nfunc_ip_forward_udp_bootps(struct users *u);

int func_ip_helper_ip(struct users *u);
int nfunc_ip_helper_ip(struct users *u);

int func_ip_route_ip(struct users *u);
int nfunc_ip_route_ip(struct users *u);

int func_ip_route_default(struct users *u);
int nfunc_ip_route_default(struct users *u);

int func_garp_timer_leaveall(struct users *u);
int nfunc_garp_timer_leaveall(struct users *u);
int func_gmrp(struct users *u);
int nfunc_gmrp(struct users *u);
int func_ip_mroute(struct users *u);
int nfunc_ip_mroute(struct users *u);
int nfunc_ip_allmroute(struct users *u);
int func_ip_multi_routing(struct users *u);
int nfunc_ip_multi_routing(struct users *u);

int func_ip_igmp_querier_time(struct users *u);
int nfunc_ip_igmp_querier_time(struct users *u);

int func_ip_pim_bsr(struct users *u);
int nfunc_ip_pim_bsr(struct users *u);

int func_ip_pim_dm(int enable);
int func_ip_pim_dr_priority(struct users *u);
int nfunc_ip_pim_dr(struct users *u);

int func_set_dhcpd_server();
int nfunc_set_dhcpd_server();

typedef struct strlst
{	
    char dst[18];
    char mask[18];
    char gateway[18];
	unsigned int subnet; 
	int netmask;
	int  metric;	
    int  dev;
}STRLst;

int func_ip_pim_rp_add_over(struct users *u);
int func_ip_pim_rp_add_all(struct users *u);

int nfunc_ip_pim_rp_add_over(struct users *u);
int func_ip_pim_rp_add_acl(struct users *u);
int nfunc_ip_pim_rp_add_acl(struct users *u);

int func_ip_pim_can(struct users *u);
int nfunc_ip_pim_can(struct users *u);

int func_ipv6_pim_rp_add_over(struct users *u);
int nfunc_ipv6_pim_rp_add_over(struct users *u);
int func_ipv6_pim_rp_add_acl(struct users *u);
int nfunc_ipv6_pim_rp_add_acl(struct users *u);

int func_ipv6_pim_can(struct users *u);
int nfunc_ipv6_pim_can(struct users *u);

int func_bfd_enable(struct users *u);
int nfunc_bfd_enable(struct users *u);

int func_bfd_all(struct users *u);
int nfunc_bfd_all(struct users *u);

int func_ipv6_pim_bsr(struct users *u);
int nfunc_ipv6_pim_bsr(struct users *u);

int func_port_garp_timer_hold(struct users *u);
int func_port_garp_timer_join(struct users *u);
int func_port_garp_timer_leave(struct users *u);
int nfunc_port_garp_timer_hold(struct users *u);
int nfunc_port_garp_timer_join(struct users *u);
int nfunc_port_garp_timer_leave(struct users *u);

int func_ip_dns_proxy(int enable);
int func_ipv6_dhcp_client(struct users *u);
int nfunc_ipv6_dhcp_client(struct users *u);
#endif

