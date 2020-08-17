#ifndef __FUNC_CLEAR__
#define __FUNC_CLEAR__

#define CLEAR_ALL_TELNET	100	/*added by wei.zhang*/
#define CLEAR_ALL_SSH		100	/*added by wei.zhang*/
#define MAX_VTY_NUM 16

#define SOCK_PATH_SSH_SERVER	"/tmp/ssh_server"		/*add by wei.zhang*/
#define SOCK_PATH_SSH_CLIENT	"/tmp/ssh_client"		/*add by wei.zhang*/


int func_clear_arp(struct users *u);
int func_clear_logging(struct users *u);
int func_clear_counters(struct users *u);
int func_clear_mac(struct users *u);
int func_clear_telnet(struct users *u, int line_id);
int func_clear_access(struct users *u);
int func_clear_name(struct users *u);
int func_clear_ssh(struct users *u, int lineid);

int func_clear_ip_dhcp_binding_addr(struct users *u);
int func_clear_ip_dhcp_binding_all(struct users *u);
int func_clear_ipv6_dhcp_binding_all(struct users *u);
int func_clear_ipv6_dhcp_binding_addr(struct users *u);

int func_clear_ipv6_mroute_pim_all(struct users *u);
int func_clear_ipv6_mroute_pim_group(struct users *u);
int func_clear_ipv6_mroute_pim_group_src(struct users *u);

int func_clear_ipv6_pim_rp(struct users *u);
int func_clear_ipv6_pim_rp_ip(struct users *u);

int func_clear_ip_igmp_group(struct users *u);

int func_clear_ip_mroute_pim_all(struct users *u);
int func_clear_ip_mroute_pim_group(struct users *u);
int func_clear_ip_mroute_pim_group_src(struct users *u);

int func_clear_ip_pim_rp(struct users *u);
int func_clear_ip_pim_rp_ip(struct users *u);

int func_clear_ipv6_mld_group_int(struct users *u);
int func_clear_ipv6_mld_group_int_ip(struct users *u);

#endif

