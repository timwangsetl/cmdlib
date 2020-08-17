#ifndef __DO_CLEAR__
#define __DO_CLEAR__


/* extern functions */
extern int do_test(int argc, char *argv[], struct users *u);
extern int do_test_param(int argc, char *argv[], struct users *u);

/* clock commands parse function */
static int do_clear(int argc, char *argv[], struct users *u);
static int do_arp(int argc, char *argv[], struct users *u);
static int do_logging(int argc, char *argv[], struct users *u);
static int do_counters(int argc, char *argv[], struct users *u);
static int do_mac(int argc, char *argv[], struct users *u);
static int do_telnet_clear(int argc, char *argv[], struct users *u);
static int do_access(int argc, char *argv[], struct users *u);
static int do_mac_add(int argc, char *argv[], struct users *u);
static int do_telnet_index(int argc, char *argv[], struct users *u);
static int do_access_counters(int argc, char *argv[], struct users *u);
static int do_access_counters_name(int argc, char *argv[], struct users *u);
int init_cli_clear(void);
static int do_ssh_clear(int argc, char *argv[], struct users *u);
static int do_ssh_index(int argc, char *argv[], struct users *u);

static int do_ip(int argc, char *argv[], struct users *u);
static int do_ipv6(int argc, char *argv[], struct users *u);
static int do_ip_dhcp(int argc, char *argv[], struct users *u);
static int do_ip_dhcp_binding(int argc, char *argv[], struct users *u);
static int do_ip_dhcp_binding_addr(int argc, char *argv[], struct users *u);
static int do_ip_dhcp_binding_all(int argc, char *argv[], struct users *u);
static int do_ipv6_dhcp(int argc, char *argv[], struct users *u);
static int do_ipv6_dhcp_binding(int argc, char *argv[], struct users *u);
static int do_ipv6_dhcp_binding_addr(int argc, char *argv[], struct users *u);

static int do_ipv6_mld(int argc, char *argv[], struct users *u);
static int do_ipv6_mld_group(int argc, char *argv[], struct users *u);
static int do_ipv6_mld_group_int(int argc, char *argv[], struct users *u);
static int do_ipv6_mld_group_int_ip(int argc, char *argv[], struct users *u);

static int do_ipv6_mroute(int argc, char *argv[], struct users *u);
static int do_ipv6_mroute_pim(int argc, char *argv[], struct users *u);
static int do_ipv6_mroute_pim_all(int argc, char *argv[], struct users *u);
static int do_ipv6_mroute_pim_group(int argc, char *argv[], struct users *u);
static int do_ipv6_mroute_pim_group_src(int argc, char *argv[], struct users *u);

static int do_ipv6_pim(int argc, char *argv[], struct users *u);
static int do_ipv6_pim_rp(int argc, char *argv[], struct users *u);
static int do_ipv6_pim_rp_ip(int argc, char *argv[], struct users *u);

static int do_ip_igmp(int argc, char *argv[], struct users *u);
static int do_ip_igmp_group(int argc, char *argv[], struct users *u);
static int do_ip_igmp_group_int(int argc, char *argv[], struct users *u);
static int do_ip_igmp_group_int_ip(int argc, char *argv[], struct users *u);

static int do_ip_mroute(int argc, char *argv[], struct users *u);
static int do_ip_mroute_pim(int argc, char *argv[], struct users *u);
static int do_ip_mroute_pim_sm(int argc, char *argv[], struct users *u);
static int do_ip_mroute_pim_all(int argc, char *argv[], struct users *u);
static int do_ip_mroute_pim_group(int argc, char *argv[], struct users *u);
static int do_ip_mroute_pim_group_src(int argc, char *argv[], struct users *u);

static int do_ip_pim(int argc, char *argv[], struct users *u);
static int do_ip_pim_rp(int argc, char *argv[], struct users *u);
static int do_ip_pim_rp_ip(int argc, char *argv[], struct users *u);



#endif

