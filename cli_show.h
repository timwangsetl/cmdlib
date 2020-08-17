#ifndef __DO_SHOW__
#define __DO_SHOW__

/* extern functions */
extern int do_test(int argc, char *argv[], struct users *u);
extern int do_test_param(int argc, char *argv[], struct users *u);

/* show commands parse function */
static int do_show(int argc, char *argv[], struct users *u);

/* show aaa commands parse function */
static int do_show_aaa(int argc, char *argv[], struct users *u);
static int do_show_aaa_users(int argc, char *argv[], struct users *u);

/* show access-list commands parse function */
static int do_show_access(int argc, char *argv[], struct users *u);
int func_show_access_list();
static void cli_show_mac_blackhole(void);
static void cli_show_mac_age(void);

/* show aggregator-group commands parse function */
static int do_show_agg(int argc, char *argv[], struct users *u);
static int do_show_agg_grp(int argc, char *argv[], struct users *u);
static int do_show_agg_grp_bri(int argc, char *argv[], struct users *u);
static int do_show_agg_grp_det(int argc, char *argv[], struct users *u);
static int do_show_agg_grp_sum(int argc, char *argv[], struct users *u);
static int do_show_agg_brief(int argc, char *argv[], struct users *u);
static int do_show_agg_detail(int argc, char *argv[], struct users *u);
static int do_show_agg_load(int argc, char *argv[], struct users *u);
static int do_show_agg_summary(int argc, char *argv[], struct users *u);

/* show arp commands parse function */
static int do_show_arp(int argc, char *argv[], struct users *u);

/* show clock commands parse function */
static int do_show_clock(int argc, char *argv[], struct users *u);

/* show dot1x commands parse function */
static int do_show_dot1x(int argc, char *argv[], struct users *u);
static int do_show_dot1x_info(int argc, char *argv[], struct users *u);
static int do_show_dot1x_inter(int argc, char *argv[], struct users *u);
static int do_show_dot1x_stat(int argc, char *argv[], struct users *u);

/* show exec-timeout commands parse function */
static int do_show_exec_timeout(int argc, char *argv[], struct users *u);
static int do_show_flow_interval(int argc, char *argv[], struct users *u);

/* show history commands parse function */
static int do_show_history(int argc, char *argv[], struct users *u);

/* show interface commands parse function */
static int do_show_inter(int argc, char *argv[], struct users *u);
static int do_show_inter_bri(int argc, char *argv[], struct users *u);
static int do_show_inter_ddm(int argc, char *argv[], struct users *u);
static int do_show_inter_agg(int argc, char *argv[], struct users *u);

/* show ip commands parse function */
static int do_show_ip(int argc, char *argv[], struct users *u);
static int do_show_ip_access(int argc, char *argv[], struct users *u);
static int do_show_ip_access_word(int argc, char *argv[], struct users *u);
static int do_show_ip_dhcp(int argc, char *argv[], struct users *u);
static int do_show_ip_dhcp_snoop(int argc, char *argv[], struct users *u);
static int do_show_ip_dhcp_snoop_bind(int argc, char *argv[], struct users *u);
static int do_show_ip_dhcp_snoop_bind_all(int argc, char *argv[], struct users *u);
static int do_show_ip_dhcp_snoop_bind_vlan(int argc, char *argv[], struct users *u);

static int do_show_ip_igmp_sn(int argc, char *argv[], struct users *u);
static int do_show_ip_inter(int argc, char *argv[], struct users *u); 
static int do_show_ip_source(int argc, char *argv[], struct users *u);
//static int do_show_ip_source_snoop(int argc, char *argv[], struct users *u);
static int do_show_ip_source_binding(int argc, char *argv[], struct users *u);
static int do_show_ip_inter_bri(int argc, char *argv[], struct users *u);
static int do_show_ip_inter_det(int argc, char *argv[], struct users *u);

/* show lldp commands parse function */
static int do_show_lldp(int argc, char *argv[], struct users *u);
static int do_show_lldp_neigh(int argc, char *argv[], struct users *u);
static int do_show_lldp_neigh_det(int argc, char *argv[], struct users *u);
static int do_show_lldp_inter(int argc, char *argv[], struct users *u);

/* show logging commands parse function */
static int do_show_logging(int argc, char *argv[], struct users *u);

/* show loopback commands parse function */
static int do_show_loopback(int argc, char *argv[], struct users *u);

/* show mac commands parse function */
static int do_show_mac(int argc, char *argv[], struct users *u);
static int do_show_mac_addr(int argc, char *argv[], struct users *u);
static int do_show_mac_addr_value(int argc, char *argv[], struct users *u);
static int do_show_mac_addr_dynamic(int argc, char *argv[], struct users *u);
static int do_show_mac_addr_dyna_inter(int argc, char *argv[], struct users *u);
static int do_show_mac_addr_inter(int argc, char *argv[], struct users *u);
static int do_show_mac_addr_mul(int argc, char *argv[], struct users *u);
static int do_show_mac_addr_static(int argc, char *argv[], struct users *u);
static int do_show_mac_addr_vlan(int argc, char *argv[], struct users *u);
static int do_show_mac_addr_blackhole(int argc, char *argv[], struct users *u);

/* show memory commands parse function */
static int do_show_mem(int argc, char *argv[], struct users *u);

/* show mirror commands parse function */
static int do_show_mirr(int argc, char *argv[], struct users *u);
static int do_show_mirror_session(int argc, char *argv[], struct users *u);

/* show mst configuration function */
static int do_show_mstcfg(int argc, char *argv[], struct users *u);

/* show ntp commands parse function */
static int do_show_ntp(int argc, char *argv[], struct users *u);

/* show policy-map commands parse function */
static int do_show_pol(int argc, char *argv[], struct users *u);
static int do_show_one_pol_map(int argc, char *argv[], struct users *u);


/* show process commands parse function */
static int do_show_process(int argc, char *argv[], struct users *u);
static int do_show_process_cpu(int argc, char *argv[], struct users *u);

/* show rnning-config commands parse function */
static int do_show_running(int argc, char *argv[], struct users *u);
static int do_show_running_inter(int argc, char *argv[], struct users *u);

/* show spaning-tree commands parse function */
static int do_show_spanning(int argc, char *argv[], struct users *u);
static int do_show_spanning_mst(int argc, char *argv[], struct users *u);
static int do_show_spanning_mst_id(int argc, char *argv[], struct users *u);

/* show startup-config commands parse function */
static int do_show_startup(int argc, char *argv[], struct users *u);

/* show ssh commands parse function */
static int do_show_ssh(int argc, char *argv[], struct users *u);

/* show telnet commands parse function */
static int do_show_telnet(int argc, char *argv[], struct users *u);

/* show version commands parse function */
static int do_show_version(int argc, char *argv[], struct users *u);

/* show vlan commands parse function */
static int do_show_vlan(int argc, char *argv[], struct users *u);
static int do_show_vlan_id(int argc, char *argv[], struct users *u);
static int do_show_vlan_inter(int argc, char *argv[], struct users *u);
static int do_show_vlan_dot1q(int argc, char *argv[], struct users *u);

/* interface port */
static int do_show_interface_ethernet(int argc, char *argv[], struct users *u);
static int do_show_interface_num(int argc, char *argv[], struct users *u);
static int do_show_interface_slash(int argc, char *argv[], struct users *u);
static int do_show_interface_port(int argc, char *argv[], struct users *u);

static int do_show_interface_vlan(int argc, char *argv[], struct users *u);
static int do_show_interface_vlan_id(int argc, char *argv[], struct users *u);

/* interface range port */
static int do_show_interface_range_port(int argc, char *argv[], struct users *u);
static int do_show_interface_range_num(int argc, char *argv[], struct users *u);
static int do_show_interface_range_slash(int argc, char *argv[], struct users *u);
static int do_show_interface_range_port_start(int argc, char *argv[], struct users *u);
static int do_show_interface_range_hyphen(int argc, char *argv[], struct users *u);
static int do_show_interface_range_comma(int argc, char *argv[], struct users *u);
static int do_show_interface_range_port_end(int argc, char *argv[], struct users *u);
static int do_show_interface_range_comma_end(int argc, char *argv[], struct users *u);

static int do_show_dot1x_int(int argc, char *argv[], struct users *u);
static int do_show_dy_interface(int argc, char *argv[], struct users *u);
static int do_show_ipv6(int argc, char *argv[], struct users *u);
static int do_show_ipv6_interface(int argc, char *argv[], struct users *u);
static int do_show_ipv6_source(int argc, char *argv[], struct users *u);
static int do_show_ipv6_interface_brief(int argc, char *argv[], struct users *u);
static int do_show_ipv6_dhcp(int argc, char *argv[], struct users *u);
static int show_ipv6_dhcp_snooping(int argc, char *argv[], struct users *u);
static int show_ipv6_dhcp_snooping_binding(int argc, char *argv[], struct users *u);

static int do_show_ipv6_interface_vlan(int argc, char *argv[], struct users *u);
static int do_show_ipv6_interface_vlan_id(int argc, char *argv[], struct users *u);
static int do_show_ipv6_ospf_neighbor(int argc, char *argv[], struct users *u);
static int do_show_ipv6_rip_hops(int argc, char *argv[], struct users *u);
static int do_show_ipv6_neighbors(int argc, char *argv[], struct users *u);
static int do_show_ipv6_ospf(int argc, char *argv[], struct users *u);
static int do_show_ipv6_rip(int argc, char *argv[], struct users *u);
static int do_show_ipv6_route(int argc, char *argv[], struct users *u);

static int do_show_ipv6_mld(int argc, char *argv[], struct users *u);
static int do_show_ipv6_mld_int(int argc, char *argv[], struct users *u);
static int do_show_ipv6_mld_int_vlan(int argc, char *argv[], struct users *u);
static int do_show_ipv6_mld_int_vlan_num(int argc, char *argv[], struct users *u);
static int do_show_ipv6_mld_group(int argc, char *argv[], struct users *u);
static int do_show_ipv6_mld_detail(int argc, char *argv[], struct users *u);

static int do_show_ipv6_dhcp_snooping_binding_all(int argc, char *argv[], struct users *u);
static int do_show_error(int argc, char *argv[], struct users *u);
static int do_show_error_detect(int argc, char *argv[], struct users *u);
static int do_show_error_recovery(int argc, char *argv[], struct users *u);

static int do_show_ip_dhcp_snoop_source_mac(int argc, char *argv[], struct users *u);


static int do_show_line(int argc, char *argv[], struct users *u);
static int do_vty(int argc, char *argv[], struct users *u);
static int do_vty_first(int argc, char *argv[], struct users *u);
static int do_vty_last(int argc, char *argv[], struct users *u);

static int do_show_vrrp(int argc, char *argv[], struct users *u);
static int do_show_vrrp_brief(int argc, char *argv[], struct users *u);
static int do_show_vrrp_int(int argc, char *argv[], struct users *u);
static int do_show_vrrp_int_vlan(int argc, char *argv[], struct users *u);

static int do_show_bgp(int argc, char *argv[], struct users *u);
static int do_show_isis(int argc, char *argv[], struct users *u);
static int do_show_bgp_ipv6(int argc, char *argv[], struct users *u);
static int do_show_bgp_ipv6_unicast(int argc, char *argv[], struct users *u);
static int do_show_isis_neighbors(int argc, char *argv[], struct users *u);


static int do_show_gvrp(int argc, char *argv[], struct users *u);
static int do_show_ipv6_dhcp_binding(int argc, char *argv[], struct users *u);
static int do_show_ipv6_dhcp_inter(int argc, char *argv[], struct users *u);
static int do_show_ipv6_dhcp_pool(int argc, char *argv[], struct users *u);
static int do_show_ipv6_dhcp_pool_name(int argc, char *argv[], struct users *u);
static int do_show_ip_dhcp_binding(int argc, char *argv[], struct users *u);
static int do_show_ip_dhcp_server(int argc, char *argv[], struct users *u);
static int do_show_ip_dhcp_binding_addr(int argc, char *argv[], struct users *u);
static int do_show_ip_dhcp_binding_all(int argc, char *argv[], struct users *u);
static int do_show_ip_dhcp_binding_manual(int argc, char *argv[], struct users *u);
static int do_show_ip_dhcp_binding_dynamic(int argc, char *argv[], struct users *u);
static int do_show_ip_dhcp_server_stats(int argc, char *argv[], struct users *u);
static int do_show_gvrp_stats(int argc, char *argv[], struct users *u);
static int do_show_gvrp_stats_inter(int argc, char *argv[], struct users *u);

static int do_show_ip_route(int argc, char *argv[], struct users *u);

static int do_show_ip_ospf(int argc, char *argv[], struct users *u);
static int do_show_ip_ospf_neighbor(int argc, char *argv[], struct users *u);

static int do_show_ip_rip(int argc, char *argv[], struct users *u);

static int do_show_clns(int argc, char *argv[], struct users *u);
static int do_show_clns_neighbor(int argc, char *argv[], struct users *u);

static int do_show_ip_bgp(int argc, char *argv[], struct users *u);
static int do_show_ip_bgp_summary(int argc, char *argv[], struct users *u);

static int do_show_ip_mroute(int argc, char *argv[], struct users *u);
static int do_show_ip_mroute_static(int argc, char *argv[], struct users *u);
static int do_show_ip_mroute_pim(int argc, char *argv[], struct users *u);
static int do_show_ip_mroute_pim_group(int argc, char *argv[], struct users *u);
static int do_show_ip_mroute_pim_group_src(int argc, char *argv[], struct users *u);
static int do_show_ip_pim(int argc, char *argv[], struct users *u);
static int do_show_ip_pim_neighbor(int argc, char *argv[], struct users *u);
static int do_show_ip_pim_neighbor_int(int argc, char *argv[], struct users *u);
static int do_show_ip_pim_interface(int argc, char *argv[], struct users *u);
static int do_show_ip_pim_interface_int(int argc, char *argv[], struct users *u);

static int do_show_ip_mroute_sm(int argc, char *argv[], struct users *u);

static int do_show_ip_sm(int argc, char *argv[], struct users *u);
static int do_show_ip_sm_neighbor(int argc, char *argv[], struct users *u);
static int do_show_ip_sm_neighbor_int(int argc, char *argv[], struct users *u);

static int do_show_ip_sm_rp(int argc, char *argv[], struct users *u);
static int do_show_ip_sm_rp_map(int argc, char *argv[], struct users *u);
static int do_show_ip_sm_rp_met(int argc, char *argv[], struct users *u);

static int do_show_garp(int argc, char *argv[], struct users *u);
static int do_show_garp_timer(int argc, char *argv[], struct users *u);
static int do_show_garp_stats(int argc, char *argv[], struct users *u);
static int do_show_garp_stats_inter(int argc, char *argv[], struct users *u);
static int do_show_gmrp(int argc, char *argv[], struct users *u);
static int do_show_gmrp_status(int argc, char *argv[], struct users *u);
static int do_show_gmrp_stats(int argc, char *argv[], struct users *u);
static int do_show_gmrp_stats_inter(int argc, char *argv[], struct users *u);

static int do_show_ip_igmp(int argc, char *argv[], struct users *u);
static int do_show_ip_igmp_int(int argc, char *argv[], struct users *u);
static int do_show_ip_igmp_int_vlan(int argc, char *argv[], struct users *u);
static int do_show_ip_igmp_int_vlan_num(int argc, char *argv[], struct users *u);
static int do_show_ip_igmp_group(int argc, char *argv[], struct users *u);
static int do_show_ip_igmp_detail(int argc, char *argv[], struct users *u);

static int do_show_ipv6_mroute(int argc, char *argv[], struct users *u);
static int do_show_ipv6_mroute_static(int argc, char *argv[], struct users *u);
static int do_show_ipv6_mroute_pim(int argc, char *argv[], struct users *u);
static int do_show_ipv6_mroute_pim_group(int argc, char *argv[], struct users *u);
static int do_show_ipv6_mroute_pim_group_src(int argc, char *argv[], struct users *u);

static int do_show_bfd(int argc, char *argv[], struct users *u);
static int do_show_bfd_neighbors(int argc, char *argv[], struct users *u);
static int do_show_bfd_neighbors_details(int argc, char *argv[], struct users *u);

static int do_show_filter(int argc, char *argv[], struct users *u);

static int do_show_tunnel(int argc, char *argv[], struct users *u);

static int do_show_cluster(int argc, char *argv[], struct users *u);

static int do_show_ring(int argc, char *argv[], struct users *u);
static int do_show_ring_id(int argc, char *argv[], struct users *u);
static int do_show_svn_version(int argc, char *argv[], struct users *u);

static int do_show_erps_instance_id(int argc, char *argv[], struct users *u);
static int do_show_erps_ring_id(int argc, char *argv[], struct users *u);
static int do_show_erps(int argc, char *argv[], struct users *u);
static int do_show_erps_ring(int argc, char *argv[], struct users *u);
static int do_show_erps_instance(int argc, char *argv[], struct users *u);
int func_show_erps_profile(struct users *u);
static int do_show_erps_profile(int argc, char *argv[], struct users *u);
static int do_show_multicast_vlan(int argc, char *argv[], struct users *u);

#endif
