#ifndef __DO_VLAN__
#define __DO_VLAN__



/* extern functions */
extern int do_test(int argc, char *argv[], struct users *u);
extern int do_test_param(int argc, char *argv[], struct users *u);

/* vlan commands parse function */
static int do_vlan(int argc, char *argv[], struct users *u);
static int no_vlan(int argc, char *argv[], struct users *u);
static int do_private_vlan(int argc, char *argv[], struct users *u);

static int do_vlan_name(int argc, char *argv[], struct users *u);
static int no_vlan_name(int argc, char *argv[], struct users *u);

static int do_vlan_ip(int argc, char *argv[], struct users *u);
static int no_vlan_ip(int argc, char *argv[], struct users *u);

static int do_vlan_ipv6(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_dhcp(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_dhcp_realy(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_dhcp_realy_address (int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_dhcp_relay(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_dhcp(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_address_local(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_address_global(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_address(int argc, char *argv[], struct users *u);


static int do_vlan_shutdown(int argc, char *argv[], struct users *u);
static int no_vlan_shutdown(int argc, char *argv[], struct users *u);

static int do_vlan_ip_access_group(int argc, char *argv[], struct users *u);
static int no_vlan_ip_access_group(int argc, char *argv[], struct users *u);

static int do_vlan_ip_address(int argc, char *argv[], struct users *u);
static int no_vlan_ip_address(int argc, char *argv[], struct users *u);

static int do_vlan_ip_access_group_in(int argc, char *argv[], struct users *u);
static int no_vlan_ip_access_group_in(int argc, char *argv[], struct users *u);
static int do_vlan_ip_access_group_out(int argc, char *argv[], struct users *u);
static int no_vlan_ip_access_group_out(int argc, char *argv[], struct users *u);

static int do_vlan_ipv6_address(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_address(int argc, char *argv[], struct users *u);

static int do_vlan_ip_address_dhcp(int argc, char *argv[], struct users *u);
static int do_vlan_ip_address_static(int argc, char *argv[], struct users *u);

static int do_vlan_ipv6_address_global(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_address_local(int argc, char *argv[], struct users *u);

static int do_vlan_ipv6_enable(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_enable(int argc, char *argv[], struct users *u);

static int do_vlan_ipv6_ospf(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_ospf_pid(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_ospf_pid_area(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_ospf_pid_area_id(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_ospf_pid_area_id(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_ospf(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_ospf_pid(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_ospf_pid_area(int argc, char *argv[], struct users *u);

static int do_vlan_ipv6_rip(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_rip_name(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_rip_name_enable(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_rip(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_rip_name(int argc, char *argv[], struct users *u);

static int do_vlan_ipv6_router(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_router_isis(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_router(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_router_isis(int argc, char *argv[], struct users *u);

static int do_vlan_ipv6_isis(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_isis(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_traffic(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_traffic(int argc, char *argv[], struct users *u);

static int do_vlan_ipv6_isis_circuit(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_isis_circuit(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_isis_circuit_level_1(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_isis_circuit_level_1_2(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_isis_circuit_level_2_o(int argc, char *argv[], struct users *u);

static int do_vlan_ipv6_traffic(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_traffic_name(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_traffic_name_in(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_traffic_name_out(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_traffic(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_traffic_name(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_traffic_name_in(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_traffic_name_out(int argc, char *argv[], struct users *u);

static int do_vlan_ipv6_mld(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_mld_join(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_mld_join_addr(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_mld_join_addr_in(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_mld_join_addr_ex(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_mld_join_addr_in_src(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_mld_join_addr_ex_src(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_mld(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_mld_join(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_mld_join_addr(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_mld_join_addr_in(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_mld_join_addr_ex(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_mld_join_addr_in_src(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_mld_join_addr_ex_src(int argc, char *argv[], struct users *u);

static int do_vlan_ipv6_mld_querier(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_mld_querier_time(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_mld_querier(int argc, char *argv[], struct users *u);

static int do_vlan_ipv6_mld_query(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_mld_query_time(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_mld_query(int argc, char *argv[], struct users *u);

static int do_vlan_ipv6_mld_static(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_mld_static_all(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_mld_static_all_in(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_mld_static_all_in_src(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_mld_static_group(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_mld_static_group_in(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_mld_static_group_in_src(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_mld_static(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_mld_static_all(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_mld_static_all_in(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_mld_static_all_in_src(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_mld_static_group(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_mld_static_group_in(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_mld_static_group_in_src(int argc, char *argv[], struct users *u);

static int do_vlan_vrrp(int argc, char *argv[], struct users *u);
static int no_vlan_vrrp(int argc, char *argv[], struct users *u);

static int do_vlan_vrrp_num(int argc, char *argv[], struct users *u);
static int no_vlan_vrrp_num(int argc, char *argv[], struct users *u);
static int do_vlan_vrrp_num_desc(int argc, char *argv[], struct users *u);
static int no_vlan_vrrp_num_desc(int argc, char *argv[], struct users *u);
static int do_vlan_vrrp_num_ip(int argc, char *argv[], struct users *u);
static int no_vlan_vrrp_num_ip(int argc, char *argv[], struct users *u);
static int do_vlan_vrrp_num_preempt(int argc, char *argv[], struct users *u);
static int no_vlan_vrrp_num_preempt(int argc, char *argv[], struct users *u);
static int do_vlan_vrrp_num_priority(int argc, char *argv[], struct users *u);
static int no_vlan_vrrp_num_priority(int argc, char *argv[], struct users *u);
static int do_vlan_vrrp_num_desc_line(int argc, char *argv[], struct users *u);
static int do_vlan_vrrp_num_ip_addr(int argc, char *argv[], struct users *u);
static int no_vlan_vrrp_num_ip_addr(int argc, char *argv[], struct users *u);
static int do_vlan_vrrp_num_priority_level(int argc, char *argv[], struct users *u);

static int do_gvrp(int argc, char *argv[], struct users *u);
static int no_gvrp(int argc, char *argv[], struct users *u);

static int do_vlan_arp(int argc, char *argv[], struct users *u);
static int no_vlan_arp(int argc, char *argv[], struct users *u);
static int do_vlan_arp_timeout(int argc, char *argv[], struct users *u);
static int no_vlan_arp_timeout(int argc, char *argv[], struct users *u);
static int do_vlan_arp_timeout_sec(int argc, char *argv[], struct users *u);


static int do_vlan_arp_send(int argc, char *argv[], struct users *u);
static int do_vlan_arp_send_interval(int argc, char *argv[], struct users *u);
static int do_vlan_arp_send_interval_sec(int argc, char *argv[], struct users *u);
static int no_vlan_arp_send(int argc, char *argv[], struct users *u);
static int no_vlan_arp_send_interval(int argc, char *argv[], struct users *u);

static int do_vlan_ip_proxy_arp(int argc, char *argv[], struct users *u);
static int no_vlan_ip_proxy_arp(int argc, char *argv[], struct users *u);

static int do_vlan_ip_igmp(int argc, char *argv[], struct users *u);
static int do_interface_vlan_ip_igmp_querier(int argc, char *argv[], struct users *u);
static int do_interface_vlan_ip_igmp_querier_time(int argc, char *argv[], struct users *u);
static int no_vlan_ip_igmp(int argc, char *argv[], struct users *u);
static int no_interface_vlan_ip_igmp_querier(int argc, char *argv[], struct users *u);

static int do_interface_vlan_ip_igmp_query(int argc, char *argv[], struct users *u);
static int do_interface_vlan_ip_igmp_query_time(int argc, char *argv[], struct users *u);
static int no_interface_vlan_ip_igmp_query(int argc, char *argv[], struct users *u);

static int do_interface_vlan_ip_igmp_static(int argc, char *argv[], struct users *u);
static int do_interface_vlan_ip_igmp_static_ip(int argc, char *argv[], struct users *u);
static int do_interface_vlan_ip_igmp_static_ip_in(int argc, char *argv[], struct users *u);
static int do_interface_vlan_ip_igmp_static_ip_in_source(int argc, char *argv[], struct users *u);
static int no_interface_vlan_ip_igmp_static(int argc, char *argv[], struct users *u);
static int no_interface_vlan_ip_igmp_static_ip(int argc, char *argv[], struct users *u);

static int do_interface_vlan_ip_igmp_version(int argc, char *argv[], struct users *u);
static int do_interface_vlan_ip_igmp_version_1(int argc, char *argv[], struct users *u);
static int do_interface_vlan_ip_igmp_version_2(int argc, char *argv[], struct users *u);
static int do_interface_vlan_ip_igmp_version_3(int argc, char *argv[], struct users *u);
static int no_interface_vlan_ip_igmp_version(int argc, char *argv[], struct users *u);

static int do_vlan_ip_pim(int argc, char *argv[], struct users *u);
static int no_vlan_ip_pim(int argc, char *argv[], struct users *u);

static int do_vlan_ip_pim_sm(int argc, char *argv[], struct users *u);
static int no_vlan_ip_pim_sm(int argc, char *argv[], struct users *u);

static int do_vlan_ip_pim_dr(int argc, char *argv[], struct users *u);
static int no_vlan_ip_pim_dr(int argc, char *argv[], struct users *u);
static int do_vlan_pim_dr_priority(int argc, char *argv[], struct users *u);

static int do_vlan_ipv6_pim(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_pim(int argc, char *argv[], struct users *u);

static int do_vlan_ipv6_pim_bsr(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_pim_bsr(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_pim_dr(int argc, char *argv[], struct users *u);
static int no_vlan_ipv6_pim_dr(int argc, char *argv[], struct users *u);
static int do_vlan_ipv6_pim_dr_priority(int argc, char *argv[], struct users *u);

static int do_vlan_vrrp_num_associate(int argc, char *argv[], struct users *u);
static int do_vlan_vrrp_num_associate_ip(int argc, char *argv[], struct users *u);
static int no_vlan_vrrp_num_associate(int argc, char *argv[], struct users *u);

static int do_vlan_vrrp_num_auth(int argc, char *argv[], struct users *u);
static int do_vlan_vrrp_num_auth_str(int argc, char *argv[], struct users *u);
static int no_vlan_vrrp_num_auth(int argc, char *argv[], struct users *u);

static int do_vlan_vrrp_num_timer(int argc, char *argv[], struct users *u);
static int do_vlan_vrrp_timer(int argc, char *argv[], struct users *u);
static int no_vlan_vrrp_timer(int argc, char *argv[], struct users *u);
static no_vlan_vrrp_auth(int argc, char *argv[], struct users *u);
static int do_vlan_vrrp_auth(int argc, char *argv[], struct users *u);

static int do_vlan_ip_rip(int argc, char *argv[], struct users *u);
static int do_interface_vlan_ip_rip_bfd(int argc, char *argv[], struct users *u);
static int no_vlan_ip_rip(int argc, char *argv[], struct users *u);
static int no_interface_vlan_ip_rip_bfd(int argc, char *argv[], struct users *u);

static int do_vlan_ip_ospf(int argc, char *argv[], struct users *u);
static int do_interface_vlan_ip_ospf_bfd(int argc, char *argv[], struct users *u);
static int no_vlan_ip_ospf(int argc, char *argv[], struct users *u);
static int no_interface_vlan_ip_ospf_bfd(int argc, char *argv[], struct users *u);

static int do_vlan_ip_bgp(int argc, char *argv[], struct users *u);
static int do_interface_vlan_ip_bgp_bfd(int argc, char *argv[], struct users *u);
static int no_vlan_ip_bgp(int argc, char *argv[], struct users *u);
static int no_interface_vlan_ip_bgp_bfd(int argc, char *argv[], struct users *u);

static int do_vlan_ip_isis(int argc, char *argv[], struct users *u);
static int do_interface_vlan_ip_isis_bfd(int argc, char *argv[], struct users *u);
static int no_vlan_ip_isis(int argc, char *argv[], struct users *u);
static int no_interface_vlan_ip_isis_bfd(int argc, char *argv[], struct users *u);

static int do_vlan_ip_static(int argc, char *argv[], struct users *u);
static int do_interface_vlan_ip_static_bfd(int argc, char *argv[], struct users *u);
static int no_vlan_ip_static(int argc, char *argv[], struct users *u);
static int no_interface_vlan_ip_static_bfd(int argc, char *argv[], struct users *u);

static int do_vlan_vrrp_num_bfd(int argc, char *argv[], struct users *u);
static int do_vlan_vrrp_num_bfd_ip(int argc, char *argv[], struct users *u);
static int no_vlan_vrrp_num_bfd(int argc, char *argv[], struct users *u);

static int do_vlan_bfd(int argc, char *argv[], struct users *u);
static int do_vlan_bfd_int(int argc, char *argv[], struct users *u);
static int do_vlan_bfd_int_time(int argc, char *argv[], struct users *u);
static int do_vlan_bfd_int_time_rx(int argc, char *argv[], struct users *u);
static int do_vlan_bfd_int_time_rx_time(int argc, char *argv[], struct users *u);
static int do_vlan_bfd_int_time_rx_time_plier(int argc, char *argv[], struct users *u);
static int do_vlan_bfd_int_time_rx_time_plier_val(int argc, char *argv[], struct users *u);
static int no_vlan_bfd(int argc, char *argv[], struct users *u);
static int no_vlan_bfd_int(int argc, char *argv[], struct users *u);

static int do_vlan_bfd_auth(int argc, char *argv[], struct users *u);
static int do_vlan_bfd_auth_md5(int argc, char *argv[], struct users *u);
static int do_vlan_bfd_auth_md5_key(int argc, char *argv[], struct users *u);
static int do_vlan_bfd_auth_simple(int argc, char *argv[], struct users *u);
static int do_vlan_bfd_auth_simple_key(int argc, char *argv[], struct users *u);
static int no_vlan_bfd_auth(int argc, char *argv[], struct users *u);
static int no_vlan_bfd_auth_md5(int argc, char *argv[], struct users *u);
static int no_vlan_bfd_auth_simple(int argc, char *argv[], struct users *u);

static int do_vlan_router_isis(int argc, char *argv[], struct users *u);
static int do_interface_vlan_router_isis(int argc, char *argv[], struct users *u);
static int no_vlan_router_isis(int argc, char *argv[], struct users *u);
static int no_interface_vlan_router_isis(int argc, char *argv[], struct users *u);

int init_cli_vlan(void);

static int do_supervlan(int argc, char *argv[], struct users *u);
static int no_supervlan(int argc, char *argv[], struct users *u);


static int do_subvlan(int argc, char *argv[], struct users *u);
static int no_subvlan(int argc, char *argv[], struct users *u);

static int do_vlan_subvlan(int argc, char *argv[], struct users *u);

static int do_ip_helper(int argc, char *argv[], struct users *u);
static int no_ip_helper(int argc, char *argv[], struct users *u);
static int do_ip_helper_ip(int argc, char *argv[], struct users *u);
static int no_ip_helper_ip(int argc, char *argv[], struct users *u);
static int do_multicast_subvlan(int argc, char *argv[], struct users *u);
static int do_multicast_vlan(int argc, char *argv[], struct users *u);
static int no_multicast_vlan(int argc, char *argv[], struct users *u);
static int do_multicast_vlan_id(int argc, char *argv[], struct users *u);
static int do_multicast_vlan_enable(int argc, char *argv[], struct users *u);
static int no_multicast_vlan_enable(int argc, char *argv[], struct users *u);

#endif
