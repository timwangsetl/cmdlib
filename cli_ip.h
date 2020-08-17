#ifndef __DO_INTERFANCE__
#define __DO_INTERFANCE__

/* extern functions */
extern int do_test(int argc, char *argv[], struct users *u);
extern int do_test_param(int argc, char *argv[], struct users *u);


/*ip commands parse function */
static int do_ip(int argc, char *argv[], struct users *u);
static int do_ip_acl(int argc, char *argv[], struct users *u);
static int do_ip_acl_mode(int argc, char *argv[], struct users *u);

static int do_arp(int argc, char *argv[], struct users *u);

static int do_ip_arp_mode(int argc, char *argv[], struct users *u);
static int do_ip_arp_ins(int argc, char *argv[], struct users *u);

static int do_dhcp(int argc, char *argv[], struct users *u);
static int do_dhcpd(int argc, char *argv[], struct users *u);
static int do_ip_dhcpd_start(int argc, char *argv[], struct users *u);
static int do_ip_dhcp_realy(int argc, char *argv[], struct users *u);
static int do_ip_dhcp_snooping(int argc, char *argv[], struct users *u);
static int do_ip_dhcp_snooping_vlan(int argc, char *argv[], struct users *u);
static int do_ip_dhcp_snooping_datebase_flash(int argc, char *argv[], struct users *u);
static int do_ip_dhcp_snooping_datebase_delay(int argc, char *argv[], struct users *u);
static int do_ip_dhcp_snooping_datebase(int argc, char *argv[], struct users *u);
static int do_ip_dhcp_snooping_source_mac(int argc, char *argv[], struct users *u);


static int do_http(int argc, char *argv[], struct users *u);
static int do_http_server(int argc, char *argv[], struct users *u);
static int do_name_server(int argc, char *argv[], struct users *u);

static int do_dns(int argc, char *argv[], struct users *u);
static int no_dns(int argc, char *argv[], struct users *u);
static int do_ip_dns_proxy(int argc, char *argv[], struct users *u);
static int no_ip_dns_proxy(int argc, char *argv[], struct users *u);

static int do_igmp_snooping_timer_querier(int argc, char *argv[], struct users *u);
static int do_igmp_snooping(int argc, char *argv[], struct users *u);
static int do_igmp_snooping_querier(int argc, char *argv[], struct users *u);
static int do_igmp_snooping_timer(int argc, char *argv[], struct users *u);
static int do_igmp_snooping_timer_survival(int argc, char *argv[], struct users *u);

static int do_default_gateway(int argc, char *argv[], struct users *u);

static int do_ipv6(int argc, char *argv[], struct users *u);
static int do_ipv6_acl(int argc, char *argv[], struct users *u);
static int do_ipv6_acl_mode_s(int argc, char *argv[], struct users *u);
static int no_ipv6_acl_mode_s(int argc, char *argv[], struct users *u);
static int do_ipv6_name_server(int argc, char *argv[], struct users *u);
static int no_ipv6_name_server(int argc, char *argv[], struct users *u);
static int do_ipv6_name(int argc, char *argv[], struct users *u);
static int do_ipv6_default_gateway(int argc, char *argv[], struct users *u);
static int do_ipv6_default_g(int argc, char *argv[], struct users *u);
static int no_ipv6_default_gateway(int argc, char *argv[], struct users *u);
static int do_ipv6_dhcp_snooping(int argc, char *argv[], struct users *u);
static int do_ipv6_dhcp(int argc, char *argv[], struct users *u);
static int no_ipv6_dhcp_snooping(int argc, char *argv[], struct users *u);
static int do_ipv6_set(int argc, char *argv[], struct users *u);
static int no_ipv6_set(int argc, char *argv[], struct users *u);
static int do_ipv6_addr(int argc, char *argv[], struct users *u);
static int no_ipv6_addr(int argc, char *argv[], struct users *u);


static int do_ipv6_nd(int argc, char *argv[], struct users *u);
static int no_ipv6_nd(int argc, char *argv[], struct users *u);
static int do_ipv6_nd_cache(int argc, char *argv[], struct users *u);
static int no_ipv6_nd_cache(int argc, char *argv[], struct users *u);
static int do_ipv6_nd_cache_expire(int argc, char *argv[], struct users *u);
static int no_ipv6_nd_cache_expire(int argc, char *argv[], struct users *u);
static int do_ipv6_nd_cache_expire_time(int argc, char *argv[], struct users *u);

static int do_ipv6_router(int argc, char *argv[], struct users *u);
static int no_ipv6_router(int argc, char *argv[], struct users *u);
static int do_ipv6_router_ospf(int argc, char *argv[], struct users *u);
static int no_ipv6_router_ospf(int argc, char *argv[], struct users *u);
static int do_ipv6_router_rip(int argc, char *argv[], struct users *u);
static int no_ipv6_router_rip(int argc, char *argv[], struct users *u);
static int do_ipv6_router_isis(int argc, char *argv[], struct users *u);
static int no_ipv6_router_isis(int argc, char *argv[], struct users *u);
static int do_ipv6_router_ospf_pid(int argc, char *argv[], struct users *u);
static int no_ipv6_router_ospf_pid(int argc, char *argv[], struct users *u);
static int do_ipv6_router_rip_str(int argc, char *argv[], struct users *u);
static int no_ipv6_router_rip_str(int argc, char *argv[], struct users *u);

static int do_ipv6_unicast(int argc, char *argv[], struct users *u);
static int no_ipv6_unicast(int argc, char *argv[], struct users *u);

static int do_cos(int argc, char *argv[], struct users *u);
static int do_cos_map_n(int argc, char *argv[], struct users *u);
static int do_cos_num(int argc, char *argv[], struct users *u);

static int do_cos_num_n(int argc, char *argv[], struct users *u);
static int do_cos_map_n(int argc, char *argv[], struct users *u);

static int no_cos(int argc, char *argv[], struct users *u);
static int no_cos_num_n(int argc, char *argv[], struct users *u);


static int do_source(int argc, char *argv[], struct users *u);
static int do_ip_source_bind(int argc, char *argv[], struct users *u);
static int do_source_bind_mac(int argc, char *argv[], struct users *u);
static int do_ip_source_vlan(int argc, char *argv[], struct users *u);
static int do_source_vlan_ip(int argc, char *argv[], struct users *u);
static int do_source_bind_vlan_ip(int argc, char *argv[], struct users *u);
static int do_source_bind_vlan(int argc, char *argv[], struct users *u);
static int do_ip_acl_mode_s(int argc, char *argv[], struct users *u);

/* interface port */
static int do_source_vlan_interface_ethernet(int argc, char *argv[], struct users *u);
static int do_source_vlan_interface_num(int argc, char *argv[], struct users *u);
static int do_source_vlan_interface_slash(int argc, char *argv[], struct users *u);
static int do_source_vlan_interface_port(int argc, char *argv[], struct users *u);

static int no_name_server(int argc, char *argv[], struct users *u);
static int no_default_gateway(int argc, char *argv[], struct users *u);
static int no_ip_acl_mode(int argc, char *argv[], struct users *u);
static int no_ip_acl_mode_s(int argc, char *argv[], struct users *u);
static int no_name_server(int argc, char *argv[], struct users *u);
static int no_dhcp(int argc, char *argv[], struct users *u);
static int no_dhcpd(int argc, char *argv[], struct users *u);
static int no_ip_dhcpd_start(int argc, char *argv[], struct users *u);
static int no_ip_dhcp_bind(int argc, char *argv[], struct users *u);
static int no_ip_dhcp_snooping(int argc, char *argv[], struct users *u);
static int no_ip_dhcp_snooping_vlan_all(int argc, char *argv[], struct users *u);
static int no_ip_dhcp_snooping_vlan_number(int argc, char *argv[], struct users *u);


static int no_http_server(int argc, char *argv[], struct users *u);
static int no_source_bind_vlan(int argc, char *argv[], struct users *u);
static int no_igmp_snooping(int argc, char *argv[], struct users *u);
static int no_ip_arp_mode(int argc, char *argv[], struct users *u);
static int no_igmp_snooping_querier(int argc, char *argv[], struct users *u);

static int no_igmp_snooping_timer_querier_q(int argc, char *argv[], struct users *u);
static int no_igmp_snooping_timer_s(int argc, char *argv[], struct users *u);
static int no_igmp_snooping_timer(int argc, char *argv[], struct users *u);
static int no_source_mac(int argc, char *argv[], struct users *u);
static int no_ip_source_vlan(int argc, char *argv[], struct users *u);
static int no_ip_source_bind(int argc, char *argv[], struct users *u);
static int no_source_mac(int argc, char *argv[], struct users *u);

static int do_dscp(int argc, char *argv[], struct users *u);
static int do_dscp_enable(int argc, char *argv[], struct users *u);
static int no_dscp_map_n(int argc, char *argv[], struct users *u);
static int do_dscp_value(int argc, char *argv[], struct users *u);
static int no_dscp(int argc, char *argv[], struct users *u);
static int do_dscp_map(int argc, char *argv[], struct users *u);
static int do_dscp_id(int argc, char *argv[], struct users *u);
static int do_ipv6_route(int argc, char *argv[], struct users *u);
static int no_ipv6_route(int argc, char *argv[], struct users *u);
static int do_ipv6_mld(int argc, char *argv[], struct users *u);
static int no_ipv6_mld(int argc, char *argv[], struct users *u);
static int do_ipv6_route_ipv6(int argc, char *argv[], struct users *u);
static int no_ipv6_route_ipv6(int argc, char *argv[], struct users *u);
static int do_ipv6_route_ipv6_next(int argc, char *argv[], struct users *u);
static int no_ipv6_route_all(int argc, char *argv[], struct users *u);
static int do_ipv6_mld_snooping(int argc, char *argv[], struct users *u);
static int no_ipv6_mld_snooping(int argc, char *argv[], struct users *u);

static int do_igmp_snooping_vlan(int argc, char *argv[], struct users *u);

static int no_igmp_snooping_vlan(int argc, char *argv[], struct users *u);
static int do_igmp_snooping_vlan_num(int argc, char *argv[], struct users *u);
static int no_ip_dhcp_snooping_vlan_num(int argc, char *argv[], struct users *u);

static int do_ip_dhcp_pool(int argc, char *argv[], struct users *u);
static int no_ip_dhcp_pool(int argc, char *argv[], struct users *u);
static int do_ipv6_dhcp_pool(int argc, char *argv[], struct users *u);
static int no_ipv6_dhcp_pool(int argc, char *argv[], struct users *u);
static int do_dhcpv6(int argc, char *argv[], struct users *u);
static int no_dhcpv6(int argc, char *argv[], struct users *u);

static int do_ip_forward(int argc, char *argv[], struct users *u);
static int no_ip_forward(int argc, char *argv[], struct users *u);
static int do_ip_forward_udp(int argc, char *argv[], struct users *u);
static int no_ip_forward_udp(int argc, char *argv[], struct users *u);
static int do_ip_forward_udp_bootps(int argc, char *argv[], struct users *u);
static int no_ip_forward_udp_bootps(int argc, char *argv[], struct users *u);

static int do_ip_helper(int argc, char *argv[], struct users *u);
static int no_ip_helper(int argc, char *argv[], struct users *u);
static int do_ip_helper_ip(int argc, char *argv[], struct users *u);
static int no_ip_helper_ip(int argc, char *argv[], struct users *u);

static int do_ip_route(int argc, char *argv[], struct users *u);
static int no_ip_route(int argc, char *argv[], struct users *u);
static int do_ip_route_default(int argc, char *argv[], struct users *u);
static int do_ip_route_default_ip(int argc, char *argv[], struct users *u);
static int no_ip_route_default(int argc, char *argv[], struct users *u);
static int do_ip_route_ip(int argc, char *argv[], struct users *u);
static int do_ip_route_ip_mask(int argc, char *argv[], struct users *u);
static int do_ip_route_ip_mask_next(int argc, char *argv[], struct users *u);
static int no_ip_route_ip(int argc, char *argv[], struct users *u);
static int no_ip_route_ip_mask(int argc, char *argv[], struct users *u);
static int no_ip_route_ip_mask_next(int argc, char *argv[], struct users *u);

static int do_garp(int argc, char *argv[], struct users *u);
static int do_garp_timer(int argc, char *argv[], struct users *u);
static int do_garp_timer_leaveall(int argc, char *argv[], struct users *u);
static int do_garp_timer_leaveall_value(int argc, char *argv[], struct users *u);
static int no_garp(int argc, char *argv[], struct users *u);
static int no_garp_timer(int argc, char *argv[], struct users *u);
static int no_garp_timer_leaveall(int argc, char *argv[], struct users *u);
static int do_gmrp(int argc, char *argv[], struct users *u);
static int no_gmrp(int argc, char *argv[], struct users *u);
static int do_ip_mroute(int argc, char *argv[], struct users *u);
static int do_ip_mroute_ip(int argc, char *argv[], struct users *u);

static int do_ip_mroute_ip_mask(int argc, char *argv[], struct users *u);
static int do_ip_mroute_ip_mask_rpf(int argc, char *argv[], struct users *u);
static int do_ip_mroute_ip_mask_rpf_int(int argc, char *argv[], struct users *u);
static int do_ip_mroute_interface_ethernet(int argc, char *argv[], struct users *u);
static int do_ip_mroute_interface_num(int argc, char *argv[], struct users *u);
static int do_ip_mroute_interface_slash(int argc, char *argv[], struct users *u);
static int do_ip_mroute_interface_port(int argc, char *argv[], struct users *u);
static int no_ip_mroute(int argc, char *argv[], struct users *u);
static int no_ip_mroute_ip(int argc, char *argv[], struct users *u);
static int no_ip_mroute_ip_mask(int argc, char *argv[], struct users *u);
static int do_ip_multi_routing(int argc, char *argv[], struct users *u);
static int no_ip_multi_routing(int argc, char *argv[], struct users *u);

static int do_ip_igmp(int argc, char *argv[], struct users *u);
static int do_ip_igmp_querier(int argc, char *argv[], struct users *u);
static int do_ip_igmp_querier_time(int argc, char *argv[], struct users *u);
static int no_ip_igmp(int argc, char *argv[], struct users *u);
static int no_ip_igmp_querier(int argc, char *argv[], struct users *u);

static int do_ip_pim(int argc, char *argv[], struct users *u);
static int do_ip_pim_bsr(int argc, char *argv[], struct users *u);
static int no_ip_pim(int argc, char *argv[], struct users *u);
static int no_ip_pim_bsr(int argc, char *argv[], struct users *u);
static int do_ip_pim_sm_priority(int argc, char *argv[], struct users *u);
static int do_ip_pim_bsr_pri(int argc, char *argv[], struct users *u);


static int do_ip_pim_dm(int argc, char *argv[], struct users *u);
static int no_ip_pim_dm(int argc, char *argv[], struct users *u);

static int do_ip_pim_dr(int argc, char *argv[], struct users *u);
static int do_ip_pim_dr_priority(int argc, char *argv[], struct users *u);
static int no_ip_pim_dr(int argc, char *argv[], struct users *u);

static int do_ip_pim_rp(int argc, char *argv[], struct users *u);
static int do_ip_pim_rp_add(int argc, char *argv[], struct users *u);
static int do_ip_pim_rp_add_netmask(int argc, char *argv[], struct users *u);
static int do_ip_route_pimsm_mask(int argc, char *argv[], struct users *u);
static int do_ip_pim_rp_add_over(int argc, char *argv[], struct users *u);
static int do_ip_pim_rp_add_acl(int argc, char *argv[], struct users *u);
static int no_ip_pim_rp(int argc, char *argv[], struct users *u);
static int no_ip_pim_rp_add(int argc, char *argv[], struct users *u);
static int no_ip_pim_rp_add_over(int argc, char *argv[], struct users *u);
static int no_ip_pim_rp_add_acl(int argc, char *argv[], struct users *u);

static int do_ip_pim_can(int argc, char *argv[], struct users *u);
static int no_ip_pim_can(int argc, char *argv[], struct users *u);
static int do_pim_sm_cantime(int argc, char *argv[], struct users *u);
static int do_pim_sm_cantime_int(int argc, char *argv[], struct users *u);
static int do_pim_sm_priority(int argc, char *argv[], struct users *u);
static int do_pim_sm_priority_int(int argc, char *argv[], struct users *u);

static int do_ipv6_pim(int argc, char *argv[], struct users *u);
static int no_ipv6_pim(int argc, char *argv[], struct users *u);

static int do_ipv6_pim_bsr(int argc, char *argv[], struct users *u);
static int no_ipv6_pim_bsr(int argc, char *argv[], struct users *u);

static int do_ipv6_pim_rp(int argc, char *argv[], struct users *u);
static int do_ipv6_pim_rp_add(int argc, char *argv[], struct users *u);
static int do_ipv6_pim_rp_add_over(int argc, char *argv[], struct users *u);
static int do_ipv6_pim_rp_add_acl(int argc, char *argv[], struct users *u);
static int no_ipv6_pim_rp(int argc, char *argv[], struct users *u);
static int no_ipv6_pim_rp_add(int argc, char *argv[], struct users *u);
static int no_ipv6_pim_rp_add_over(int argc, char *argv[], struct users *u);
static int no_ipv6_pim_rp_add_acl(int argc, char *argv[], struct users *u);

static int do_ipv6_pim_dr_priority(int argc, char *argv[], struct users *u);

static int do_ipv6_pim_can(int argc, char *argv[], struct users *u);
static int no_ipv6_pim_can(int argc, char *argv[], struct users *u);

static int do_bfd(int argc, char *argv[], struct users *u);
static int do_bfd_enable(int argc, char *argv[], struct users *u);
static int do_bfd_all(int argc, char *argv[], struct users *u);
static int no_bfd(int argc, char *argv[], struct users *u);
static int no_bfd_enable(int argc, char *argv[], struct users *u);
static int no_bfd_all(int argc, char *argv[], struct users *u);

static int do_inter_port_garp_timer_hold(int argc, char *argv[], struct users *u);
static int do_inter_port_garp_timer_join(int argc, char *argv[], struct users *u);
static int do_inter_port_garp_timer_leave(int argc, char *argv[], struct users *u);
static int do_inter_port_garp_timer_hold_value(int argc, char *argv[], struct users *u);
static int do_inter_port_garp_timer_join_value(int argc, char *argv[], struct users *u);
static int do_inter_port_garp_timer_leave_value(int argc, char *argv[], struct users *u);

static int no_inter_port_garp_timer(int argc, char *argv[], struct users *u);
static int no_inter_port_garp_timer_hold(int argc, char *argv[], struct users *u);
static int no_inter_port_garp_timer_join(int argc, char *argv[], struct users *u);
static int no_inter_port_garp_timer_leave(int argc, char *argv[], struct users *u);

static int do_ip_set(int argc, char *argv[], struct users *u);
static int do_ip_and_mask(int argc, char *argv[], struct users *u);
static int do_ipv6_dhcp_client(int argc, char *argv[], struct users *u);

static int no_ipv6_dhcp_client(int argc, char *argv[], struct users *u);

#endif

