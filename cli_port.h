#ifndef __DO_PORT__
#define __DO_PORT__


#define INT_PORT_BROAD 1
#define INT_PORT_MUL 2
#define INT_PORT_UNI 3

#define INT_PORT_BROAD_POS	(MAX_V_INT-1)
#define INT_PORT_MUL_POS	(INT_PORT_BROAD_POS-1)
#define INT_PORT_UNI_POS	(INT_PORT_MUL_POS-1)

#define NO_FORBID 			0x00000001
#define NO_AUTHENTICATION 	0x00000002
#define NO_PORT_CONTROL 	0x00000004

#define NO_BLOCK			0x00000010
#define NO_LOOPBACK 		0x00000020
#define NO_PORTSEC			0x00000040
#define NO_PROTECTED 		0x00000080
#define NO_RATELIMIT 		0x00000100


/* extern functions */
extern int do_test(int argc, char *argv[], struct users *u);
extern int do_test_param(int argc, char *argv[], struct users *u);

/* aggregator-group commands parse function */

static int do_interface_trunk(int argc, char *argv[], struct users *u);
static int no_interface_trunk(int argc, char *argv[], struct users *u);
static int do_interface_trunk_group(int argc, char *argv[], struct users *u);
static int do_interface_trunk_mode(int argc, char *argv[], struct users *u);
static int do_interface_trunk_mode_lacp(int argc, char *argv[], struct users *u);
static int do_interface_trunk_mode_static(int argc, char *argv[], struct users *u);

/* arp commands parse function */

static int no_inspection_trust(int argc, char *argv[], struct users *u);
static int do_interface_arp(int argc, char *argv[], struct users *u);
static int do_arp_inspection(int argc, char *argv[], struct users *u);
static int do_inspection_trust(int argc, char *argv[], struct users *u);

/* interface cos commands parse function */
static int do_inter_cos(int argc, char *argv[], struct users *u);
static int do_inter_cos_default(int argc, char *argv[], struct users *u);
static int no_inter_cos_default(int argc, char *argv[], struct users *u);

/* speed commands parse function */
static int do_speed(int argc, char *argv[], struct users *u);
static int do_speed_auto(int argc, char *argv[], struct users *u);
static int do_speed_giga(int argc, char *argv[], struct users *u);
static int do_speed_hundred(int argc, char *argv[], struct users *u);
static int do_speed_ten(int argc, char *argv[], struct users *u);
static int no_do_speed(int argc, char *argv[], struct users *u);


/* duplex commands parse function */
static int do_duplex(int argc, char *argv[], struct users *u);
static int no_do_duplex(int argc, char *argv[], struct users *u);
static int do_duplex_auto(int argc, char *argv[], struct users *u);
static int do_duplex_full(int argc, char *argv[], struct users *u);
static int do_duplex_half(int argc, char *argv[], struct users *u);


/* switchport commands parse function */
static int no_do_sw_loop(int argc, char *argv[], struct users *u);
static int do_sw_loop(int argc, char *argv[], struct users *u);

static int no_do_sw_pro(int argc, char *argv[], struct users *u);
static int do_sw_pro(int argc, char *argv[], struct users *u);

static int do_sw_block_broad(int argc, char *argv[], struct users *u);
static int do_sw_block_mul(int argc, char *argv[], struct users *u);
static int do_sw_block_uni(int argc, char *argv[], struct users *u);
static int do_sw_block(int argc, char *argv[], struct users *u);
static int no_do_sw_block_broad(int argc, char *argv[], struct users *u);
static int no_do_sw_block_mul(int argc, char *argv[], struct users *u);
static int no_do_sw_block_uni(int argc, char *argv[], struct users *u);



static int no_do_sw_mode(int argc, char *argv[], struct users *u);
static int do_sw_mode_pri_vlan_pro(int argc, char *argv[], struct users *u);
static int do_sw_mode_pri_vlan_host(int argc, char *argv[], struct users *u);
static int do_sw_mode_pri_vlan(int argc, char *argv[], struct users *u);
static int do_sw_mode_tru(int argc, char *argv[], struct users *u);
static int do_sw_mode_acc(int argc, char *argv[], struct users *u);
static int do_sw_mode_pri_vlan_pro_add(int argc, char *argv[], struct users *u);
static int do_sw_mode(int argc, char *argv[], struct users *u);

static int do_sw_portsec(int argc, char *argv[], struct users *u);
static int do_sw_portsec_dy(int argc, char *argv[], struct users *u);
static int no_do_sw_portsec_dy(int argc, char *argv[], struct users *u);
static int no_do_sw_portsec_mo(int argc, char *argv[], struct users *u);
static int do_sw_portsec_dy_max(int argc, char *argv[], struct users *u);
static int do_sw_portsec_mo(int argc, char *argv[], struct users *u);
static int do_sw_portsec_mo_sta(int argc, char *argv[], struct users *u);
static int do_sw_portsec_mo_dy(int argc, char *argv[], struct users *u);
static int do_sw_portsec_mo_sta_acc(int argc, char *argv[], struct users *u);


static int do_switchport(int argc, char *argv[], struct users *u);

static int do_trunk(int argc, char *argv[], struct users *u);
static int no_do_tru_vlan_untagged(int argc, char *argv[], struct users *u);
static int no_do_trunk_vlan_allo(int argc, char *argv[], struct users *u);
static int do_tru_vlan_untagged(int argc, char *argv[], struct users *u);
static int do_trunk_vlan_allo(int argc, char *argv[], struct users *u);
static int do_tru_vlan_untag_word(int argc, char *argv[], struct users *u);
static int do_trunk_vlan_allo_word(int argc, char *argv[], struct users *u);

static int do_vlan(int argc, char *argv[], struct users *u);
static int no_do_vlan(int argc, char *argv[], struct users *u);


static int do_rate_limit(int argc, char *argv[], struct users *u);
static int do_rate_limit_egr(int argc, char *argv[], struct users *u);
static int do_rate_limit_ing(int argc, char *argv[], struct users *u);
static int no_do_rate_limit_egr(int argc, char *argv[], struct users *u);
static int no_do_rate_limit_ing(int argc, char *argv[], struct users *u);


/* description commands parse function */
static int no_do_inter_port_description(int argc, char *argv[], struct users *u);
static int no_do_inter_port_trunk_description(int argc, char *argv[], struct users *u);
static int do_inter_port_description(int argc, char *argv[], struct users *u);
static int do_inter_port_trunk_description(int argc, char *argv[], struct users *u);
static int do_inter_port_description_line(int argc, char *argv[], struct users *u);
static int do_inter_port_trunk_description_line(int argc, char *argv[], struct users *u);

/* interface dhcp commands parse function */

static int do_inter_port_dhcp(int argc, char *argv[], struct users *u);

/* interface flow_control commands parse function */
static int do_inter_port_flo_control(int argc, char *argv[], struct users *u);
static int do_inter_port_flo_control_off(int argc, char *argv[], struct users *u);
static int do_inter_port_flo_control_on(int argc, char *argv[], struct users *u);

static int do_inter_port_ip(int argc, char *argv[], struct users *u);
static int no_inter_port_ip(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_acc_grp(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_acc_grp(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_arp(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_arp_inspect(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_arp_inspect_limit(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_arp_inspect_limit_rate(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_arp_inspect_trust(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_dhcp(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_dhcp_sno(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_dhcp_sno_trus(int argc, char *argv[], struct users *u);
static int no_do_inter_port_ip_acc_grp(int argc, char *argv[], struct users *u);
static int no_do_inter_port_ip_arp_inspect_limit(int argc, char *argv[], struct users *u);
static int no_do_inter_port_ip_arp_inspect_trust(int argc, char *argv[], struct users *u);
static int no_do_inter_port_ip_dhcp_sno_trus(int argc, char *argv[], struct users *u);


/* dot1x commands parse function in port-tree or gport-tree*/
static int do_interface_dot1x(int argc, char *argv[], struct users *u);
static int do_dot1x_forbid(int argc, char *argv[], struct users *u);
static int do_forbid_multinetworkadapter(int argc, char *argv[], struct users *u);
static int do_dot1x_authentication(int argc, char *argv[], struct users *u);
static int do_authentication_type(int argc, char *argv[], struct users *u);
static int do_type_chap(int argc, char *argv[], struct users *u);
static int do_type_eap(int argc, char *argv[], struct users *u);
static int do_authentication_method(int argc, char *argv[], struct users *u);
static int do_dot1x_portcontrol(int argc, char *argv[], struct users *u);
static int do_portcontrol_auto(int argc, char *argv[], struct users *u);
static int do_portcontrol_forceauthorized(int argc, char *argv[], struct users *u);
static int do_portcontrol_forceunauthorized(int argc, char *argv[], struct users *u);
static int do_dot1x_maxuser(int argc, char *argv[], struct users *u);


/* no dot1x commands parse function in port-tree or gport-tree*/
static int no_dot1x_maxuser(int argc, char *argv[], struct users *u);
static int no_interface_dot1x(int argc, char *argv[], struct users *u);


/* interface mac commands parse function */
static int do_inter_port_mac(int argc, char *argv[], struct users *u);
static int do_inter_port_mac_acc_grp(int argc, char *argv[], struct users *u);
static int no_do_inter_port_mac_acc_grp(int argc, char *argv[], struct users *u);
static int do_mac_learn_limit(int argc, char *argv[], struct users *u);
static int no_mac_learn_limit(int argc, char *argv[], struct users *u);


/* interface qos commands parse function */
static int do_inter_qos(int argc, char *argv[], struct users *u);
static int do_inter_qos_policy(int argc, char *argv[], struct users *u);
static int do_inter_qos_policy_ingress(int argc, char *argv[], struct users *u);
static int no_inter_qos_policy(int argc, char *argv[], struct users *u);

/* interface rmon commands parse function */
static int do_inter_port_rmon(int argc, char *argv[], struct users *u);
static int do_inter_port_rmon_collet(int argc, char *argv[], struct users *u);
static int do_inter_port_rmon_collet_histy(int argc, char *argv[], struct users *u);
static int do_inter_port_rmon_collet_histy_bucket(int argc, char *argv[], struct users *u);
static int do_inter_port_rmon_collet_histy_bucket_intev(int argc, char *argv[], struct users *u);
static int do_inter_port_rmon_collet_histy_bucket_intev_own(int argc, char *argv[], struct users *u);
static int do_inter_port_rmon_collet_histy_bucket_own(int argc, char *argv[], struct users *u);
static int do_inter_port_rmon_collet_histy_intev(int argc, char *argv[], struct users *u);
static int do_inter_port_rmon_collet_histy_intev_bucket(int argc, char *argv[], struct users *u);
static int do_inter_port_rmon_collet_histy_intev_bucket_own(int argc, char *argv[], struct users *u);
static int do_inter_port_rmon_collet_stats(int argc, char *argv[], struct users *u);
static int do_inter_port_rmon_collet_stats_own(int argc, char *argv[], struct users *u);
static int do_inter_port_rmon_collet_stats_own_bucket(int argc, char *argv[], struct users *u);


/* interface storm-control commands parse function */
static int do_inter_port_storm_contr_broad(int argc, char *argv[], struct users *u);
static int do_inter_port_storm_contr_mul(int argc, char *argv[], struct users *u);
static int do_inter_port_storm_contr_unicast(int argc, char *argv[], struct users *u);
static int do_inter_port_storm_control(int argc, char *argv[], struct users *u);
static int do_inter_port_storm_contr_broad_thresd(int argc, char *argv[], struct users *u);
static int do_inter_port_storm_contr_mul_thresd(int argc, char *argv[], struct users *u);
static int do_inter_port_storm_contr_uni_thresd(int argc, char *argv[], struct users *u);
static int no_do_inter_port_storm_contr_uni_thresd(int argc, char *argv[], struct users *u);
static int no_do_inter_port_storm_contr_mul_thresd(int argc, char *argv[], struct users *u);
static int no_do_inter_port_storm_contr_broad_thresd(int argc, char *argv[], struct users *u);

/* stp commands parse function in interface mode*/
static int do_stp_int(int argc, char *argv[], struct users *u);

/* stp bpdufilter commands parse function in interface mode*/
static int do_stp_int_bpduf(int argc, char *argv[], struct users *u);
static int do_stp_int_bpduf_dis(int argc, char *argv[], struct users *u);
static int do_stp_int_bpduf_en(int argc, char *argv[], struct users *u);

/* stp bpduguard commands parse function in interface mode*/
static int do_stp_int_bpdug(int argc, char *argv[], struct users *u);
static int do_stp_int_bpdug_dis(int argc, char *argv[], struct users *u);
static int do_stp_int_bpdug_en(int argc, char *argv[], struct users *u);

/* stp cost commands parse function in interface mode*/
static int do_stp_int_cost(int argc, char *argv[], struct users *u);

/* stp guard commands parse function in interface mode*/
static int do_stp_int_guard(int argc, char *argv[], struct users *u);
static int do_stp_int_guard_none(int argc, char *argv[], struct users *u);
static int do_stp_int_guard_root(int argc, char *argv[], struct users *u);

/* stp link-type commands parse function in interface mode*/
static int do_stp_int_link(int argc, char *argv[], struct users *u);
static int do_stp_int_link_point(int argc, char *argv[], struct users *u);
static int do_stp_int_link_shared(int argc, char *argv[], struct users *u);

/* stp port-priority commands parse function in interface mode*/
static int do_stp_int_portp(int argc, char *argv[], struct users *u);

/* stp portfast commands parse function in interface mode*/
static int do_stp_int_portf(int argc, char *argv[], struct users *u);

/* no stp commands parse function in interface mode*/
static int no_do_stp_int_bpduf(int argc, char *argv[], struct users *u);
static int no_do_stp_int_bpdug(int argc, char *argv[], struct users *u);
static int no_do_stp_int_cost(int argc, char *argv[], struct users *u);
static int no_do_stp_int_guard(int argc, char *argv[], struct users *u);
static int no_do_stp_int_link(int argc, char *argv[], struct users *u);
static int no_do_stp_int_portp(int argc, char *argv[], struct users *u);
static int no_do_stp_int_portf(int argc, char *argv[], struct users *u);

/* interface shutdown commands parse function */
static int do_shutdown(int argc, char *argv[], struct users *u);
static int no_do_shutdown(int argc, char *argv[], struct users *u);

/*   try to filter dhcp packet by port                   */
static int do_inter_port_dhcp_filter_t(int argc, char *argv[], struct users *u);
static int no_inter_port_dhcp_filter_t(int argc, char *argv[], struct users *u);
static int do_dhcp_rate(int argc, char *argv[], struct users *u);
static int do_dhcp_rate_num(int argc, char *argv[], struct users *u);
static int no_inter_port_dhcp(int argc, char *argv[], struct users *u);


/*IPV6*/
static int do_inter_port_ipv6_acc_grp(int argc, char *argv[], struct users *u);
static int do_inter_port_ipv6(int argc, char *argv[], struct users *u);
static int no_do_inter_port_ipv6_acc_grp(int argc, char *argv[], struct users *u);
static int do_inter_port_ipv6_dhcp(int argc, char *argv[], struct users *u);
static int do_inter_port_ipv6_dhcp_sno(int argc, char *argv[], struct users *u);
static int do_inter_port_ipv6_dhcp_sno_trus(int argc, char *argv[], struct users *u);
static int no_do_inter_port_ipv6_dhcp_sno_trus(int argc, char *argv[], struct users *u);

static int do_inter_port_gvrp(int argc, char *argv[], struct users *u);
static int no_inter_port_gvrp(int argc, char *argv[], struct users *u);


static int do_inter_port_ip_router(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_router_isis(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_router_isis_id(int argc, char *argv[], struct users *u);
static int no_inter_port_ip_router(int argc, char *argv[], struct users *u);
static int no_inter_port_ip_router_isis(int argc, char *argv[], struct users *u);

static int do_inter_port_ipv6_nd(int argc, char *argv[], struct users *u);
static int do_inter_port_ipv6_nd_cache(int argc, char *argv[], struct users *u);
static int do_inter_port_ipv6_nd_cache_expire(int argc, char *argv[], struct users *u);
static int do_inter_port_ipv6_nd_cache_expire_sec(int argc, char *argv[], struct users *u);
static int no_inter_port_ipv6_nd(int argc, char *argv[], struct users *u);
static int no_inter_port_ipv6_nd_cache(int argc, char *argv[], struct users *u);
static int no_inter_port_ipv6_nd_cache_expire(int argc, char *argv[], struct users *u);

static int do_inter_port_ipv6_router(int argc, char *argv[], struct users *u);
static int do_inter_port_ipv6_router_ospf(int argc, char *argv[], struct users *u);
static int do_inter_port_ipv6_router_ospf_area(int argc, char *argv[], struct users *u);
static int do_inter_port_ipv6_router_ospf_area_id(int argc, char *argv[], struct users *u);
static int do_inter_port_ipv6_router_ospf_area_id_tag(int argc, char *argv[], struct users *u);
static int do_inter_port_ipv6_router_ospf_area_id_tag_tag(int argc, char *argv[], struct users *u);
static int do_inter_port_ipv6_router_ospf_area_id_tag_tag_instance(int argc, char *argv[], struct users *u);
static int do_inter_port_ipv6_router_ospf_area_id_tag_tag_instance_id(int argc, char *argv[], struct users *u);
static int no_inter_port_ipv6_router(int argc, char *argv[], struct users *u);
static int no_inter_port_ipv6_router_ospf(int argc, char *argv[], struct users *u);
static int no_inter_port_ipv6_router_ospf_area(int argc, char *argv[], struct users *u);

static int do_inter_port_ipv6_router_rip(int argc, char *argv[], struct users *u);
static int no_inter_port_ipv6_router_rip(int argc, char *argv[], struct users *u);

static int do_inter_port_ipv6_router_isis(int argc, char *argv[], struct users *u);
static int do_inter_port_ipv6_router_isis_id(int argc, char *argv[], struct users *u);
static int no_inter_port_ipv6_router_isis(int argc, char *argv[], struct users *u);

static int do_inter_port_gmrp(int argc, char *argv[], struct users *u);
static int no_inter_port_gmrp(int argc, char *argv[], struct users *u);

static int do_inter_port_garp(int argc, char *argv[], struct users *u);
static int do_inter_port_garp_timer(int argc, char *argv[], struct users *u);
static int do_inter_port_garp_timer_hold(int argc, char *argv[], struct users *u);
static int do_inter_port_garp_timer_join(int argc, char *argv[], struct users *u);
static int do_inter_port_garp_timer_leave(int argc, char *argv[], struct users *u);
static int do_inter_port_garp_timer_hold_value(int argc, char *argv[], struct users *u);
static int do_inter_port_garp_timer_join_value(int argc, char *argv[], struct users *u);
static int do_inter_port_garp_timer_leave_value(int argc, char *argv[], struct users *u);
static int no_inter_port_garp(int argc, char *argv[], struct users *u);
static int no_inter_port_garp_timer(int argc, char *argv[], struct users *u);
static int no_inter_port_garp_timer_hold(int argc, char *argv[], struct users *u);
static int no_inter_port_garp_timer_join(int argc, char *argv[], struct users *u);
static int no_inter_port_garp_timer_leave(int argc, char *argv[], struct users *u);

static int do_inter_port_ip_igmp(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_igmp_join(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_igmp_join_group(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_igmp_join_group_in(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_igmp_join_group_ex(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_igmp_join_group_in_src(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_igmp_join_group_ex_src(int argc, char *argv[], struct users *u);
static int no_inter_port_ip_igmp(int argc, char *argv[], struct users *u);
static int no_inter_port_ip_igmp_join(int argc, char *argv[], struct users *u);
static int no_inter_port_ip_igmp_join_group(int argc, char *argv[], struct users *u);
static int no_inter_port_ip_igmp_join_group_in(int argc, char *argv[], struct users *u);
static int no_inter_port_ip_igmp_join_group_ex(int argc, char *argv[], struct users *u);
static int no_inter_port_ip_igmp_join_group_in_src(int argc, char *argv[], struct users *u);
static int no_inter_port_ip_igmp_join_group_ex_src(int argc, char *argv[], struct users *u);

static int do_inter_port_ip_igmp_querier(int argc, char *argv[], struct users *u);
static int no_inter_port_ip_igmp_querier(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_igmp_querier_time(int argc, char *argv[], struct users *u);

static int do_inter_port_ip_igmp_last_query(int argc, char *argv[], struct users *u);
static int no_inter_port_ip_igmp_last_query(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_igmp_last_query_time(int argc, char *argv[], struct users *u);

static int do_inter_port_ip_igmp_query(int argc, char *argv[], struct users *u);
static int no_inter_port_ip_igmp_query(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_igmp_query_time(int argc, char *argv[], struct users *u);

static int do_inter_port_ip_igmp_static(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_igmp_static_all(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_igmp_static_all_in(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_igmp_static_all_in_src(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_igmp_static_group(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_igmp_static_group_in(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_igmp_static_group_in_src(int argc, char *argv[], struct users *u);

static int no_inter_port_ip_igmp_static(int argc, char *argv[], struct users *u);
static int no_inter_port_ip_igmp_static_all(int argc, char *argv[], struct users *u);
static int no_inter_port_ip_igmp_static_all_in(int argc, char *argv[], struct users *u);
static int no_inter_port_ip_igmp_static_all_in_src(int argc, char *argv[], struct users *u);
static int no_inter_port_ip_igmp_static_group(int argc, char *argv[], struct users *u);
static int no_inter_port_ip_igmp_static_group_in(int argc, char *argv[], struct users *u);
static int no_inter_port_ip_igmp_static_group_in_src(int argc, char *argv[], struct users *u);

static int do_inter_port_ip_igmp_version(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_igmp_version_1(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_igmp_version_2(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_igmp_version_3(int argc, char *argv[], struct users *u);
static int no_inter_port_ip_igmp_version(int argc, char *argv[], struct users *u);

static int do_inter_port_ip_pim(int argc, char *argv[], struct users *u);
static int no_inter_port_ip_pim(int argc, char *argv[], struct users *u);

static int do_inter_port_ip_pim_bsr(int argc, char *argv[], struct users *u);
static int no_inter_port_ip_pim_bsr(int argc, char *argv[], struct users *u);

static int do_inter_port_ip_pim_dr(int argc, char *argv[], struct users *u);
static int no_inter_port_ip_pim_dr(int argc, char *argv[], struct users *u);
static int do_inter_port_ip_pim_dr_int(int argc, char *argv[], struct users *u);

static int do_inter_port_lldp(int argc, char *argv[], struct users *u);
static int do_inter_port_lldp_transmit(int argc, char *argv[], struct users *u);
static int do_inter_port_lldp_receive(int argc, char *argv[], struct users *u);
static int no_inter_port_lldp(int argc, char *argv[], struct users *u);
static int no_inter_port_lldp_transmit(int argc, char *argv[], struct users *u);
static int no_inter_port_lldp_receive(int argc, char *argv[], struct users *u);

static int do_inter_port_tunnel(int argc, char *argv[], struct users *u);
static int do_inter_port_tunnel_stp(int argc, char *argv[], struct users *u);
static int no_inter_port_tunnel(int argc, char *argv[], struct users *u);
static int no_inter_port_tunnel_stp(int argc, char *argv[], struct users *u);

static int do_ring(int argc, char *argv[], struct users *u);
static int do_ring_id(int argc, char *argv[], struct users *u);
static int no_ring(int argc, char *argv[], struct users *u);


static int do_port_mtu(int argc, char *argv[], struct users *u);
static int no_port_mtu(int argc, char *argv[], struct users *u);
static int do_port_mtu_jumbo(int argc, char *argv[], struct users *u);
static int no_port_mtu_jumbo(int argc, char *argv[], struct users *u);
static int do_port_mtu_jumbo_int(int argc, char *argv[], struct users *u);
static int no_port_mtu_jumbo_int(int argc, char *argv[], struct users *u);


static int do_sw_qinq(int argc, char *argv[], struct users *u);
static int no_do_sw_qinq(int argc, char *argv[], struct users *u);
static int do_sw_mode_qinq(int argc, char *argv[], struct users *u);
static int no_do_sw_mode_qinq(int argc, char *argv[], struct users *u);
static int do_switch_qinq_translate_new(int argc, char *argv[], struct users *u);
static int do_switch_qinq_translate(int argc, char *argv[], struct users *u);
static int no_do_sw_trans_qinq(int argc, char *argv[], struct users *u);
static int do_sw_trans_qinq(int argc, char *argv[], struct users *u);
static int no_do_sw_mode_qinq_type(int argc, char *argv[], struct users *u);
static int do_sw_mode_qinq_type(int argc, char *argv[], struct users *u);

static int do_sw_mode_qinquplink(int argc, char *argv[], struct users *u);
static int no_do_sw_mode_qinquplink(int argc, char *argv[], struct users *u);

static int do_dot1x_guest_vlan(int argc, char *argv[], struct users *u);
static int no_dot1x_guest_vlan(int argc, char *argv[], struct users *u);


static int no_do_sw_mode_flat_type(int argc, char *argv[], struct users *u);
static int do_sw_mode_flat_type(int argc, char *argv[], struct users *u);

static int do_vlan_mapping(int argc, char *argv[], struct users *u);
static int do_mapping_new(int argc, char *argv[], struct users *u);
static int do_mapping_to_new(int argc, char *argv[], struct users *u);
static int do_mapping_value(int argc, char *argv[], struct users *u);
static int do_mapping_to_value(int argc, char *argv[], struct users *u);
static int do_mapping_translate_new(int argc, char *argv[], struct users *u);
static int do_mapping_translate_value(int argc, char *argv[], struct users *u);
static int no_mapping(int argc, char *argv[], struct users *u);


#endif
