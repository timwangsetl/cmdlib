#ifndef __FUNC_PORT__
#define __FUNC_PORT__

//---------------------interface aggregator-group------------------------
int func_interface_trunk_mode_lacp(struct users *u);
int func_interface_trunk_mode_static(struct users *u);
int nfunc_remove_trunk_interface(struct users *u);

//---------------------------interface arp------------------------------

int func_if_arp_inspection(struct users *u);
int nfunc_if_arp_inspection(struct users *u);


int nfunc_ip_arp_inspect_limit(struct users *u);
int nfunc_ip_arp_inspect_trust(struct users *u);
int func_ip_arp_inspect_limit_rate(struct users *u);
int func_ip_arp_inspect_trust(struct users *u);

//---------------------------interface cos------------------------------

int nfunc_inter_cos_default(struct users *u);
int func_cos_default(struct users *u);


//---------------------------interface spanning-tree------------------------------

int func_stp_int_bpduf_dis(struct users *u);
int func_stp_int_bpduf_en(struct users *u);
int func_stp_int_bpdug_en(struct users *u);
int func_stp_int_bpdug_dis(struct users *u);
int func_stp_int_cost(struct users *u);
int func_stp_int_guard_none(struct users *u);
int func_stp_int_guard_root(struct users *u);
int func_stp_int_link_point(struct users *u);
int func_stp_int_link_shared(struct users *u);
int func_stp_int_portp(struct users *u);
int func_stp_int_portf(struct users *u);
int nfunc_stp_int_bpduf(struct users *u);
int nfunc_stp_int_bpdug(struct users *u);
int nfunc_stp_int_cost(struct users *u);
int nfunc_stp_int_guard(struct users *u);
int nfunc_stp_int_link(struct users *u);
int nfunc_stp_int_portp(struct users *u);
int nfunc_stp_int_portf(struct users *u);


int func_ip_acc_grp(struct users *u);
int nfunc_ip_acc_grp(struct users *u);

int func_flo_con_off(struct users *u);
int func_flo_con_on(struct users *u);

int func_duplex_half(struct users *u);
int func_duplex_full(struct users *u);
int func_duplex_auto(struct users *u);
int nfunc_duplex(struct users *u);

int nfunc_inter_port_description(struct users *u);
int func_inter_port_description_line(struct users *u);

int nfunc_ip_dhcp_sno_trus(struct users *u);
int func_ip_dhcp_sno_trus(struct users *u);

int nfunc_mac_acc_grp(struct users *u);
int func_mac_acc_grp(struct users *u);

int nfunc_inter_qos_policy(struct users *u);
int func_inter_qos_policy_ingress(struct users *u);

int func_rmon_collet_histy(struct users *u);
int func_rmon_collet_stats(struct users *u);


int nfunc_speed(struct users *u);
int func_speed_ten(struct users *u);
int func_speed_hundred(struct users *u);
int func_speed_giga(struct users *u);
int func_speed_auto(struct users *u);

int nfunc_inter_shutdown(struct users *u);
int func_inter_shutdown(struct users *u);


int func_storm_contr_broad(struct users *u);
int func_storm_contr_mul(struct users *u);
int func_storm_contr_uni(struct users *u);
int nfunc_storm_contr_broad(struct users *u);
int nfunc_storm_contr_mul(struct users *u);
int nfunc_storm_contr_uni(struct users *u);

int nfunc_sw_block(struct users *u);
int func_sw_block(struct users *u);

int nfunc_sw_loop(struct users *u);
int func_sw_loop(struct users *u, char *port_str);

int nfunc_sw_mode(struct users *u);
int func_sw_mode_acc(struct users *u);
int func_sw_mode_pri_vlan(struct users *u);
int func_sw_mode_tru(struct users *u);
int func_sw_mode_qinq(struct users *u, int mode);

int nfunc_sw_pro(struct users *u);
int nfunc_sw_portsec_dy(struct users *u);
int nfunc_sw_portsec_mo(struct users *u);
int func_sw_portsec_dy_max(struct users *u);
int func_sw_portsec_mo_dy(struct users *u);
int func_sw_portsec_mo_sta_acc(struct users *u);
int func_sw_pro(struct users *u);

int func_inter_vlan(struct users *u);
int nfunc_inter_vlan(struct users *u);

int func_rate_limit(struct users *u);
int nfunc_rate_limit_egr(struct users *u);
int nfunc_rate_limit_ing(struct users *u);
int func_rate_limit_egr(struct users *u);
int func_rate_limit_ing(struct users *u);

int func_tru_vlan_allo(struct users *u);
int func_tru_vlan_untag(struct users *u);

int nfunc_tru_vlan_allo(struct users *u);
int nfunc_tru_vlan_untag(struct users *u);


int cli_start_dot1x();
int cli_stop_dot1x();
int func_set_dot1x_port_control(char *mode,struct users *u);
int func_set_dot1x_max_user(char *max,struct users *u);
int cli_check_interface_trunk_group(struct users *u);
void nfunc_set_max_user(struct users *u);

/* filter dhcp packet*/
int func_inter_port_dhcp_filter(struct users *u);
int nfunc_inter_port_dhcp_filter(struct users *u);

/*IPV6*/
int func_ipv6_dhcp_sno_trus(struct users *u);
int nfunc_ipv6_dhcp_sno_trus(struct users *u);
int func_ipv6_acc_grp(struct users *u);
int nfunc_ipv6_acc_grp(struct users *u);

/* IPV4 Router IS-IS */
int func_ip_router_isis(struct users *u);
int nfunc_ip_router_isis(struct users *u);


int func_port_ipv6_nd_cache_expire(struct users *u);
int nfunc_port_ipv6_nd_cache_expire(struct users *u);

int func_port_ipv6_router_ospf_area(struct users *u);
int nfunc_port_ipv6_router_ospf_area(struct users *u);

int func_port_ipv6_router_rip(struct users *u);
int nfunc_port_ipv6_router_rip(struct users *u);

int func_port_ipv6_router_isis(struct users *u);
int nfunc_port_ipv6_router_isis(struct users *u);

int func_port_gmrp(struct users *u);
int nfunc_port_gmrp(struct users *u);

int func_port_garp_timer_hold(struct users *u);
int func_port_garp_timer_join(struct users *u);
int func_port_garp_timer_leave(struct users *u);
int nfunc_port_garp_timer_hold(struct users *u);
int nfunc_port_garp_timer_join(struct users *u);
int nfunc_port_garp_timer_leave(struct users *u);


int func_port_ip_igmp_join_group(struct users *u);
int nfunc_port_ip_igmp_join_group(struct users *u);
int func_port_ip_igmp_join_group_in(struct users *u);
int nfunc_port_ip_igmp_join_group_in(struct users *u);
int func_port_ip_igmp_join_group_ex(struct users *u);
int nfunc_port_ip_igmp_join_group_ex(struct users *u);

int func_port_ip_igmp_querier_time(struct users *u);
int nfunc_port_ip_igmp_querier_time(struct users *u);

int func_port_ip_igmp_last_query_time(struct users *u);
int nfunc_port_ip_igmp_last_query_time(struct users *u);

int func_port_ip_igmp_query_time(struct users *u);
int nfunc_port_ip_igmp_query_time(struct users *u);

int func_port_ip_igmp_static_all(struct users *u);
int nfunc_port_ip_igmp_static_all(struct users *u);
int func_port_ip_igmp_static_all_in(struct users *u);
int nfunc_port_ip_igmp_static_all_in(struct users *u);
int func_port_ip_igmp_static_group(struct users *u);
int nfunc_port_ip_igmp_static_group(struct users *u);
int func_port_ip_igmp_static_group_in(struct users *u);
int nfunc_port_ip_igmp_static_group_in(struct users *u);

int func_port_ip_igmp_version_1(struct users *u);
int func_port_ip_igmp_version_2(struct users *u);
int func_port_ip_igmp_version_3(struct users *u);
int nfunc_port_ip_igmp_version(struct users *u);

int func_port_ip_pim(struct users *u);
int nfunc_port_ip_pim(struct users *u);

int func_port_ip_pim_bsr(struct users *u);
int nfunc_port_ip_pim_bsr(struct users *u);

int func_port_ip_pim_dr(struct users *u);
int nfunc_port_ip_pim_dr(struct users *u);

int func_port_lldp_transmit(struct users *u);
int nfunc_port_lldp_transmit(struct users *u);

int func_port_lldp_receive(struct users *u);
int nfunc_port_lldp_receive(struct users *u);

int func_port_mtu(struct users *u);
int nfunc_port_mtu(struct users *u);


int func_sw_qinq_mode(struct users *u, int mode);
int func_sw_mode_qinq_uplink(struct users *u, int mode);

int func_sw_qinq_trans(struct users *u);
int nfunc_sw_qinq_trans(struct users *u);

int nfunc_set_guest_vlan(struct users *u);
int func_set_guest_vlan_id(char *vlan_id, struct users *u);

#endif

