#ifndef __FUNC_VLAN__
#define __FUNC_VLAN__

int func_vlan(struct users *u);
int nfunc_vlan(struct users *u);
int func_vname(struct users *u);
int nfunc_vname(struct users *u);
int func_ip_adress_static(struct users *u);
int func_ip_adress_dhcp(struct users *u);
int nfunc_ip_adress(struct users *u);
int func_ip_access_in(struct users *u);
int func_ip_access_out(struct users *u);
int nfunc_ip_access_in(struct users *u);
int nfunc_ip_access_out(struct users *u);
int func_ipv6_global(struct users *u);
int func_vlan_ipv6_dhcp_realy_address(struct users *u);
int cli_set_ipv6_realy(char *host);
int nfunc_vlan_ipv6_dhcp_realy();
void nfunc_vlan_ipv6_address_local();

int func_ipv6_local(struct users *u);
int nfunc_ipv6_adress(struct users *u);
int func_shutdown(struct users *u);
int nfunc_shutdown(struct users *u);

int func_vlan_ipv6_enable(struct users *u);
int nfunc_vlan_ipv6_enable(struct users *u);
int func_vlan_ipv6_ospf(struct users *u);
int nfunc_vlan_ipv6_ospf(struct users *u);
int func_vlan_ipv6_rip(struct users *u);
int nfunc_vlan_ipv6_rip(struct users *u);
int func_vlan_ipv6_router(struct users *u);
int nfunc_vlan_ipv6_router(struct users *u);
int func_vlan_ipv6_isis_circuit_level_1(struct users *u);
int func_vlan_ipv6_isis_circuit_level_1_2(struct users *u);
int func_vlan_ipv6_isis_circuit_level_2_o(struct users *u);
int nfunc_vlan_ipv6_isis(struct users *u);
int func_vlan_ipv6_traffic_name_in(struct users *u);
int func_vlan_ipv6_traffic_name_out(struct users *u);
int nfunc_vlan_ipv6_traffic_name_in(struct users *u);
int nfunc_vlan_ipv6_traffic_name_out(struct users *u);

int func_vlan_ipv6_mld_join_addr(struct users *u);
int func_vlan_ipv6_mld_join_addr_in_src(struct users *u);
int func_vlan_ipv6_mld_join_addr_ex_src(struct users *u);
int nfunc_vlan_ipv6_mld_join_addr(struct users *u);
int nfunc_vlan_ipv6_mld_join_addr_in_src(struct users *u);
int nfunc_vlan_ipv6_mld_join_addr_ex_src(struct users *u);

int func_vlan_ipv6_mld_querier(struct users *u);
int nfunc_vlan_ipv6_mld_querier(struct users *u);

int func_vlan_ipv6_mld_query(struct users *u);
int nfunc_vlan_ipv6_mld_query(struct users *u);

int func_vlan_ipv6_mld_static_all(struct users *u);
int func_vlan_ipv6_mld_static_all_in(struct users *u);
int func_vlan_ipv6_mld_static_group(struct users *u);
int func_vlan_ipv6_mld_static_group_in(struct users *u);
int nfunc_vlan_ipv6_mld_static_all(struct users *u);
int nfunc_vlan_ipv6_mld_static_all_in(struct users *u);
int nfunc_vlan_ipv6_mld_static_group(struct users *u);
int nfunc_vlan_ipv6_mld_static_group_in(struct users *u);

int func_vlan_vrrp_num_preempt(struct users *u);
int func_vlan_vrrp_num_desc_line(struct users *u);
int func_vlan_vrrp_num_ip_addr(struct users *u);
int func_vlan_vrrp_num_priority_level(struct users *u);
int nfunc_vlan_vrrp_num_desc(struct users *u);
int nfunc_vlan_vrrp_num_ip_addr(struct users *u);
int nfunc_vlan_vrrp_num_preempt(struct users *u);
int nfunc_vlan_vrrp_num_priority(struct users *u);

int func_gvrp(struct users *u);
int nfunc_gvrp(struct users *u);

int func_vlan_arp_timeout(struct users *u);
int nfunc_vlan_arp_timeout(struct users *u);

int func_vlan_arp_send_interval(struct users *u);
int nfunc_vlan_arp_send_interval(struct users *u);

int func_ip_proxy_arp(struct users *u);
int nfunc_ip_proxy_arp(struct users *u);

int func_vlan_ip_igmp_querier_time(struct users *u);
int nfunc_vlan_ip_igmp_querier_time(struct users *u);

int func_ip_igmp_query_time(struct users *u);
int nfunc_ip_igmp_query_time(struct users *u);

int func_ip_igmp_static_group(struct users *u);
int nfunc_ip_igmp_static_group(struct users *u);
int func_ip_igmp_static_group_source(struct users *u);

int func_ip_igmp_version_1(struct users *u);
int func_ip_igmp_version_2(struct users *u);
int func_ip_igmp_version_3(struct users *u);
int nfunc_ip_igmp_version(struct users *u);

int func_vlan_ip_pim(struct users *u);
int nfunc_vlan_ip_pim(struct users *u);

int func_vlan_ip_pim_sm(struct users *u);
int nfunc_vlan_ip_pim_sm(struct users *u);

int func_vlan_ip_pim_dr(struct users *u);
int nfunc_vlan_ip_pim_dr(struct users *u);

int func_vlan_ipv6_pim(struct users *u);
int nfunc_vlan_ipv6_pim(struct users *u);

int func_vlan_ipv6_pim_bsr(struct users *u);
int nfunc_vlan_ipv6_pim_bsr(struct users *u);
int func_vlan_ipv6_pim_dr_priority(struct users *u);
int nfunc_vlan_ipv6_pim_dr_priority(struct users *u);

int func_vlan_vrrp_num_associate_ip(struct users *u);
int nfunc_vlan_vrrp_num_associate_ip(struct users *u);

int func_vlan_vrrp_num_auth(struct users *u);
int nfunc_vlan_vrrp_num_auth(struct users *u);

int func_vlan_vrrp_num_timer(struct users *u);
int nfunc_vlan_vrrp_num_timer(struct users *u);
int nfunc_vlan_vrrp_num_auth(struct users *u);

int func_vlan_ip_rip_bfd(struct users *u);
int nfunc_vlan_ip_rip_bfd(struct users *u);

int func_vlan_ip_ospf_bfd(struct users *u);
int nfunc_vlan_ip_ospf_bfd(struct users *u);

int func_vlan_ip_bgp_bfd(struct users *u);
int nfunc_vlan_ip_bgp_bfd(struct users *u);

int func_vlan_ip_isis_bfd(struct users *u);
int nfunc_vlan_ip_isis_bfd(struct users *u);

int func_vlan_ip_static_bfd(struct users *u);
int nfunc_vlan_ip_static_bfd(struct users *u);

int func_vlan_vrrp_num_bfd(struct users *u);
int nfunc_vlan_vrrp_num_bfd(struct users *u);

int func_vlan_bfd(struct users *u);
int nfunc_vlan_bfd(struct users *u);

int func_vlan_bfd_auth_md5(struct users *u);
int nfunc_vlan_bfd_auth_md5(struct users *u);

int func_vlan_bfd_auth_simple(struct users *u);
int nfunc_vlan_bfd_auth_simple(struct users *u);

int func_vlan_router_isis(struct users *u);
int nfunc_vlan_router_isis(struct users *u);

int func_supervlan(struct users *u);
int nfunc_supervlan(struct users *u);

int func_subvlan(struct users *u);
int nfunc_subvlan(struct users *u);

int func_ip_helper_ip(struct users *u);
int nfunc_ip_helper_ip(struct users *u);

static int cli_set_cpu_ip_acl(char *acl_name, int direction);

#endif

