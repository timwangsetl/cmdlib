#ifndef __FUNC_ROUTER__
#define __FUNC_ROUTER__


int func_router_bgp(struct users *u);
int nfunc_router_bgp(struct users *u);
int func_router_isis(struct users *u);
int nfunc_router_isis(struct users *u);

int func_router_ospf(struct users *u);
int nfunc_router_ospf(struct users *u);

int func_ospf_id(struct users *u);
int nfunc_ospf_id(struct users *u);

int func_ospf_network(struct users *u);
int func_ospf_network_mask(struct users *u);
int nfunc_ospf_network(struct users *u);
int func_ospf_network_ad(struct users *u);
int func_ospf_network_nad(struct users *u);

int func_router_rip(struct users *u);
int nfunc_router_rip(struct users *u);

int func_rip_auto_summary(struct users *u);
int nfunc_rip_auto_summary(struct users *u);
int func_rip_default_originate(struct users *u);
int nfunc_rip_default_originate(struct users *u);

int func_rip_network_ip(struct users *u);
int func_rip_network_ip_mask(struct users *u);
int nfunc_rip_network(struct users *u);

int func_rip_version_1(struct users *u);
int func_rip_version_2(struct users *u);
int nfunc_rip_version(struct users *u);

int func_isis_net(struct users *u);
int nfunc_isis_net(struct users *u);

int func_isis_type_1(struct users *u);
int func_isis_type_2(struct users *u);
int func_isis_type_1_2(struct users *u);
int nfunc_isis_type(struct users *u);

int func_bgp_neighbor(struct users *u);
int nfunc_bgp_neighbor(struct users *u);

int func_bgp_neighbor_activate(struct users *u);

int func_bgp_network(struct users *u);
int nfunc_bgp_network(struct users *u);
int nfunc_bgp_network_sub(struct users *u);
int nfunc_rip_network_sub(struct users *u);
int nfunc_ospf_network_sub(struct users *u);

int func_rip_default_static(struct users *u);
int nfunc_rip_default_static(struct users *u);
int func_rip_default_ospf(struct users *u);
int nfunc_rip_default_ospf(struct users *u);
int func_rip_default_bgp(struct users *u);
int nfunc_rip_default_bgp(struct users *u);
int func_ospf_default_static(struct users *u);
int nfunc_ospf_default_static(struct users *u);
int func_ospf_default_rip(struct users *u);
int nfunc_ospf_default_rip(struct users *u);
int func_ospf_default_bgp(struct users *u);
int nfunc_ospf_default_bgp(struct users *u);
int func_bgp_default_static(struct users *u);
int nfunc_bgp_default_static(struct users *u);
int func_bgp_default_rip(struct users *u);
int nfunc_bgp_default_rip(struct users *u);
int func_bgp_default_ospf(struct users *u);
int nfunc_bgp_default_ospf(struct users *u);

int func_rip_connected(struct users *u);
int nfunc_rip_connected(struct users *u);
int func_ospf_connected(struct users *u);
int nfunc_ospf_connected(struct users *u);
int func_bgp_connected(struct users *u);
int nfunc_bgp_connected(struct users *u);

int func_rip_network_ipv6(struct users *u);
int nfunc_rip_network_ipv6(struct users *u);
int func_ospf_network_ipv6(struct users *u);
int nfunc_ospf_network_ipv6(struct users *u);

int func_bgp_id(struct users *u);
int nfunc_bpg_id(struct users *u);

int func_bgp_ipv6_neighbor(struct users *u);
int nfunc_bgp_ipv6_neighbor(struct users *u);

int func_bgp_network_ipv6(struct users *u);
int nfunc_bgp_network_ipv6(struct users *u);

int check_ipv6_same_subnet(char *lan_ipv6addr, char *lan_ipv6gateway);


int func_router_pimsm(struct users *u);
int func_router_pimdm(struct users *u);

int func_bfd_ospf_enable(int enable);

#endif

