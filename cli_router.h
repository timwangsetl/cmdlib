#ifndef __DO_ROUTER__
#define __DO_ROUTER__


static int do_router(int argc, char *argv[], struct users *u);
static int no_router(int argc, char *argv[], struct users *u);
int do_router_bgp(int argc, char *argv[], struct users *u);
int no_router_bgp(int argc, char *argv[], struct users *u);
int do_router_isis(int argc, char *argv[], struct users *u);
int no_router_isis(int argc, char *argv[], struct users *u);

static int do_router_ospf(int argc, char *argv[], struct users *u);
static int no_router_ospf(int argc, char *argv[], struct users *u);

static int do_ospf_id(int argc, char *argv[], struct users *u);
static int do_ospf_id_ip(int argc, char *argv[], struct users *u);
static int no_ospf_id(int argc, char *argv[], struct users *u);

static int do_ospf_network(int argc, char *argv[], struct users *u);
static int no_ospf_network(int argc, char *argv[], struct users *u);
static int do_ospf_network_ip(int argc, char *argv[], struct users *u);
static int do_ospf_network_ip_mask(int argc, char *argv[], struct users *u);
static int do_ospf_network_ip_mask_area(int argc, char *argv[], struct users *u);
static int do_ospf_network_ip_mask_area_id(int argc, char *argv[], struct users *u);
static int do_ospf_network_ip_mask_area_mask(int argc, char *argv[], struct users *u);
static int do_ospf_network_ip_mask_area_id_ad(int argc, char *argv[], struct users *u);
static int do_ospf_network_ip_mask_area_id_nad(int argc, char *argv[], struct users *u);

static int do_rip_connected(int argc, char *argv[], struct users *u);
static int no_do_rip_connected(int argc, char *argv[], struct users *u);
static int do_ospf_connected(int argc, char *argv[], struct users *u);
static int no_do_ospf_connected(int argc, char *argv[], struct users *u);
int do_bgp_connected(int argc, char *argv[], struct users *u);
static int no_do_bgp_connected(int argc, char *argv[], struct users *u);

static int do_router_rip(int argc, char *argv[], struct users *u);
static int no_router_rip(int argc, char *argv[], struct users *u);

static int do_router_pim_sm(int argc, char *argv[], struct users *u);
static int do_router_pim_dm(int argc, char *argv[], struct users *u);
static int no_router_pim_dm(int argc, char *argv[], struct users *u);

static int do_rip_auto_summary(int argc, char *argv[], struct users *u);
static int no_rip_auto_summary(int argc, char *argv[], struct users *u);
static int do_rip_default(int argc, char *argv[], struct users *u);
static int no_rip_default(int argc, char *argv[], struct users *u);

static int do_rip_default_originate(int argc, char *argv[], struct users *u);
static int no_rip_default_originate(int argc, char *argv[], struct users *u);
static int do_rip_default_static(int argc, char *argv[], struct users *u);
static int no_rip_default_static(int argc, char *argv[], struct users *u);
static int do_rip_default_ospf(int argc, char *argv[], struct users *u);
static int no_rip_default_ospf(int argc, char *argv[], struct users *u);
static int do_rip_default_bgp(int argc, char *argv[], struct users *u);
static int no_rip_default_bgp(int argc, char *argv[], struct users *u);
static int do_ospf_default_static(int argc, char *argv[], struct users *u);
static int no_ospf_default_static(int argc, char *argv[], struct users *u);
static int do_ospf_default_rip(int argc, char *argv[], struct users *u);
static int no_ospf_default_rip(int argc, char *argv[], struct users *u);
static int do_ospf_default_bgp(int argc, char *argv[], struct users *u);
static int no_ospf_default_bgp(int argc, char *argv[], struct users *u);
int do_bgp_default_static(int argc, char *argv[], struct users *u);
int no_bgp_default_static(int argc, char *argv[], struct users *u);
int do_bgp_default_rip(int argc, char *argv[], struct users *u);
int no_bgp_default_rip(int argc, char *argv[], struct users *u);
int do_bgp_default_ospf(int argc, char *argv[], struct users *u);
int no_bgp_default_ospf(int argc, char *argv[], struct users *u);

static int do_rip_network(int argc, char *argv[], struct users *u);
static int do_rip_network_ip(int argc, char *argv[], struct users *u);
static int do_rip_network_ip_mask(int argc, char *argv[], struct users *u);
static int no_rip_network(int argc, char *argv[], struct users *u);

static int do_rip_version(int argc, char *argv[], struct users *u);
static int do_rip_version_1(int argc, char *argv[], struct users *u);
static int do_rip_version_2(int argc, char *argv[], struct users *u);
static int no_rip_version(int argc, char *argv[], struct users *u);

int do_isis_net(int argc, char *argv[], struct users *u);
int do_isis_net_str(int argc, char *argv[], struct users *u);
int no_isis_net(int argc, char *argv[], struct users *u);

int do_isis_type(int argc, char *argv[], struct users *u);
int do_isis_type_1(int argc, char *argv[], struct users *u);
int do_isis_type_2(int argc, char *argv[], struct users *u);
int do_isis_type_1_2(int argc, char *argv[], struct users *u);
int no_isis_type(int argc, char *argv[], struct users *u);

int do_bgp_neighbor(int argc, char *argv[], struct users *u);
int do_bgp_neighbor_ip(int argc, char *argv[], struct users *u);
int do_bgp_neighbor_ip_remote(int argc, char *argv[], struct users *u);
int do_bgp_neighbor_ip_remote_id(int argc, char *argv[], struct users *u);
int no_bgp_neighbor(int argc, char *argv[], struct users *u);
int no_bgp_neighbor_ip(int argc, char *argv[], struct users *u);

int do_bgp_neighbor_ip_activate(int argc, char *argv[], struct users *u);

int do_bgp_network(int argc, char *argv[], struct users *u);
int do_bgp_network_ip(int argc, char *argv[], struct users *u);
int no_bgp_network(int argc, char *argv[], struct users *u);

static int do_ospf_default(int argc, char *argv[], struct users *u);
static int no_ospf_default(int argc, char *argv[], struct users *u);
int do_bgp_default(int argc, char *argv[], struct users *u);
int no_bgp_default(int argc, char *argv[], struct users *u);

int do_no_bgp_network_ip(int argc, char *argv[], struct users *u);
static int no_ospf_network_ip(int argc, char *argv[], struct users *u);
static int no_rip_network_ip(int argc, char *argv[], struct users *u);

static int do_rip_network_ipv6(int argc, char *argv[], struct users *u);
static int no_rip_network_ipv6(int argc, char *argv[], struct users *u);

static int do_ospf_network_ipv6(int argc, char *argv[], struct users *u); 
static int do_ospf_network_ipv6_area(int argc, char *argv[], struct users *u);
static int do_ospf_network_ipv6_area_id(int argc, char *argv[], struct users *u);
static int no_ospf_network_ipv6(int argc, char *argv[], struct users *u);

static int do_bgp_id(int argc, char *argv[], struct users *u);
static int do_bgp_id_ip(int argc, char *argv[], struct users *u);
static int no_bgp_id(int argc, char *argv[], struct users *u);

int do_bgp_neighbor_ipv6(int argc, char *argv[], struct users *u);
int do_bgp_neighbor_ipv6_remote(int argc, char *argv[], struct users *u);
int do_bgp_neighbor_ipv6_remote_id(int argc, char *argv[], struct users *u);
int no_bgp_neighbor_ipv6(int argc, char *argv[], struct users *u);

int do_bgp_network_ipv6(int argc, char *argv[], struct users *u);
int no_bgp_network_ipv6(int argc, char *argv[], struct users *u);

static int do_ospf_bfd(int argc, char *argv[], struct users *u);
static int do_bfd_ospf_all(int argc, char *argv[], struct users *u);

static int no_ospf_bfd(int argc, char *argv[], struct users *u);
static int no_bfd_ospf_all(int argc, char *argv[], struct users *u);

#endif

