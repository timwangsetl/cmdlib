#ifndef __ACL__
#define __ACL__

extern int do_test(int argc, char *argv[], struct users *u);
extern int do_test_param(int argc, char *argv[], struct users *u);

/* IP access-list */
/* Do functions */
static int do_ip_acl_deny(int argc, char *argv[], struct users *u);
static int do_ip_acl_permit(int argc, char *argv[], struct users *u);

/* extended access-list */
static int do_ip_acl_ext_ip(int argc, char *argv[], struct users *u);
static int do_ip_acl_ext_tcp(int argc, char *argv[], struct users *u);
static int do_ip_acl_ext_udp(int argc, char *argv[], struct users *u);
static int do_ip_acl_ext_protocol_num(int argc, char *argv[], struct users *u);

static int do_ip_acl_ext_src_any(int argc, char *argv[], struct users *u);
static int do_ip_acl_ext_src_ip(int argc, char *argv[], struct users *u);
static int do_ip_acl_ext_dst_any(int argc, char *argv[], struct users *u);
static int do_ip_acl_ext_dst_ip(int argc, char *argv[], struct users *u);

static int do_ip_acl_ext_opt_time_range(int argc, char *argv[], struct users *u);
static int do_ip_acl_ext_opt_tos(int argc, char *argv[], struct users *u);
static int do_ip_acl_ext_opt_precedence(int argc, char *argv[], struct users *u);
static int do_ip_acl_ext_opt_location(int argc, char *argv[], struct users *u);
static int do_ip_acl_ext_opt_vlan(int argc, char *argv[], struct users *u);

/* standard access-list */
static int do_ip_acl_std_src_any(int argc, char *argv[], struct users *u);
static int do_ip_acl_std_src_ip(int argc, char *argv[], struct users *u);

static int do_ip_acl_std_opt_location(int argc, char *argv[], struct users *u);

/* Negative functions */
/* extended access-list */
static int do_ip_acl_ext_src_port_eq(int argc, char *argv[], struct users *u);
static int do_ip_acl_ext_dst_port_eq(int argc, char *argv[], struct users *u);

static int no_ip_acl_ext_dst_any(int argc, char *argv[], struct users *u);
static int no_ip_acl_ext_dst_ip(int argc, char *argv[], struct users *u);

static int no_ip_acl_ext_dst_port_eq(int argc, char *argv[], struct users *u);
static int no_ip_acl_ext_opt_time_range(int argc, char *argv[], struct users *u);
static int no_ip_acl_ext_opt_tos(int argc, char *argv[], struct users *u);
static int no_ip_acl_ext_opt_precedence(int argc, char *argv[], struct users *u);
static int no_ip_acl_ext_opt_vlan(int argc, char *argv[], struct users *u);

/* standard access-list */
static int no_ip_acl_std_src_any(int argc, char *argv[], struct users *u);
static int no_ip_acl_std_src_ip(int argc, char *argv[], struct users *u);

/* IPv6 access-list */
/* Do functions */
static int do_ipv6_acl_deny(int argc, char *argv[], struct users *u);
static int do_ipv6_acl_permit(int argc, char *argv[], struct users *u);

static int do_ipv6_acl_std_src_any(int argc, char *argv[], struct users *u);
static int do_ipv6_acl_std_src_ip(int argc, char *argv[], struct users *u);
static int do_ipv6_acl_std_opt_location(int argc, char *argv[], struct users *u);

/* Negative functions */
static int no_ipv6_acl_std_src_any(int argc, char *argv[], struct users *u);
static int no_ipv6_acl_std_src_ip(int argc, char *argv[], struct users *u);


/* MAC access-list */
/* Do functions */
static int do_mac_acl_deny(int argc, char *argv[], struct users *u);
static int do_mac_acl_permit(int argc, char *argv[], struct users *u);

static int do_mac_acl_src_any(int argc, char *argv[], struct users *u);
static int do_mac_acl_src_host(int argc, char *argv[], struct users *u);
static int do_mac_acl_dst_any(int argc, char *argv[], struct users *u);
static int do_mac_acl_dst_host(int argc, char *argv[], struct users *u);

static int do_mac_acl_ethertype(int argc, char *argv[], struct users *u);

/* Negative functions */
static int no_mac_acl_dst_any(int argc, char *argv[], struct users *u);
static int no_mac_acl_dst_host(int argc, char *argv[], struct users *u);

static int no_mac_acl_ethertype(int argc, char *argv[], struct users *u);

#endif

