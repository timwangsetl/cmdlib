#ifndef __DO_DHCP__
#define __DO_DHCP__


static int do_service(int argc, char *argv[], struct users *u);
static int no_service(int argc, char *argv[], struct users *u);
static int do_service_dhcp(int argc, char *argv[], struct users *u);
static int no_service_dhcp(int argc, char *argv[], struct users *u);
static int do_service_dhcpv6(int argc, char *argv[], struct users *u);
static int no_service_dhcpv6(int argc, char *argv[], struct users *u);
static int do_ip_dns(int argc, char *argv[], struct users *u);
static int no_ip_dns(int argc, char *argv[], struct users *u);
static int do_ip_gateway(int argc, char *argv[], struct users *u);
static int no_ip_gateway(int argc, char *argv[], struct users *u);
static int do_ip_domain(int argc, char *argv[], struct users *u);
static int no_ip_domain(int argc, char *argv[], struct users *u);
static int do_ip_lease(int argc, char *argv[], struct users *u);
static int no_ip_lease(int argc, char *argv[], struct users *u);
static int do_ip_network(int argc, char *argv[], struct users *u);
static int no_ip_network(int argc, char *argv[], struct users *u);
static int do_ip_range(int argc, char *argv[], struct users *u);
static int no_ip_range(int argc, char *argv[], struct users *u);
static int do_ip_option(int argc, char *argv[], struct users *u);
static int no_ip_option(int argc, char *argv[], struct users *u);

static int do_ip_dns_addr(int argc, char *argv[], struct users *u);
static int do_ip_gateway_addr(int argc, char *argv[], struct users *u);
static int do_ip_domain_name(int argc, char *argv[], struct users *u);
static int do_ip_lease_days(int argc, char *argv[], struct users *u);
static int do_ip_lease_infinite(int argc, char *argv[], struct users *u);
static int do_ip_lease_days_hours(int argc, char *argv[], struct users *u);
static int do_ip_lease_days_hours_minutes(int argc, char *argv[], struct users *u);
static int do_ip_network_ip(int argc, char *argv[], struct users *u);
static int do_ip_network_ip_mask(int argc, char *argv[], struct users *u);
static int do_ip_option_code(int argc, char *argv[], struct users *u);
static int no_ip_option_code(int argc, char *argv[], struct users *u);
static int do_ip_option_code_ascii(int argc, char *argv[], struct users *u);
static int do_ip_option_code_hex(int argc, char *argv[], struct users *u);
static int do_ip_option_code_ip(int argc, char *argv[], struct users *u);
static int do_ip_option_code_ascii_str(int argc, char *argv[], struct users *u);
static int do_ip_option_code_hex_hex(int argc, char *argv[], struct users *u);
static int do_ip_option_code_ip_addr(int argc, char *argv[], struct users *u);
static int do_ipv6_dns(int argc, char *argv[], struct users *u);
static int no_ipv6_dns(int argc, char *argv[], struct users *u);

static int do_ipv6_domain(int argc, char *argv[], struct users *u);
static int no_ipv6_domain(int argc, char *argv[], struct users *u);
static int do_ipv6_lifetime(int argc, char *argv[], struct users *u);
static int no_ipv6_lifetime(int argc, char *argv[], struct users *u);
static int do_ipv6_network(int argc, char *argv[], struct users *u);
static int no_ipv6_network(int argc, char *argv[], struct users *u);
static int do_ipv6_dns_addr(int argc, char *argv[], struct users *u);
static int do_ipv6_domain_name(int argc, char *argv[], struct users *u);
static int do_ipv6_lifetime_time(int argc, char *argv[], struct users *u);
static int do_ipv6_lifetime_infinite(int argc, char *argv[], struct users *u);
static int do_ipv6_lifetime_pre_time(int argc, char *argv[], struct users *u);
static int do_ipv6_lifetime_pre_infinite(int argc, char *argv[], struct users *u);
static int do_ipv6_network_start(int argc, char *argv[], struct users *u);
static int do_ipv6_network_end(int argc, char *argv[], struct users *u);

static int do_startip(int argc, char *argv[], struct users *u);
static int do_endip(int argc, char *argv[], struct users *u);

#endif

