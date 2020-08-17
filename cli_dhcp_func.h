#ifndef __FUNC_DHCP__
#define __FUNC_DHCP__


int func_service_dhcp(struct users *u);
int func_service_dhcpv6(struct users *u);
int nfunc_service_dhcp(struct users *u);
int nfunc_service_dhcpv6(struct users *u);
int nfunc_ip_dns(struct users *u);
int func_ip_dns_addr(struct users *u);
int nfunc_ip_gateway(struct users *u);
int func_ip_gateway_addr(struct users *u);
int nfunc_ip_domain(struct users *u);
int func_ip_domain_name(struct users *u);
int nfunc_ip_lease(struct users *u);
int func_ip_lease_days(struct users *u);
int func_ip_lease_days_hours(struct users *u);
int func_ip_lease_days_hours_minutes(struct users *u);
int func_ip_lease_infinite(struct users *u);
int nfunc_ip_network(struct users *u);
int func_ip_network_ip_mask(struct users *u);
int nfunc_ip_option_code(struct users *u);
int func_ip_option_code_ascii_str(struct users *u);
int func_ip_option_code_hex_hex(struct users *u);
int func_ip_option_code_ip_addr(struct users *u);
int nfunc_ipv6_dns(struct users *u);
int func_ipv6_dns_addr(struct users *u);
int nfunc_ipv6_domain(struct users *u);
int func_ipv6_domain_name(struct users *u);
int nfunc_ipv6_lifetime(struct users *u);
int func_ipv6_lifetime_pre_time(struct users *u);
int func_ipv6_lifetime_pre_infinite(struct users *u);
int nfunc_ipv6_network(struct users *u);
int func_ipv6_network_addr(struct users *u);


int func_ip_dhcp_range(struct users *u);
int nfunc_ip_range(struct users *u);

int fun_set_dhcpd_enable(int pool);
int nfun_set_dhcpd_disable(int pool);

typedef struct dhcpd_conf_t{
    char subnet[24];
    char gateway[16];
    char range[32];
    char lease[16];
    char dns[16];
    char name[32];
}dhcpd_conf;

#endif

