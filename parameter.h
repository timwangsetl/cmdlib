#ifndef __PARAMETER__
#define __PARAMETER__

#define STATIC_PARAM	0
#define DYNAMIC_PARAM	1

extern struct parameter *cli_cmds2param(struct cmds *cmds_ptr);
extern struct cmds *cli_param2cmds(struct parameter *param_ptr);

extern int cli_param_get_int(int type, int cnt, int *v_int, struct users *u);
extern int cli_param_get_string(int type, int cnt, char *v_str, struct users *u);
extern int cli_param_get_range_edge(int type, int *v_range_edge, struct users *u);
extern int cli_param_get_range(int type, char *v_range, struct users *u);
extern int cli_param_get_ipv4(int type, int cnt, struct in_addr *v_sin_addr, char *buff, int len, struct users *u);
extern int cli_param_get_ipv6(int type, int cnt, struct in6_addr *v_sin6_addr, char *buff, int len, struct users *u);

extern int cli_param_set_int(int type, int cnt, int v_int, struct users *u);
extern int cli_param_set_string(int type, int cnt, char *v_str, struct users *u);
extern int cli_param_set_ipv4(int type, int cnt, struct in_addr *s, struct users *u);
extern int cli_param_set_ipv6(int type, int cnt, struct in6_addr *s6, struct users *u);

extern int cli_param_set(int type, struct parameter *param, struct users *u);

extern int cli_param_int32_format(char *s, int min, int max, struct users *u);
extern int cli_param_int(int argc, char *argv[], struct users *u, struct parameter *param);
extern int cli_param_int32_range_format(char *s, int min, int max, struct users *u);
extern int cli_param_int_range(int argc, char *argv[], struct users *u, struct parameter *param);
extern int cli_param_int32_multi_format(char *s, int min, int max, struct users *u);
extern int cli_param_int_multi(int argc, char *argv[], struct users *u, struct parameter *param);
extern int cli_param_word_format(char *s, int min, int max, struct users *u);
extern int cli_param_word(int argc, char *argv[], struct users *u, struct parameter *param);
extern int cli_param_line(int argc, char *argv[], struct users *u, struct parameter *param);
extern int cli_param_mac_format(char *s, struct users *u);
extern int cli_param_mac(int argc, char *argv[], struct users *u, struct parameter *param);
extern int cli_param_time_format(char *s, struct users *u);
extern int cli_param_time(int argc, char *argv[], struct users *u, struct parameter *param);
extern int cli_param_ipv4_format(int type, char *s, struct users *u);
extern int cli_param_ipv4(int argc, char *argv[], struct users *u, struct parameter *param);
extern int cli_param_ipv6_format(int type, char *s, struct users *u);
extern int cli_param_ipv6(int argc, char *argv[], struct users *u, struct parameter *param);

extern int cli_param_prefix(char *cmds_name, char *s, struct users *u);
extern int cli_param_port_suffix(int type, char *s, int min, int max, struct users *u);
extern int cli_param_vlan_suffix(int type, char *s, int min, int max, struct users *u);
extern int cli_param_trunk_suffix(int type, char *s, int min, int max, struct users *u);

extern int cli_param_port(int argc, char *argv[], struct users *u, struct parameter *param);
extern int cli_param_vlan(int argc, char *argv[], struct users *u, struct parameter *param);
extern int cli_param_trunk(int argc, char *argv[], struct users *u, struct parameter *param);

int cli_mac_blackhole_vid(char *src_mac, int src_vid);

#endif
