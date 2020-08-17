#ifndef __FUNC_MAC__
#define __FUNC_MAC__

static void del_static_mac_cfg();

int func_mac_acl_name(struct users *u);
int nfunc_mac_acl_name(struct users *u);

#define ONET_MAGIC 0x4F4E6574
int func_set_mac_static_address(int flag, char *mac_str, char *vid_str, char *port_str);
int func_set_aging_time(char *age);

int nfunc_mac_by_mac_vid(struct users *u);
int nfunc_set_aging_time_default();
int func_set_mac_blackhole(char *mac,int vid);
int func_del_mac_blackhole(char *mac,int vid);

#endif

