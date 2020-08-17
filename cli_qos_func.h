#ifndef __FUNC_QOS__
#define __FUNC_QOS__

#define QOS_CLASSITY_IP		0x00000001
#define QOS_CLASSITY_DSCP	0x00000002
#define QOS_CLASSITY_MAC	0x00000004
#define QOS_CLASSITY_VLAN	0x00000008
#define QOS_CLASSITY_COS	0x00000010
#define QOS_CLASSITY_ANY	0x00000020
#define QOS_CLASSITY_DROP_P	0x00000040


int func_qos_policy_map(struct users *u);

int func_qos_classify(struct users *u);
int func_qos_sch_po_sp(struct users *u);
int func_qos_sch_po_wrr(struct users *u);
int func_qos_sch_po_drr(struct users *u);
int func_qos_sch_po_wfq(struct users *u);

int func_qos_sch_wrr_ban_1(struct users *u);
int func_qos_sch_wrr_ban_2(struct users *u);
int func_qos_sch_wrr_ban_3(struct users *u);
int func_qos_sch_wrr_ban_4(struct users *u);
int func_qos_sch_wrr_ban_5(struct users *u);
int func_qos_sch_wrr_ban_6(struct users *u);
int func_qos_sch_wrr_ban_7(struct users *u);
int func_qos_sch_wrr_ban_8(struct users *u);


int nfunc_classify_ip_access(struct users *u);
int nfunc_classify_dscp(struct users *u);
int nfunc_classify_mac_acc(struct users *u);
int nfunc_classify_vlan(struct users *u);
int nfunc_classify_cos(struct users *u);
int nfunc_classify_any(struct users *u);



int func_class_band(struct users *u);
int func_class_drop(struct users *u);
int func_class_set_cos(struct users *u);
int func_class_set_dscp(struct users *u);
int func_class_set_vlanid(struct users *u);
int nfunc_class_band(struct users *u);
int nfunc_class_drop(struct users *u);
int nfunc_class_set_cos(struct users *u);
int nfunc_class_set_dscp(struct users *u);
int nfunc_class_set_vlanid(struct users *u);
int nfunc_qos_policy_map(struct users *u);
int nfunc_sched_pol(struct users *u);
int nfunc_sched_wrr_band(struct users *u);

int func_filter_period(struct users *u);
int nfunc_filter_period(struct users *u);

int func_filter_threshold(struct users *u);
int nfunc_filter_threshold(struct users *u);

int func_filter_block(struct users *u);
int nfunc_filter_block(struct users *u);

int func_filter_igmp(struct users *u);
int nfunc_filter_igmp(struct users *u);

int func_filter_ip_source(struct users *u);
int nfunc_filter_ip_source(struct users *u);

int func_filter_arp(struct users *u);
int nfunc_filter_arp(struct users *u);

int func_filter_enable(struct users *u);
int nfunc_filter_enable(struct users *u);

int func_cluster_member_id(struct users *u);
int nfunc_cluster_member_id(struct users *u);

int func_ring_enable(struct users *u, int mode);
int nfunc_ring_id(struct users *u);

int do_trust_dot1p_set(struct users *u);
int no_trust_dot1p_set(struct users *u);
int do_trust_dscp_set(struct users *u);
int no_trust_dscp_set(struct users *u);
int no_qos_set(struct users *u);

#endif

