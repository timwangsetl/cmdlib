#ifndef __DO_QOS__
#define __DO_QOS__

/* extern functions */
extern int do_test(int argc, char *argv[], struct users *u);
extern int do_test_param(int argc, char *argv[], struct users *u);

/* scheduler commands parse function */
static int do_scheduler(int argc, char *argv[], struct users *u);

/* scheduler policy commands parse function */
static int do_sched_pol(int argc, char *argv[], struct users *u);
static int do_sched_pol_sp(int argc, char *argv[], struct users *u);
static int do_sched_pol_wrr(int argc, char *argv[], struct users *u);
static int do_sched_pol_drr(int argc, char *argv[], struct users *u);
static int do_sched_pol_wfq(int argc, char *argv[], struct users *u);

/* scheduler wrr commands parse function */
static int do_sched_wrr(int argc, char *argv[], struct users *u);
static int do_sched_wrr_band(int argc, char *argv[], struct users *u);
static int do_sched_wrr_band_1(int argc, char *argv[], struct users *u);
static int do_sched_wrr_band_2(int argc, char *argv[], struct users *u);
static int do_sched_wrr_band_3(int argc, char *argv[], struct users *u);
static int do_sched_wrr_band_4(int argc, char *argv[], struct users *u);
static int do_sched_wrr_band_5(int argc, char *argv[], struct users *u);
static int do_sched_wrr_band_6(int argc, char *argv[], struct users *u);
static int do_sched_wrr_band_7(int argc, char *argv[], struct users *u);
static int do_sched_wrr_band_8(int argc, char *argv[], struct users *u);

/* policy-map commands parse function */
static int do_policy_map(int argc, char *argv[], struct users *u);

/* classify commands parse function */
static int do_classify(int argc, char *argv[], struct users *u);
static int no_classify(int argc, char *argv[], struct users *u);
static int do_classify_exit(int argc, char *argv[], struct users *u);
/* classify ip commands parse function */
static int do_classify_ip(int argc, char *argv[], struct users *u);
static int no_classify_ip(int argc, char *argv[], struct users *u);
static int do_classify_ip_access(int argc, char *argv[], struct users *u);
static int no_classify_ip_access(int argc, char *argv[], struct users *u);

/* classify dscp commands parse function */
static int do_classify_dscp(int argc, char *argv[], struct users *u);
static int no_classify_dscp(int argc, char *argv[], struct users *u);

/* classify mac commands parse function */
static int do_classify_mac(int argc, char *argv[], struct users *u);
static int do_classify_mac_access(int argc, char *argv[], struct users *u);
static int no_classify_mac_access(int argc, char *argv[], struct users *u);

/* classify vlan commands parse function */
static int do_classify_vlan(int argc, char *argv[], struct users *u);
static int no_classify_vlan(int argc, char *argv[], struct users *u);

/* classify cos commands parse function */
static int do_classify_cos(int argc, char *argv[], struct users *u);
static int no_classify_cos(int argc, char *argv[], struct users *u);

/* classify any commands parse function */
static int do_classify_any(int argc, char *argv[], struct users *u);
static int no_classify_any(int argc, char *argv[], struct users *u);



/* interface qos commands parse function */

static int do_class_bandwidth(int argc, char *argv[], struct users *u);
static int do_class_drop(int argc, char *argv[], struct users *u);
static int do_class_set(int argc, char *argv[], struct users *u);
static int do_class_set_cos(int argc, char *argv[], struct users *u);
static int do_class_set_dscp(int argc, char *argv[], struct users *u);
static int do_class_set_vlanid(int argc, char *argv[], struct users *u);
static int no_class_bandwidth(int argc, char *argv[], struct users *u);
static int no_class_drop(int argc, char *argv[], struct users *u);
static int no_class_set(int argc, char *argv[], struct users *u);
static int no_class_set_cos(int argc, char *argv[], struct users *u);
static int no_class_set_dscp(int argc, char *argv[], struct users *u);
static int no_class_set_vlanid(int argc, char *argv[], struct users *u);
static int no_scheduler(int argc, char *argv[], struct users *u);
static int no_policy_map(int argc, char *argv[], struct users *u);
static int no_sched_pol(int argc, char *argv[], struct users *u);
static int no_sched_wrr(int argc, char *argv[], struct users *u);
static int no_sched_wrr_band(int argc, char *argv[], struct users *u);

static int do_filter(int argc, char *argv[], struct users *u);
static int no_filter(int argc, char *argv[], struct users *u);

static int do_filter_period(int argc, char *argv[], struct users *u);
static int do_filter_period_time(int argc, char *argv[], struct users *u);
static int no_filter_period(int argc, char *argv[], struct users *u);

static int do_filter_threshold(int argc, char *argv[], struct users *u);
static int do_filter_threshold_value(int argc, char *argv[], struct users *u);
static int no_filter_threshold(int argc, char *argv[], struct users *u);

static int do_filter_block(int argc, char *argv[], struct users *u);
static int do_filter_block_value(int argc, char *argv[], struct users *u);
static int no_filter_block(int argc, char *argv[], struct users *u);

static int do_filter_igmp(int argc, char *argv[], struct users *u);
static int no_filter_igmp(int argc, char *argv[], struct users *u);

static int do_filter_ip(int argc, char *argv[], struct users *u);
static int do_filter_ip_source(int argc, char *argv[], struct users *u);
static int no_filter_ip(int argc, char *argv[], struct users *u);
static int no_filter_ip_source(int argc, char *argv[], struct users *u);

static int do_filter_arp(int argc, char *argv[], struct users *u);
static int no_filter_arp(int argc, char *argv[], struct users *u);

static int do_filter_enable(int argc, char *argv[], struct users *u);
static int no_filter_enable(int argc, char *argv[], struct users *u);

static int do_cluster(int argc, char *argv[], struct users *u);
static int no_cluster(int argc, char *argv[], struct users *u);

static int do_cluster_member(int argc, char *argv[], struct users *u);
static int do_cluster_member_id(int argc, char *argv[], struct users *u);
static int do_cluster_member_id_mac(int argc, char *argv[], struct users *u);
static int do_cluster_member_id_mac_addr(int argc, char *argv[], struct users *u);
static int no_cluster_member(int argc, char *argv[], struct users *u);
static int no_cluster_member_id(int argc, char *argv[], struct users *u);

static int do_ring(int argc, char *argv[], struct users *u);
static int do_ring_id(int argc, char *argv[], struct users *u);
static int do_ring_id_mode(int argc, char *argv[], struct users *u);
static int do_ring_id_mode_single(int argc, char *argv[], struct users *u);
static int do_ring_id_mode_double(int argc, char *argv[], struct users *u);
static int do_ring_id_mode_coupling(int argc, char *argv[], struct users *u);
static int no_ring(int argc, char *argv[], struct users *u);
static int no_ring_id(int argc, char *argv[], struct users *u);

static int do_qos(int argc, char *argv[], struct users *u);
static int no_qos(int argc, char *argv[], struct users *u);
static int do_trust_dscp(int argc, char *argv[], struct users *u);
static int no_trust_dscp(int argc, char *argv[], struct users *u);
static int do_trust_dot1p(int argc, char *argv[], struct users *u);
static int no_trust_dot1p(int argc, char *argv[], struct users *u);
static int do_trust(int argc, char *argv[], struct users *u);
static int no_trust(int argc, char *argv[], struct users *u);

static int do_sched_pol_wred(int argc, char *argv[], struct users *u);

#endif

