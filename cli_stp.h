#ifndef __DO_STP__
#define __DO_STP__


/* extern functions */
extern int do_test(int argc, char *argv[], struct users *u);
extern int do_test_param(int argc, char *argv[], struct users *u);

/* stp commands parse function */
static int do_stp(int argc, char *argv[], struct users *u);

/* stp mode commands parse function */
static int do_stp_mode(int argc, char *argv[], struct users *u);
static int do_stp_mode_rstp(int argc, char *argv[], struct users *u);
static int do_stp_mode_mstp(int argc, char *argv[], struct users *u);

/* stp mst */
static int do_stp_mst(int argc, char *argv[], struct users *u);
static int do_stp_mst_word(int argc, char *argv[], struct users *u);
static int do_stp_mst_word_priority(int argc, char *argv[], struct users *u);
static int do_stp_mst_word_priority_param(int argc, char *argv[], struct users *u);
static int do_stp_mst_word_root(int argc, char *argv[], struct users *u);
static int do_stp_mst_word_root_param(int argc, char *argv[], struct users *u);

static int do_stp_mst_configuration(int argc, char *argv[], struct users *u);

static int do_mst_abort(int argc, char *argv[], struct users *u);

static int do_mst_ctree(int argc, char *argv[], struct users *u);
static int do_mst_ctree_param(int argc, char *argv[], struct users *u);
static int do_mst_dtree(int argc, char *argv[], struct users *u);
static int do_mst_dtree_param(int argc, char *argv[], struct users *u);

static int do_mst_instance(int argc, char *argv[], struct users *u);
static int do_mst_instance_id(int argc, char *argv[], struct users *u);
static int do_mst_instance_id_vlan(int argc, char *argv[], struct users *u);
static int do_mst_instance_id_vlan_line(int argc, char *argv[], struct users *u);

static int do_mst_name(int argc, char *argv[], struct users *u);
static int do_mst_name_word(int argc, char *argv[], struct users *u);

static int do_mst_privlan(int argc, char *argv[], struct users *u);
static int do_mst_privlan_sync(int argc, char *argv[], struct users *u);

static int do_mst_revision(int argc, char *argv[], struct users *u);
static int do_mst_revision_param(int argc, char *argv[], struct users *u);

static int do_mst_show(int argc, char *argv[], struct users *u);
static int do_mst_show_current(int argc, char *argv[], struct users *u);
static int do_mst_show_pending(int argc, char *argv[], struct users *u);

static int do_stp_mst_fwdtime(int argc, char *argv[], struct users *u);
static int do_stp_mst_fwdtime_param(int argc, char *argv[], struct users *u);

static int do_stp_mst_hellotime(int argc, char *argv[], struct users *u);
static int do_stp_mst_hellotime_param(int argc, char *argv[], struct users *u);

static int do_stp_mst_maxage(int argc, char *argv[], struct users *u);
static int do_stp_mst_maxage_param(int argc, char *argv[], struct users *u);
static int do_stp_mst_maxhops(int argc, char *argv[], struct users *u);
static int do_stp_mst_maxhops_param(int argc, char *argv[], struct users *u);

/* stp rstp commands parse function */
static int do_stp_rstp(int argc, char *argv[], struct users *u);
static int do_stp_stp(int argc, char *argv[], struct users *u);
static int do_stp_rstp_forwardtime(int argc, char *argv[], struct users *u);
static int do_stp_rstp_hellotime(int argc, char *argv[], struct users *u);
static int do_stp_rstp_maxage(int argc, char *argv[], struct users *u);
static int do_stp_rstp_priority(int argc, char *argv[], struct users *u);

/* stp portfast commands parse function */
static int do_stp_portfast(int argc, char *argv[], struct users *u);
static int do_stp_portfast_bpdufilter(int argc, char *argv[], struct users *u);
static int do_stp_portfast_bpdu_defau(int argc, char *argv[], struct users *u);
static int do_stp_mode_stp(int argc, char *argv[], struct users *u);

/* no stp commands parse function */
static int no_do_stp(int argc, char *argv[], struct users *u);

/* no stp mst commands parse function */
static int no_do_stp_mst(int argc, char *argv[], struct users *u);

static int no_do_mst_instance(int argc, char *argv[], struct users *u);
static int no_do_mst_instance_id(int argc, char *argv[], struct users *u);
static int no_do_mst_instance_id_vlan_line(int argc, char *argv[], struct users *u);
static int no_do_mst_name(int argc, char *argv[], struct users *u);
static int no_do_mst_revision(int argc, char *argv[], struct users *u);

static int no_do_stp_mst_word_prio(int argc, char *argv[], struct users *u);
static int no_do_stp_mst_word_rt(int argc, char *argv[], struct users *u);

static int no_do_stp_mst_fwdtime(int argc, char *argv[], struct users *u);

static int no_do_stp_mst_hellotime(int argc, char *argv[], struct users *u);

static int no_do_stp_mst_maxage(int argc, char *argv[], struct users *u);

static int no_do_stp_mst_maxhops(int argc, char *argv[], struct users *u);

/* no stp rstp commands parse function */
static int no_do_stp_rstp_forwardtime(int argc, char *argv[], struct users *u);
static int no_do_stp_rstp_hellotime(int argc, char *argv[], struct users *u);
static int no_do_stp_rstp_maxage(int argc, char *argv[], struct users *u);
static int no_do_stp_rstp_priority(int argc, char *argv[], struct users *u);

/* no stp portfast bpdufilter default commands parse function */
static int no_do_stp_portfast_bpdu_defau(int argc, char *argv[], struct users *u);





#endif
