#ifndef __FUNC_STP__
#define __FUNC_STP__

#define STP_MODE_RSTP 0x00000001
#define STP_MODE_MSTP 0x00000002
#define INSTANCE_ROOT_PRIMARY 0x00000010
#define INSTANCE_ROOT_SECONDARY 0x00000020

/* forward-time/hello-time/max-age check function */
static int cli_check_stp_time(int flag, int time);

/*Enable stp function*/
int func_stp_mode_rstp(struct users *u);
int func_stp_mode_stp(struct users *u);

/*stp rstp forward-time/hello-time/max-age/priority function*/
int func_stp_rstp_forwardtime(struct users *u);
int func_stp_rstp_hellotime(struct users *u);
int func_stp_rstp_maxage(struct users *u);
int func_stp_rstp_priority(struct users *u);

/*stp portfast bpdufilter default function*/
int func_stp_portfast_bpdu_defau(struct users *u);

/*Disable stp function*/
int nfunc_stp_enable(struct users *u);

int nfunc_stp_mode_rstp(struct users *u);
int nfunc_stp_mode_mstp(void);

/*no stp rstp forward-time/hello-time/max-age/priority function*/
int nfunc_stp_rstp_forwardtime(struct users *u);
int nfunc_stp_rstp_hellotime(struct users *u);
int nfunc_stp_rstp_maxage(struct users *u);
int nfunc_stp_rstp_priority(struct users *u);

/*no stp portfast bpdufilter default function*/
int nfunc_stp_portfast_bpdu_defau(struct users *u);



/* Enable mstp fuction */
int func_stp_mode_mstp(struct users *u);

/* MST function */
int func_stp_mst_word_priority(struct users *u);
int func_stp_mst_word_root(struct users *u);

int func_mst_instance_id_vlan_line(struct users *u);
int func_mst_name_word(struct users *u);
int func_mst_privlan_sync(struct users *u);
int func_mst_revision_param(struct users *u);
int func_mst_show(struct users *u);
int func_mst_show_current(struct users *u);

int func_stp_mst_fwdtime_param(struct users *u);
int func_stp_mst_maxage_param(struct users *u);

int func_stp_mst_hellotime_param(struct users *u);
int func_stp_mst_maxhops_param(struct users *u);

int func_stp_portfast_bpdufilter(struct users *u);

/* Disable mst function */
int nfunc_stp_mst_word_prio(struct users *u);
int nfunc_stp_mst_word_rt(struct users *u);

int nfunc_mst_instance_id(struct users *u);
int nfunc_mst_instance_id_vlan_line(struct users *u);
int nfunc_mst_name(struct users *u);
int nfunc_mst_revision(struct users *u);

int nfunc_stp_mst_fwdtime(struct users *u);
int nfunc_stp_mst_maxage(struct users *u);

int nfunc_stp_mst_hellotime(struct users *u);
int nfunc_stp_mst_maxhops(struct users *u);

int nfunc_stp_portfast_bpdufilter(struct users *u);

#endif

