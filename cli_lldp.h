#ifndef __DO_LLDP__
#define __DO_LLDP__

#define LLDP_1_POS      	1
#define LLDP_2_POS      	2
#define LLDP_3_POS      	3

/* extern functions */
extern int do_test(int argc, char *argv[], struct users *u);
extern int do_test_param(int argc, char *argv[], struct users *u);

/* lldp commands parse function */
static int do_lldp(int argc, char *argv[], struct users *u);
static int do_lldp_run(int argc, char *argv[], struct users *u);
static int do_set_holdtime(int argc, char *argv[], struct users *u);
static int do_set_interval_time(int argc, char *argv[], struct users *u);

static int no_lldp_run(int argc, char *argv[], struct users *u);
static int no_set_holdtime(int argc, char *argv[], struct users *u);
static int no_set_interval_time(int argc, char *argv[], struct users *u);
#endif
