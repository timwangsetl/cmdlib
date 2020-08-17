#ifndef __DO_OTHERS__
#define __DO_OTHERS__

/* extern functions */
extern int do_test(int argc, char *argv[], struct users *u);
extern int do_test_param(int argc, char *argv[], struct users *u);

static int do_traceroute(int argc, char *argv[], struct users *u);
static int cmd_traceroute(int argc, char *argv[], struct users *u);

static int do_anti_dos(int argc, char *argv[], struct users *u);
static int do_anti_dos_ena(int argc, char *argv[], struct users *u);

static int do_exec_timeout(int argc, char *argv[], struct users *u);
static int do_flow_interval(int argc, char *argv[], struct users *u);
static int cmd_exec_timeout(int argc, char *argv[], struct users *u);
static int cmd_flow_interval(int argc, char *argv[], struct users *u);
static int no_exec_timeout(int argc, char *argv[], struct users *u);
static int no_flow_interval(int argc, char *argv[], struct users *u);

static int no_dot1q(int argc, char *argv[], struct users *u);
static int do_dot1q(int argc, char *argv[], struct users *u);
static int do_dot1q_tpid(int argc, char *argv[], struct users *u);
static int no_dot1q_tpid(int argc, char *argv[], struct users *u);
static int do_dot1q_tpid_word(int argc, char *argv[], struct users *u);


static int do_error_disable_recover(int argc, char *argv[], struct users *u);
static int no_error_disable_recover(int argc, char *argv[], struct users *u);
static int do_error_disable_recover_enable(int argc, char *argv[], struct users *u);
static int do_error_disable_recover_time(int argc, char *argv[], struct users *u);
static int cmd_error_disable_recover_timeout(int argc, char *argv[], struct users *u);

#endif

