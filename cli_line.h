#ifndef __DO_LINE__
#define __DO_LINE__

/* extern functions */
extern int do_test(int argc, char *argv[], struct users *u);
extern int do_test_param(int argc, char *argv[], struct users *u);

/* mac commands parse function */
static int do_line(int argc, char *argv[], struct users *u);
static int do_console(int argc, char *argv[], struct users *u);
static int do_vty(int argc, char *argv[], struct users *u);
static int do_vty_first(int argc, char *argv[], struct users *u);
static int do_vty_last(int argc, char *argv[], struct users *u);
static int do_login(int argc, char *argv[], struct users *u);
static int do_login_method(int argc, char *argv[], struct users *u);
static int do_login_method_name(int argc, char *argv[], struct users *u);
static int no_login_method(int argc, char *argv[], struct users *u);
static int do_absolute_timeout(int argc, char *argv[], struct users *u);		
static int do_set_absolute_timeout(int argc, char *argv[], struct users *u);	
static int no_do_vty_first(int argc, char *argv[], struct users *u);
static int no_do_vty_last(int argc, char *argv[], struct users *u);
static int do_exec_timeout(int argc, char *argv[], struct users *u);
static int do_set_exec_timeout(int argc, char *argv[], struct users *u);
static int no_exec_timeout(int argc, char *argv[], struct users *u);

int init_cli_line(void);

#endif

