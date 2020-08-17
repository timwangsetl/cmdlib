#ifndef __DO_DOT1X__
#define __DO_DOT1X__


/* dot1x commands parse function in config-tree*/
static int do_dot1x(int argc, char *argv[], struct users *u);
static int do_dot1x_enable(int argc, char *argv[], struct users *u);
static int do_dot1x_re_authentication(int argc, char *argv[], struct users *u);
static int do_re_authentication(int argc, char *argv[], struct users *u);
static int do_dot1x_timeout(int argc, char *argv[], struct users *u);
static int do_timeout(int argc, char *argv[], struct users *u);
static int do_timeout_reauthperiod(int argc, char *argv[], struct users *u);


static int do_guest_vlan(int argc, char *argv[], struct users *u);
static int no_guest_vlan(int argc, char *argv[], struct users *u);
/* no dot1x commands parse function in config-tree*/
static int no_dot1x(int argc, char *argv[], struct users *u);
static int no_timeout(int argc, char *argv[], struct users *u);



#endif
