#ifndef __DO_CLOCK__
#define __DO_CLOCK__

#define 	NTP_SERVER		0x00000001

/* extern functions */
extern int do_test(int argc, char *argv[], struct users *u);
extern int do_test_param(int argc, char *argv[], struct users *u);

/* clock commands parse function */
static int do_clock(int argc, char *argv[], struct users *u);
static int do_clock_set(int argc, char *argv[], struct users *u);
static int do_clock_set_curtime(int argc, char *argv[], struct users *u);
static int do_clock_set_day(int argc, char *argv[], struct users *u);
static int do_clock_set_month(int argc, char *argv[], struct users *u);
static int do_clock_set_year(int argc, char *argv[], struct users *u);
static int config_do_clock(int argc, char *argv[], struct users *u);
static int do_clock_timezone(int argc, char *argv[], struct users *u);
static int do_timezone_name(int argc, char *argv[], struct users *u);
static int do_name_offset(int argc, char *argv[], struct users *u);
static int no_clock_timezone(int argc, char *argv[], struct users *u);
static int do_ntp(int argc, char *argv[], struct users *u);
static int do_ntp_server(int argc, char *argv[], struct users *u);
static int do_ntp_server_ip(int argc, char *argv[], struct users *u);
static int do_ntp_query(int argc, char *argv[], struct users *u);
static int no_ntp_query(int argc, char *argv[], struct users *u);
static int do_ntp_minutes(int argc, char *argv[], struct users *u);
static int no_ntp(int argc, char *argv[], struct users *u);

/*----------------------------------------------------------------------------------------------------------------*/
#if 0
static int do_dot1q(int argc, char *argv[], struct users *u);
static int no_dot1q(int argc, char *argv[], struct users *u);
#endif
/*----------------------------------------------------------------------------------------------------------------*/

#endif
