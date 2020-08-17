#ifndef __DO_CLOCK__
#define __DO_CLOCK__

#define 	NTP_SERVER		0x00000001

/* extern functions */
extern int do_test(int argc, char *argv[], struct users *u);
extern int do_test_param(int argc, char *argv[], struct users *u);

static int do_time_range(int argc, char *argv[], struct users *u);
static int do_time_range_name(int argc, char *argv[], struct users *u);
static int no_time_range_name(int argc, char *argv[], struct users *u);

static int do_time_range_absolute(int argc, char *argv[], struct users *u);
static int do_time_range_absolute_1(int argc, char *argv[], struct users *u);
static int do_time_range_absolute_2(int argc, char *argv[], struct users *u);
static int do_time_range_absolute_3(int argc, char *argv[], struct users *u);
static int do_time_range_absolute_4(int argc, char *argv[], struct users *u);
static int do_time_range_absolute_5(int argc, char *argv[], struct users *u);
static int do_time_range_absolute_6(int argc, char *argv[], struct users *u);
static int do_time_range_absolute_7(int argc, char *argv[], struct users *u);
static int do_time_range_absolute_8(int argc, char *argv[], struct users *u);
static int do_time_range_absolute_9(int argc, char *argv[], struct users *u);
static int do_time_range_absolute_10(int argc, char *argv[], struct users *u);

static int do_time_range_periodic(int argc, char *argv[], struct users *u);
static int do_time_range_periodic_1(int argc, char *argv[], struct users *u);
static int do_time_range_periodic_2(int argc, char *argv[], struct users *u);
static int do_time_range_periodic_3(int argc, char *argv[], struct users *u);
static int do_time_range_periodic_4(int argc, char *argv[], struct users *u);
static int do_time_range_periodic_5(int argc, char *argv[], struct users *u);
static int do_time_range_periodic_6(int argc, char *argv[], struct users *u);


/*----------------------------------------------------------------------------------------------------------------*/
#if 0
static int do_dot1q(int argc, char *argv[], struct users *u);
static int no_dot1q(int argc, char *argv[], struct users *u);
#endif
/*----------------------------------------------------------------------------------------------------------------*/

#endif
