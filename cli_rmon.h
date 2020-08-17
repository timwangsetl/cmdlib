#ifndef __DO_RMON__
#define __DO_RMON__

/* Rmon subcmds maskbit */
#define RMON_FALLING_THR_MSK		0x000000001
#define RMON_RISING_EVENT_MSK		0x000000002

#define RMON_OWNER_MSK			0x000000004
#define RMON_FALLING_EVENT_MSK	0x000000008

/* Rmon opt value in postion of u->x_param */
#define RMON_ALARM_NUM			0
#define RMON_SAMPLE_INTVERVAL		1
#define RMON_RISING_THR			2
#define RMON_FALLING_THR			3

#define RMON_EVENT_NUM			4

#define RMON_MODE_FLAG			5
#define RMON_MODE_DELTA			1
#define RMON_MODE_ABSOLUTE		2

extern int do_test(int argc, char *argv[], struct users *u);
extern int do_test_param(int argc, char *argv[], struct users *u);

static int do_rmon(int argc, char *argv[], struct users *u);
static int do_rmon_alarm(int argc, char *argv[], struct users *u);
static int do_rmon_alarm_delta(int argc, char *argv[], struct users *u);
static int do_rmon_alarm_absolute(int argc, char *argv[], struct users *u);
static int do_rmon_alarm_mode_rising(int argc, char *argv[], struct users *u);
static int do_rmon_alarm_mode_falling(int argc, char *argv[], struct users *u);
static int do_rmon_alarm_mode_rising_event(int argc, char *argv[], struct users *u);
static int do_rmon_alarm_mode_owner(int argc, char *argv[], struct users *u);
static int do_rmon_alarm_mode_falling_event(int argc, char *argv[], struct users *u);

static int do_rmon_event(int argc, char *argv[], struct users *u);
static int do_rmon_event_description(int argc, char *argv[], struct users *u);
static int do_rmon_event_log(int argc, char *argv[], struct users *u);
static int do_rmon_event_trap(int argc, char *argv[], struct users *u);

static int no_rmon_alarm(int argc, char *argv[], struct users *u);
static int no_rmon_event(int argc, char *argv[], struct users *u);

#endif
