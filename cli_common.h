#ifndef __COMMON__
#define __CCOMMON__

#define USER_PASSWORD                    0x00000001
#define USER_PRIVILEGE                   0x00000002
#define ZERO_SEVEN                       0x00000004
#define PASSWORD_LINE                    0x00000008
#define PRIVILEGE	                     0x00000010

extern int do_test(int argc, char *argv[], struct users *u);
extern int do_test_param(int argc, char *argv[], struct users *u);

static int do_exit(int argc, char *argv[], struct users *u);
static int do_help(int argc, char *argv[], struct users *u);

static int do_end(int argc, char *argv[], struct users *u);
static int do_no(int argc, char *argv[], struct users *u);
static int do_default(int argc, char *argv[], struct users *u);

static int do_ena(int argc, char *argv[], struct users *u);
static int do_ena_level(int argc, char *argv[], struct users *u);
static int do_config(int argc, char *argv[], struct users *u);

static int do_chinese(int argc, char *argv[], struct users *u);
static int do_english(int argc, char *argv[], struct users *u);
static int do_reboot(int argc, char *argv[], struct users *u);
static int do_restore_factery(int argc, char *argv[], struct users *u);
static int do_username(int argc, char *argv[], struct users *u);
static int do_username_password(int argc, char *argv[], struct users *u);
static int do_username_privilege(int argc, char *argv[], struct users *u);
static int do_password_0(int argc, char *argv[], struct users *u);
static int do_password_7(int argc, char *argv[], struct users *u);
static int do_password_line(int argc, char *argv[], struct users *u);


static int do_hostname(int argc, char *argv[], struct users *u);

static int do_quit(int argc, char *argv[], struct users *u);

static int no_username(int argc, char *argv[], struct users *u);
static int no_hostname(int argc, char *argv[], struct users *u);

#endif

