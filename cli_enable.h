#ifndef __DO_ENABLE__
#define __DO_ENABLE__

#define ZERO_SEVEN                           0x00000001
#define PASSWORD_LINE                        0x00000002
#define LEVEL_MASK                           0x00000004

static int do_enble(int argc, char *argv[], struct users *u);
static int do_enable_password(int argc, char *argv[], struct users *u);
static int no_enable_password(int argc, char *argv[], struct users *u);
static int do_password_0(int argc, char *argv[], struct users *u);
static int do_password_7(int argc, char *argv[], struct users *u);
static int do_password_line(int argc, char *argv[], struct users *u);
static int do_secret_line(int argc, char *argv[], struct users *u);

static int do_passwd_level(int argc, char *argv[], struct users *u);
static int do_passwd_level_line(int argc, char *argv[], struct users *u);
static int no_passwd_level_line(int argc, char *argv[], struct users *u);

static int do_secret_level(int argc, char *argv[], struct users *u);
static int do_secret_level_line(int argc, char *argv[], struct users *u);
static int no_secret_level_line(int argc, char *argv[], struct users *u);


static int do_enable_secret(int argc, char *argv[], struct users *u);
static int no_enable_secret(int argc, char *argv[], struct users *u);

static int do_secret_0(int argc, char *argv[], struct users *u);
static int do_secret_5(int argc, char *argv[], struct users *u);

static int no_enable_secret(int argc, char *argv[], struct users *u);
#endif

