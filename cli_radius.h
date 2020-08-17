#ifndef __DO_DOT1X__
#define __DO_DOT1X__

#define HOST_ACCTPORT 0X00000001
#define HOST_AUTHPORT 0X00000002

#define ACCTPORT_POS 0X00000001
#define AUTHPORT_POS 0X00000002

/* dot1x commands parse function in config-tree*/
static int do_radiusserver(int argc, char *argv[], struct users *u);
static int do_radius_host(int argc, char *argv[], struct users *u);
static int do_host_acctport(int argc, char *argv[], struct users *u);
static int do_host_authport(int argc, char *argv[], struct users *u);
static int do_radius_key(int argc, char *argv[], struct users *u);

/* no radiusserver commands parse function in config-tree*/
static int no_radius_host(int argc, char *argv[], struct users *u);
static int no_radius_key(int argc, char *argv[], struct users *u);

#endif



