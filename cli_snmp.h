#ifndef __DO_SNMP__
#define __DO_SNMP__

/* snmp user authentication */
#define SNMP_USER_AUTH_MD5      1
#define SNMP_USER_AUTH_SHA      2

/* snmp user Encryption */
#define SNMP_USER_PRIV_3DES     1
#define SNMP_USER_PRIV_AES      2
#define SNMP_USER_PRIV_DES      3

/* option value in postion of u->x_param */
#define SNMP_USER_AUTH          MAX_V_INT - 1
#define SNMP_USER_PRIV          MAX_V_INT - 2

/* extern functions */
extern int do_test(int argc, char *argv[], struct users *u);
extern int do_test_param(int argc, char *argv[], struct users *u);

/* snmp commands parse function */
static int do_snmp(int argc, char *argv[], struct users *u);

/* snmp community commands parse function */
static int do_snmp_community(int argc, char *argv[], struct users *u);
static int do_snmp_commu_ro(int argc, char *argv[], struct users *u);
static int do_snmp_commu_rw(int argc, char *argv[], struct users *u);
static int no_snmp_community(int argc, char *argv[], struct users *u);

/* snmp contact commands parse function */
static int do_snmp_contact(int argc, char *argv[], struct users *u);
static int no_snmp_contact(int argc, char *argv[], struct users *u);
/* snmp host commands parse function */
static int do_snmp_host(int argc, char *argv[], struct users *u);
static int no_snmp_host(int argc, char *argv[], struct users *u);

/* snmp location commands parse function */
static int do_snmp_location(int argc, char *argv[], struct users *u);
static int no_snmp_location(int argc, char *argv[], struct users *u);

/* snmp user commands parse function */
static int do_snmp_user(int argc, char *argv[], struct users *u);
static int no_snmp_user(int argc, char *argv[], struct users *u);
static int do_snmp_user_auth(int argc, char *argv[], struct users *u);
static int do_snmp_user_auth_md5(int argc, char *argv[], struct users *u);
static int do_snmp_user_auth_sha(int argc, char *argv[], struct users *u);
static int do_snmp_user_auth_algo_priv(int argc, char *argv[], struct users *u);
static int do_snmp_user_auth_algo_priv_3des(int argc, char *argv[], struct users *u);
static int do_snmp_user_auth_algo_priv_aes(int argc, char *argv[], struct users *u);
static int do_snmp_user_auth_algo_priv_des(int argc, char *argv[], struct users *u);
static int do_snmp_user_auth_algo_priv_encr_ro(int argc, char *argv[], struct users *u);
static int do_snmp_user_auth_algo_priv_encr_rw(int argc, char *argv[], struct users *u);

static int do_snmp_view(int argc, char *argv[], struct users *u);
static int no_snmp_view(int argc, char *argv[], struct users *u);

#endif
