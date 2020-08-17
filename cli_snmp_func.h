#ifndef __FUNC_SNMP__
#define __FUNC_SNMP__
#define SNMP_PASSWORD_LEN_MIN 8
#define SNMP_PASSWORD_LEN_MAX 32
/*static int cli_snmp_set(void);
static int cli_snmp_set_info(void);
static int cli_snmp_set_location(int argc, char **argv);
static int cli_snmp_set_user(char *name, char *auth, char *auth_passwd, char *priv, char *priv_passwd, int mode);
*/

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

extern int SYSTEM(const char *format, ...);
extern int nvram_set(char *name,char *data);
extern int cli_nvram_conf_get(int type, unsigned char *addr);
extern int cli_nvram_conf_free(int type, unsigned char *addr);
extern int cli_nvram_conf_set(int type, unsigned char *addr);

int func_snmp_commu_ro(struct users *u);
int func_snmp_commu_rw(struct users *u);
int nfunc_snmp_commu(struct users *u);
int func_snmp_contact(struct users *u);
int nfunc_snmp_contact(struct users *u);
int func_snmp_host(struct users *u);
int nfunc_snmp_host(struct users *u);
int func_snmp_location(struct users *u);
int nfunc_snmp_location(struct users *u);
int func_md5(struct users *u);
int func_sha(struct users *u);
int func_ro(struct users *u);
int func_rw(struct users *u);
int nfunc_snmp_users(struct users *u);

int func_snmp_enable(struct users *u);
int nfunc_snmp_enable(struct users *u);

#endif

