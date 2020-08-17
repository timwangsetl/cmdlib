#ifndef __AAA_H
#define __AAA_H

/* option subcmds maskbit */
#define AAA_OPT_ENABLE                (1 << 1)
#define AAA_OPT_LOCAL                 (1 << 2)
#define AAA_OPT_LOCAL_CASE            (1 << 3)
#define AAA_OPT_GROUP                 (1 << 4)
#define AAA_OPT_NONE                  (1 << 5)
#define AAA_OPT_LINE                  (1 << 6)
#define AAA_OPT_IF_AUTHENTICATED      (1 << 7)

extern int do_test(int argc, char *argv[], struct users *u);
extern int do_test_param(int argc, char *argv[], struct users *u);

/* commands parse function */
static int do_aaa(int argc, char *argv[], struct users *u);
static int do_accounting(int argc, char *argv[], struct users *u);
static int do_authentication(int argc, char *argv[], struct users *u);
static int do_authorization(int argc, char *argv[], struct users *u);
static int do_group(int argc, char *argv[], struct users *u);

// authentication
static int do_authentication_banner(int argc, char *argv[], struct users *u);
static int do_authentication_dot1x(int argc, char *argv[], struct users *u);
static int do_authentication_dot1x_name(int argc, char *argv[], struct users *u);
static int do_authentication_dot1x_list_group(int argc, char *argv[], struct users *u);
static int do_authentication_dot1x_list_group_done(int argc, char *argv[], struct users *u);
static int do_authentication_dot1x_list_other(int argc, char *argv[], struct users *u);
static int do_authentication_fail_message(int argc, char *argv[], struct users *u);
static int do_authentication_enable(int argc, char *argv[], struct users *u);
static int do_authentication_enable_name(int argc, char *argv[], struct users *u);
static int do_authentication_enable_list_group(int argc, char *argv[], struct users *u);
static int do_authentication_enable_list_group_done(int argc, char *argv[], struct users *u);
static int do_authentication_enable_list_other(int argc, char *argv[], struct users *u);
static int do_authentication_login(int argc, char *argv[], struct users *u);
static int do_authentication_login_name(int argc, char *argv[], struct users *u);
static int do_authentication_login_list_group(int argc, char *argv[], struct users *u);
static int do_authentication_login_list_group_done(int argc, char *argv[], struct users *u);
static int do_authentication_login_list_other(int argc, char *argv[], struct users *u);

static int do_authentication_password_prompt(int argc, char *argv[], struct users *u);
static int do_authentication_username_prompt(int argc, char *argv[], struct users *u);

// accounting
static int do_accounting_conn_exec(int argc, char *argv[], struct users *u);
static int do_accounting_conn_exec_list(int argc, char *argv[], struct users *u);
static int do_accounting_conn_exec_list_group(int argc, char *argv[], struct users *u);
static int do_accounting_conn_exec_list_group_done(int argc, char *argv[], struct users *u);
static int do_accounting_conn_exec_list_none(int argc, char *argv[], struct users *u);
static int do_accounting_conn_exec_list_action(int argc, char *argv[], struct users *u);


static int do_authorization_commands(int argc, char *argv[], struct users *u);
static int do_authorization_commands_level(int argc, char *argv[], struct users *u);
static int do_authorization_commands_level_list(int argc, char *argv[], struct users *u);
static int do_authorization_commands_level_list_group(int argc, char *argv[], struct users *u);
static int do_authorization_commands_level_list_group_done(int argc, char *argv[], struct users *u);
static int do_authorization_commands_level_list_other(int argc, char *argv[], struct users *u);


static int do_authorization_exec_net(int argc, char *argv[], struct users *u);
static int do_authorization_exe_net_list(int argc, char *argv[], struct users *u);
static int no_authorization_exe_net_list(int argc, char *argv[], struct users *u);
static int do_authorization_exe_net_list_group(int argc, char *argv[], struct users *u);
static int do_authorization_exe_net_list_group_done(int argc, char *argv[], struct users *u);
static int do_authorization_exe_net_list_other(int argc, char *argv[], struct users *u);


static int do_authorization_config(int argc, char *argv[], struct users *u);
static int no_authorization_config(int argc, char *argv[], struct users *u);

static int do_group_server(int argc, char *argv[], struct users *u);
static int do_group_server_list(int argc, char *argv[], struct users *u);

static int no_authentication_password_prompt(int argc, char *argv[], struct users *u);
static int no_authentication_username_prompt(int argc, char *argv[], struct users *u);
static int no_authentication_dot1x_name(int argc, char *argv[], struct users *u);
static int no_authentication_enable_name(int argc, char *argv[], struct users *u);
static int no_authentication_login_name(int argc, char *argv[], struct users *u);

static int no_accounting_conn_exec_list(int argc, char *argv[], struct users *u);
static int no_authorization_commands_level(int argc, char *argv[], struct users *u);
static int no_authorization_commands_level_list(int argc, char *argv[], struct users *u);
static int do_group_server(int argc, char *argv[], struct users *u);

static int no_authentication_banner(int argc, char *argv[], struct users *u);    
static int no_authentication_fail_message(int argc, char *argv[], struct users *u);   


#endif /*  __AAA_H  */
