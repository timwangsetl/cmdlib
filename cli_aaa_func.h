#ifndef __FUNC_AAA_H
#define __FUNC_AAA_H

extern char *get_line_ptr(struct users *u);

int func_authentication_banner(struct users *u);
int nfunc_authentication_banner();

int func_authentication_fail_message(struct users *u);
int nfunc_authentication_fail_message();

int func_authentication_username_prompt(struct users *u);
int nfunc_authentication_username_prompt();

int func_authentication_password_prompt(struct users *u);
int nfunc_authentication_password_prompt();

int func_authentication_dot1x_list(const char *buf);
int nfunc_authentication_dot1x_list(struct users *u);

int func_authentication_enable_list(const char *buf);
int nfunc_authentication_enable_list(struct users *u);

int func_authentication_login_list(const char *buf);
int nfunc_authentication_login_list(struct users *u);


int func_accounting_conn_exec_list_group_done(struct users *u);
int nfunc_accounting_conn_exec_list_done(struct users *u);
int func_accounting_conn_exec_list_none(u);

#endif

