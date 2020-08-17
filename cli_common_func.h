#ifndef __FUNC_COMMON__
#define __FUNC_COMMON__

int func_username_passwd_line(struct users *u);
int func_username_privilege(struct users *u);

int nfunc_username(struct users *u);

int func_hostname(struct users *u);
int nfunc_hostname(struct users *u);

int func_enable(struct users *u);

#endif

