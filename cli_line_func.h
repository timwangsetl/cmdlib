#ifndef _CLI_LINE_FUN_H
#define _CLI_LINE_FUN_H

int func_login_method_name(struct users *u);
int nfunc_login_method(struct users *u);
int func_set_absolute_timeout(struct users *u, int line_id0, int line_id1, int absolute_time);
int func_create_vty_users(struct users *u, int vty_first, int vty_last);
static int setlock(int fd, int type);
int nfunc_line_vty(struct users *u);
int func_set_exec_timeout(struct users *u);
int nfunc_set_exec_timeout(struct users *u);

#define	MAX_VTY	16	

#endif
