#ifndef __FUNC_CLOCK__
#define __FUNC_CLOCK__
/* extern functions */
int func_time_range_set(struct users *u);

static int cli_delete_time_range_list(char *name);
int cli_set_time_range_nvram(char *name_str);

int func_time_range_name(struct users *u);
int nfunc_time_range_name(struct users *u);

/*----------------------------------------------------------------------------------------------------------------*/
#if 0
int func_config_dot1q(struct users *u);
int nfunc_config_dot1q(struct users *u);
#endif

/*----------------------------------------------------------------------------------------------------------------*/

#endif

