#ifndef __FUNC_ERR_DIS_REC__
#define __FUNC_ERR_DIS_REC__

int func_set_errdisable_detect(int iCase);
int func_set_recover_detect(int iCase);
int func_set_recover_time(char *pStr);
int nfunc_set_errdisable_detect(int iCase);
int nfunc_set_recover_detect(int iCase);
int nfunc_set_recover_time(void);

#endif

