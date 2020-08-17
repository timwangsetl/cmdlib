#ifndef __FUNC_ENABLE_H
#define __FUNC_ENABLE_H

int func_passwd_line(struct users *u);
int nfunc_passwd_line(struct users *u);

int func_secret_line(struct users *u);
int nfunc_secret_line(struct users *u);

int switch_crc(unsigned char *src);
void switch_encrypted(unsigned char *src, unsigned char *hash);
int passwd_set(char *passwd, int length, int level, int is_encrypted);

#endif /* __FUNC_ENABLE_H */
