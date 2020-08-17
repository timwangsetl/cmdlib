#ifndef __FUNC_LOGIN__
#define __FUNC_LOGIN__

/* option subcmds maskbit */
#define SSH_L			0x00000001
#define SSH_D			0x00000002
#define SSH_P			0x00000004
#define SSH_C			0x00000008
#define CIPHER_DES		0x00000010
#define CIPHER_BLOW		0x00000020

extern int SYSTEM(const char *format, ...);
extern int nvram_set(char *name,char *data);
int func_telnet_ip(struct users *u);
int func_telnet_ipv6(struct users *u);
int func_telnet_host(struct users *u);
int func_ssh(struct users *u);
int func_ssh_enable(struct users *u);
int nfunc_ssh_enable(struct users *u);

#endif

