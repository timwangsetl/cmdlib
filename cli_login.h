#ifndef __DO_MIRROR__
#define __DO_MIRROR__


/* option value in postion of u->x_param */
#define SSH_L_POS			1
#define SSH_D_POS			2

/* option subcmds maskbit */
#define SSH_L			0x00000001
#define SSH_D			0x00000002
#define SSH_P			0x00000004
#define SSH_C			0x00000008
#define CIPHER_DES		0x00000010
#define CIPHER_BLOW		0x00000020

/* extern functions */
extern int do_test(int argc, char *argv[], struct users *u);
extern int do_test_param(int argc, char *argv[], struct users *u);

/* ssh and telnet commands parse function */
static int do_ssh(int argc, char *argv[], struct users *u);
static int do_ssh_d(int argc, char *argv[], struct users *u);
static int do_ssh_l(int argc, char *argv[], struct users *u);
static int do_telnet(int argc, char *argv[], struct users *u);
static int do_telnet_ip(int argc, char *argv[], struct users *u);
static int do_telnet_ipv6(int argc, char *argv[], struct users *u);
static int do_telnet_host(int argc, char *argv[], struct users *u);
static int do_ssh_server(int argc, char *argv[], struct users *u);
static int no_ssh_server(int argc, char *argv[], struct users *u);
static int do_ssh_enable(int argc, char *argv[], struct users *u);
static int do_ssh_p(int argc, char *argv[], struct users *u); 
static int do_ssh_c(int argc, char *argv[], struct users *u); 
static int do_ssh_pi(int argc, char *argv[], struct users *u); 
static int do_ssh_cblow(int argc, char *argv[], struct users *u); 
static int do_ssh_cdes(int argc, char *argv[], struct users *u); 
#endif 
