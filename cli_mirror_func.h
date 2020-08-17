#ifndef __FUNC_MIRROR__
#define __FUNC_MIRROR__

#define MIRROR_IF_SRC	0x00000001
#define MIRROR_IF_DST	0x00000002

#define MIRROR_IF_RX	0x00000004
#define MIRROR_IF_TX	0x00000008
#define MIRROR_IF_BOTH	0x00000010

#define MIRROR_IF_FAST_PORT	0x08000000
#define MIRROR_IF_GIGA_PORT	0x10000000
#define MIRROR_IF_XE_PORT	0x20000000

extern int nvram_set(char *name,char *data);
extern int str2bit(char *input, uint64_t *value);
extern char * bit2str(uint64_t pmaps);


/*mirror destination port function*/
int func_mirror_interface_dst(struct users *u);

/*mirror source port function*/
int func_mirror_interface_src(struct users *u);

/*no mirror function*/
int nfunc_session_num(struct users *u);

/*no mirror source port function*/
int nfunc_mirror_interface_src(struct users *u);

int func_mirror_soure_vlan(struct users *u);

int nfunc_mirror_vlan_by_session(struct users *u);

#endif

