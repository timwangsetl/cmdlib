#ifndef __FUNC_FILESYS__
#define __FUNC_FILESYS__

#define COPY_SRC_FLASH		0x00000001
#define COPY_SRC_TFTP		0x00000002
#define COPY_SRC_START		0x00000008


#define COPY_DST_FLASH		0x00010000
#define COPY_DST_TFTP		0x00020000


#define COPY_REMOTE_IP		0x20000000
#define COPY_SRC_FILE		0x40000000
#define COPY_DST_FILE		0x80000000

#define COPY_SRC_WORD		1
#define COPY_DST_WORD		2

struct cmds *cli_filesys_init_filename_cmds(int type);

int func_copy(struct users *u);
int func_dir(struct users *u);
int func_mkdir(struct users *u);
int func_pwd();
int func_rmdir(struct users *u);
int func_cd(struct users *u);
int func_rename(struct users *u);
int func_write();
int func_delete();
int func_format();
int func_delete_file(struct users *u);

#define HW_ID_LEN 70
#define PID_LEN		70
#define STARTUP_CONFIG  VFS_TMP_PATH"/startup-config"
#define KERNEL_PATH	"/dev/mtdblock1"
#define IOS MODULE".bin"
#define PATH "/tmp/"IOS
#define LOCAL_FILE "/tmp/tmp_vfs_file"
#define VFS_ROOT "/tmp/vfs_root"	
#define SHOW_RUNNING_FILE "/tmp/current_config"
#define SHOW_STARTUP_FILE "/tmp/vfs_root/startup_config"

typedef unsigned char	u_int8_t;

extern int SYSTEM(const char *format, ...);

extern int readFileBin(char *path, char **data);
extern void writeFileBin(char *path, char *data, int len);

typedef struct{
    u_int8_t	magic_s[7];	/* FeiXunB */
    u_int8_t	ver_control[2];	/* version control */
    u_int8_t	download[2];	/* download control */
    u_int8_t	hw_id[32];  	/* H/W ID */ 
    u_int8_t	hw_ver[2];  	/* H/W version */
    u_int8_t	p_id[4];    	/* Product ID */
    u_int8_t	protocol_id[2];	/* Protocol ID */	
    u_int8_t	fun_id[2];	/* Function ID */
    unsigned long strlen;	/* File length */
    u_int8_t	fw_ver[2];	/* F/W version */
    u_int8_t	start[2];	/* Starting code segment */
    u_int8_t	c_size[2];	/* Code size (kbytes) */
    u_int8_t	magic_e[7];	/* ONet */
}product_pid_t;

#endif

