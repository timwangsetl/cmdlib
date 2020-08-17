#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/stat.h>
#include <net/if.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/file.h>
#include <syslog.h>
#include <termios.h>

#include <arpa/inet.h>

#include "console.h"
#include "cmdparse.h"
#include "parameter.h"

#include "cli_filesys_func.h"
#include "nvram.h"


extern int do_copy_src_name(int argc, char *argv[], struct users *u);
extern int do_copy_dst_name(int argc, char *argv[], struct users *u);


extern int  create_startup_config();
extern int nvram_running_commit();
extern int nvram_commit2(char *path);

int vfs_commit()
{
    return 0;
}

static ssize_t read_context(const char *path, char *buf, ssize_t size) 
{
	if (!buf)
		return -1;
	
	if (access(path, F_OK)) {
		writeFileBin("/tmp/vfs_pwd", VFS_ROOT, strlen(VFS_ROOT));	
	}
		
	FILE *fp = fopen(path, "r+");
	if (fp == NULL) {
		vty_output("path: %s, errno = %d\n", path, errno);
		return -1;
	}

	size = fread(buf, 1, size, fp);

	if (size < 0) {
		
		return -1;
	}

	fclose(fp);

	for ( size = 0; *buf; buf++, size++) {
		if (*buf == ' ')
			*buf = '\0';
	}
	
	return size;
}


static int creat_fake_image_link()
{
	DIR *dp = NULL;
	struct dirent *dirp = NULL;
	struct stat  dstat;
	int flag = 0;
	
	chdir(VFS_ROOT);
	
	if ((dp = opendir(VFS_ROOT)) == NULL) {
		vty_output("can't open file system \n");
		return -1;
	}
	
	while ((dirp = readdir(dp)) != NULL) {
		if (dirp->d_name[0] == '.')
			continue;

		lstat(dirp->d_name, &dstat);
		if (S_ISLNK(dstat.st_mode)){
			flag = 1;
		}
	}

	if (!flag) {
		system("ln -fs /tmp/tmp_img "IOS);
	}
	
	closedir(dp);
	return 0;
}

// return count: file count;
// name = filename1 '\0' filename2 '\0' ...
static int get_filename(char *name)
{
	DIR *dp = NULL;
	int count = 0;
	struct dirent *dirp = NULL;
	struct stat dstat; 
	char *p = name; 
	int fd;

	if (!name) {
		return -1;
	}

	if (creat_fake_image_link())
		return -1;

	fd = open(".", O_RDONLY);
	if (fd < 0) {
		perror("open");
		return -1;
	}

	chdir(VFS_ROOT);
	if ((dp = opendir(VFS_ROOT)) == NULL) {
		vty_output("Can't open filesystem, please reboot and try again.\n");
		return -1;
	}

	while ((dirp = readdir(dp)) != NULL) {
		if (dirp->d_name[0] == '.')
			continue;

		lstat(dirp->d_name, &dstat);
		if (S_ISDIR(dstat.st_mode))
			continue;

		memcpy(p, dirp->d_name, strlen(dirp->d_name));
		p += strlen(p);
		p++;		
		count++;
	}	

	fchdir(fd);
	close(fd);
	
	return count;
}

struct cmds *cli_filesys_init_filename_cmds(int type)
{
	int i = 0, count = 0;
	char *name; 
	char *p = NULL;

	name = (char *)calloc(sizeof(char), 256); 
	if (!name) {
		vty_output("error, unable to alloc memory.\n");
		return NULL;
	}

	count = get_filename(name);
	if (count == -1) {
		free(name);
		return NULL;
	}

	struct cmds *sub_cmds = NULL;	
	struct cmds *cmds_ptr = NULL;

	sub_cmds = (struct cmds *)malloc((count+1)*sizeof(struct cmds));
	if(!sub_cmds) {
		free(name);
		return NULL;
	}
	memset(sub_cmds, '\0', (count+1)*sizeof(struct cmds));

	for (cmds_ptr = sub_cmds, p = name;
			i < count; cmds_ptr++, i++, p += strlen(p) + 1) {
		cmds_ptr->name = p;
		cmds_ptr->matchmode = CLI_CMD;
		cmds_ptr->pv_level = 0;

		if(type == COPY_SRC_WORD){
	 	cmds_ptr->func = do_copy_src_name; 
			cmds_ptr->end_flag = CLI_END_NONE;
		} else if(type == COPY_DST_WORD){
		   cmds_ptr->func = do_copy_dst_name; 
			cmds_ptr->end_flag = CLI_END_FLAG;
		}

		cmds_ptr->nopref = NULL;
		cmds_ptr->defpref = NULL;
		cmds_ptr->yhp = NULL;
		cmds_ptr->hhp = NULL;
	}

	/* CMDS_END */
	cmds_ptr->name = NULL;

	return sub_cmds;
	
}

int func_copy(struct users *u)
{
	struct in_addr s;
	struct stat dstat;
	FILE *fp;
	int img_len = 0;
	int len;
	char ip_addr[MAX_ARGV_LEN] = {'\0'};
	char src_file[MAX_ARGV_LEN] = {'\0'};
	char dst_file[MAX_ARGV_LEN] = {'\0'};
	char *lan_ipaddr = nvram_safe_get("lan_ipaddr");
	char *ip_staticip_enable = nvram_safe_get("ip_staticip_enable");

	if(strlen(lan_ipaddr) == 0 && *ip_staticip_enable == '1') {
		printf("Please set ip address first\n");
		free(lan_ipaddr);
		free(ip_staticip_enable);
		return -1;
	}
	free(lan_ipaddr);
	free(ip_staticip_enable);

	memset(&s, '\0', sizeof(struct in_addr));
	cli_param_get_ipv4(DYNAMIC_PARAM, 0, &s, ip_addr, sizeof(ip_addr), u);

	cli_param_get_string(DYNAMIC_PARAM, 0, src_file, u);
	cli_param_get_string(DYNAMIC_PARAM, 1, dst_file, u);

	if((ISSET_CMD_MSKBIT(u, COPY_SRC_FLASH)) && (!ISSET_CMD_MSKBIT(u, COPY_SRC_START)))		/* copy flash:src_file tftp:dst_file ip_addr */
	{
		if(ISSET_CMD_MSKBIT(u, COPY_DST_TFTP))
		{
			int ret = -1;
			char buf[256] = {0};
			get_filename(buf);
			char *ptr = buf;
			while (*ptr) {
				if (!strcasecmp(ptr, src_file)) {
					strcpy(src_file, ptr);
					ret = 0;
					break;
				}
				ptr += strlen(ptr) + 1;
			}

			chdir(VFS_ROOT);
			lstat(src_file, &dstat);
			if (S_ISLNK(dstat.st_mode)) {
				{
					printf("please wait...\n");
					SYSTEM("cat /dev/mtdblock0 /dev/mtdblock1 /dev/mtdblock2  > /tmp/tmp_img");
					SYSTEM("tftp -p -r %s -l /tmp/tmp_img %s", dst_file, ip_addr);
					unlink("/tmp/tmp_img");
					vty_output("finish.\n");
				}
			} else {
				if (ret) {
					vty_output("%s not exist.\n", src_file);
					return -1;
				}

				vty_output("please wait...\n");
						
				SYSTEM("tftp -p -r %s -l /tmp/vfs_root/%s %s", dst_file, src_file, ip_addr);
			
				vty_output("finish.\n"); 
			}
		}
		else
			DEBUG_MSG(1, "Unknow source!!\n", NULL);
	}
	else if(ISSET_CMD_MSKBIT(u, COPY_SRC_START))		/* copy startup_config tftp:dst_file ip_addr */
	{
		if(ISSET_CMD_MSKBIT(u, COPY_DST_TFTP))
		{
			chdir(VFS_TMP_PATH);
		    func_show_startup();
		    
			vty_output("please wait...\n");
					
			SYSTEM("tftp -p -r %s -l /tmp/vfs_root/%s %s", dst_file, src_file, ip_addr);
		
			vty_output("finish.\n");
		}
	}
	else if(ISSET_CMD_MSKBIT(u, COPY_SRC_TFTP))		/* copy tftp:src_file flash:dst_file ip_addr */
	{
		if(ISSET_CMD_MSKBIT(u, COPY_DST_FLASH))
		{
			chdir(VFS_ROOT);
			lstat(src_file, &dstat);
			printf("please wait...\n");           
			SYSTEM("tftp -g -r %s -l %s %s", src_file, LOCAL_FILE, ip_addr);

			int fd;
			fd = open(LOCAL_FILE, O_RDONLY);
			if (fd < 0) {
				return -1;
			}

			len = lseek(fd, 0, SEEK_END);
			close(fd);
			
			if (len < 1) {
				printf("get data from tftp server failed.\n");
				unlink(LOCAL_FILE);	 
				return -1;
			}
		
			if (len > 64*1024) {
				/* Jialong, 2012.4.12 */
				printf("It is very dangerous to update IOS, are you sure(y/n)? ");
				char ch;
				pid_t pid;
				while((ch = getc(stdin)) == ' ');
				printf("\n");

				if (ch == 'Y' || ch == 'y') {
					syslog(LOG_NOTICE, "[CONFIG-5-UPDATE]: update system, %s\n", getenv("LOGIN_LOG_MESSAGE"));
					if ((pid = fork()) == 0) {
						SYSTEM("/usr/sbin/upgrade %s", LOCAL_FILE);
						exit(0);
					}
					waitpid (pid, NULL, 0);
				} else
					unlink(LOCAL_FILE);
			} else {
				SYSTEM("cp -rf %s /tmp/vfs_root/%s", LOCAL_FILE, dst_file);
				vfs_commit();
				printf("finish.\n"); 
				printf("Commit succeed, if you want to enable the configuration, reboot first!\n");
				unlink(LOCAL_FILE);  
		   }
		} 
		else
			DEBUG_MSG(1, "Invalid destination!!\n", NULL);
	}
	else
		DEBUG_MSG(1, "Unknow source!!\n", NULL);

	return 0;   
}


static int vfs_dir(const char *name)
{
	DIR *dp = NULL;
	struct dirent *dirp = NULL;
	struct stat  dstat;
	int total;
	char *pwd = calloc(1, 256);
	char *p = NULL;
	int fd=0;
	const char *root = VFS_ROOT;
	char fullname[0x100] = {0};
	char *file_type = NULL;
	char 	datestring[0x100] = {0};
	int flag = 0;
	
	total = read_context("/tmp/vfs_pwd", pwd, 0x100);
	if (total == -1) {
		vty_output("_____error\n");
		return -1;
	}
	
	if (!strncmp(pwd, root, strlen(root))) {
		p = pwd + strlen(root);
		if (*p != '\0' && *p != '/') {
			free(pwd);
			pwd = calloc(1, strlen(root) + 1);
			if(pwd == NULL)
				return -1;
			strcpy(pwd, root);
			writeFileBin("/tmp/vfs_pwd", pwd, strlen(pwd));				
		}
	} else {
		free(pwd);
		pwd = calloc(1, strlen(root) + 1);
		if(pwd == NULL)
			return -1;
		strcpy(pwd, root);
		writeFileBin("/tmp/vfs_pwd", pwd, strlen(pwd));	
	}
	
	chdir(pwd);
	
	if (!(strlen(name) == 1 && name[0] == '.')) {
		if (name[1] == '.') {
			vty_output("invalid name: %s\n", name);
			free(pwd);
			return -1;
		}
		p = pwd + strlen(pwd);
			
		if (name[0] == '/') {
			sprintf(pwd, "%s%s",pwd, name);
		} else {
			sprintf(pwd, "%s/%s",pwd, name);
		}
	}
		
	if ((dp = opendir(pwd)) == NULL) {
		p = pwd + strlen(root);
		vty_output("can't open %s \n", p);
		
		free(pwd);
		return -1;
	}
	
	if((fd=open("/dev/mtdblock2", O_RDONLY)) < 0)
	   	return -1;
	total = lseek(fd,0,SEEK_END);
	close(fd);
	if((fd=open("/dev/mtdblock1", O_RDONLY)) < 0)
	   	return -1;
	total += lseek(fd,0,SEEK_END);
	close(fd);
	
	vty_output("%-10s%-10s%-20s%-10s\n", "type", "size", "time", "name");
	vty_output("---------------------------------------------\n");
	while ((dirp = readdir(dp)) != NULL) {
		if (dirp->d_name[0] == '.')
			continue;

		sprintf(fullname, "%s/%s", pwd, dirp->d_name);
		lstat(fullname, &dstat);
		if (S_ISDIR(dstat.st_mode)) {
			file_type = "directory";
		} else if (S_ISREG(dstat.st_mode)) {
			file_type = "file";
		} else if (S_ISLNK(dstat.st_mode)){
			flag = 1;
			file_type = "file";
		}

		strftime(datestring, 30, "%Y-%m-%d %H:%M", localtime(&dstat.st_ctime));
		if (S_ISLNK(dstat.st_mode))
			vty_output("%-10s%-10d%-20s%-10s\n", file_type, total,datestring, dirp->d_name);
		else
			vty_output("%-10s%-10d%-20s%-10s\n", file_type, dstat.st_size,datestring, dirp->d_name);
	}
	if(!flag && !strcmp(pwd, root)) {
		system("ln -fs /tmp/tmp_img "IOS);
		vty_output("%-10s%-10d%-20s%-10s\n", "file", total, datestring, IOS);
	}
	
	closedir(dp);
	free(pwd);
	return 0;
}

int func_dir(struct users *u)
{
	char dir[MAX_ARGV_LEN] = {'\0'};
	
	cli_param_get_string(STATIC_PARAM, 0, dir, u);
	if(strlen(dir) == 0)
		strcpy(dir, ".");
	vfs_dir(dir);
	
	return 0;
}


int func_mkdir(struct users *u)
{
	char *pwd = calloc(1, 256);
	char *p = NULL;
	const char *root = VFS_TMP_PATH;
	int ret, size;
	char name[MAX_ARGV_LEN] = {'\0'};

	cli_param_get_string(STATIC_PARAM, 0, name, u);

	size = read_context("/tmp/vfs_pwd", pwd, 0x100);
	if (size == -1) {
		vty_output("_____error\n");
		return -1;
	}

	if (!strncmp(pwd, root, strlen(root))) {
		p = pwd + strlen(root);
		if (*p != '\0' && *p != '/') {
			free(pwd);
			pwd = calloc(1, strlen(root) + 1);
			if(pwd == NULL)
				return -1;
			strcpy(pwd, root);
			writeFileBin("/tmp/vfs_pwd", pwd, strlen(pwd));				
		}
	} else {
		free(pwd);
		pwd = calloc(1, strlen(root) + 1);
		if(pwd == NULL)
			return -1;
		strcpy(pwd, root);
		writeFileBin("/tmp/vfs_pwd", pwd, strlen(pwd));	
	}

	chdir(pwd);

	if (strchr(name, '/') || strchr(name, '-') || strchr(name, '~') || strchr(name, '.')) {
		fprintf(stdout, "invalid directory name.\n");
		return -1;
	}

	ret = mkdir(name, 0755);
	
	if (ret) {
		vty_output("unable to create directory : %s, please check name has existed!\n", name);
	}

	free(pwd);
	vfs_commit();
	return ret;
}

int func_pwd()
{
	char *pwd = calloc(1, 256);
	char *p = NULL;
	int size;
	char *root = VFS_TMP_PATH;

	size = read_context("/tmp/vfs_pwd", pwd, 0x100);
	if (size == -1) {
		vty_output("_____error\n");
		return -1;
	}

	if (!strncmp(pwd, root, strlen(root))) {
		p = pwd + strlen(root);
		if (*p != '\0' && *p != '/') {
			free(pwd);
			pwd = calloc(1, strlen(root) + 1);
			if(pwd == NULL)
				return -1;
			strcpy(pwd, root);
			writeFileBin("/tmp/vfs_pwd", pwd, strlen(pwd));				
		}
	} else {
		free(pwd);
		pwd = calloc(1, strlen(root) + 1);
		if(pwd == NULL)
			return -1;
		strcpy(pwd, root);
		writeFileBin("/tmp/vfs_pwd", pwd, strlen(pwd));	
	}

	p = pwd + strlen(root);

	if (!*p) {
		p = "/";
	}

	vty_output("%s\n", p);

	free(pwd);
	return 0;
}

int func_rmdir(struct users *u)
{
	char *pwd = calloc(1, 256);
	char *p = NULL;
	const char *root = VFS_TMP_PATH;
	char fullname[0x100] = {0};
	char name[MAX_ARGV_LEN] = {'\0'};
	int size;

	size = read_context("/tmp/vfs_pwd", pwd, 0x100);
	if (size == -1) {
		vty_output("_____error\n");
		return -1;
	}

	cli_param_get_string(STATIC_PARAM, 0, name, u);

	if (!strncmp(pwd, root, strlen(root))) {
		p = pwd + strlen(root);
		if (*p != '\0' && *p != '/') {
			free(pwd);
			pwd = calloc(1, strlen(root) + 1);
			if(pwd == NULL)
				return -1;
			strcpy(pwd, root);
			writeFileBin("/tmp/vfs_pwd", pwd, strlen(pwd));				
		}
	} else {
		free(pwd);
		pwd = calloc(1, strlen(root) + 1);
		if(pwd == NULL)
			return -1;
		strcpy(pwd, root);
		writeFileBin("/tmp/vfs_pwd", pwd, strlen(pwd));	
	}

	chdir(pwd);

	if ((!strncmp(name, "..", 2) && !strcmp(pwd, root))
			|| strstr(name,  "/.") || strchr(name, '~') || strchr(name, '-')){
		vty_output("unable to remove %s.\n", name);
		return -1;
	}

	if (name[0] == '/') {
		sprintf(fullname, "%s%s", pwd, name);
		rmdir(fullname);
	} else {
		rmdir(name);
	}

	free(pwd);

	vfs_commit();
		
	return 0;
}

int func_cd(struct users *u)
{
	DIR *dp;
	char *pwd = calloc(1, 256);
	char *p = NULL;
	int size;
	const char *root = VFS_TMP_PATH;
	char path[0x100] = {0};

	char name[MAX_ARGV_LEN] = {'\0'};
	
	//readFileBin("/tmp/vfs_pwd", &pwd);
	size = read_context("/tmp/vfs_pwd", pwd, 0x100);
	if (size == -1) {
		vty_output("_____error\n");
		return -1;
	}
	
	if (u)
		cli_param_get_string(STATIC_PARAM, 0, name, u);
	else 
		strcpy(name, "..");

	if (!strncmp(pwd, root, strlen(root))) {
		p = pwd + strlen(root);
		if (*p != '\0' && *p != '/') {
			free(pwd);
			pwd = calloc(1, strlen(root) + 1);
			if(pwd == NULL)
				return -1;
			strcpy(pwd, root);
			writeFileBin("/tmp/vfs_pwd", pwd, strlen(pwd));				
		}
	} else {
		free(pwd);
		pwd = calloc(1, strlen(root) + 1);
		if(pwd == NULL)
			return -1;
		strcpy(pwd, root);
		writeFileBin("/tmp/vfs_pwd", pwd, strlen(pwd));	
	}
	
//	printf("pwd = %s, name = %s\n", pwd, name);
	if (!strcmp(name, "..")) {
		if (!strcmp(pwd, root)) {
				vty_output("current position is the root directoy.\n");
				return -1;
		}

		strcpy(path, pwd);

		p = strrchr(path, '/');
		*p = '\0';
	} else {
		if (strchr(name, '.')) {
			vty_output("invalid directory name : %s\n", name);
			return -1;
		}

		if (name[0] == '/') {
			if (strlen(name) == 1) {
				sprintf(path, "%s", root);
			} else {
				sprintf(path, "%s%s", pwd, name);
			}			
		} else {
			sprintf(path, "%s/%s", pwd, name);
			if (name[strlen(name)-1] == '/') {
				path[strlen(path) -1] = '\0';
			}
		}
	}

	if ((dp = opendir(path)) == NULL) {
		p = path + strlen(root);
		vty_output("can't open %s\n", p);
		return -1;
	}

	free(pwd);
	closedir(dp);
	writeFileBin("/tmp/vfs_pwd", path, strlen(path));

	return 0;
}


int func_rename(struct users *u)
{
	char *pwd = calloc(1, 256);
	char *p = NULL;
	char *root = VFS_TMP_PATH;
	char path_src[0x100] = {0};
	char path_dst[0x100] = {0};
	int ret, size;
	char src[MAX_ARGV_LEN] = {'\0'};
	char dst[MAX_ARGV_LEN] = {'\0'};
	
	cli_param_get_string(STATIC_PARAM, 0, src, u);
	cli_param_get_string(DYNAMIC_PARAM, 0, dst, u);

	size = read_context("/tmp/vfs_pwd", pwd, 0x100);
	if (size == -1) {
		vty_output("_____error\n");
		return -1;
	}
	
	if (!strncmp(pwd, root, strlen(root))) {
		p = pwd + strlen(root);
		if (*p != '\0' && *p != '/') {
			free(pwd);
			pwd = calloc(1, strlen(root) + 1);
			if(pwd == NULL)
				return -1;
			strcpy(pwd, root);
			writeFileBin("/tmp/vfs_pwd", pwd, strlen(pwd));				
		}
	} else {
		free(pwd);
		pwd = calloc(1, strlen(root) + 1);
		if(pwd == NULL)
			return -1;
		strcpy(pwd, root);
		writeFileBin("/tmp/vfs_pwd", pwd, strlen(pwd));	
	}

	chdir(vfs_dir);

	if ((!strncmp(src, "..", 2) && !strcmp(pwd, root))
			|| strstr(src, "/.") || src[0] == '~' || src[0] == '-'){
		vty_output("invalid source directory.\n");
		return -1;
	}

	if ((!strncmp(dst, ".", 2) && !strcmp(pwd, root))
			|| strchr(dst, '/') || dst[0] == '~' || dst[0] == '-'){
			vty_output("invalid destination directory.\n");
		return -1;
	}
		
	if (src[0] == '/') {
		sprintf(path_src, "%s%s", pwd, src);
	} else {
		sprintf(path_src, "%s/%s", pwd, src);
	}

	if (dst[0] == '/') {
		sprintf(path_dst, "%s%s", pwd, dst);
	} else {
		sprintf(path_dst, "%s/%s", pwd, dst);
	}

	ret = rename(path_src, path_dst);
	if (ret) {
		fprintf(stderr, "rename error.\n");
	}
	
	free(pwd);
	vfs_commit();
	return  0;
}

int func_write()
{
	int ret;
	printf("Saving current configuration...\n");
	
	create_startup_config();
	
	ret = nvram_commit();

	if (!ret)
		printf("OK!\n");
	
//	ret = nvram_running_commit();

	return ret;
}

int func_delete()
{
	char ch;
    char * lo_ip=nvram_safe_get("lo_ip");

	printf("Are you sure to reset factory default(y/n)? ");
	while(1) {		
		ch = getc(stdin);		
		if(ch == ' ')
			continue;
		if( (ch == 'Y')||(ch == 'y') ) {
			printf("\n");
			unlink("/tmp/vfs_root/startup_config");	
            system("cp /etc/default /tmp/nvram");
#if (defined SZ56150M)   
            nvram_set("lo_ip", lo_ip); 
#endif 
            nvram_commit();

			printf("Commit succeed, if you want to enable the configuration, will reboot!\n");
			syslog(LOG_NOTICE, "[CONFIG-5-DELETE]: Restore factory default, %s\n", getenv("LOGIN_LOG_MESSAGE"));
	        //system("sleep 1 && echo reboot > /proc/watchdog && echo reboot > /proc/wtd &");
			system("sleep 1 && echo reboot > /proc/wtd &");

			break;
		} else {
			printf("\n");
			break;
		}
	}
	free(lo_ip);
	return 0;
}

int func_delete_file(struct users *u)
{
	char *pwd = NULL;
	char *p = NULL;
	char *root = VFS_TMP_PATH;
	char fullname[0x100] = {0};
	char name[MAX_ARGV_LEN] = {'\0'};
	cli_param_get_string(STATIC_PARAM, 0, name, u);
	struct stat  dstat;	
	
	readFileBin("/tmp/vfs_pwd", &pwd);

	if (!pwd) {
		pwd = calloc(1,strlen(root) + 1);
		if(pwd == NULL)
			return -1;
		strcpy(pwd, root);
		writeFileBin("/tmp/vfs_pwd", pwd, strlen(pwd));	
	}
	if (!strncmp(pwd, root, strlen(root))) {
		p = pwd + strlen(root);
		if (*p != '\0' && *p != '/') {
			free(pwd);
			pwd = calloc(1, strlen(root) + 1);
			if(pwd == NULL)
				return -1;
			strcpy(pwd, root);
			writeFileBin("/tmp/vfs_pwd", pwd, strlen(pwd));				
		}
	} else {
		free(pwd);
		pwd = calloc(1, strlen(root) + 1);
		if(pwd == NULL)
			return -1;
		strcpy(pwd, root);
		writeFileBin("/tmp/vfs_pwd", pwd, strlen(pwd));	
	}
	
	chdir(pwd);

	lstat(name, &dstat);
	if (S_ISLNK(dstat.st_mode)){
		vty_output("This is a system image, if you delete will cause the system not working properly !!!\n");
		return -1;
	}
		
	if ((!strncmp(name, "..", 2) && !strcmp(pwd, root))
			|| strstr(name,  "/.") || strchr(name, '~') || strchr(name, '-')){
		vty_output("unable to remove %s.\n", name);
		free(pwd);
		return -1;
	}

	if (name[0] == '/') {
		sprintf(fullname, "%s%s", pwd, name);
		remove(fullname);
	} else {
		remove(name);
	}

	free(pwd);
	vfs_commit();
		
	return 0;
}

int func_format()
{
	char vfs[0x40] = {0};
	char ch;

	printf("all files will be erased, are you sure(y/n)? ");
	while(1) {
		ch = getc(stdin);
		if(ch == ' ')
			continue;
		if((ch == 'Y')||(ch == 'y') ) {
			printf("\n");
			sprintf(vfs, "rm -rf %s/* >/dev/null 2>&1", VFS_TMP_PATH);
			system(vfs);
			nvram_commit2("/etc/default");
			printf("Format succeed!System has erased all files in current directory and will reboot,please wait......\n");
			kill(1,SIGTERM);
			break;
		}else {
			printf("\n");
			break;
		}
	}
	return 0;
}

