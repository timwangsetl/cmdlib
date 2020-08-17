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
#include <sys/file.h>
#include <syslog.h>
#include <termios.h>

#include <arpa/inet.h>

#include "console.h"
#include "cmdparse.h"
#include "parameter.h"


#include "cli_filesys_func.h"

#include "cli_filesys.h"

static struct topcmds filesys_topcmds[] = {
	{ "cd", 0, ENA_TREE, do_cd, NULL, NULL, 0, 0, 0,
		"Change directory", "改变目录" },
	{ "copy", 0, ENA_TREE, do_copy, NULL, NULL, 0, 0, 0,
		"Copy configuration or image data", "复制配置或镜像文件" },
	{ "delete", 0, ENA_TREE, do_delete, NULL, NULL, 0, 0, 0,
		"Delete a file", "删除文件" },
	{ "dir", 0, ENA_TREE, do_dir, NULL, NULL, 1, 0, 0,
		"List files in flash memory", "显示闪存里文件" },
	{ "format", 0, ENA_TREE, do_format, NULL, NULL, 1, 0, 0,
		"Format file system", "格式化文件系统" },
	{ "md", 0, ENA_TREE, do_md, NULL, NULL, 0, 0, 0,
		"Create directory", "创建目录" },
	{ "pwd", 0, ENA_TREE, do_pwd, NULL, NULL, 1, 0, 0,
		"Display current directory", "显示当前目录路径" },
	{ "rd", 0, ENA_TREE, do_rd, NULL, NULL, 0, 0, 0,
		"Delete a directory", "删除目录" },
	{ "rename", 0, ENA_TREE, do_mv, NULL, NULL, 0, 0, 0,
		"Rename a file", "重命名" },
	{ "write", 0, ENA_TREE, do_write, NULL, NULL, 1, 0, 0,
		"Save current configuration", "保存当前配置" },
	{ TOPCMDS_END },
};

static struct cmds cd[] = {
	{ "..", CLI_CMD, 0, 0, do_cd_dir, NULL, NULL, 1, 0, 0,
		"the immediately higher level", "上一级目录" },
	{ "WORD", CLI_WORD, 0, 0, do_cd_dir, NULL, NULL, 1, 0, 0,
		"directory name", "目录名" },		
	{ CMDS_END },	
};

static struct cmds rd[] = {
	{ "WORD", CLI_WORD, 0, 0, do_rd_dir, NULL, NULL, 1, 0, 0,
		"directory name", "目录名" },		
	{ CMDS_END },	
};

static struct cmds md[] = {
	{ "WORD", CLI_WORD, 0, 0, do_md_dir, NULL, NULL, 1, 0, 0,
		"directory name", "目录名" },		
	{ CMDS_END },	
};

static struct cmds delete[] = {
	{ "WORD", CLI_WORD, 0, 0, do_delete_file, NULL, NULL, 1, 0, 0,
		"file name", "文件名" },
	{ "<cr>", CLI_CMD, 0, 0, NULL, NULL, NULL, 1, 0, 0,
		"delete startup-config", "删除配置文件" },		
	{ CMDS_END },	
};

static struct cmds dir[] = {
	{ "WORD", CLI_WORD, 0, 0, do_dir_dir, NULL, NULL, 1, 0, 0,
		"directory name", "目录名" },	
	{ CMDS_END },	
};

static struct cmds mv[] = {
	{ "WORD", CLI_WORD, 0, 0, do_mv_file, NULL, NULL, 1, 0, 0,
		"old file name", "原文件名" },	
	{ CMDS_END },	
};


// -----------------------------------------------------------------------------
// copy
static struct cmds copy_src_cmds[] = {
	{ "flash:", CLI_CMD_NO_BLANK, 0, COPY_SRC_FLASH, do_copy_src_flash, NULL, NULL, CLI_END_NONE, 0, 0,
		"Copy file from system flash memory", "从 flash 里复制文件" },
	{ "startup-config", CLI_CMD, 0, COPY_SRC_START, do_copy_src_start, NULL, NULL, CLI_END_NONE, 0, 0,
		"Copy startup configuration file", "拷贝系统配置文件" },	
	{ "tftp:", CLI_CMD_NO_BLANK, 0, COPY_SRC_TFTP, do_copy_src_tftp, NULL, NULL, CLI_END_NONE, 0, 0,
		"Copy file from tftp server", "从 tftp 里复制文件" },	
	{ CMDS_END },	
};

#if 1
static struct cmds *copy_src_name_cmds = NULL;

static struct cmds copy_src_tftp_cmds[] = {
	{ "WORD", CLI_WORD, 0, 0, do_copy_src_name, NULL, NULL, CLI_END_NONE, 0, 0,
		"The source file name", "源文件名" },	
	{ CMDS_END }
};
#endif

static struct cmds copy_dst_cmds[] = {
	{ "flash:", CLI_CMD_NO_BLANK, 0, COPY_DST_FLASH, do_copy_dst_flash, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Copy file to system flash memory", "到 flash " },	
	{ "tftp:", CLI_CMD_NO_BLANK , 0, COPY_DST_TFTP, do_copy_dst_tftp, NULL, NULL, CLI_END_FLAG, 0, 0,
		"Copy file from tftp server", "到 tftp " },	
	{ CMDS_END },	
};

#if 1
static struct cmds *copy_dst_name_cmds = NULL;

static struct cmds copy_dst_tftp_cmds[] = {
	{ "WORD", CLI_WORD, 0, 0, do_copy_dst_name, NULL, NULL, CLI_END_FLAG, 0, 0,
		"The destination file name", "目标文件名" },
	{ CMDS_END }
};
#endif

//  <end>***********************************************************************

static int do_cd(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(cd, argc, argv, u);

	return retval;  
} 

static int do_cd_dir(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2( argc, argv, u);
	if (!retval) {
		/* Do application function */
	//	do_test_param(argc, argv, u);
		
		if ( argv[0][0] == '.' && (argv[0][1] == '\0' || argv[0][1] == '.')) {
			func_cd(NULL);
		} else {
			func_cd(u);
		}
	}

    return retval;
} 

// 
static int do_pwd(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if (!retval) {
		/* Do application function */
		//do_test_param(argc, argv, u);
		func_pwd();
	}
    
    return retval;    
} 

// remove directory 
static int do_rd(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(rd, argc, argv, u);

	return retval;  
} 


static int do_rd_dir(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2( argc, argv, u);
	if (!retval) {
		/* Do application function */
		//do_test_param(argc, argv, u);
		func_rmdir(u);
	}
    
    return retval;    
} 

// create directory
static int do_md(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(md, argc, argv, u);

	return retval;  
} 


static int do_md_dir(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if (!retval) {
		/* Do application function */
	//	do_test_param(argc, argv, u);
		func_mkdir(u);
	}

    return retval;    
} 

// delete file
static int do_delete(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((argc - u->args_offset) == 0)
	{
		/* Do application function */
		//do_test_param(argc, argv, u);
		func_delete();

		SET_CMD_ST(u, CMD_ST_END);
	}

	retval = sub_cmdparse(delete, argc, argv, u);

	return retval;  
} 

static int do_delete_file(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if (!retval) {
		/* Do application function */
		//do_test_param(argc, argv, u);
		func_delete_file(u);
	}

    return retval;    
} 

// list directory content
static int do_dir(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* Do application function */
		func_dir(u);

		return retval;  
	}
	
	retval = sub_cmdparse(dir, argc, argv, u);

	return retval;  
} 

static int do_dir_dir(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if (!retval) {
		/* Do application function */
		func_dir(u);
	//	do_test_param(argc, argv, u);
	}

    return retval;    
} 

// format file system
static int do_format(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if (!retval) {
		//do_test_param(argc, argv, u);
		func_format();
	}
    
    return retval;    
} 

// save running config to nvram
static int do_write(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = cmdend2(argc, argv, u);
	if (!retval) {
		/* Do application function */
		//do_test_param(argc, argv, u);
		func_write();
	}
    
    return retval;    
} 

// rename file or directory
static int do_mv(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	retval = sub_cmdparse(mv, argc, argv, u);

	return retval;  
} 


static int do_mv_file(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	struct parameter param;
	memset(&param, 0, sizeof(struct parameter));

	/* Init paramter struct */
	param.type = CLI_WORD;
	param.name = "WORD";
	param.ylabel = "new file name";
    param.hlabel = "新文件名";
	param.flag = 1;

	/* Get next parameter value */
	if((retval = getparameter(argc, argv, u, &param)) != 0)
		return retval;

	/* Restore the paramter to u->d_param struct */
	cli_param_set_string(DYNAMIC_PARAM, 0, param.value.v_string, u);

	/* Check command end or not */
	retval = cmdend2(argc, argv, u);
	if(retval == 0) 
	{
		/* Do application function */
		//do_test_param(argc, argv, u);
		func_rename(u);
	}

	return retval;
}


static int do_copy(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if(ISSET_CMD_ST(u, CMD_ST_BLOCK))
	{
		char src_file[MAX_ARGV_LEN] = {'\0'};
		char dst_file[MAX_ARGV_LEN] = {'\0'};
		
		struct parameter param;
		memset(&param, 0, sizeof(struct parameter));
		
		if(!ISSET_CMD_MSKBIT(u, COPY_REMOTE_IP))
		{
			SET_CMD_MSKBIT(u, COPY_REMOTE_IP);

			/* parameter type */
			param.type = CLI_IPV4;
			if((retval = getparameter(argc, argv, u, &param)) != 0)
			{
				CLEAR_CMD_ST(u, CMD_ST_BLOCK);
				return -1;
			}
			
			/* Record remote ip */
			cli_param_set(DYNAMIC_PARAM, &param, u);

			if(!ISSET_CMD_MSKBIT(u, COPY_SRC_START)) {
				/* next prompt */
				cli_param_get_string(STATIC_PARAM, 0, src_file, u);	
				prompt_output(u, "Source filename [%s]? ", src_file);
			}
			else
			{
				strcpy(src_file, "startup_config");
				cli_param_set_string(STATIC_PARAM, 0, src_file, u);
				cli_param_set_string(DYNAMIC_PARAM, 0, src_file, u);
				
				cli_param_get_string(STATIC_PARAM, 1, dst_file, u);
				prompt_output(u, "Destination filename [%s]? ", ((strlen(dst_file) != 0)? dst_file: src_file));
			}
			return 0;
		}
		
		if((!ISSET_CMD_MSKBIT(u, COPY_SRC_FILE)) && (!ISSET_CMD_MSKBIT(u, COPY_SRC_START)))
		{
			SET_CMD_MSKBIT(u, COPY_SRC_FILE);

			/* get src file name */
			cli_param_get_string(STATIC_PARAM, 0, src_file, u);
			
			if(argc == 1)
			{
				/* no src file */
				if(strlen(src_file) == 0)
				{
					CLEAR_CMD_ST(u, CMD_ST_BLOCK);
					return -1;
				}
				
				/* invalid <cr> */
				cli_param_set_string(DYNAMIC_PARAM, 0, src_file, u);
			}
			else
			{
				/* parameter type */
				param.type = CLI_WORD;
				
				/* get the input string */
				if((retval = getparameter(argc, argv, u, &param)) != 0)
				{
					CLEAR_CMD_ST(u, CMD_ST_BLOCK);
					return -1;
				}

				/* Record src filename */
				cli_param_set_string(DYNAMIC_PARAM, 0, param.value.v_string, u);

				/* Get src file name */
				cli_param_get_string(DYNAMIC_PARAM, 0, src_file, u);
				
			}
							
			
			/* next prompt */
			cli_param_get_string(STATIC_PARAM, 1, dst_file, u);
			prompt_output(u, "Destination filename [%s]? ", ((strlen(dst_file) != 0)? dst_file: src_file));
			
			return 0;
		}

		if(!ISSET_CMD_MSKBIT(u, COPY_DST_FILE))
		{
			SET_CMD_MSKBIT(u, COPY_DST_FILE);

			/* get dst file name */
			cli_param_get_string(STATIC_PARAM, 1, dst_file, u);
			
			/* dst filename is empty, get src filename */
			if(strlen(dst_file) == 0)
				cli_param_get_string(DYNAMIC_PARAM, 0, dst_file, u);
			
			if(argc == 1)
			{
				/* invalid <cr> */
				cli_param_set_string(DYNAMIC_PARAM, 1, dst_file, u);
			}
			else
			{
				/* parameter type */
				param.type = CLI_WORD;
				
				/* get the input string */
				if((retval = getparameter(argc, argv, u, &param)) != 0)
				{
					CLEAR_CMD_ST(u, CMD_ST_BLOCK);
					return -1;
				}
				
				/* Record dst filename */
				cli_param_set_string(DYNAMIC_PARAM, 1, param.value.v_string, u);
			}

			func_copy(u);
			
		}

		//do_test_param(argc, argv, u);
		CLEAR_CMD_ST(u, CMD_ST_BLOCK);

		return 0;
	}
	else
		retval = sub_cmdparse(copy_src_cmds, argc, argv, u);

	return retval;  
} 

static int do_copy_src_flash(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* mask destination flash */
	SET_CMD_MSKBIT(u, COPY_DST_FLASH);

	if(*argv[0] == '\0')
	{
		/* args offset */
		argc --;	argv ++;
		
		/* parse next sub cmds */
		retval = sub_cmdparse(copy_dst_cmds, argc, argv, u);
	}
	else
	{
		copy_src_name_cmds = cli_filesys_init_filename_cmds(COPY_SRC_WORD);
		
		retval = sub_cmdparse(copy_src_name_cmds, argc, argv, u);

		free(copy_src_name_cmds->name);
		free(copy_src_name_cmds);
	}
	
	return retval;
}

static int do_copy_src_start(int argc, char *argv[], struct users *u)
{
	int retval = -1;
	
	/* mask destination flash */
	SET_CMD_MSKBIT(u, COPY_DST_FLASH);
	
	retval = sub_cmdparse(copy_dst_cmds, argc, argv, u);

	return retval;
}

static int do_copy_src_tftp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* mask destination tftp */
	SET_CMD_MSKBIT(u, COPY_DST_TFTP);
	
	if(*argv[0] == '\0')
	{
		/* args offset */
		argc --;	argv ++;

		/* parse next sub cmds */
		retval = sub_cmdparse(copy_dst_cmds, argc, argv, u);
	}
	else
		retval = sub_cmdparse(copy_src_tftp_cmds, argc, argv, u);
	
	return retval;
}

int do_copy_src_name(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Record src filename */
	cli_param_set_string(STATIC_PARAM, 0, argv[0], u);

	retval = sub_cmdparse(copy_dst_cmds, argc, argv, u);
	
	return retval;
}

static int do_copy_dst_flash(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if(*argv[0] == '\0')
	{
		/* args offset */
		argc --;	argv ++;

		if((retval = cmdend2(argc, argv, u)) == 0)
		{
			/* set cmd_st block status */
			SET_CMD_ST(u, CMD_ST_BLOCK);

			/* custom promptbuf */		
			prompt_output(u, "Address or name of remote host []? ");		
		}
	}
	else
	{
		copy_dst_name_cmds = cli_filesys_init_filename_cmds(COPY_DST_WORD);
		
		retval = sub_cmdparse(copy_dst_name_cmds, argc, argv, u);

		free(copy_dst_name_cmds->name);
		free(copy_dst_name_cmds);
	}
	
	return retval;
}

static int do_copy_dst_tftp(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	if(*argv[0] == '\0')
	{
 
		/* args offset */
		argc --;	argv ++;

		if((retval = cmdend2(argc, argv, u)) == 0)
		{ 
			/* set cmd_st block status */
			SET_CMD_ST(u, CMD_ST_BLOCK);

			/* custom promptbuf */
			prompt_output(u, "Address or name of remote host []? ");
		}
        
	}
	else
		retval = sub_cmdparse(copy_dst_tftp_cmds, argc, argv, u);        
	
	return retval;
}

int do_copy_dst_name(int argc, char *argv[], struct users *u)
{
	int retval = -1;

	/* Record dst filename */
	cli_param_set_string(STATIC_PARAM, 1, argv[0], u);

	if((retval = cmdend2(argc, argv, u)) == 0)
	{
		/* set cmd_st block status */
		SET_CMD_ST(u, CMD_ST_BLOCK);

		/* custom promptbuf */
		prompt_output(u, "Address or name of remote host []? ");
	}
	
	return retval;
}

int init_cli_filesys(void)
{
	int retval = -1;

	retval = registerncmd(filesys_topcmds, (sizeof(filesys_topcmds)/sizeof(struct topcmds) - 1));
	DEBUG_MSG(1, "init_cli_filesys retval = %d\n", retval);

	return retval;
}


