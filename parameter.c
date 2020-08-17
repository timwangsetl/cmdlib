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


struct cmds *cli_param2cmds(struct parameter *param_ptr)
{
	struct cmds *cmds_ptr = NULL;
	
	if(param_ptr == NULL)
		return NULL;
	
	if((cmds_ptr = (struct cmds *)malloc(sizeof(struct cmds))) == NULL)
	{
		DEBUG_MSG(1, "Error: cmds_ptr malloc failed!!\n", NULL);
		return NULL;
	}
	memset(cmds_ptr, '\0', sizeof(struct cmds));
	
	cmds_ptr->name = param_ptr->name;
	cmds_ptr->matchmode = param_ptr->type;
	cmds_ptr->argcmin = param_ptr->min;
	cmds_ptr->argcmax = param_ptr->max;
	cmds_ptr->yhp = param_ptr->ylabel;
	cmds_ptr->hhp = param_ptr->hlabel;
	cmds_ptr->end_flag = param_ptr->flag;
	
	return cmds_ptr;
}

struct parameter *cli_cmds2param(struct cmds *cmds_ptr)
{
	struct parameter *param_ptr = NULL;
	
	if(cmds_ptr == NULL)
		return NULL;
	
	if((param_ptr = (struct parameter *)malloc(sizeof(struct parameter))) == NULL)
	{
		DEBUG_MSG(1, "Error: param_ptr malloc failed!!\n", NULL);
		return NULL;
	}
	memset(param_ptr, '\0', sizeof(struct parameter));

	 param_ptr->name = cmds_ptr->name;
	 param_ptr->type = cmds_ptr->matchmode;
	 param_ptr->min = cmds_ptr->argcmin;
	 param_ptr->max = cmds_ptr->argcmax;
	 param_ptr->ylabel = cmds_ptr->yhp;
	 param_ptr->hlabel = cmds_ptr->hhp;
	 param_ptr->flag = cmds_ptr->end_flag;
	
	return param_ptr;
}

/* all cnt start of '0' */
/* 0:done -1:error */
int cli_param_get_int(int type, int cnt, int *v_int, struct users *u)
{
	struct g_param *t_param = NULL;
	
	if(u == NULL)
		return -1;

	if(type == STATIC_PARAM)
		t_param = &(u->s_param);
	else if(type == DYNAMIC_PARAM)
		t_param = &(u->d_param);
	else
		return -1;
	
	if(cnt  < 0 || cnt > MAX_V_INT || v_int == NULL)
		return -1;

	*v_int = t_param->v_int[cnt];

	return 0;	
}

/* 0:done -1:error */
int cli_param_get_string(int type, int cnt, char *v_str, struct users *u)
{
	struct g_param *t_param = NULL;
	
	if(u == NULL)
		return -1;

	if(type == STATIC_PARAM)
		t_param = &(u->s_param);
	else if(type == DYNAMIC_PARAM)
		t_param = &(u->d_param);
	else
		return -1;
	
	if(cnt  < 0 || cnt > MAX_V_STRING || v_str == NULL)
		return -1;

	memcpy(v_str, t_param->v_string[cnt], strlen(t_param->v_string[cnt]));
	
	return 0;
}

/* 0:done -1:error */
int cli_param_get_range_edge(int type, int *v_range_edge, struct users *u)
{
	struct g_param *t_param = NULL;
	
	if(u == NULL)
		return -1;

	if(type == STATIC_PARAM)
		t_param = &(u->s_param);
	else if(type == DYNAMIC_PARAM)
		t_param = &(u->d_param);
	else
		return -1;
	
	if(v_range_edge == NULL)
		return -1;

	*v_range_edge = t_param->v_range_edge;
	
	return 0;
}

/* 0:done -1:error */
int cli_param_get_range(int type, char *v_range, struct users *u)
{
	struct g_param *t_param = NULL;
	
	if(u == NULL)
		return -1;

	if(type == STATIC_PARAM)
		t_param = &(u->s_param);
	else if(type == DYNAMIC_PARAM)
		t_param = &(u->d_param);
	else
		return -1;
	
	if(v_range == NULL)
		return -1;

	memcpy(v_range, t_param->v_range, strlen(t_param->v_range));
	
	return 0;
}

/* 0:done -1:error */
int cli_param_get_ipv4(int type, int cnt, struct in_addr *v_sin_addr, char *buff, int len, struct users *u)
{
	char addr[MAX_ARGV_LEN] = {'\0'};
	struct g_param *t_param = NULL;
	
	if(u == NULL)
		return -1;

	if(type == STATIC_PARAM)
		t_param = &(u->s_param);
	else if(type == DYNAMIC_PARAM)
		t_param = &(u->d_param);
	else
		return -1;

	if(cnt  < 0 || cnt > MAX_V_IP || v_sin_addr == NULL)
		return -1;

	memcpy(v_sin_addr, &t_param->v_sin_addr[cnt], sizeof(struct in_addr));
	
	if(buff != NULL && len > 0)
	{
		memset(addr, '\0', sizeof(addr));
		inet_ntop(AF_INET, v_sin_addr, addr, sizeof(addr));
		v_sin_addr->s_addr = ntohl(v_sin_addr->s_addr);
		
		if(strlen(addr) < len)
			memcpy(buff, addr, strlen(addr));
	}

	return 0;
}

/* 0:done -1:error */
int cli_param_get_ipv6(int type, int cnt, struct in6_addr *v_sin6_addr, char *buff, int len, struct users *u)
{
	char addr6[MAX_ARGV_LEN] = {'\0'};
	struct g_param *t_param = NULL;
	
	if(u == NULL)
		return -1;

	if(type == STATIC_PARAM)
		t_param = &(u->s_param);
	else if(type == DYNAMIC_PARAM)
		t_param = &(u->d_param);
	else
		return -1;

	if(cnt < 0 || cnt > MAX_V_IPV6 || v_sin6_addr == NULL)
		return -1;

	memcpy(v_sin6_addr, &t_param->v_sin6_addr[cnt], sizeof(struct in6_addr));

	if(buff != NULL && len > 0)
	{
		memset(addr6, '\0', sizeof(addr6));
		inet_ntop(AF_INET6, v_sin6_addr, addr6, sizeof(addr6));
		
		if(t_param->v_int[MAX_V_INT+cnt] != 0)
			sprintf(addr6, "%s/%d", addr6, t_param->v_int[MAX_V_INT+cnt]);	//oop!!
		
		if(strlen(addr6) < len)
			memcpy(buff, addr6, strlen(addr6));
	}

	return 0;
}

/* all cnt start of '0' */
/* 0:done -1:error */
int cli_param_set_int(int type, int cnt, int v_int, struct users *u)
{
	struct g_param *t_param = NULL;
	
	if(u == NULL)
		return -1;

	if(type == STATIC_PARAM)
		t_param = &(u->s_param);
	else if(type == DYNAMIC_PARAM)
		t_param = &(u->d_param);
	else
		return -1;
	
	if(cnt  < 0 || cnt > MAX_V_INT)
		return -1;

	t_param->v_int[cnt] = v_int;
	t_param->v_int_cnt += 1;

	return 0;
}

/* 0:done -1:error */
int cli_param_set_string(int type, int cnt, char *v_str, struct users *u)
{
	struct g_param *t_param = NULL;
	
	if(u == NULL)
		return -1;

	if(type == STATIC_PARAM)
		t_param = &(u->s_param);
	else if(type == DYNAMIC_PARAM)
		t_param = &(u->d_param);
	else
		return -1;
	
	if(cnt  < 0 || cnt > MAX_V_STRING || v_str == NULL)
		return -1;

	if(strlen(v_str) > (MAX_ARGV_LEN - 1))
		return -1;

	memset(t_param->v_string[cnt], '\0', MAX_ARGV_LEN);
	memcpy(t_param->v_string[cnt], v_str, strlen(v_str));
	t_param->v_string_cnt += 1;
	
	return 0;
}

/* 0:done -1:error */
int cli_param_set_ipv4(int type, int cnt, struct in_addr *s, struct users *u)
{
	char buff[MAX_ARGV_LEN] = {'\0'};
	struct g_param *t_param = NULL;
	
	if(u == NULL)
		return -1;

	if(type == STATIC_PARAM)
		t_param = &(u->s_param);
	else if(type == DYNAMIC_PARAM)
		t_param = &(u->d_param);
	else
		return -1;
	
	if(cnt  < 0 || cnt > MAX_V_IP || s == NULL)
		return -1;

	memset(buff, '\0', sizeof(buff));
	if(inet_ntop(AF_INET, s, buff, sizeof(buff)) == NULL)
		return -1;

	memset(&t_param->v_sin_addr[cnt], '\0', sizeof(struct in_addr));
	memcpy(&t_param->v_sin_addr[cnt], s, sizeof(struct in_addr));
	t_param->v_sin_addr_cnt += 1;

	return 0;
}

/* 0:done -1:error */
int cli_param_set_ipv6(int type, int cnt, struct in6_addr *s6, struct users *u)
{
	char buff[MAX_ARGV_LEN] = {'\0'};
	struct g_param *t_param = NULL;
	
	if(u == NULL)
		return -1;

	if(type == STATIC_PARAM)
		t_param = &(u->s_param);
	else if(type == DYNAMIC_PARAM)
		t_param = &(u->d_param);
	else
		return -1;

	if(cnt < 0 || cnt > MAX_V_IPV6 || s6 == NULL)
		return -1;

	memset(buff, '\0', sizeof(buff));
	if(inet_ntop(AF_INET6, s6, buff, sizeof(buff)) == NULL)
		return -1;

	memset(&t_param->v_sin6_addr[cnt], '\0', sizeof(struct in6_addr));
	memcpy(&t_param->v_sin6_addr[cnt], s6, sizeof(struct in6_addr));
	t_param->v_sin6_addr_cnt += 1;

	return 0;
}

/* 0:done -1:error */
int cli_param_set(int type, struct parameter *param, struct users *u)
{
	struct g_param *t_param = NULL;

	if(type == STATIC_PARAM)
		t_param = &(u->s_param);
	else if(type == DYNAMIC_PARAM)
		t_param = &(u->d_param);
	else
		return -1;
	
	DEBUG_MSG(1, "type=%d, param->type=%d\n", type, param->type);
	
	switch(param->type)
	{
		case CLI_INT_UNUSAL:
			if((t_param->v_range_len + strlen(param->value0.v_string)) < MAC_V_STR_LEN)
			{
				/* Copy the buffer */
				memcpy(&(t_param->v_range[t_param->v_range_len]), param->value0.v_string, 
					strlen(param->value0.v_string));
				t_param->v_range_len += strlen(param->value0.v_string);

				t_param->v_range_edge = param->value.v_int;
			}
			else
				return -1;
			break;
			
		case CLI_INT:
		case CLI_LINE:
			if(t_param->v_int_cnt < MAX_V_INT)
			{
				t_param->v_int[t_param->v_int_cnt] = param->value.v_int;
				t_param->v_int_cnt += 1;
			}
			else
				return -1;
			break;
			
		case CLI_INT_RANGE:
		case CLI_INT_MULTI:
		case CLI_WORD:
		case CLI_MAC:
		case CLI_TIME:
			if(t_param->v_string_cnt < MAX_V_INT)
			{
				memcpy(t_param->v_string[t_param->v_string_cnt], param->value.v_string, 
					strlen((param->value.v_string)));
				t_param->v_string_cnt += 1;
			}
			else
				return -1;
			break;
	
		case CLI_IPV4:
		case CLI_IPV4_MASK:
			if(t_param->v_sin_addr_cnt < MAX_V_IP)
			{
				memcpy(&(t_param->v_sin_addr[t_param->v_sin_addr_cnt]), 
					&(param->value.v_sin_addr), sizeof(struct in_addr));
				t_param->v_sin_addr_cnt += 1;
			}
			else
				return -1;
			break;
			
		case CLI_IPV6:
		case CLI_IPV6_MASK:
		case CLI_IPV6_NOMASK:
			if(t_param->v_int_cnt < MAX_V_IPV6)
			{
				memcpy(&(t_param->v_sin6_addr[t_param->v_sin6_addr_cnt]), 
					&(param->value.v_sin6_addr), sizeof(struct in6_addr));
				t_param->v_int[(MAX_V_INT+t_param->v_sin6_addr_cnt)] = param->value0.v_int;
				t_param->v_sin6_addr_cnt += 1;
				
				DEBUG_MSG(1, "v_sin6_addr_cnt=%d, param->value0.v_int =%d\n", 
					t_param->v_sin6_addr_cnt, param->value0.v_int );
			}
			else
				return -1;
			break;
			
		default :
			DEBUG_MSG(1, "Unknow type!!\n", NULL);
			return -1;
			break;
	}

	return 0;
}

/* 0:done -1:error */
int cli_param_int32_format(char *s, int min, int max, struct users *u)
{
	int len = 0, value = 0, signed_flag = 0;
	char *str = s;

	if(u == NULL || s == NULL)
		return -1;

	if(*str == '-' || *str == '+')
		signed_flag = 1;
	
	if(((len = strlen(str)) - signed_flag) == 0)
		goto check_int32_incomplete;
	
	if(len > 11
		|| (len == 11 && !signed_flag)
		|| (len == 11 && signed_flag && strcmp(str+1, "2147483647") > 0)
		|| (len == 10 && strcmp(str, "2147483647") > 0))		//"4294967295"?
		goto check_int32_error;

	str += signed_flag;
	while(*str != '\0')
	{
		if(*str < '0' || *str > '9')
		{
			u->err_ptr += (str - s);
			goto check_int32_error;
		}
		str++;
	}

	value = atoi(s);
	if((min != 0 || max != 0)
		&& ((value < min) || (value > max)))
	{
		SET_ERR_NO(u, CLI_ERR_INT_RANGE);
		return -1;
	}
	return 1;

check_int32_error:
	SET_ERR_NO(u, CLI_ERR_INT_FORMAT);
	return -1;
	
check_int32_incomplete:
	SET_ERR_NO(u, CLI_ERR_INCOMPLETE_CMD);
	return 0;
}

int cli_param_int32_range_format(char *s, int min, int max, struct users *u)
{
	int retval = 0, signed_flag = 0;
	int len = 0, value1 = 0, value2 = 0;
	char *str = s, *str1 = NULL;
	char buff[MAX_ARGV_LEN] = {'\0'};
	
	if(u == NULL || s == NULL)
		return -1;

	if(*str == '-' || *str == '+')
		signed_flag = 1;

	if(((len = strlen(str)) - signed_flag) == 0)
		goto check_int32_range_incomplete;
	
	while(*str != '\0')
	{
		if((*str < '0' || *str > '9')
			&& *str != '-' && *str != '+')
			goto check_int32_range_error;
		str++;
	}

	str = s;
	if((str1 = strchr((str + signed_flag), '-')) == NULL)
		goto check_int32_range_incomplete;
	else
	{	
		memset(buff, '\0', sizeof(buff));
		memcpy(buff, str, str1 - str);

		if((strlen(buff) - signed_flag) == 0)
			goto check_int32_range_error;
		
		if((retval = cli_param_int32_format(buff, min, max, u)) != 1)
			return retval;
		
		value1 = atoi(buff);

		str1 ++;signed_flag = 0;
		if(*str1 == '-' || *str1 == '+')
			signed_flag = 1;
		
		if(((len = strlen(str1)) - signed_flag) == 0)
			goto check_int32_range_incomplete;
		
		memset(buff, '\0', sizeof(buff));
		strcpy(buff, str1);
	
		if((retval = cli_param_int32_format(buff, min, max, u)) != 1)
			return retval;
		
		value2 = atoi(buff);
	
		if(value1 > value2)
		{
			SET_ERR_NO(u, CLI_ERR_INT_RANGE);
			u->args_offset += 1;
			return -1;
		}
	}
	return 1;

check_int32_range_error:
	SET_ERR_NO(u, CLI_ERR_INT_FORMAT);
	return -1;

check_int32_range_incomplete:
	SET_ERR_NO(u, CLI_ERR_INCOMPLETE_CMD);
	return 0;
}

int cli_param_int32_multi_format(char *s, int min, int max, struct users *u)
{
	int retval = 0, len = 0;
	char *str = s, *str1 = NULL, *str2 = NULL;
	char buff[MAX_ARGV_LEN] = {'\0'};
	
	if(u == NULL || s == NULL)
		return -1;

	if((len = strlen(str)) == 0)
		goto check_int32_multi_incomplete;

	while(*str != '\0')
	{
		if((*str < '0' || *str > '9')
			&& *str != '-' && *str != ',')
			goto check_int32_multi_error;
		str++;
	}
	
	str1 = str = s;
	while(str1 != NULL)
	{
		memset(buff, '\0', sizeof(buff));
		if((str1 = strchr(str, ',')) == NULL)
			memcpy(buff, str, strlen(str));
		else
		{			
			memcpy(buff, str, str1-str);
			
			if(strlen(buff) == 0)
				goto check_int32_multi_error;
			
			str = str1 + 1;
			
			if(str == '\0')
				goto check_int32_multi_incomplete;
		}

		if((str2 = strchr(buff, '-')) != NULL)
		{
			if(str2 == buff)
				goto check_int32_multi_error;
			
			retval = cli_param_int32_range_format(buff, min, max, u);
			
			
			if(retval < 0) 
				goto check_int32_multi_error;
			else if(retval == 0)
				goto check_int32_multi_incomplete;
		}
		else
		{
			retval = cli_param_int32_format(buff, min, max, u);
			
			
			if(retval < 0) 
				goto check_int32_multi_error;
			else if(retval == 0)
				goto check_int32_multi_incomplete;
		}
	}
	
	return 1;
	
check_int32_multi_error:
	SET_ERR_NO(u, CLI_ERR_INT_FORMAT);
	return -1;

check_int32_multi_incomplete:
	SET_ERR_NO(u, CLI_ERR_INCOMPLETE_CMD);
	return 0;
}

int cli_param_int(int argc, char *argv[], struct users *u, struct parameter *param)
{
	if(argc < 1 || argv == NULL || u == NULL || param == NULL)
		return -1;

	DEBUG_MSG(1, " argc=%d, argv[0]=%s\n", argc, argv[0]);
	
	if(param->type == CLI_INT)
	{
		if(strstr(argv[0], HELP_SUFFIX) != NULL
			|| strstr(argv[0], TAB_SUFFIX) != NULL)
			return 1;
		
		if(cli_param_int32_format(argv[0], param->min, param->max, u) != 1)
			return -1;

		param->value.v_int = atoi(argv[0]);
		u->args_offset += 1;
		return 0;
	}
	else if(param->type == CLI_INT_RANGE)
	{
		if(strstr(argv[0], HELP_SUFFIX) != NULL
			|| strstr(argv[0], TAB_SUFFIX) != NULL)
			return 1;
		
		if(cli_param_int32_range_format(argv[0], param->min, param->max, u) != 1)
			return -1;

		memcpy(param->value.v_string, argv[0], strlen(argv[0]));
		u->args_offset += 1;
		return 0;
	}
	else if(param->type == CLI_INT_MULTI)
	{
		if(strstr(argv[0], HELP_SUFFIX) != NULL
			|| strstr(argv[0], TAB_SUFFIX) != NULL)
			return 1;
		
		if(cli_param_int32_multi_format(argv[0], param->min, param->max, u) != 1)
			return -1;

		memcpy(param->value.v_string, argv[0], strlen(argv[0]));
		u->args_offset += 1;
		return 0;
	}
	else if(param->type == CLI_INT_UNUSAL)
	{
		int s_len = 0;
		char buff[MAX_ARGV_LEN] = {'\0'};

		memcpy(buff, argv[0], strlen(argv[0]));
		if(buff[0] == '-' || buff[0] == '+')
			s_len += 1;
		while(buff[s_len] <= '9' && buff[s_len] >= '0')
			s_len ++;
		memset(&buff[s_len], '\0', strlen(&buff[s_len]));

		if(strlen(buff) == 0)
		{
			SET_ERR_NO(u, CLI_ERR_INT_FORMAT);
			return -1;
		}
			
		if(cli_param_int32_format(buff, param->min, param->max, u) != 1)
			return -1;

		param->value.v_int = atoi(buff);
		memcpy(param->value0.v_string, buff, strlen(buff));

		DEBUG_MSG(1, " value.v_int=%d, value0.v_string=%s\n", param->value.v_int, param->value0.v_string);
		
		if(s_len == strlen(argv[0]))
			u->args_offset += 1;
		else
			argv[0] += s_len;
		
		return 0;
	}
	else
		DEBUG_MSG(1, "Unknow type!!\n", NULL);

	return -1;
}

int cli_param_word_format(char *s, int min, int max, struct users *u)
{
	int len = 0;
	char *str = s;
	
	if(u == NULL || s == NULL)
		return -1;
	
	if((len = strlen(str)) == 0)
		goto check_word_incomplete;

	if(len > MAX_ARGV_LEN)
		goto check_word_error;

	if((min != 0 || max != 0)
		&& ((len < min) || (len > max)))
		goto check_word_error;

	return 1;

check_word_error:
	SET_ERR_NO(u, CLI_ERR_WORD_LENTH);
	return -1;

check_word_incomplete:
	SET_ERR_NO(u, CLI_ERR_INCOMPLETE_CMD);
	return 0;
}

/* 0:done -1:error */
int cli_param_word(int argc, char *argv[], struct users *u, struct parameter *param)
{
	if(argc < 1 || argv == NULL || u == NULL || param == NULL)
		return -1;

	DEBUG_MSG(1, " argc=%d, argv[0]=%s\n", argc, argv[0]);
	
	if(param->type == CLI_WORD)
	{
		if(strstr(argv[0], HELP_SUFFIX) != NULL
			|| strstr(argv[0], TAB_SUFFIX) != NULL)
			return 1;
		
		if(cli_param_word_format(argv[0], param->min, param->max, u) != 1)
			return -1;
		
		memcpy(param->value.v_string, argv[0], strlen(argv[0]));
		u->args_offset += 1;
		return 0;
	}
	else
		DEBUG_MSG(1, "Unknow type!!\n", NULL);

	return -1;	
}

/* 0:done -1:error */
int cli_param_line(int argc, char *argv[], struct users *u, struct parameter *param)
{
	if(argc < 1 || argv == NULL || u == NULL || param == NULL)
		return -1;

	if(param->type == CLI_LINE)
	{
		if(strstr(argv[argc-1], HELP_SUFFIX) != NULL)
		{
			if(param->flag == CLI_END_FLAG){
				vty_output("  <cr>\n");
				return 1;
			}else{
				vty_output("  LINE	<cr>\n");
			    return 1;
			}
		}
		else if(strstr(argv[argc-1], TAB_SUFFIX) != NULL)
			return 1;
		
		char *ptr = NULL;
		if((ptr = strstr(u->linebuf, argv[0])) == NULL)
			return -1;

#if 0
		memcpy(param->value.v_string, argv[0], strlen(argv[0]));
#else
		param->value.v_int = (int)(ptr);
#endif
		u->args_offset += argc;
		return 0;
	}
	else
		DEBUG_MSG(1, "Unknow type!!\n", NULL);

	return -1;	
}

int cli_param_mac_format(char *s, struct users *u)
{
	int len = 0, is_zero = 0;
	char *str = s;
	
	if(u == NULL || s == NULL)
		return -1;

	if((len = strlen(str)) == 0)
		goto check_mac_incomplete;

	if(len > 17)
		goto check_mac_error;

	str = s;
	for(len=0; *str!='\0'; str++,len++) 
	{
		if( (2 == len)||(14==len)||(11==len)||(8==len)||(5==len) ) 
		{
			if(*str == ':') 
				continue;
			else	
			{
				u->err_ptr += (str - s);
				goto check_mac_error;
			}
		}
#if 0	
		if( ((*str>='0')&&(*str<='9'))
			||((*str>='a')&&(*str<='f'))
			||((*str>='A')&&(*str<='F')) )
		{
			if('0' == *str) 	
				is_zero++;
			
			if(12 == is_zero)	
				goto check_mac_error;
		}
		else
			goto check_mac_error;
#else
		if((*str < '0' || *str >'9')
			&& (*str < 'a' || *str > 'f')
			&& (*str < 'A' || *str > 'F'))
		{
			u->err_ptr += (str - s);
			goto check_mac_error;
		}

		if(*str == '0')	is_zero++;
		if(is_zero == 12)	
			goto check_mac_error;
#endif		
	}
	
	if(len == 17)
		return 1;
	else
		goto check_mac_incomplete;

check_mac_error:
	SET_ERR_NO(u, CLI_ERR_MAC_FORMAT);
	return -1;

check_mac_incomplete:
	SET_ERR_NO(u, CLI_ERR_INCOMPLETE_CMD);
	return 0;
}

/* 0:done -1:error */
int cli_param_mac(int argc, char *argv[], struct users *u, struct parameter *param)
{	
	if(argc < 1 || argv == NULL || u == NULL || param == NULL)
		return -1;
	
	DEBUG_MSG(1, " argc=%d, argv[0]=%s\n", argc, argv[0]);

	if(param->type == CLI_MAC)
	{
		if(strstr(argv[0], HELP_SUFFIX) != NULL
			|| strstr(argv[0], TAB_SUFFIX) != NULL)
			return 1;
		
		if(cli_param_mac_format(argv[0], u) != 1)
			return -1;

		memcpy(param->value.v_string, argv[0], strlen(argv[0]));
		u->args_offset += 1;
		return 0;
	}
	else
		DEBUG_MSG(1, "Unknow type!!\n", NULL);
		
	return -1;
}

int cli_param_time_format(char *s, struct users *u)
{
	int len = 0, time_int = 0;
	char *str = s, *p_dot = NULL;
	char buff[MAX_ARGV_LEN]= {'\0'};
	
	if(u == NULL || s == NULL)
		return -1;

	if((len = strlen(str)) == 0)
		goto check_time_incomplete;

	if(len > 8)
		goto check_time_error;

	memset(buff, '\0', sizeof(buff));
	memcpy(buff, str, len);
	
	for(len=0; *str != '\0'; str++,len++) 
	{
		if(2 == len ||8==len || 5==len) 
		{
			if(*str == ':') 
				continue;
			else	
			{
				u->err_ptr += (str - s);
				goto check_time_error;
			}
		}
	
		if(*str < '0' || *str >'9')
		{
			u->err_ptr += (str - s);
			goto check_time_error;
		}
	}

	if((p_dot = strtok(buff, ":")) != NULL)
	{
		time_int = atoi(p_dot);
		if(time_int > 24 || time_int < 0)
			goto check_time_error;
	}
	else
		goto check_time_error;

	if((p_dot = strtok(NULL, ":")) != NULL)
	{
		time_int = atoi(p_dot);
		if(time_int > 60 || time_int < 0)
			goto check_time_error;
	}
	else
		goto check_time_incomplete;
	
	if((p_dot = strtok(NULL, ":")) != NULL)
	{
		time_int = atoi(p_dot);
		if(time_int > 60 || time_int < 0)
			goto check_time_error;
	}
	else
		goto check_time_incomplete;
	
	return 1;
	
check_time_error:
	SET_ERR_NO(u, CLI_ERR_TIME_FORMAT);
	return -1;

check_time_incomplete:
	SET_ERR_NO(u, CLI_ERR_INCOMPLETE_CMD);
	return 0;
}

/* 0:done -1:error */
int cli_param_time(int argc, char *argv[], struct users *u, struct parameter *param)
{
		
	if(argc < 1 || argv == NULL || u == NULL || param == NULL)
		return -1;
	
	DEBUG_MSG(1, " argc=%d, argv[0]=%s\n", argc, argv[0]);

	if(param->type == CLI_TIME)
	{
		if(strstr(argv[0], HELP_SUFFIX) != NULL
			|| strstr(argv[0], TAB_SUFFIX) != NULL)
			return 1;
		
		if(cli_param_time_format(argv[0], u) != 1)
			return -1;
			
		memcpy(param->value.v_string, argv[0], strlen(argv[0]));
		u->args_offset += 1;
		return 0;
	}
	else
		DEBUG_MSG(1, "Unknow type!!\n", NULL);
		
	return -1;
}

int cli_param_ipv4_format(int type, char *s, struct users *u)
{
	int len = 0, dot_cnt = 0, value = 0, i = 0;
	char *str = s, *p_dot = NULL;
	char buff[MAX_ARGV_LEN] = {'\0'};
	struct in_addr sin_addr;

	if(u == NULL || s == NULL)
		return -1;

	if((len = strlen(str)) == 0)
		goto check_ip_incomplete;

	if(len > 15)
		goto check_ip_error;

	memset(buff, '\0', sizeof(buff));
	memcpy(buff, str, len);
	
	if(strstr(str, "..") != NULL
		|| strstr(str, "...") != NULL)
		goto check_ip_error;
	
	for(len=0; *str != '\0'; str++,len++) 
	{
		if(*str == '.') 
		{
			if(len == 0 || ++dot_cnt > 3)
			{
				u->err_ptr += (str - s);
				goto check_ip_error;
			}
			
			continue;
		}
	
		if(*str < '0' || *str > '9')
		{
			u->err_ptr += (str - s);
			goto check_ip_error;
		}
	}

	if((p_dot = strtok(buff, ".")) != NULL)
	{
		value = atoi(p_dot);
		if(value > 255 || value < 0)
			goto check_ip_error;
	}
	else
		goto check_ip_error;
	
	do
	{
		if((p_dot = strtok(NULL, ".")) != NULL)
		{
			value = atoi(p_dot);
			if(value > 255 || value < 0)
				goto check_ip_error;
		}
		else
			goto check_ip_incomplete;

		i++;
	}while(i < dot_cnt);

	memset(&sin_addr, 0, sizeof(struct in_addr));
	if(inet_pton(AF_INET, s, (void *)&sin_addr) != 1)
		goto check_ip_error;
		
	sin_addr.s_addr = swap32(sin_addr.s_addr);	
	if(type == CLI_IPV4_MASK)
	{
		uint32_t mask_bit = 0x80000000, flag = 0;
		for(i = 31; i > 0; i--)
		{
			if((mask_bit & (sin_addr.s_addr)) == 0)
				flag = 1;
			else
			{
				if(flag == 1)
				{
					SET_ERR_NO(u, CLI_ERR_IPV4_NETMASK_FORMAT);
					return -1;
				}
			}
			mask_bit >>= 1;
		}
	}
	
	return 1;
	
check_ip_error:
	SET_ERR_NO(u, CLI_ERR_IPV4_FORMAT);
	return -1;

check_ip_incomplete:
	SET_ERR_NO(u, CLI_ERR_INCOMPLETE_CMD);
	return 0;
}

/* 0:done -1:error */
int cli_param_ipv4(int argc, char *argv[], struct users *u, struct parameter *param)
{
	struct in_addr s;

	if(argc < 1 || argv == NULL || u == NULL || param == NULL)
		return -1;

	DEBUG_MSG(1, " argc=%d, argv[0]=%s\n", argc, argv[0]);

	if(param->type == CLI_IPV4 || param->type == CLI_IPV4_MASK)
	{
		if(strstr(argv[0], HELP_SUFFIX) != NULL
			|| strstr(argv[0], TAB_SUFFIX) != NULL)
			return 1;
		
		if(cli_param_ipv4_format(param->type, argv[0], u) != 1)
			return -1;

		if(inet_pton(AF_INET, argv[0], (void *)&s) == 1)
		{
			memcpy((void *)&param->value.v_sin_addr, (void *)&s, sizeof(struct in_addr));
			u->args_offset += 1;
			return 0;
		}
	}
	else
		DEBUG_MSG(1, "Unknow type!!\n", NULL);

	return -1;
}

int cli_param_ipv6_format(int type, char *s, struct users *u)
{
	int len = 0, value = 0;
	int dot_cnt = 0, dot2_cnt = 0;
	char *str = s, *str2 = NULL, *p1 = NULL;
	char buff[MAX_ARGV_LEN] = {'\0'};
	struct in_addr sin6_addr;

	if(u == NULL || s == NULL)
		return -1;

	if((len = strlen(str)) == 0)
		goto check_ipv6_incomplete;

	if(len > 43)
		goto check_ipv6_error;
	
	str = strchr(s, '/');
	memset(buff, '\0', sizeof(buff));
	if(str == NULL)
		memcpy(buff, s, len);
	else if(str != NULL)
	{
		if(type == CLI_IPV6_NOMASK)
		{
			SET_ERR_NO(u, CLI_ERR_IPV6_NOMASK);
			return -1;
		}
		else
			memcpy(buff, s, str-s);
	}

	if(strlen(buff) > 39)
		goto check_ipv6_error;

	str2 = buff;
	if(strstr(str2, ":::") != NULL
		|| strstr(str2, "::::") != NULL
		|| strstr(str2, ":::::") != NULL
		|| strstr(str2, "::::::") != NULL
		|| strstr(str2, ":::::::") != NULL)
		goto check_ipv6_error;
	
	for(len=0; *str2 != '\0'; str2++,len++) 
	{
		if(*str2 == ':') 
		{
			if(len == 0 || ++dot_cnt > 7)
			{
				u->err_ptr += (str2 - buff);
				goto check_ipv6_error;
			}

			if(*(str2+1) == ':')
				dot2_cnt ++;

			if(*(str2+1) == '\0')
				goto check_ipv6_incomplete;
			
			continue;
		}
	
		if((*str2 < '0' || *str2 >'9')
			&& (*str2 < 'a' || *str2 > 'f')
			&& (*str2 < 'A' || *str2 > 'F'))
			goto check_ipv6_error;
	}

	if(dot_cnt < 7 && dot2_cnt < 1)
		goto check_ipv6_incomplete;
	
	if(inet_pton(AF_INET6, buff, (void *)&sin6_addr) != 1) 
		goto check_ipv6_error;
	
	if(type == CLI_IPV6_MASK && str == NULL)
		goto check_ipv6_incomplete;

	if((type == CLI_IPV6_MASK && str != NULL)
		|| (type == CLI_IPV6 && str != NULL))
	{
		p1 = str + 1;
		if(*p1 == '\0')
			goto check_ipv6_incomplete;
		
		while(*p1 != '\0')
		{
			if(*p1 < '0' || *p1 > '9')
			{
				u->err_ptr += (p1 - s);
				SET_ERR_NO(u, CLI_ERR_IPV6_MASK);
				return -1;
			}
			
			p1 ++;
		}
		value = atoi(str + 1);
		
		if(value < 0 || value > 128)
		{
			u->err_ptr += ((str + 1) - s);
			SET_ERR_NO(u, CLI_ERR_IPV6_MASK);
			return -1;
		}
	}

	return 1;
	
check_ipv6_error:
	SET_ERR_NO(u, CLI_ERR_IPV6_FORMAT);
	return -1;

check_ipv6_incomplete:
	SET_ERR_NO(u, CLI_ERR_INCOMPLETE_CMD);
	return 0;
}

/* 0:done -1:error */
int cli_param_ipv6(int argc, char *argv[], struct users *u, struct parameter *param)
{
	int value = 0;
	char *str = NULL;
	char buff[MAX_ARGV_LEN] = {'\0'}, mask[16] = {'\0'};
	struct in6_addr s6;

	if(argc < 1 || argv == NULL || u == NULL || param == NULL)
		return -1;
	
	DEBUG_MSG(1, " argc=%d, argv[0]=%s\n", argc, argv[0]);
	
	if(param->type == CLI_IPV6
		|| param->type == CLI_IPV6_MASK
		|| param->type ==  CLI_IPV6_NOMASK)
	{
		if(strstr(argv[0], HELP_SUFFIX) != NULL
			|| strstr(argv[0], TAB_SUFFIX) != NULL)
			return 1;
		
		if(cli_param_ipv6_format(param->type, argv[0], u) != 1)
			return -1;

		memset(buff, '\0', sizeof(buff));
		memset(mask, '\0', sizeof(mask));
		if((str = strchr(argv[0], '/')) != NULL)
		{
			memcpy(buff, argv[0], str-argv[0]);
			memcpy(mask, str+1, strlen(str+1));
			value = atoi(mask);
		}
		else
			memcpy(buff, argv[0], strlen(argv[0]));
			
		if(inet_pton(AF_INET6, buff, (void *)&s6) == 1)
		{
			param->value0.v_int = value;
			memcpy((void *)&param->value.v_sin6_addr, (void *)&s6, sizeof(struct in6_addr));
			u->args_offset += 1;
			return 0;
		}
	}
	else
		DEBUG_MSG(1, "Unknow type!!\n", NULL);
	
	return -1;
}

/* 0:success  1:exists -1:error*/
int cli_mac_blackhole_vid(char *src_mac, int src_vid)
{
	int vid_tmp = 0;
	char vid[8] = {0};
	char mac[24] = {0};
	char *pt = NULL, *p_tok = NULL;	
	char *mac_bloackhole = nvram_safe_get("mac_bloackhole");

	if((NULL == src_mac) || (0 == src_vid))
		return -1;
	
	pt = mac_bloackhole;

	p_tok = strtok(pt, ",");
	while( p_tok ){	
		sprintf(mac, "%s", p_tok);
		
		p_tok = strtok(NULL, ";");	
		sprintf(vid, "%s", p_tok);
		
		vid_tmp = atoi(vid);

		if((! strcmp(mac, src_mac)) && (vid_tmp == src_vid))
		{
			free(mac_bloackhole);
			return 1;
		}
		
		if(p_tok)
			p_tok = strtok(NULL, ",");
	}
	
	free(mac_bloackhole);
	return 0;
}
