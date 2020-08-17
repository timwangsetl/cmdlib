#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>

#include "console.h"
#include "cmdparse.h"
#include "parameter.h"

#ifdef CLI_AAA_MODULE
#include "cli_aaa_func.h"

struct aaa_auth_list {
	char name[MAX_ARGV_LEN];
	char servers[4][MAX_ARGV_LEN];
};

struct aaa_acct_list {
	char name[MAX_ARGV_LEN];
	int action;
	char servers[4][MAX_ARGV_LEN];
};

/* format
 * aaa_authx_list=default@radius|tacacs+;*/
static int get_aaa_auth_list(const char *name, struct aaa_auth_list **auth_list)
{
	char *list_name, *entry, *buf;
	struct aaa_auth_list *tmp = NULL;
	int i, j;

	list_name = nvram_safe_get(name);

	entry = list_name;
	
	for (i = 0; *entry; i++) {
		tmp = realloc(tmp, sizeof(*tmp) * (i + 1));
		memset(&tmp[i], '\0', sizeof(*tmp));

		buf = strsep(&entry, ";");
		strcpy(tmp[i].name, strsep(&buf, "@"));

		for (j = 0; j < 4 && buf && *buf; j++) {
			strcpy(tmp[i].servers[j], strsep(&buf, "|"));
		}
	}

	*auth_list = tmp;
	free(list_name);
	
	return i;
}

/* create auth list to save in nvram */
static int set_aaa_auth_list(char *list_name, struct aaa_auth_list *auth_list, int count)
{
	char *auth_list_value = calloc(count, sizeof(*auth_list) + 5);
	int i, j;

	if (auth_list == NULL)
		return -1;

	for (i = 0; i < count; i++) {
		sprintf(auth_list_value, "%s%s@%s", 
				auth_list_value, auth_list[i].name, auth_list[i].servers[0]);
		for (j = 1; (j<4 &&*auth_list[i].servers[j]); j++) {
			sprintf(auth_list_value, "%s|%s", 
					auth_list_value, auth_list[i].servers[j]);
		}
		strcat(auth_list_value, ";");
	}
	
	nvram_set(list_name, auth_list_value);

/* 	printf("%s\n", auth_list_value);
 */
	free(auth_list_value);

	return 0;
}

/* remove auth list */
static int remove_aaa_auth_list(char *list_name, struct aaa_auth_list **auth_list, int count)
{
	int i;
	struct aaa_auth_list *tmp;

	for (i = 0, tmp = *auth_list; i < count; i++) {
		if (!strcmp(list_name, tmp[i].name)) {
			if (i < (count - 1))
				memmove(&tmp[i], &tmp[i + 1], (count - i - 1) * sizeof(*tmp));

			break;
		}
	}
	
	if (i == count) {
		vty_output("%s isn't exist.\n", list_name);
		return -1;
	}

	return --count;
}

/* format
 * aaa_acct_list=default|action, radius|tacacs+;*/
static int get_aaa_acct_list(const char *name, struct aaa_acct_list **acct_list)
{
	char *list_name, *entry, *buf;
	struct aaa_acct_list *tmp = NULL;
	int i, j;

	list_name = nvram_safe_get(name);
    if(strlen(list_name)<3){
		free(list_name);
        return -1;
	}
	entry = list_name;
	
	for (i = 0; *entry; i++) {
		tmp = realloc(tmp, sizeof(*tmp) * (i + 1));
		memset(&tmp[i], '\0', sizeof(*tmp));

		buf = strsep(&entry, ";");
		strcpy(tmp[i].name, strsep(&buf, "@"));
		tmp[i].action = *strsep(&buf, ",");

		for (j = 0; j < 4 && buf; j++) {
			strcpy(tmp[i].servers[j], strsep(&buf, "|"));
		}
	}

	*acct_list = tmp;
	free(list_name);
	
	return i;
}

/* create accout list to save in nvram */
static int set_aaa_acct_list(char *list_name, struct aaa_acct_list *acct_list, int count)
{
	char *acct_list_value = calloc(count, sizeof(*acct_list));
	int i, j;

	if (acct_list == NULL)
		return -1;

	for (i = 0; i < count; i++) {
		sprintf(acct_list_value, "%s%s@%c,%s", 
				acct_list_value, acct_list[i].name, acct_list[i].action, acct_list[i].servers[0]);
		for (j = 1; *acct_list[i].servers[j]; j++) {
			sprintf(acct_list_value, "%s|%s", 
					acct_list_value, acct_list[i].servers[j]);
		}
		strcat(acct_list_value, ";");
	}
	
	nvram_set(list_name, acct_list_value);

/* 	printf("%s\n", acct_list_value);
 */
	free(acct_list_value);

	return 0;
}

/* remove accout list */
static int remove_aaa_acct_list(char *list_name, struct aaa_acct_list **acct_list, int count)
{
	int i;
	struct aaa_acct_list *tmp;

	for (i = 0, tmp = *acct_list; i < count; i++) {
		if (!strcmp(list_name, tmp[i].name)) {
			if (i < (count - 1))
				memmove(&tmp[i], &tmp[i + 1], (count - i - 1) * sizeof(*tmp));

			break;
		}
	}
	
	if (i == count) {
		vty_output("%s isn't exist.\n", list_name);
		return -1;
	}

	return --count;
}


static int __set_auth_list(const char *name, const char *buf)
{
	struct aaa_auth_list *auth_list, new;
	int count, i = 0;

	count = get_aaa_auth_list(name, &auth_list);
	
	if (count == -1)
		return -1;

	memset(&new, '\0', sizeof(new));
	char *p = buf;
	strcpy(new.name, strsep(&p, "@"));
	while (p && *p && i < 4) {
		strcpy(new.servers[i++], strsep(&p, "|"));
	}

	for (i = 0; i < count; i++) {
		if (!strcmp(new.name, auth_list[i].name)) {
			memcpy(&auth_list[i], &new, sizeof(new));
			break;
		}
	}

	if (i == count) {
		auth_list = realloc(auth_list, sizeof(*auth_list) * (count + 1));
		memcpy(&auth_list[count], &new, sizeof(new));
		count++;
	}

	set_aaa_auth_list(name, auth_list, count);

	free(auth_list);

	return 0;
}


static int __reset_auth_list(const char *name, char *buf)
{	
	struct aaa_auth_list *auth_list;
	int count;

	count = get_aaa_auth_list(name, &auth_list);
	if (count == -1)
		return -1;

	count = remove_aaa_auth_list(buf, &auth_list, count);
	if (count == -1)
		return -1;

	set_aaa_auth_list(name, auth_list, count);
	
	free(auth_list);

	return 0;
}

/* aaa authentication bannner */
int func_authentication_banner(struct users *u)
{
	int line;
	int retval;

	cli_param_get_int(DYNAMIC_PARAM, 0, &line, u);
  	retval = nvram_set("aaa_auth_banner", (char *)line);
  	
	return retval;
}


int nfunc_authentication_banner()
{
	int retval;

  	retval = nvram_set("aaa_auth_banner", "");
  	
	return retval;
}

/* aaa authentication fail message */
int func_authentication_fail_message(struct users *u)
{
	int line;
	int retval;

	cli_param_get_int(DYNAMIC_PARAM, 0, &line, u);
  	retval = nvram_set("aaa_auth_fail_message", (char *)line);
  	
	return retval;
}


int nfunc_authentication_fail_message()
{
	int retval;

  	retval = nvram_set("aaa_auth_fail_message", "");

	return retval;
}

/* aaa authentication password prompt */
int func_authentication_password_prompt(struct users *u)
{
	int line;
	int retval;

	cli_param_get_int(DYNAMIC_PARAM, 0, &line, u);
  	retval = nvram_set("aaa_auth_password_prompt", (char *)line);
  	
	return retval;
}


int nfunc_authentication_password_prompt()
{
	int retval;

  	retval = nvram_set("aaa_auth_password_prompt", "");

	return 0;
}

/* aaa authentication username prompt */
int func_authentication_username_prompt(struct users *u)
{
	int line;
	int retval;

	cli_param_get_int(DYNAMIC_PARAM, 0, &line, u);
  	retval = nvram_set("aaa_auth_username_prompt", (char *)line);
  	
	return retval;
}


int nfunc_authentication_username_prompt()
{
	int retval;

  	retval = nvram_set("aaa_auth_username_prompt", "");

	return 0;
}


int func_authentication_dot1x_list(const char *buf)
{
	int retval;

	retval = __set_auth_list("aaa_auth_dot1x", buf);

	return retval;
}


int nfunc_authentication_dot1x_list(struct users *u)
{
	int retval;
	int len;
	char name[MAX_ARGV_LEN] = {0};

	cli_param_get_string(STATIC_PARAM, 0, name, u);
	if(strlen(name) == 0){
		memcpy(name, "default", 7);
	}

	retval = __reset_auth_list("aaa_auth_dot1x", name);

	return retval;
}


int func_authentication_enable_list(const char *buf)
{
	int retval;

	retval = __set_auth_list("aaa_auth_enable", buf);

	return retval;
}


int nfunc_authentication_enable_list(struct users *u)
{
	int retval;
	int len;
	char name[MAX_ARGV_LEN] = {0};

	cli_param_get_string(STATIC_PARAM, 0, name, u);
	if(strlen(name) == 0){
		memcpy(name, "default", 7);
	}

	retval = __reset_auth_list("aaa_auth_enable", name);

	return retval;
}


int func_authentication_login_list(const char *buf)
{
	int retval;

	retval = __set_auth_list("aaa_auth_login", buf);

	return retval;
}


int nfunc_authentication_login_list(struct users *u)
{
	int retval;
	int len;
	char name[MAX_ARGV_LEN] = {0};

	cli_param_get_string(STATIC_PARAM, 0, name, u);
	if(strlen(name) == 0){
		memcpy(name, "default", 7);
	}
	retval = __reset_auth_list("aaa_auth_login", name);

	return retval;
}


int func_accounting_conn_exec_list_group_done(struct users *u)
{
	char list_name[MAX_ARGV_LEN] = {0};
	char group_name[MAX_ARGV_LEN] = {0};
	char *con_exec_name;
	int action, con_exec;

	cli_param_get_string(DYNAMIC_PARAM, 0, &list_name, u);
	cli_param_get_string(DYNAMIC_PARAM, 1, &group_name, u);
	cli_param_get_int(DYNAMIC_PARAM, 0, &con_exec, u);
	cli_param_get_int(DYNAMIC_PARAM, 1, &action, u);
	
	if (*list_name == '\0')
		cli_param_get_string(STATIC_PARAM, 0, &list_name, u);

	if (*list_name == '\0')
		strcpy(list_name, "default");

	struct aaa_acct_list *acct_list;
	int count;

	if (con_exec == 'e')
		con_exec_name = "aaa_acct_exec";
	else 
		con_exec_name = "aaa_acct_con";


	count = get_aaa_acct_list(con_exec_name, &acct_list);
	
	if (count == -1)
		return -1;

	int i;
	for (i = 0; i < count; i++) {
		if (!strcmp(list_name, acct_list[i].name)) {
			memset(acct_list[i].servers, '\0', MAX_ARGV_LEN * 4);
			acct_list[i].action = action;
			/* others will be finshed in future */
			strcpy(acct_list[i].servers[0], group_name);
			break;
		}
	}

	if (i == count) {
		acct_list = realloc(acct_list, sizeof(*acct_list) * (count + 1));
		memset(&acct_list[count], '\0', sizeof(*acct_list));
		strcpy(acct_list[count].name, list_name);
		acct_list[count].action = action;
		strcpy(acct_list[count].servers[0], group_name);
		count++;
	}

	set_aaa_acct_list(con_exec_name, acct_list, count);

	free(acct_list);

	return 0;
}


int nfunc_accounting_conn_exec_list_done(struct users *u)
{
	char list_name[MAX_ARGV_LEN] = {0};
	char group_name[MAX_ARGV_LEN] = {0};
	char *con_exec_name;
	int action, con_exec;

	cli_param_get_string(DYNAMIC_PARAM, 0, &list_name, u);
	cli_param_get_int(DYNAMIC_PARAM, 0, &con_exec, u);
	
	if (*list_name == '\0')
		cli_param_get_string(STATIC_PARAM, 0, &list_name, u);

	if (*list_name == '\0')
		strcpy(list_name, "default");

	struct aaa_acct_list *acct_list;
	int count;

	if (con_exec == 'e')
		con_exec_name = "aaa_acct_exec";
	else 
		con_exec_name = "aaa_acct_con";

	count = get_aaa_acct_list(con_exec_name, &acct_list);
	if (count == -1)
		return -1;

	count = remove_aaa_acct_list(list_name, &acct_list, count);
	if (count == -1)
		return -1;

	set_aaa_acct_list(con_exec_name, acct_list, count);
	
	free(acct_list);

	return 0;
}


int func_accounting_conn_exec_list_none(u)
{
	char list_name[MAX_ARGV_LEN] = {0};
	char *con_exec_name;
	int action, con_exec;

	cli_param_get_string(DYNAMIC_PARAM, 0, &list_name, u);
	cli_param_get_int(DYNAMIC_PARAM, 0, &con_exec, u);
	action = '0';
	
	if (*list_name == '\0')
		cli_param_get_string(STATIC_PARAM, 0, &list_name, u);

	if (*list_name == '\0')
		strcpy(list_name, "default");

	struct aaa_acct_list *acct_list;
	int count;

	if (con_exec == 'e')
		con_exec_name = "aaa_acct_exec";
	else 
		con_exec_name = "aaa_acct_con";


	count = get_aaa_acct_list(con_exec_name, &acct_list);
	
	if (count == -1)
		return -1;

	int i;
	for (i = 0; i < count; i++) {
		if (!strcmp(list_name, acct_list[i].name)) {
			memset(acct_list[i].servers, '\0', MAX_ARGV_LEN * 4);
			acct_list[i].action = action;
			/* others will be finshed in future */
			strcpy(acct_list[i].servers[0], "none");
			break;
		}
	}

	if (i == count) {
		acct_list = realloc(acct_list, sizeof(*acct_list) * (count + 1));
		memset(&acct_list[count], '\0', sizeof(*acct_list));
		strcpy(acct_list[count].name, list_name);
		acct_list[count].action = action;
		strcpy(acct_list[count].servers[0], "none");
		count++;
	}

	set_aaa_acct_list(con_exec_name, acct_list, count);

	free(acct_list);

	return 0;
}
#endif
