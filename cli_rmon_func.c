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

#include "cli_rmon_func.h"

int func_rmon_alarm(struct users *u)
{
	vty_output("  The command doesn't support in this version!!\n");

	return 0;
}

int nfunc_rmon_alarm(struct users *u)
{
	vty_output("  The command doesn't support in this version!!\n");

	return 0;
}

int func_rmon_event(struct users *u)
{
	vty_output("  The command doesn't support in this version!!\n");

	return 0;
}

int nfunc_rmon_event(struct users *u)
{
	vty_output("  The command doesn't support in this version!!\n");

	return 0;
}


