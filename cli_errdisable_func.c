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

#include "cli_errdisable_func.h"
#include "../bcmutils/bcmutils.h"

/*
 * Function Name:func_set_errdisable_detect
 *
 * Parameters: int iCase -- event cause error-disable 
 * 
 *
 * Function description: enable error-disable detect event
 *      
 * Returns: success
 * 
 * Author:  shanming.ren
 * Date:    2011-11-22
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
int func_set_errdisable_detect(int iCase)
{
    char *err_disable_cfg = cli_nvram_safe_get(CLI_ERR_DISABLE, "err_disable_cfg");
    
    *(err_disable_cfg + iCase) = '1';
    nvram_set("err_disable_cfg", err_disable_cfg);
    free(err_disable_cfg);
    
    return 1;
}

/*
 * Function Name:func_set_recover_detect
 *
 * Parameters: int iCase -- enable error-disable recover event
 * 
 *
 * Function description:
 *      
 * Returns: success
 * 
 * Author:  shanming.ren
 * Date:    2011-11-22
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
int func_set_recover_detect(int iCase)
{
    char *err_recover_cfg = cli_nvram_safe_get(CLI_ERR_RECOVER, "err_recover_cfg");
    
    *(err_recover_cfg + iCase) = '1';
    nvram_set("err_recover_cfg", err_recover_cfg);
    free(err_recover_cfg);
    return 1;
}

/*
 * Function Name:func_set_recover_time
 *
 * Parameters: char* pStr -- string of recover time
 * 
 *
 * Function description: set err-disable recover time
 *      
 * Returns: int
 * 
 * Author:  shanming.ren
 * Date:    2011-11-22
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
int func_set_recover_time(char *pStr)
{
    nvram_set("err_recover_time", pStr);
    return 1;
}

/*
 * Function Name:func_set_errdisable_detect
 *
 * Parameters: int iCase -- event cause error-disable 
 * 
 *
 * Function description: disable error-disable detect event
 *      
 * Returns: success
 * 
 * Author:  shanming.ren
 * Date:    2011-11-22
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
int nfunc_set_errdisable_detect(int iCase)
{
    char *err_disable_cfg = cli_nvram_safe_get(CLI_ERR_DISABLE, "err_disable_cfg");
    
    *(err_disable_cfg + iCase) = '0';
    nvram_set("err_disable_cfg", err_disable_cfg);
    free(err_disable_cfg);
    
    return 1;
}

/*
 * Function Name:func_set_recover_detect
 *
 * Parameters: int iCase -- disable error-disable recover event
 * 
 *
 * Function description:
 *      
 * Returns: success
 * 
 * Author:  shanming.ren
 * Date:    2011-11-22
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
int nfunc_set_recover_detect(int iCase)
{
    char *err_recover_cfg = cli_nvram_safe_get(CLI_ERR_RECOVER, "err_recover_cfg");
    
    *(err_recover_cfg + iCase) = '0';
    nvram_set("err_recover_cfg", err_recover_cfg);
    free(err_recover_cfg);
    return 1;
}

/*
 * Function Name:func_set_recover_time
 *
 * Parameters: 
 * 
 *
 * Function description: set err-disable recover time to default
 *      
 * Returns: int
 * 
 * Author:  shanming.ren
 * Date:    2011-11-22
 *********************Revision History****************
 Date       Version     Modifier       Modifications

 */
int nfunc_set_recover_time(void)
{
    char *err_recover_time = nvram_safe_get_def("err_recover_time");
    nvram_set("err_recover_time", err_recover_time);
    free(err_recover_time);
    return 1;
}

























