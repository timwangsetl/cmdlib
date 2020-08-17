#ifndef __FUNC_ACL__
#define __FUNC_ACL__

/* Acl mode:permit or deny */
#define ACL_MODE_POS			(MAX_V_INT-1)
#define ACL_DENY				0
#define ACL_PERMIT				1

/* IP access-list */
/* Option position*/
#define IP_ACL_PRO_POS			(ACL_MODE_POS - 1)
#define IP_ACL_SRC_POS			(IP_ACL_PRO_POS - 1)
#define IP_ACL_DST_POS			(IP_ACL_SRC_POS - 1)

#define IP_ACL_SRC_PORT_POS			(IP_ACL_DST_POS - 1)
#define IP_ACL_DST_PORT_POS			(IP_ACL_SRC_PORT_POS - 1)
#define IP_ACL_TOS_POS				(IP_ACL_DST_PORT_POS - 1)
#define IP_ACL_PRECEDENCE_POS		(IP_ACL_TOS_POS - 1)
#define IP_ACL_LOCATION_POS			(IP_ACL_PRECEDENCE_POS - 1)
#define IP_ACL_VLAN_POS		        (IP_ACL_LOCATION_POS - 1)
#define IP_ACL_TIME_RANGE_POS		0

/* Option */
#define IP_ACL_PRO_IP				1
#define IP_ACL_PRO_TCP				2
#define IP_ACL_PRO_UDP				3
#define IP_ACL_PRO_NUM				4

#define IP_ACL_SRC_ANY			1
#define IP_ACL_SRC_IP			2
#define IP_ACL_DST_ANY			1
#define IP_ACL_DST_IP			2

/* Submask */
#define IP_ACL_SRC_PORT_MSK		0x00000001
#define IP_ACL_DST_PORT_MSK		0x00000002
#define IP_ACL_TIME_RANGE_MSK	0x00000004
#define IP_ACL_TOS_MSK			0x00000008
#define IP_ACL_PRECEDENCE_MSK	0x00000010
#define IP_ACL_LOCATION_MSK		0x00000020
#define IP_ACL_VLAN_MSK		    0x00000040

/* MAC access-list */
/* Option position*/
#define MAC_ACL_SRC_POS			(ACL_MODE_POS - 1)
#define MAC_ACL_DST_POS			(MAC_ACL_SRC_POS - 1)

/* Option */
#define MAC_ACL_SRC_ANY			1
#define MAC_ACL_SRC_HOST		2
#define MAC_ACL_DST_ANY			1
#define MAC_ACL_DST_HOST		2

int func_ip_acl_ext(struct users *u);
int func_ip_acl_std(struct users *u);

int nfunc_ip_acl_ext(struct users *u);
int nfunc_ip_acl_std(struct users *u);

int func_mac_acl(struct users *u);
//int nfunc_mac_acl(struct users *u);

static int nfunc_mac_acl_any_any(struct users *u);

#endif

