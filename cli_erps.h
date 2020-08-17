#ifndef __DO_CLOCK__
#define __DO_CLOCK__

#define 	NTP_SERVER		0x00000001
/*----------------------------------------------------------------------------------------------------------------*/
static int do_erps(int argc, char *argv[], struct users *u);
static int do_no_erps(int argc, char *argv[], struct users *u);
static int do_erp_ring_east_port(int argc, char *argv[], struct users *u);
static int do_erps_ring_id_mode(int argc, char *argv[], struct users *u);
static int do_erp_ring_west_port(int argc, char *argv[], struct users *u);
static int do_erps_ring_config(int argc, char *argv[], struct users *u);
static int do_interface_erps_west_ethernet(int argc, char *argv[], struct users *u);
static int do_interface_erps_east_ethernet(int argc, char *argv[], struct users *u);
static int do_erps_ring_instance_id(int argc, char *argv[], struct users *u);
static int do_erps_mst_configuration(int argc, char *argv[], struct users *u);
static int do_erps_instance_rapl(int argc, char *argv[], struct users *u);
static int no_erps_instance_rapl(int argc, char *argv[], struct users *u);
static int do_erps_instance_rapl_vlan(int argc, char *argv[], struct users *u);
static int do_erps_instance_rapl_vlan_id(int argc, char *argv[], struct users *u);

static int do_erps_instance_ring_id(int argc, char *argv[], struct users *u);
static int no_erps_instance_ring_id(int argc, char *argv[], struct users *u);
static int do_erps_instance_rpl_role(int argc, char *argv[], struct users *u);
static int no_erps_instance_rpl_role(int argc, char *argv[], struct users *u);

static int do_erps_instance_profile(int argc, char *argv[], struct users *u);
static int no_erps_instance_profile(int argc, char *argv[], struct users *u);
static int do_erps_instance_timer(int argc, char *argv[], struct users *u);
static int do_erps_instance_wait_to_restort(int argc, char *argv[], struct users *u);
static int do_erps_instance_set_wait_to_restort(int argc, char *argv[], struct users *u);
static int do_erps_instance_default_wait_to_restort(int argc, char *argv[], struct users *u);
static int do_erps_instance_hold_off(int argc, char *argv[], struct users *u);
static int do_erps_instance_set_hold_off(int argc, char *argv[], struct users *u);
static int do_erps_instance_default_hold_off(int argc, char *argv[], struct users *u);
static int do_erps_instance_guard_timer(int argc, char *argv[], struct users *u);
static int do_erps_instance_set_guard_timer(int argc, char *argv[], struct users *u);
static int do_erps_instance_default_guard_timer(int argc, char *argv[], struct users *u);
static int do_erps_instance_ring_config(int argc, char *argv[], struct users *u);
static int do_erps_instance_profile_config(int argc, char *argv[], struct users *u);
static int do_erps_instance_rpl_role_config(int argc, char *argv[], struct users *u);
static int no_erp_ring_id(int argc, char *argv[], struct users *u);
static int no_erps_ring_id_mode(int argc, char *argv[], struct users *u);
static int do_erps_instance_mst_id(int argc, char *argv[], struct users *u);
static int do_erps_instance_mst_config(int argc, char *argv[], struct users *u);
static int no_erps_instance_mst_config(int argc, char *argv[], struct users *u);
static int no_erps_instance_mst_id(int argc, char *argv[], struct users *u);
static int do_erps_instance_neighbor(int argc, char *argv[], struct users *u);
static int do_erps_instance_next_neighbor(int argc, char *argv[], struct users *u);
static int do_erps_instance_rpl_owner(int argc, char *argv[], struct users *u);
static int do_erps_instance_rpl_none_owner(int argc, char *argv[], struct users *u);
static int do_erps_instance_subring_block(int argc, char *argv[], struct users *u);
static int do_erps_instance_sub_ring(int argc, char *argv[], struct users *u);
static int do_erps_instance_sub_ring_block(int argc, char *argv[], struct users *u);
static int do_erps_instance_sub_ring_block_east(int argc, char *argv[], struct users *u);
static int do_erps_instance_sub_ring_block_west(int argc, char *argv[], struct users *u);
static int do_erps_instance_neighbor_east(int argc, char *argv[], struct users *u);
static int do_erps_instance_neighbor_west(int argc, char *argv[], struct users *u);
static int do_erps_instance_next_neighbor_east(int argc, char *argv[], struct users *u);
static int do_erps_instance_next_neighbor_west(int argc, char *argv[], struct users *u);
static int do_erps_instance_owner_east(int argc, char *argv[], struct users *u);
static int do_erps_instance_owner_west(int argc, char *argv[], struct users *u);
static int do_erps_instance_none_owner_east(int argc, char *argv[], struct users *u);
static int do_erps_instance_none_owner_west(int argc, char *argv[], struct users *u);
static int do_erps_instance_virtual_channel(int argc, char *argv[], struct users *u);
static int do_erps_instance_virtual_channel_id(int argc, char *argv[], struct users *u);
static int do_erps_instance_virtual_channel_attached_instance(int argc, char *argv[], struct users *u);
static int do_erps_instance_virtual_channel_config(int argc, char *argv[], struct users *u);
static int do_erps_instance_enable_config(int argc, char *argv[], struct users *u);
static int do_erps_instance_disable_config(int argc, char *argv[], struct users *u);
static int no_erps_ring_instance_id(int argc, char *argv[], struct users *u);
static int no_erps_mst_configuration(int argc, char *argv[], struct users *u);
static int do_erps_instance_revertive_config(int argc, char *argv[], struct users *u);
static int do_erps_instance_none_revertive_config(int argc, char *argv[], struct users *u);
int func_erps_inst_revert_config(struct users *u);
int func_erps_inst_none_revert_config(struct users *u);
static int do_erps_instance_level_config(int argc, char *argv[], struct users *u);
int func_erps_inst_level_config(struct users *u);
int func_erps_no_ring_config(struct users *u);
static int do_erps_instance_level(int argc, char *argv[], struct users *u);
static int no_erps_instance_level(int argc, char *argv[], struct users *u);
int func_erps_inst_time_guand_time_default_config(struct users *u);
int func_erps_inst_time_hold_off_default_config(struct users *u);
int func_erps_inst_time_wait_to_default_config(struct users *u);
static int do_erps_instance_profile_config(int argc, char *argv[], struct users *u);
static int do_erps_instance_profile_default_config(int argc, char *argv[], struct users *u);

#endif
