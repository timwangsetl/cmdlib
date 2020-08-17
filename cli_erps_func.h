#ifndef __FUNC_CLOCK__
#define __FUNC_CLOCK__
/* extern functions */
#define  CONFIG_NUM 10
int func_erps_ring_config(struct users *u);
int func_erps_inst_mst_id_config(struct users *u);
int func_erps_inst_ring_id_config(struct users *u);
int func_erps_inst_rpl_owner_east_config(struct users *u);
int func_erps_inst_rpl_owner_west_config(struct users *u);
int func_erps_inst_rpl_next_neighbor_east_config(struct users *u);
int func_erps_inst_rpl_next_neighbor_west_config(struct users *u);
int func_erps_inst_virtual_instance_config(struct users *u);
int func_erps_inst_delete_config(struct users *u);
int func_erps_inst_profile_config(struct users *u);
int func_erps_inst_profile_default_config(struct users *u);

/*----------------------------------------------------------------------------------------------------------------*/

#endif

