#ifndef __FILE_SYS_H
#define __FILE_SYS_H

static int do_cd(int argc, char *argv[], struct users *u);
static int do_cd_dir(int argc, char *argv[], struct users *u);
static int do_pwd(int argc, char *argv[], struct users *u);
static int do_rd(int argc, char *argv[], struct users *u);
static int do_rd_dir(int argc, char *argv[], struct users *u);
static int do_delete(int argc, char *argv[], struct users *u);
static int do_delete_file(int argc, char *argv[], struct users *u);

static int do_dir(int argc, char *argv[], struct users *u);
static int do_dir_dir(int argc, char *argv[], struct users *u);
static int do_format(int argc, char *argv[], struct users *u);
static int do_md(int argc, char *argv[], struct users *u);
static int do_md_dir(int argc, char *argv[], struct users *u);

static int do_mv(int argc, char *argv[], struct users *u);
static int do_mv_file(int argc, char *argv[], struct users *u);
static int do_write(int argc, char *argv[], struct users *u);

static int do_copy(int argc, char *argv[], struct users *u);
static int do_copy_src_flash(int argc, char *argv[], struct users *u);
static int do_copy_src_tftp(int argc, char *argv[], struct users *u);
int do_copy_src_name(int argc, char *argv[], struct users *u);
static int do_copy_dst_flash(int argc, char *argv[], struct users *u);
static int do_copy_dst_tftp(int argc, char *argv[], struct users *u);
int do_copy_dst_name(int argc, char *argv[], struct users *u);
static int do_copy_src_start(int argc, char *argv[], struct users *u);

#endif
