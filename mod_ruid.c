/*
 * name: mod_ruid
 * version: 0.6
 * author: stanojr@websupport.sk
 * license: apache licence
 * homepage & documentation: http://websupport.sk/~stanojr/projects/mod_ruid/
 *
 * based on mod_suid - http://bluecoara.net/servers/apache/mod_suid2_en.phtml
 * Copyright 2004 by Hideo NAKAMITSU. All rights reserved
 * Copyright 2004 by Pavel Stano. All rights reserved
 *
 * instalation: /usr/apache/bin/apxs -a -i -l cap -c mod_ruid.c
 */

#include "apr_strings.h"
#include "apr_md5.h"
#include "apr_file_info.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "mpm_common.h"

#include <sys/prctl.h>
#include <sys/capability.h>

#define MODULE			"mod_ruid"

#define SUID_DEFAULT_UID	48
#define SUID_DEFAULT_GID	48
#define SUID_MIN_UID		100
#define SUID_MIN_GID		100

#define RUID_MAXGROUPS		4

typedef struct
{
#define	RUID_MODE_STAT		0
#define	RUID_MODE_CONF		1
	int8_t ruid_mode;

	uid_t suid_uid;
	gid_t suid_gid;
	uid_t default_uid;
	gid_t default_gid;
	uid_t min_uid;
	gid_t min_gid;

	gid_t groups[RUID_MAXGROUPS];
	int8_t groupsnr;
	int coredump;
	int coredumpsize;
} ruid_config_t;

module AP_MODULE_DECLARE_DATA ruid_module;

static void *create_config (apr_pool_t * p, server_rec *s)
{
	ruid_config_t *conf = apr_palloc (p, sizeof (*conf));

	conf->ruid_mode=RUID_MODE_STAT;
	conf->suid_uid=SUID_DEFAULT_UID;
	conf->suid_gid=SUID_DEFAULT_GID;
	conf->default_uid=SUID_DEFAULT_UID;
	conf->default_gid=SUID_DEFAULT_GID;
	conf->min_uid=SUID_MIN_UID;
	conf->min_gid=SUID_MIN_GID;
	conf->groupsnr=0;
	conf->coredump=0;
	conf->coredumpsize=0;

	return conf;
}

/* configure option functions */
static const char * set_mode (cmd_parms * cmd, void *mconfig, const char *arg)
{
	ruid_config_t *conf = ap_get_module_config (cmd->server->module_config, &ruid_module);
	const char *err = ap_check_cmd_context (cmd, NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);

	if (err != NULL) {
		return err;
	}

	if (strcasecmp(arg,"config")==0) {
		conf->ruid_mode=RUID_MODE_CONF;
	} else {
		conf->ruid_mode=RUID_MODE_STAT;
	}

	return NULL;
}

static const char * set_coredump (cmd_parms * cmd, void *mconfig, const char *arg)
{
	ruid_config_t *conf = ap_get_module_config (cmd->server->module_config, &ruid_module);
	const char *err = ap_check_cmd_context (cmd, NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);

	if (err != NULL) {
		return err;
	}

	if (strcasecmp(arg,"on")==0) {
		conf->coredump=1;
	}

	return NULL;
}

static const char * set_coredumpsize (cmd_parms * cmd, void *mconfig, const char *arg)
{
	ruid_config_t *conf = ap_get_module_config (cmd->server->module_config, &ruid_module);
	const char *err = ap_check_cmd_context (cmd, NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);

	if (err != NULL) {
		return err;
	}

	conf->coredumpsize=atoi(arg);

	return NULL;
}

static const char * set_groups (cmd_parms * cmd, void *mconfig, const char *arg)
{
	ruid_config_t *conf = ap_get_module_config (cmd->server->module_config, &ruid_module);
	const char *err = ap_check_cmd_context (cmd, NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);

	if (err != NULL) {
		return err;
	}

	if (conf->groupsnr<RUID_MAXGROUPS) {
		conf->groups[conf->groupsnr++] = ap_gname2id (arg);
	}
	
	return NULL;
}

static const char * set_minuidgid (cmd_parms * cmd, void *mconfig, const char *uid, const char *gid)
{
	ruid_config_t *conf = ap_get_module_config (cmd->server->module_config, &ruid_module);
	const char *err = ap_check_cmd_context (cmd, NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);

	if (err != NULL) {
		return err;
	}

	conf->min_uid = ap_uname2id(uid);
	conf->min_gid = ap_gname2id(gid);

	return NULL;
}

static const char * set_defuidgid (cmd_parms * cmd, void *mconfig, const char *uid, const char *gid)
{
	ruid_config_t *conf = ap_get_module_config (cmd->server->module_config, &ruid_module);
	const char *err = ap_check_cmd_context (cmd, NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);

	if (err != NULL) {
		return err;
	}

	conf->default_uid = ap_uname2id(uid);
	conf->default_gid = ap_gname2id(gid);

	return NULL;
}

static const char * set_uidgid (cmd_parms * cmd, void *mconfig, const char *uid, const char *gid)
{
	ruid_config_t *conf = ap_get_module_config (cmd->server->module_config, &ruid_module);
	const char *err = ap_check_cmd_context (cmd, NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);

	if (err != NULL) {
		return err;
	}

	conf->suid_uid = ap_uname2id(uid);
	conf->suid_gid = ap_gname2id(gid);

	return NULL;
}


/* configure options in httpd.conf */
static const command_rec ruid_cmds[] = {
	/* configuration of httpd.conf */
	AP_INIT_TAKE1 ("RMode", set_mode, NULL, RSRC_CONF, "stat or config (default stat)"),
	AP_INIT_TAKE1 ("RCoreDump", set_coredump, NULL, RSRC_CONF, "on or off (default off)"),
	AP_INIT_TAKE1 ("RCoreDumpSize", set_coredumpsize, NULL, RSRC_CONF, "0 for unlimited, or size of coredump (default 0)"),
	AP_INIT_ITERATE ("RGroups", set_groups, NULL, RSRC_CONF, "Set aditional groups"),
	AP_INIT_TAKE2 ("RMinUidGid", set_minuidgid, NULL, RSRC_CONF, "Minimal uid or gid file/dir, else set[ug]id to default (RDefaultUidGid)"),
	AP_INIT_TAKE2 ("RDefaultUidGid", set_defuidgid, NULL, RSRC_CONF, "If uid or gid is < than RMinUidGid set[ug]id to this uid gid"),
	AP_INIT_TAKE2 ("RUidGid", set_uidgid, NULL, RSRC_CONF, "Minimal uid or gid file/dir, else set[ug]id to default (User,Group)"),
	{NULL}
};


/* run in post config hook ( we are parent process and we are uid 0) */
static int ruid_init (apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
	ruid_config_t *conf = ap_get_module_config (s->module_config, &ruid_module);

	/* keep capabilities after setuid */
	prctl(PR_SET_KEEPCAPS,1);
	if (conf->coredump) {
		struct rlimit rlim;

		if (conf->coredumpsize==0) {
			rlim.rlim_cur=RLIM_INFINITY;
			rlim.rlim_max=RLIM_INFINITY;
		} else {
			rlim.rlim_cur=conf->coredumpsize;
			rlim.rlim_max=conf->coredumpsize;
		}
		setrlimit(RLIMIT_CORE,&rlim);
	}

	/* if conf->coredump!=0 set httpd process dumpable */
	if (conf->coredump) {
		prctl(PR_SET_DUMPABLE,1);
	}


	return OK;
}

/* run after child init we are uid User and gid Group */
static void ruid_child_init (apr_pool_t *p, server_rec *s)
{
	ruid_config_t *conf = ap_get_module_config (s->module_config, &ruid_module);
	cap_t cap;
	cap_value_t capval[3];

	/* init cap with all zeros */
	cap=cap_init();
	capval[0]=CAP_SETUID;
	capval[1]=CAP_SETGID;
	capval[2]=CAP_DAC_OVERRIDE;
	cap_set_flag(cap,CAP_PERMITTED,3,capval,CAP_SET);
	if (cap_set_proc(cap)!=0) {
		ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s CRITICAL ERROR ruid_child_init:cap_set_proc failed", MODULE);
	}
	cap_free(cap);

	/* if conf->coredump!=0 set httpd process dumpable */
	if (conf->coredump) {
		prctl(PR_SET_DUMPABLE,1);
	}

}

static int ruid_suidback (request_rec * r)
{
	ruid_config_t *conf = ap_get_module_config (r->server->module_config,  &ruid_module);
	struct stat filestat;
	int i;
	cap_t cap;
	cap_value_t capval[3];

	cap=cap_get_proc();
	capval[0]=CAP_SETUID;
	capval[1]=CAP_SETGID;
	cap_set_flag(cap,CAP_EFFECTIVE,2,capval,CAP_SET);
	if (cap_set_proc(cap)!=0) {
		ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s CRITICAL ERROR ruid_suidback:cap_set_proc failed before setuid", MODULE);
	}
	cap_free(cap);

	setgroups(0,NULL);
	setgid(unixd_config.group_id);
	setuid(unixd_config.user_id);

	cap=cap_get_proc();
	capval[0]=CAP_SETUID;
	capval[1]=CAP_SETGID;
	cap_set_flag(cap,CAP_EFFECTIVE,3,capval,CAP_CLEAR);

	if (cap_set_proc(cap)!=0) {
		ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s CRITICAL ERROR ruid_suidback:cap_set_proc failed after setuid", MODULE);
	}
	cap_free(cap);

	return DECLINED;
}

static int ruid_setup (request_rec * r) {

	cap_t cap;
	cap_value_t capval[1];

	cap=cap_get_proc();
	capval[0]=CAP_DAC_OVERRIDE;
	cap_set_flag(cap,CAP_EFFECTIVE,1,capval,CAP_SET);
	if (cap_set_proc(cap)!=0) {
		ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s CRITICAL ERROR ruid_setup:cap_set_proc failed", MODULE);
	}
	cap_free(cap);

	return DECLINED;
}

/* run in map_to_storage hook */
static int ruid_uiiii (request_rec * r)
{
	ruid_config_t *conf = ap_get_module_config (r->server->module_config,  &ruid_module);
	struct stat filestat;
	int i;
	cap_t cap;
	cap_value_t capval[3];

	cap=cap_get_proc();
	capval[0]=CAP_SETUID;
	capval[1]=CAP_SETGID;
	cap_set_flag(cap,CAP_EFFECTIVE,2,capval,CAP_SET);
	if (cap_set_proc(cap)!=0) {
		ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s CRITICAL ERROR ruid_mainstuff:cap_set_proc failed before setuid", MODULE);
	}
	cap_free(cap);

/* DEUBG
	ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s r->finfo.fname: %s r->filename: %s r->finfo.group: %d r->finfo.user: %d r->hostname: %s r->method: %s r->handler: %s r->unparsed_uri: %s r->path_info: %s r->canonical_filename: %s r->finfo.filetype: %d r->finfo.valid&APR_FINFO_USER: %d",MODULE,r->finfo.fname,r->filename,r->finfo.group,r->finfo.user,r->hostname,r->method,r->handler,r->unparsed_uri,r->path_info,r->canonical_filename,r->finfo.filetype,r->finfo.valid&APR_FINFO_USER);
*/

	if (conf->ruid_mode==RUID_MODE_STAT) {
		/* set uid,gid to uid,gid of file
		 * if file does not exist, finfo.user and finfo.group is set to uid,gid of parent directory
		 */
		conf->suid_gid=r->finfo.group;
		conf->suid_uid=r->finfo.user;
	} else if (conf->ruid_mode==RUID_MODE_CONF) {
		/* nothing, we already set uid,gid in httpd.conf */
	}

	/* if uid of filename is less than conf->min_uid then set to conf->default_uid */
	if (conf->suid_uid < conf->min_uid) {
		conf->suid_uid=conf->default_uid;
		
	}
	if (conf->suid_gid < conf->min_gid) {
		conf->suid_gid=conf->default_gid;
	}
	
	if (conf->groupsnr>0) {
   		setgroups (conf->groupsnr, conf->groups);
	} else {
		setgroups(0,NULL);
	}
  
	/* final set[ug]id */
	if (setgid (conf->suid_gid) != 0)
	{
		ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s %s %s setgid(%d) failed. getgid=%d getuid=%d", MODULE, ap_get_server_name (r), r->the_request, conf->suid_gid, getgid (), getuid());
		return HTTP_FORBIDDEN;
	}
	if (setuid (conf->suid_uid) != 0)
	{
		ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s %s %s setuid(%d) failed. getuid=%d", MODULE, ap_get_server_name (r), r->the_request, conf->suid_uid, getuid ());
		return HTTP_FORBIDDEN;
	}

	/* clear capabilties from effective set */
	cap=cap_get_proc();
	capval[0]=CAP_SETUID;
	capval[1]=CAP_SETGID;
	capval[2]=CAP_DAC_OVERRIDE;
	cap_set_flag(cap,CAP_EFFECTIVE,3,capval,CAP_CLEAR);

	if (cap_set_proc(cap)!=0) {
		ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s CRITICAL ERROR ruid_mainstuff:cap_set_proc failed after setuid", MODULE);
	}
	cap_free(cap);

	/* if conf->coredump!=0 set httpd process dumpable */
	if (conf->coredump) {
		prctl(PR_SET_DUMPABLE,1);
	}

	return DECLINED;
}

static void register_hooks (apr_pool_t * p)
{
	ap_hook_post_config (ruid_init, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_child_init (ruid_child_init, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_post_read_request(ruid_setup, NULL, NULL,APR_HOOK_MIDDLE);
	ap_hook_header_parser(ruid_uiiii, NULL, NULL, APR_HOOK_FIRST);
	ap_hook_log_transaction (ruid_suidback, NULL, NULL, APR_HOOK_LAST);
}

module AP_MODULE_DECLARE_DATA ruid_module = {
	STANDARD20_MODULE_STUFF,
	NULL,				/* dir config creater */
	NULL,				/* dir merger --- default is to override */
	create_config,			/* server config */
	NULL,				/* merge server config */
	ruid_cmds,			/* command apr_table_t */
	register_hooks			/* register hooks */
};
