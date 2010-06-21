/*
   mod_ruid2 0.8.2
   Copyright (C) 2010 Monshouwer Internet Diensten

   Author: Kees Monshouwer

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

   Based on:
   - mod_suid - http://bluecoara.net/servers/apache/mod_suid2_en.phtml
     Copyright 2004 by Hideo NAKAMITSU. All rights reserved
   - mod_ruid - http://websupport.sk/~stanojr/projects/mod_ruid/
     Copyright 2004 by Pavel Stano. All rights reserved

   Instalation:
   - /usr/apache/bin/apxs -a -i -l cap -c mod_ruid2.c
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

#include <unistd.h>
#include <sys/prctl.h>
#include <sys/capability.h>

#define MODULE_NAME		"mod_ruid2"
#define MODULE_VERSION		"0.8.2"

#define RUID_DEFAULT_UID	48
#define RUID_DEFAULT_GID	48
#define RUID_MIN_UID		100
#define RUID_MIN_GID		100

#define RUID_MAXGROUPS		4

#define RUID_MODE_STAT		0
#define RUID_MODE_CONF		1
#define RUID_MODE_UNDEFINED	2

#define RUID_CAP_MODE_DROP	0
#define RUID_CAP_MODE_KEEP	1
#define RUID_CAP_MODE_UNDEFINED 2

#define UNSET			-1


typedef struct
{
	int8_t ruid_mode;

	uid_t ruid_uid;
	gid_t ruid_gid;
	gid_t groups[RUID_MAXGROUPS];
	int8_t groupsnr;
	int8_t ruid_cap_mode;
} ruid_dir_config_t;


typedef struct
{
	uid_t default_uid;
	gid_t default_gid;
	uid_t min_uid;
	gid_t min_gid;

	int coredump;
} ruid_config_t;


module AP_MODULE_DECLARE_DATA ruid2_module;


static void *create_dir_config(apr_pool_t *p, char *d)
{
	ruid_dir_config_t *dconf = apr_pcalloc (p, sizeof(*dconf));

	dconf->ruid_mode=RUID_MODE_UNDEFINED;
	dconf->ruid_uid=UNSET;
	dconf->ruid_gid=UNSET;
	dconf->groupsnr=0;
	dconf->ruid_cap_mode=RUID_CAP_MODE_UNDEFINED;

	return dconf;
}


static void *merge_dir_config(apr_pool_t *p, void *base, void *overrides)
{
	ruid_dir_config_t *parent = base;
	ruid_dir_config_t *child = overrides;
	ruid_dir_config_t *conf = apr_pcalloc(p, sizeof(ruid_dir_config_t));

	if (child->ruid_mode == RUID_MODE_UNDEFINED) {
		conf->ruid_mode = parent->ruid_mode;
	} else {
		conf->ruid_mode = child->ruid_mode;
	}
	if (conf->ruid_mode == RUID_MODE_STAT) {
		conf->ruid_uid=RUID_DEFAULT_UID;
		conf->ruid_gid=RUID_DEFAULT_GID;
		conf->groupsnr=0;
	} else {
		conf->ruid_uid = (child->ruid_uid == UNSET) ? parent->ruid_uid : child->ruid_uid;
		conf->ruid_gid = (child->ruid_gid == UNSET) ? parent->ruid_gid : child->ruid_gid;
		if (child->groupsnr > 0) {
			memcpy(conf->groups, child->groups, sizeof(child->groups));
			conf->groupsnr = child->groupsnr;
		} else {
			memcpy(conf->groups, parent->groups, sizeof(parent->groups));
			conf->groupsnr = parent->groupsnr;
		}
	}
	if (child->ruid_cap_mode == RUID_CAP_MODE_UNDEFINED) {
		conf->ruid_cap_mode = parent->ruid_cap_mode;
	} else {
		conf->ruid_cap_mode = child->ruid_cap_mode;
	}

	return conf;
}


static void *create_config (apr_pool_t *p, server_rec *s)
{
	ruid_config_t *conf = apr_palloc (p, sizeof (*conf));

	conf->default_uid=RUID_DEFAULT_UID;
	conf->default_gid=RUID_DEFAULT_GID;
	conf->min_uid=RUID_MIN_UID;
	conf->min_gid=RUID_MIN_GID;

	conf->coredump=0;

	return conf;
}


/* configure option functions */
static const char * set_mode (cmd_parms * cmd, void *mconfig, const char *arg)
{
	ruid_dir_config_t *conf = (ruid_dir_config_t *) mconfig;
	const char *err = ap_check_cmd_context (cmd, NOT_IN_FILES | NOT_IN_LIMIT);

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


static const char * set_groups (cmd_parms * cmd, void *mconfig, const char *arg)
{
	ruid_dir_config_t *conf = (ruid_dir_config_t *) mconfig;
	const char *err = ap_check_cmd_context (cmd, NOT_IN_FILES | NOT_IN_LIMIT);

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
	ruid_config_t *conf = ap_get_module_config (cmd->server->module_config, &ruid2_module);
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
	ruid_config_t *conf = ap_get_module_config (cmd->server->module_config, &ruid2_module);
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
	ruid_dir_config_t *conf = (ruid_dir_config_t *) mconfig;
	const char *err = ap_check_cmd_context (cmd, NOT_IN_FILES | NOT_IN_LIMIT);

	if (err != NULL) {
		return err;
	}

	conf->ruid_uid = ap_uname2id(uid);
	conf->ruid_gid = ap_gname2id(gid);

	return NULL;
}


static const char * set_cap_mode (cmd_parms *cmd, void *mconfig, int flag)
{
	ruid_dir_config_t *conf = (ruid_dir_config_t *) mconfig;
	const char *err = ap_check_cmd_context (cmd, NOT_IN_FILES | NOT_IN_LIMIT);

	if (err != NULL) {
		return err;
	}

	conf->ruid_cap_mode = (flag ? RUID_CAP_MODE_DROP : RUID_CAP_MODE_KEEP);

	return NULL;
}


/* configure options in httpd.conf */
static const command_rec ruid_cmds[] = {

	AP_INIT_TAKE1 ("RMode", set_mode, NULL, RSRC_CONF | ACCESS_CONF, "stat or config (default stat)"),
	AP_INIT_ITERATE ("RGroups", set_groups, NULL, RSRC_CONF | ACCESS_CONF, "Set aditional groups"),
	AP_INIT_TAKE2 ("RMinUidGid", set_minuidgid, NULL, RSRC_CONF, "Minimal uid or gid file/dir, else set[ug]id to default (RDefaultUidGid)"),
	AP_INIT_TAKE2 ("RDefaultUidGid", set_defuidgid, NULL, RSRC_CONF, "If uid or gid is < than RMinUidGid set[ug]id to this uid gid"),
	AP_INIT_TAKE2 ("RUidGid", set_uidgid, NULL, RSRC_CONF | ACCESS_CONF, "Minimal uid or gid file/dir, else set[ug]id to default (User,Group)"),
	AP_INIT_FLAG ("RDropCapMode", set_cap_mode, NULL, RSRC_CONF | ACCESS_CONF, "Drop capabilities permanent after set[ug]id"),
	{NULL}
};


/* run in post config hook ( we are parent process and we are uid 0) */
static int ruid_init (apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
	/* keep capabilities after setuid */
	prctl(PR_SET_KEEPCAPS,1);
	
	return OK;
}


/* run after child init we are uid User and gid Group */
static void ruid_child_init (apr_pool_t *p, server_rec *s)
{
	ruid_config_t *conf = ap_get_module_config (s->module_config, &ruid2_module);
	cap_t cap;
	cap_value_t capval[3];

	/* add module name to signature */
	ap_add_version_component(p, MODULE_NAME "/" MODULE_VERSION);
	
	/* init cap with all zeros */
	cap=cap_init();
	capval[0]=CAP_SETUID;
	capval[1]=CAP_SETGID;
	capval[2]=CAP_DAC_READ_SEARCH;
	cap_set_flag(cap,CAP_PERMITTED,3,capval,CAP_SET);
	if (cap_set_proc(cap)!=0) {
    		ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s CRITICAL ERROR ruid_child_init:cap_set_proc failed", MODULE_NAME);
	}
	cap_free(cap);

	/* check if process is dumpable */
	if (prctl(PR_GET_DUMPABLE)) {
		conf->coredump = 1;
	}
}


static int ruid_suidback (request_rec *r)
{
	ruid_config_t *conf = ap_get_module_config(r->server->module_config, &ruid2_module);
	ruid_dir_config_t *dconf = ap_get_module_config(r->per_dir_config, &ruid2_module);

	cap_t cap;
	cap_value_t capval[2];
	
	if (dconf->ruid_cap_mode != RUID_CAP_MODE_DROP) {

		cap=cap_get_proc();
		capval[0]=CAP_SETUID;
		capval[1]=CAP_SETGID;
		cap_set_flag(cap,CAP_EFFECTIVE,2,capval,CAP_SET);
		if (cap_set_proc(cap)!=0) {
			ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s CRITICAL ERROR ruid_ruidback:cap_set_proc failed before setuid", MODULE_NAME);
		}
		cap_free(cap);

		setgroups(0,NULL);
		setgid(unixd_config.group_id);
		setuid(unixd_config.user_id);
	
		/* set httpd process dumpable after setuid */
		if (conf->coredump) {
			prctl(PR_SET_DUMPABLE,1);
		}

		cap=cap_get_proc();
		capval[0]=CAP_SETUID;
		capval[1]=CAP_SETGID;
		cap_set_flag(cap,CAP_EFFECTIVE,2,capval,CAP_CLEAR);
		if (cap_set_proc(cap)!=0) {
			ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s CRITICAL ERROR ruid_ruidback:cap_set_proc failed after setuid", MODULE_NAME);
		}
		cap_free(cap);
	}

	return DECLINED;
}


static int ruid_setup (request_rec *r) {

	cap_t cap;
	cap_value_t capval[1];

	cap=cap_get_proc();
	capval[0]=CAP_DAC_READ_SEARCH;
	cap_set_flag(cap,CAP_EFFECTIVE,1,capval,CAP_SET);
	if (cap_set_proc(cap)!=0) {
		ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s CRITICAL ERROR ruid_setup:cap_set_proc failed", MODULE_NAME);
	}
	cap_free(cap);

	return DECLINED;
}


/* run in map_to_storage hook */
static int ruid_uiiii (request_rec *r)
{
	ruid_config_t *conf = ap_get_module_config(r->server->module_config, &ruid2_module);
	ruid_dir_config_t *dconf = ap_get_module_config(r->per_dir_config, &ruid2_module);

	int retval = DECLINED;
	cap_t cap;
	cap_value_t capval[3];
	int gid, uid;

	cap=cap_get_proc();
	capval[0]=CAP_SETUID;
	capval[1]=CAP_SETGID;
	cap_set_flag(cap,CAP_EFFECTIVE,2,capval,CAP_SET);
	if (cap_set_proc(cap)!=0) {
		ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s CRITICAL ERROR ruid_uiiii:cap_set_proc failed before setuid", MODULE_NAME);
	}
	cap_free(cap);

/* DEUBG
	ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s r->finfo.fname: %s r->filename: %s r->finfo.group: %d r->finfo.user: %d r->hostname: %s r->method: %s r->handler: %s r->unparsed_uri: %s r->path_info: %s r->canonical_filename: %s r->finfo.filetype: %d r->finfo.valid&APR_FINFO_USER: %d",MODULE_NAME,r->finfo.fname,r->filename,r->finfo.group,r->finfo.user,r->hostname,r->method,r->handler,r->unparsed_uri,r->path_info,r->canonical_filename,r->finfo.filetype,r->finfo.valid&APR_FINFO_USER);
*/

	if (dconf->ruid_mode==RUID_MODE_STAT || dconf->ruid_mode==RUID_MODE_UNDEFINED) {
		/* set uid,gid to uid,gid of file
		 * if file does not exist, finfo.user and finfo.group is set to uid,gid of parent directory
		 */
		gid=r->finfo.group;
		uid=r->finfo.user;
	} else {
		gid=dconf->ruid_gid;
		uid=dconf->ruid_uid;
	}

	/* if uid of filename is less than conf->min_uid then set to conf->default_uid */
	if (uid < conf->min_uid) {
		uid=conf->default_uid;
	}
	if (gid < conf->min_gid) {
		gid=conf->default_gid;
	}

	if (dconf->groupsnr>0) {
		setgroups(dconf->groupsnr, dconf->groups);
	} else {
		setgroups(0, NULL);
	}

	/* final set[ug]id */
	if (setgid (gid) != 0)
	{
		ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s %s %s setgid(%d) failed. getgid=%d getuid=%d", MODULE_NAME, ap_get_server_name(r), r->the_request, dconf->ruid_gid, getgid(), getuid());
		retval = HTTP_FORBIDDEN;
	} else {
		if (setuid (uid) != 0)
		{
			ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s %s %s setuid(%d) failed. getuid=%d", MODULE_NAME, ap_get_server_name(r), r->the_request, dconf->ruid_uid, getuid());
			retval = HTTP_FORBIDDEN;
		}
	}
	
	/* set httpd process dumpable after setuid */
	if (conf->coredump) {
		prctl(PR_SET_DUMPABLE,1);
	}

	/* clear capabilties from effective set */
	cap=cap_get_proc();
	capval[0]=CAP_SETUID;
	capval[1]=CAP_SETGID;
	capval[2]=CAP_DAC_READ_SEARCH;
	cap_set_flag(cap,CAP_EFFECTIVE,3,capval,CAP_CLEAR);

	if (dconf->ruid_cap_mode == RUID_CAP_MODE_DROP) {
		/* clear capabilities from permitted set (permanent) */
		cap_set_flag(cap,CAP_PERMITTED,3,capval,CAP_CLEAR);

		/* kill child after this request */
		ap_max_requests_per_child = 1;
	}
		                            
	if (cap_set_proc(cap)!=0) {
		ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s CRITICAL ERROR ruid_uiiii:cap_set_proc failed after setuid", MODULE_NAME);
	}
	cap_free(cap);

	return retval;
}


static void register_hooks (apr_pool_t * p)
{
	ap_hook_post_config (ruid_init, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_child_init (ruid_child_init, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_post_read_request(ruid_setup, NULL, NULL,APR_HOOK_MIDDLE);
	ap_hook_header_parser(ruid_uiiii, NULL, NULL, APR_HOOK_FIRST);
	ap_hook_log_transaction (ruid_suidback, NULL, NULL, APR_HOOK_LAST);
}


module AP_MODULE_DECLARE_DATA ruid2_module = {
	STANDARD20_MODULE_STUFF,
	create_dir_config,		/* dir config creater */
	merge_dir_config,		/* dir merger --- default is to override */
	create_config,			/* server config */
	NULL,				/* merge server config */
	ruid_cmds,			/* command apr_table_t */
	register_hooks			/* register hooks */
};
