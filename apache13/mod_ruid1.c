/*
   WARNING: this module is beta software.

   mod_ruid1 0.8b
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
   - /usr/apache/bin/apxs -a -i -l cap -c mod_ruid1.c
*/
							     
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_conf_globals.h"

#include <unistd.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <sys/stat.h>


#define MODULE_NAME		"mod_ruid1"
#define MODULE_VERSION		"0.8b"

#define RUID_DEFAULT_UID	48
#define RUID_DEFAULT_GID	48
#define RUID_MIN_UID		100
#define RUID_MIN_GID		100

#define RUID_MAXGROUPS		4

#define RUID_MODE_STAT		0
#define RUID_MODE_CONF		1
#define RUID_MODE_UNDEFINED	2

#define UNSET			-1


typedef struct
{
	int8_t ruid_mode;

	uid_t ruid_uid;
	gid_t ruid_gid;
	gid_t groups[RUID_MAXGROUPS];
	int8_t groupsnr;
} ruid_dir_config_t;


typedef struct
{
	uid_t default_uid;
	gid_t default_gid;
	uid_t min_uid;
	gid_t min_gid;

	int coredump;
} ruid_config_t;


module MODULE_VAR_EXPORT ruid1_module;


static void *create_dir_config(pool *p, char *d)
{
	ruid_dir_config_t *dconf = ap_pcalloc (p, sizeof(*dconf));

	dconf->ruid_mode=RUID_MODE_UNDEFINED;
	dconf->ruid_uid=UNSET;
	dconf->ruid_gid=UNSET;
	dconf->groupsnr=0;

	return dconf;
}


static void *merge_dir_config(pool *p, void *base, void *overrides)
{
	ruid_dir_config_t *parent = base;
	ruid_dir_config_t *child = overrides;
	ruid_dir_config_t *conf = ap_pcalloc(p, sizeof(ruid_dir_config_t));

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

	return conf;
}


static void *create_config (pool *p, server_rec *s)
{
	ruid_config_t *conf = ap_palloc (p, sizeof (*conf));

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

	if (conf->groupsnr<RUID_MAXGROUPS) {
		conf->groups[conf->groupsnr++] = ap_gname2id (arg);
	}

	return NULL;
}


static const char * set_minuidgid (cmd_parms * cmd, void *mconfig, const char *uid, const char *gid)
{
	ruid_config_t *conf = ap_get_module_config (cmd->server->module_config, &ruid1_module);

	conf->min_uid = ap_uname2id(uid);
	conf->min_gid = ap_gname2id(gid);

	return NULL;
}


static const char * set_defuidgid (cmd_parms * cmd, void *mconfig, const char *uid, const char *gid)
{
	ruid_config_t *conf = ap_get_module_config (cmd->server->module_config, &ruid1_module);

	conf->default_uid = ap_uname2id(uid);
	conf->default_gid = ap_gname2id(gid);

	return NULL;
}


static const char * set_uidgid (cmd_parms * cmd, void *mconfig, const char *uid, const char *gid)
{
	ruid_dir_config_t *conf = (ruid_dir_config_t *) mconfig;

	conf->ruid_uid = ap_uname2id(uid);
	conf->ruid_gid = ap_gname2id(gid);

	return NULL;
}


/* configure options in httpd.conf */
static const command_rec ruid_cmds[] =
{
	{"RMode", set_mode, NULL, OR_ALL, TAKE1, "stat or config (default stat)"},
	{"RGroups", set_groups, NULL, RSRC_CONF | ACCESS_CONF, ITERATE, "Set aditional groups"},
	{"RMinUidGid", set_minuidgid, NULL, RSRC_CONF, TAKE2, "Minimal uid or gid file/dir, else set[ug]id to default (RDefaultUidGid)"},
	{"RDefaultUidGid", set_defuidgid, NULL, RSRC_CONF, TAKE2, "If uid or gid is < than RMinUidGid set[ug]id to this uid gid"},
	{"RUidGid", set_uidgid, NULL, RSRC_CONF | ACCESS_CONF, TAKE2, "Minimal uid or gid file/dir, else set[ug]id to default (User,Group)"},
	{NULL}
};


/* run in post config hook ( we are parent process and we are uid 0) */
static void ruid_init(server_rec *s, pool *p)
{
	/* keep capabilities after setuid */
	prctl(PR_SET_KEEPCAPS,1);
}


/* run after child init we are uid User and gid Group */
static void ruid_child_init (server_rec *s, pool *p)
{
	ruid_config_t *conf = ap_get_module_config (s->module_config, &ruid1_module);

	/* add module name to signature */
	ap_add_version_component("MODULE_NAME \"/\" MODULE_VERSION");

	/* check if process is dumpable */
	if (prctl(PR_GET_DUMPABLE)) {
		conf->coredump = 1;
	}
}


static int ruid_suidback (request_rec *r)
{
	ruid_config_t *conf = ap_get_module_config(r->server->module_config, &ruid1_module);

	cap_t cap;
	cap_value_t capval[2];

	cap=cap_get_proc();
	capval[0]=CAP_SETUID;
	capval[1]=CAP_SETGID;
	cap_set_flag(cap,CAP_EFFECTIVE,2,capval,CAP_SET);
	if (cap_set_proc(cap)!=0) {
		ap_log_error (APLOG_MARK, APLOG_ERR, 0, "%s CRITICAL ERROR ruid_ruidback:cap_set_proc failed before setuid", MODULE_NAME);
	}
	cap_free(cap);

	setgroups(0,NULL);
	setgid(ap_group_id);
	setuid(ap_user_id);
	
	/* set httpd process dumpable after setuid */
	if (conf->coredump) {
		prctl(PR_SET_DUMPABLE,1);
	}

	cap=cap_get_proc();
	capval[0]=CAP_SETUID;
	capval[1]=CAP_SETGID;
	cap_set_flag(cap,CAP_EFFECTIVE,2,capval,CAP_CLEAR);
	if (cap_set_proc(cap)!=0) {
		ap_log_error (APLOG_MARK, APLOG_ERR, 0, "%s CRITICAL ERROR ruid_ruidback:cap_set_proc failed after setuid", MODULE_NAME);
	}
	cap_free(cap);

	return DECLINED;
}


static int ruid_setup (request_rec *r) {

	cap_t cap;
	cap_value_t capval[1];

	cap=cap_get_proc();
	capval[0]=CAP_DAC_OVERRIDE;
	cap_set_flag(cap,CAP_EFFECTIVE,1,capval,CAP_SET);
	if (cap_set_proc(cap)!=0) {
		ap_log_error (APLOG_MARK, APLOG_ERR, 0, "%s CRITICAL ERROR ruid_setup:cap_set_proc failed", MODULE_NAME);
	}
	cap_free(cap);

	return DECLINED;
}


/* run in map_to_storage hook */
static int ruid_uiiii (request_rec *r)
{
	ruid_config_t *conf = ap_get_module_config(r->server->module_config, &ruid1_module);
	ruid_dir_config_t *dconf = ap_get_module_config(r->per_dir_config, &ruid1_module);
	int retval = DECLINED;
	struct stat fstat;
	cap_t cap;
	cap_value_t capval[3];
	int gid, uid;
	char *dir;

	cap=cap_get_proc();
	capval[0]=CAP_SETUID;
	capval[1]=CAP_SETGID;
	cap_set_flag(cap,CAP_EFFECTIVE,2,capval,CAP_SET);
	if (cap_set_proc(cap)!=0) {
		ap_log_error (APLOG_MARK, APLOG_ERR, 0, "%s CRITICAL ERROR ruid_uiiii:cap_set_proc failed before setuid", MODULE_NAME);
	}
	cap_free(cap);

/* DEUBG
	ap_log_error (APLOG_MARK, APLOG_ERR, 0, "%s r->finfo.fname: %s r->filename: %s r->finfo.group: %d r->finfo.user: %d r->hostname: %s r->method: %s r->handler: %s r->unparsed_uri: %s r->path_info: %s r->canonical_filename: %s r->finfo.filetype: %d r->finfo.valid&APR_FINFO_USER: %d",MODULE_NAME,r->finfo.fname,r->filename,r->finfo.group,r->finfo.user,r->hostname,r->method,r->handler,r->unparsed_uri,r->path_info,r->canonical_filename,r->finfo.filetype,r->finfo.valid&APR_FINFO_USER);
*/
	
	gid=dconf->ruid_gid;
        uid=dconf->ruid_uid;
		
	if (dconf->ruid_mode==RUID_MODE_STAT || dconf->ruid_mode==RUID_MODE_UNDEFINED) {
		/* set uid,gid to uid,gid of file
		 * if file does not exist, uid,gid is set to uid,gid of parent directory
		 */
		if (r->finfo.st_mode != 0) {		
			dir=ap_pstrdup(r->pool, r->filename);
		} else {
			dir=ap_pstrdup(r->pool, ap_make_dirstr_parent(r->pool, r->filename));
		}
		if (stat(dir, &fstat) == 0) {
			gid=fstat.st_gid;
		        uid=fstat.st_uid;
/* DEBUG
			ap_log_error (APLOG_MARK, APLOG_ERR, 0, "%s Filename: %s - Pathinfo: %s - gid: %d - uid: %d", MODULE_NAME, r->filename, ap_make_dirstr_parent(r->pool, r->filename), gid, uid);
*/
		} else {
		        ap_log_error (APLOG_MARK, APLOG_ERR, 0, "%s %s %s cannot stat", MODULE_NAME, ap_get_server_name (r), r->the_request);
			retval = HTTP_FORBIDDEN;
		}
	}

	if (retval == DECLINED) {
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
			ap_log_error (APLOG_MARK, APLOG_ERR, 0, "%s %s %s setgid(%d) failed. getgid=%d getuid=%d", MODULE_NAME, ap_get_server_name (r), r->the_request, dconf->ruid_gid, getgid (), getuid());
			retval = HTTP_FORBIDDEN;
		} else {
			if (setuid (uid) != 0)
			{
				ap_log_error (APLOG_MARK, APLOG_ERR, 0, "%s %s %s setuid(%d) failed. getuid=%d", MODULE_NAME, ap_get_server_name (r), r->the_request, dconf->ruid_uid, getuid ());
				retval = HTTP_FORBIDDEN;
			}
		}
	
		/* set httpd process dumpable after setuid */
		if (conf->coredump) {
			prctl(PR_SET_DUMPABLE,1);
		}
	}

	/* clear capabilties from effective set */
	cap=cap_get_proc();
	capval[0]=CAP_SETUID;
	capval[1]=CAP_SETGID;
	capval[2]=CAP_DAC_OVERRIDE;
	cap_set_flag(cap,CAP_EFFECTIVE,3,capval,CAP_CLEAR);
	if (cap_set_proc(cap)!=0) {
		ap_log_error (APLOG_MARK, APLOG_ERR, 0, "%s CRITICAL ERROR ruid_uiiii:cap_set_proc failed after setuid", MODULE_NAME);
	}
	cap_free(cap);

	return retval;
}


module MODULE_VAR_EXPORT ruid1_module =
{
	STANDARD_MODULE_STUFF,
	ruid_init,			/* initializer */
	create_dir_config,		/* dir config creater */
	merge_dir_config,		/* dir merger --- default is to override */
	create_config,			/* server config */
	NULL,				/* merge server configs */
	ruid_cmds,			/* command table */
	NULL,				/* handlers */
	NULL,				/* filename translation */
	NULL,				/* check_user_id */
	NULL,				/* check auth */
	NULL,				/* check access */
	NULL,				/* type_checker */
	NULL,				/* fixups */
	ruid_suidback,			/* logger */
	ruid_uiiii,			/* header parser */
	ruid_child_init,		/* child_init */
	NULL,				/* child_exit */
	ruid_setup			/* post read-request */
};
