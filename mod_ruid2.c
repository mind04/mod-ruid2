/*
   mod_ruid2 0.9.1
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

#define CORE_PRIVATE

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
#define MODULE_VERSION		"0.9.1"

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

#define UNSET			-1
#define SET			1


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
	int8_t stat_used;
	const char *chroot_dir;
	const char *document_root;
} ruid_config_t;


module AP_MODULE_DECLARE_DATA ruid2_module;


static int coredump, cap_mode, stat_mode, chroot_root;
static const char *old_root;


static void *create_dir_config(apr_pool_t *p, char *d)
{
	ruid_dir_config_t *dconf = apr_pcalloc (p, sizeof(*dconf));

	dconf->ruid_mode=RUID_MODE_UNDEFINED;
	dconf->ruid_uid=UNSET;
	dconf->ruid_gid=UNSET;
	dconf->groupsnr=0;

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
		if (child->groupsnr != 0) {
			memcpy(conf->groups, child->groups, sizeof(child->groups));
			conf->groupsnr = child->groupsnr;
		} else {
			memcpy(conf->groups, parent->groups, sizeof(parent->groups));
			conf->groupsnr = parent->groupsnr;
		}
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
	conf->stat_used=UNSET;
	conf->chroot_dir=NULL;
	conf->document_root=NULL;

	return conf;
}


/* configure option functions */
static const char *set_mode (cmd_parms *cmd, void *mconfig, const char *arg)
{
	ruid_config_t *conf = ap_get_module_config (cmd->server->module_config, &ruid2_module);
	ruid_dir_config_t *dconf = (ruid_dir_config_t *) mconfig;
	const char *err = ap_check_cmd_context (cmd, NOT_IN_FILES | NOT_IN_LIMIT);

	if (err != NULL) {
		return err;
	}

	if (strcasecmp(arg,"config")==0) {
		dconf->ruid_mode=RUID_MODE_CONF;
	} else {
		dconf->ruid_mode=RUID_MODE_STAT;
		conf->stat_used=SET;
	}

	return NULL;
}


static const char *set_groups (cmd_parms *cmd, void *mconfig, const char *arg)
{
	ruid_dir_config_t *dconf = (ruid_dir_config_t *) mconfig;
	const char *err = ap_check_cmd_context (cmd, NOT_IN_FILES | NOT_IN_LIMIT);

	if (err != NULL) {
		return err;
	}

	if (strcasecmp(arg,"@none")==0) {
	    dconf->groupsnr=-1;
	}
	
	if (dconf->groupsnr<RUID_MAXGROUPS && dconf->groupsnr>-1) {
		dconf->groups[dconf->groupsnr++] = ap_gname2id (arg);
	}

	return NULL;
}


static const char *set_minuidgid (cmd_parms *cmd, void *mconfig, const char *uid, const char *gid)
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


static const char *set_defuidgid (cmd_parms *cmd, void *mconfig, const char *uid, const char *gid)
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


static const char *set_uidgid (cmd_parms *cmd, void *mconfig, const char *uid, const char *gid)
{
	ruid_dir_config_t *dconf = (ruid_dir_config_t *) mconfig;
	const char *err = ap_check_cmd_context (cmd, NOT_IN_FILES | NOT_IN_LIMIT);

	if (err != NULL) {
		return err;
	}

	dconf->ruid_uid = ap_uname2id(uid);
	dconf->ruid_gid = ap_gname2id(gid);

	return NULL;
}


static const char *set_documentchroot (cmd_parms *cmd, void *mconfig, const char *chroot_dir, const char *document_root)
{
	ruid_config_t *conf = ap_get_module_config (cmd->server->module_config, &ruid2_module);
	const char *err = ap_check_cmd_context (cmd, NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);

	if (err != NULL) {
		return err;
	}

	conf->chroot_dir = chroot_dir;
	conf->document_root = document_root;
	
	return NULL;
}
                                                                        

/* configure options in httpd.conf */
static const command_rec ruid_cmds[] = {

	AP_INIT_TAKE1 ("RMode", set_mode, NULL, RSRC_CONF | ACCESS_CONF, "stat or config (default stat)"),
	AP_INIT_ITERATE ("RGroups", set_groups, NULL, RSRC_CONF | ACCESS_CONF, "Set aditional groups"),
	AP_INIT_TAKE2 ("RMinUidGid", set_minuidgid, NULL, RSRC_CONF, "Minimal uid or gid file/dir, else set[ug]id to default (RDefaultUidGid)"),
	AP_INIT_TAKE2 ("RDefaultUidGid", set_defuidgid, NULL, RSRC_CONF, "If uid or gid is < than RMinUidGid set[ug]id to this uid gid"),
	AP_INIT_TAKE2 ("RUidGid", set_uidgid, NULL, RSRC_CONF | ACCESS_CONF, "Minimal uid or gid file/dir, else set[ug]id to default (User,Group)"),
	AP_INIT_TAKE2 ("RDocumentChRoot", set_documentchroot, NULL, RSRC_CONF, "Set chroot directory and the document root inside"),
	{NULL}
};


/* run in post config hook ( we are parent process and we are uid 0) */
static int ruid_init (apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
	void *data;
	const char *userdata_key = "ruid2_init";

	/* keep capabilities after setuid */
	prctl(PR_SET_KEEPCAPS,1);

	/* initialize_module() will be called twice, and if it's a DSO
	 * then all static data from the first call will be lost. Only
	 * set up our static data on the second call. */
	apr_pool_userdata_get(&data, userdata_key, s->process->pool);
	if (!data) {
		apr_pool_userdata_set((const void *)1, userdata_key, apr_pool_cleanup_null, s->process->pool);
	} else {	                                              
		ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, MODULE_NAME "/" MODULE_VERSION " enabled");
	}
	
	return OK;
}


/* child cleanup function */
static apr_status_t ruid_child_exit(void *data)
{
	int fd = (int)((long)data);
	
	if (close(fd) < 0) {
		ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s CRITICAL ERROR closing root file descriptor (%d) failed", MODULE_NAME, fd);
		return APR_EGENERAL;
	}
	                                        
	return APR_SUCCESS;
}


/* run after child init we are uid User and gid Group */
static void ruid_child_init (apr_pool_t *p, server_rec *s)
{
	ruid_config_t *conf;
	int ncap;
	cap_t cap;
	cap_value_t capval[4];
	
	/* detect default uig/gid/groups */
	/* TODO */	

	/* add module name to signature */
	// ap_add_version_component(p, MODULE_NAME "/" MODULE_VERSION);
	
	stat_mode = UNSET;
	chroot_root = UNSET;
	while (s) {
		conf = ap_get_module_config(s->module_config, &ruid2_module);
		
		/* detect stat mode usage */
		if (conf->stat_used == SET && stat_mode == UNSET) {
			stat_mode = SET;
		}
		
		/* setup chroot jailbreak */
		if (conf->chroot_dir && chroot_root == UNSET) {
			if ((chroot_root = open("/.", O_RDONLY)) < 0) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s CRITICAL ERROR opening root file descriptor failed (%s)", MODULE_NAME, strerror(errno));
			} else {
				/* register cleanup function */
				apr_pool_cleanup_register(p, (void*)((long)chroot_root), ruid_child_exit, apr_pool_cleanup_null);
			}
		}
		
		if (stat_mode != UNSET && chroot_root != UNSET) {
			s = NULL;
		} else {
	    	        s = s->next;
	    	}
	}

	ncap = 2;
	/* init cap with all zeros */
	cap = cap_init();
	capval[0] = CAP_SETUID;
	capval[1] = CAP_SETGID;
	if (stat_mode == SET) capval[ncap++] = CAP_DAC_READ_SEARCH;
	if (chroot_root != UNSET) capval[ncap++] = CAP_SYS_CHROOT;
	cap_set_flag(cap, CAP_PERMITTED, ncap, capval, CAP_SET);
	if (cap_set_proc(cap) != 0) {
    		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s CRITICAL ERROR %s:cap_set_proc failed", MODULE_NAME, __func__);
	}
	cap_free(cap);

	/* MaxRequestsPerChild MUST be 1 to enable drop capability mode */
	cap_mode = (ap_max_requests_per_child == 1 ? RUID_CAP_MODE_DROP : RUID_CAP_MODE_KEEP);
		
	/* check if process is dumpable */
	coredump = prctl(PR_GET_DUMPABLE);
}


static int ruid_set_perm (request_rec *r, const char *from_func) 
{
	ruid_config_t *conf = ap_get_module_config(r->server->module_config, &ruid2_module);
	ruid_dir_config_t *dconf = ap_get_module_config(r->per_dir_config, &ruid2_module);
	
	int retval = DECLINED;
	int gid, uid, i;

	cap_t cap;
	cap_value_t capval[3];

	cap=cap_get_proc();
	capval[0]=CAP_SETUID;
	capval[1]=CAP_SETGID;
	cap_set_flag(cap,CAP_EFFECTIVE,2,capval,CAP_SET);
	if (cap_set_proc(cap)!=0) {
		ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s CRITICAL ERROR %s>%s:cap_set_proc failed before setuid", MODULE_NAME, from_func, __func__);
	}
	cap_free(cap);

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
		for (i=0; i < dconf->groupsnr; i++) {
			if (dconf->groups[i] < conf->min_gid) {
				dconf->groups[i]=conf->default_gid;
			}
		} 	
		setgroups(dconf->groupsnr, dconf->groups);
	} else {
		setgroups(0, NULL);
	}

	/* final set[ug]id */
	if (setgid (gid) != 0)
	{
		ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s %s %s %s>%s:setgid(%d) failed. getgid=%d getuid=%d", MODULE_NAME, ap_get_server_name(r), r->the_request, from_func, __func__, dconf->ruid_gid, getgid(), getuid());
		retval = HTTP_FORBIDDEN;
	} else {
		if (setuid (uid) != 0)
		{
			ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s %s %s %s>%s:setuid(%d) failed. getuid=%d", MODULE_NAME, ap_get_server_name(r), r->the_request, from_func, __func__, dconf->ruid_uid, getuid());
			retval = HTTP_FORBIDDEN;
		}
	}
	
	/* set httpd process dumpable after setuid */
	if (coredump) {
		prctl(PR_SET_DUMPABLE,1);
	}
	
	/* clear capabilties from effective set */
	cap=cap_get_proc();
	capval[0]=CAP_SETUID;
	capval[1]=CAP_SETGID;
	capval[2]=CAP_DAC_READ_SEARCH;
	cap_set_flag(cap,CAP_EFFECTIVE,3,capval,CAP_CLEAR);

	if (cap_mode == RUID_CAP_MODE_DROP) {
		/* clear capabilities from permitted set (permanent) */
		capval[3]=CAP_SYS_CHROOT;
		cap_set_flag(cap,CAP_PERMITTED,4,capval,CAP_CLEAR);
	}
		                            
	if (cap_set_proc(cap)!=0) {
		ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s CRITICAL ERROR %s>%s:cap_set_proc failed after setuid", MODULE_NAME, from_func, __func__);
	}
	cap_free(cap);

	return retval;
}


/* run in post_read_request hook */
static int ruid_setup (request_rec *r) {

	ruid_config_t *conf = ap_get_module_config (r->server->module_config,  &ruid2_module);
	ruid_dir_config_t *dconf = ap_get_module_config(r->per_dir_config, &ruid2_module);
	core_server_config *core = (core_server_config *) ap_get_module_config(r->server->module_config, &core_module);
         
	int ncap=0;
	cap_t cap;
	cap_value_t capval[2];

	if (dconf->ruid_mode==RUID_MODE_STAT) capval[ncap++] = CAP_DAC_READ_SEARCH;
	if (chroot_root != UNSET) capval[ncap++] = CAP_SYS_CHROOT;
	if (ncap) {
		cap=cap_get_proc();
		cap_set_flag(cap, CAP_EFFECTIVE, ncap, capval, CAP_SET);
		if (cap_set_proc(cap)!=0) {
			ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s CRITICAL ERROR %s:cap_set_proc failed", MODULE_NAME, __func__);
		}
		cap_free(cap);
	}	
	
	/* do chroot trick only if chrootdir is defined */
	if (conf->chroot_dir)
	{
		old_root = ap_document_root(r);
		core->ap_document_root = conf->document_root;
		if (chdir(conf->chroot_dir) != 0)
		{
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,"%s %s %s chdir to %s failed", MODULE_NAME, ap_get_server_name (r), r->the_request, conf->chroot_dir);
			return HTTP_FORBIDDEN;
		}
		if (chroot(conf->chroot_dir) != 0)
		{
			ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL,"%s %s %s chroot to %s failed", MODULE_NAME, ap_get_server_name (r), r->the_request, conf->chroot_dir);
			return HTTP_FORBIDDEN;
		}
	
		cap = cap_get_proc();
		capval[0] = CAP_SYS_CHROOT;
		cap_set_flag(cap, CAP_EFFECTIVE, 1, capval, CAP_CLEAR);
		if (cap_set_proc(cap) != 0 )
		{
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s CRITICAL ERROR %s:cap_set_proc failed", MODULE_NAME, __func__);
		}
		cap_free(cap);
	}
	
	if (dconf->ruid_mode==RUID_MODE_CONF)
	{
		return ruid_set_perm(r, __func__);
	} else {
		return DECLINED;
	}
}


/* run in map_to_storage hook */
static int ruid_uiiii (request_rec *r)
{
	return ruid_set_perm(r, __func__);
}


/* run in log_transaction hook */
static int ruid_suidback (request_rec *r)
{
	ruid_config_t *conf = ap_get_module_config (r->server->module_config, &ruid2_module);
	core_server_config *core = (core_server_config *) ap_get_module_config(r->server->module_config, &core_module);

	cap_t cap;
	cap_value_t capval[3];
	
	if (cap_mode == RUID_CAP_MODE_KEEP) {

		cap=cap_get_proc();
		capval[0]=CAP_SETUID;
		capval[1]=CAP_SETGID;
		capval[2]=CAP_SYS_CHROOT;
		cap_set_flag(cap, CAP_EFFECTIVE, (conf->chroot_dir ? 3 : 2), capval, CAP_SET);
		if (cap_set_proc(cap)!=0) {
			ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s CRITICAL ERROR %s:cap_set_proc failed before setuid", MODULE_NAME, __func__);
		}
		cap_free(cap);

		setgroups(0,NULL);
		setgid(unixd_config.group_id);
		setuid(unixd_config.user_id);
	
		/* set httpd process dumpable after setuid */
		if (coredump) {
			prctl(PR_SET_DUMPABLE,1);
		}
		
		/* jail break */
		if (conf->chroot_dir) {
			if (fchdir(chroot_root) < 0) {
				ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s failed to fchdir to root dir (%d) (%s)", MODULE_NAME, chroot_root, strerror(errno));
			} else {
				if (chroot(".") != 0) {
					ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s jail break failed", MODULE_NAME);
				}
			}
			core->ap_document_root = old_root;
		}

		cap=cap_get_proc();
		capval[0]=CAP_SETUID;
		capval[1]=CAP_SETGID;
		capval[2]=CAP_SYS_CHROOT;
		cap_set_flag(cap, CAP_EFFECTIVE, 3, capval, CAP_CLEAR);
		if (cap_set_proc(cap)!=0) {
			ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s CRITICAL ERROR %s:cap_set_proc failed after setuid", MODULE_NAME, __func__);
		}
		cap_free(cap);
	}

	return DECLINED;
}


static void register_hooks (apr_pool_t *p)
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
