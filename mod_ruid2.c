/*
   mod_ruid2 0.9.8
   Copyright (C) 2009-2013 Monshouwer Internet Diensten

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

   Issues:
   - https://github.com/mind04/mod-ruid2/issues
*/

#include <ap_release.h>

/* define CORE_PRIVATE for apache < 2.4 */
#if AP_SERVER_MAJORVERSION_NUMBER == 2 && AP_SERVER_MINORVERSION_NUMBER < 4
#define CORE_PRIVATE
#endif

#include <apr_strings.h>
#include <apr_md5.h>
#include <apr_file_info.h>
#include <unixd.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>
#include <mpm_common.h>

#include <unistd.h>
#include <sys/prctl.h>
#include <sys/capability.h>

#define MODULE_NAME		"mod_ruid2"
#define MODULE_VERSION		"0.9.8"

#define RUID_MIN_UID		100
#define RUID_MIN_GID		100

#define RUID_MAXGROUPS		8

#define RUID_MODE_CONF		0
#define RUID_MODE_STAT		1
#define RUID_MODE_UNDEFINED	2

#define RUID_MODE_STAT_NOT_USED	0
#define RUID_MODE_STAT_USED	1
#define RUID_CHROOT_NOT_USED	0
#define RUID_CHROOT_USED	1

#define RUID_CAP_MODE_DROP	0
#define RUID_CAP_MODE_KEEP	1

#define NONE			-2
#define UNSET			-1
#define SET			1

#define UNUSED(x) (void)(x)

/* added for apache 2.0 and 2.2 compatibility */
#if !AP_MODULE_MAGIC_AT_LEAST(20081201,0)
#define ap_unixd_config unixd_config
#endif

typedef struct
{
	int8_t ruid_mode;
	uid_t ruid_uid;
	gid_t ruid_gid;
	gid_t groups[RUID_MAXGROUPS];
	int groupsnr;
} ruid_dir_config_t;


typedef struct
{
	uid_t default_uid;
	gid_t default_gid;
	uid_t min_uid;
	gid_t min_gid;
	const char *chroot_dir;
	const char *document_root;
} ruid_config_t;


module AP_MODULE_DECLARE_DATA ruid2_module;


static int mode_stat_used	= RUID_MODE_STAT_NOT_USED;
static int chroot_used		= RUID_CHROOT_NOT_USED;
static int cap_mode		= RUID_CAP_MODE_KEEP;

static int coredump, root_handle;
static const char *old_root;

static gid_t startup_groups[RUID_MAXGROUPS];
static int startup_groupsnr;


static void *create_dir_config(apr_pool_t *p, char *d)
{
	char *dname = d;
	ruid_dir_config_t *dconf = apr_pcalloc (p, sizeof(*dconf));

	if (dname == NULL) {
		// Server config
		dconf->ruid_mode=RUID_MODE_CONF;
	} else {
		// Directory config
		dconf->ruid_mode=RUID_MODE_UNDEFINED;
	}
	dconf->ruid_uid=UNSET;
	dconf->ruid_gid=UNSET;
	dconf->groupsnr=UNSET;

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
		conf->ruid_uid=UNSET;
		conf->ruid_gid=UNSET;
		conf->groupsnr = (child->groupsnr != NONE) ? UNSET : NONE;
	} else {
		conf->ruid_uid = (child->ruid_uid == UNSET) ? parent->ruid_uid : child->ruid_uid;
		conf->ruid_gid = (child->ruid_gid == UNSET) ? parent->ruid_gid : child->ruid_gid;
		if (child->groupsnr == NONE) {
			conf->groupsnr = NONE;
		} else if (child->groupsnr > 0) {
			memcpy(conf->groups, child->groups, sizeof(child->groups));
			conf->groupsnr = child->groupsnr;
		} else if (parent->groupsnr > 0) {
			memcpy(conf->groups, parent->groups, sizeof(parent->groups));
			conf->groupsnr = parent->groupsnr;
		} else {
			conf->groupsnr = (child->groupsnr == UNSET) ? parent->groupsnr : child->groupsnr;
		}
	}

	return conf;
}


static void *create_config (apr_pool_t *p, server_rec *s)
{
	UNUSED(s);

	ruid_config_t *conf = apr_palloc (p, sizeof (*conf));

	conf->default_uid=ap_unixd_config.user_id;
	conf->default_gid=ap_unixd_config.group_id;
	conf->min_uid=RUID_MIN_UID;
	conf->min_gid=RUID_MIN_GID;
	conf->chroot_dir=NULL;
	conf->document_root=NULL;

	return conf;
}


/* configure option functions */
static const char *set_mode (cmd_parms *cmd, void *mconfig, const char *arg)
{
	ruid_dir_config_t *dconf = (ruid_dir_config_t *) mconfig;
	const char *err = ap_check_cmd_context (cmd, NOT_IN_FILES | NOT_IN_LIMIT);

	if (err != NULL) {
		return err;
	}

	if (strcasecmp(arg,"stat")==0) {
		dconf->ruid_mode=RUID_MODE_STAT;
		mode_stat_used |= RUID_MODE_STAT_USED;
	} else {
		dconf->ruid_mode=RUID_MODE_CONF;
	}

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


static const char *set_groups (cmd_parms *cmd, void *mconfig, const char *arg)
{
	ruid_dir_config_t *dconf = (ruid_dir_config_t *) mconfig;
	const char *err = ap_check_cmd_context (cmd, NOT_IN_FILES | NOT_IN_LIMIT);

	if (err != NULL) {
		return err;
	}

	if (strcasecmp(arg,"@none") == 0) {
		dconf->groupsnr=NONE;
	}

	if (dconf->groupsnr == UNSET) {
		dconf->groupsnr = 0;
	}
	if ((dconf->groupsnr < RUID_MAXGROUPS) && (dconf->groupsnr >= 0)) {
		dconf->groups[dconf->groupsnr++] = ap_gname2id (arg);
	}

	return NULL;
}


static const char *set_defuidgid (cmd_parms *cmd, void *mconfig, const char *uid, const char *gid)
{
	UNUSED(mconfig);

	ruid_config_t *conf = ap_get_module_config (cmd->server->module_config, &ruid2_module);
	const char *err = ap_check_cmd_context (cmd, NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);

	if (err != NULL) {
		return err;
	}

	conf->default_uid = ap_uname2id(uid);
	conf->default_gid = ap_gname2id(gid);

	return NULL;
}


static const char *set_minuidgid (cmd_parms *cmd, void *mconfig, const char *uid, const char *gid)
{
	UNUSED(mconfig);

	ruid_config_t *conf = ap_get_module_config (cmd->server->module_config, &ruid2_module);
	const char *err = ap_check_cmd_context (cmd, NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);

	if (err != NULL) {
		return err;
	}

	conf->min_uid = ap_uname2id(uid);
	conf->min_gid = ap_gname2id(gid);

	return NULL;
}


static const char *set_documentchroot (cmd_parms *cmd, void *mconfig, const char *chroot_dir, const char *document_root)
{
	UNUSED(mconfig);

	ruid_config_t *conf = ap_get_module_config (cmd->server->module_config, &ruid2_module);
	const char *err = ap_check_cmd_context (cmd, NOT_IN_DIR_LOC_FILE | NOT_IN_LIMIT);

	if (err != NULL) {
		return err;
	}

	conf->chroot_dir = chroot_dir;
	conf->document_root = document_root;
	chroot_used |= RUID_CHROOT_USED;

	return NULL;
}


/* configure options in httpd.conf */
static const command_rec ruid_cmds[] = {

	AP_INIT_TAKE1 ("RMode", set_mode, NULL, RSRC_CONF | ACCESS_CONF, "Set mode to config or stat (default: config)"),
	AP_INIT_TAKE2 ("RUidGid", set_uidgid, NULL, RSRC_CONF | ACCESS_CONF, "Minimal uid or gid file/dir, else set[ug]id to default (User,Group)"),
	AP_INIT_ITERATE ("RGroups", set_groups, NULL, RSRC_CONF | ACCESS_CONF, "Set additional groups"),
	AP_INIT_TAKE2 ("RDefaultUidGid", set_defuidgid, NULL, RSRC_CONF, "If uid or gid is < than RMinUidGid set[ug]id to this uid gid"),
	AP_INIT_TAKE2 ("RMinUidGid", set_minuidgid, NULL, RSRC_CONF, "Minimal uid or gid file/dir, else set[ug]id to default (RDefaultUidGid)"),
	AP_INIT_TAKE2 ("RDocumentChRoot", set_documentchroot, NULL, RSRC_CONF, "Set chroot directory and the document root inside"),
	{NULL, {NULL}, NULL, 0, NO_ARGS, NULL}
};


/* run in post config hook ( we are parent process and we are uid 0) */
static int ruid_init (apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
	UNUSED(p);
	UNUSED(plog);
	UNUSED(ptemp);

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

		/* MaxRequestsPerChild MUST be 1 to enable drop capability mode */
		if (ap_max_requests_per_child == 1) {
			ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, MODULE_NAME " is in drop capability mode");
			cap_mode = RUID_CAP_MODE_DROP;
		}
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
	UNUSED(s);

	int ncap;
	cap_t cap;
	cap_value_t capval[4];

	/* detect default supplementary group IDs */
	if ((startup_groupsnr = getgroups(RUID_MAXGROUPS, startup_groups)) == -1) {
		startup_groupsnr = 0;
		ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s ERROR getgroups() failed on child init, ignoring supplementary group IDs", MODULE_NAME);
	}

	/* setup chroot jailbreak */
	if (chroot_used == RUID_CHROOT_USED && cap_mode == RUID_CAP_MODE_KEEP) {
		if ((root_handle = open("/.", O_RDONLY)) < 0) {
			root_handle = UNSET;
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s CRITICAL ERROR opening root file descriptor failed (%s)", MODULE_NAME, strerror(errno));
		} else if (fcntl(root_handle, F_SETFD, FD_CLOEXEC) < 0) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s CRITICAL ERROR unable to set close-on-exec flag on root file descriptor (%s)", MODULE_NAME, strerror(errno));
			if (close(root_handle) < 0)
				ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s CRITICAL ERROR closing root file descriptor (%d) failed", MODULE_NAME, root_handle);
			root_handle = UNSET;
		} else {
			/* register cleanup function */
			apr_pool_cleanup_register(p, (void*)((long)root_handle), ruid_child_exit, apr_pool_cleanup_null);
		}
	} else {
		root_handle = (chroot_used == RUID_CHROOT_USED ? NONE : UNSET);
	}

	/* init cap with all zeros */
	cap = cap_init();

	capval[0] = CAP_SETUID;
	capval[1] = CAP_SETGID;
	ncap = 2;
	if (mode_stat_used == RUID_MODE_STAT_USED) {
		capval[ncap++] = CAP_DAC_READ_SEARCH;
	}
	if (root_handle != UNSET) {
		capval[ncap++] = CAP_SYS_CHROOT;
	}
	cap_set_flag(cap, CAP_PERMITTED, ncap, capval, CAP_SET);
	if (cap_set_proc(cap) != 0) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "%s CRITICAL ERROR %s:cap_set_proc failed", MODULE_NAME, __func__);
	}
	cap_free(cap);

	/* check if process is dumpable */
	coredump = prctl(PR_GET_DUMPABLE);
}


/* run during request cleanup */
static apr_status_t ruid_suidback (void *data)
{
	request_rec *r = data;

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

		setgroups(startup_groupsnr, startup_groups);
		setgid(ap_unixd_config.group_id);
		setuid(ap_unixd_config.user_id);

		/* set httpd process dumpable after setuid */
		if (coredump) {
			prctl(PR_SET_DUMPABLE,1);
		}

		/* jail break */
		if (conf->chroot_dir) {
			if (fchdir(root_handle) < 0) {
				ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s failed to fchdir to root dir (%d) (%s)", MODULE_NAME, root_handle, strerror(errno));
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


static int ruid_set_perm (request_rec *r, const char *from_func)
{
	ruid_config_t *conf = ap_get_module_config(r->server->module_config, &ruid2_module);
	ruid_dir_config_t *dconf = ap_get_module_config(r->per_dir_config, &ruid2_module);

	int retval = DECLINED;
	gid_t gid;
	uid_t uid;
	gid_t groups[RUID_MAXGROUPS];
	int groupsnr;

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

	if (dconf->ruid_mode==RUID_MODE_STAT) {
		/* set uid,gid to uid,gid of file
		 * if file does not exist, finfo.user and finfo.group is set to uid,gid of parent directory
		 */
		gid=r->finfo.group;
		uid=r->finfo.user;
	} else {
		gid=(dconf->ruid_gid == UNSET) ? ap_unixd_config.group_id : dconf->ruid_gid;
		uid=(dconf->ruid_uid == UNSET) ? ap_unixd_config.user_id : dconf->ruid_uid;
	}

	/* if uid of filename is less than conf->min_uid then set to conf->default_uid */
	if (uid < conf->min_uid) {
		uid=conf->default_uid;
	}
	if (gid < conf->min_gid) {
		gid=conf->default_gid;
	}

	/* set supplementary groups */
	if ((dconf->groupsnr == UNSET) && (startup_groupsnr > 0)) {
		memcpy(groups, startup_groups, sizeof(groups));
		groupsnr = startup_groupsnr;
	} else if (dconf->groupsnr > 0) {
		for (groupsnr = 0; groupsnr < dconf->groupsnr; groupsnr++) {
			if (dconf->groups[groupsnr] >= conf->min_gid) {
				groups[groupsnr] = dconf->groups[groupsnr];
			} else {
				groups[groupsnr] = conf->default_gid;
			}
		}
	} else {
		groupsnr = 0;
	}
	setgroups(groupsnr, groups);

	/* final set[ug]id */
	if (setgid(gid) != 0)
	{
		ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s %s %s %s>%s:setgid(%d) failed. getgid=%d getuid=%d", MODULE_NAME, ap_get_server_name(r), r->the_request, from_func, __func__, dconf->ruid_gid, getgid(), getuid());
		retval = HTTP_FORBIDDEN;
	} else {
		if (setuid(uid) != 0)
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

	if (cap_set_proc(cap)!=0) {
		ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s CRITICAL ERROR %s>%s:cap_set_proc failed after setuid", MODULE_NAME, from_func, __func__);
		retval = HTTP_FORBIDDEN;
	}
	cap_free(cap);

	return retval;
}


/* run in post_read_request hook */
static int ruid_setup (request_rec *r)
{
	/* We decline when we are in a subrequest. The ruid_setup function was
	 * already executed in the main request. */
	if (!ap_is_initial_req(r)) {
		return DECLINED;
	}

	ruid_config_t *conf = ap_get_module_config (r->server->module_config,  &ruid2_module);
	ruid_dir_config_t *dconf = ap_get_module_config(r->per_dir_config, &ruid2_module);
	core_server_config *core = (core_server_config *) ap_get_module_config(r->server->module_config, &core_module);

	int ncap=0;
	cap_t cap;
	cap_value_t capval[2];

	if (dconf->ruid_mode==RUID_MODE_STAT) capval[ncap++] = CAP_DAC_READ_SEARCH;
	if (root_handle != UNSET) capval[ncap++] = CAP_SYS_CHROOT;
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

	/* register suidback function */
	apr_pool_cleanup_register(r->pool, r, ruid_suidback, apr_pool_cleanup_null);

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
	if (!ap_is_initial_req(r)) {
		return DECLINED;
	}

	int retval = ruid_set_perm(r, __func__);

	int ncap;
	cap_t cap;
	cap_value_t capval[4];

	/* clear capabilities from permitted set (permanent) */
	if (cap_mode == RUID_CAP_MODE_DROP) {
		cap=cap_get_proc();
		capval[0]=CAP_SETUID;
		capval[1]=CAP_SETGID;
		capval[2]=CAP_DAC_READ_SEARCH;
		ncap = 2;
		if (root_handle == UNSET) capval[ncap++] = CAP_SYS_CHROOT;
		cap_set_flag(cap,CAP_PERMITTED,ncap,capval,CAP_CLEAR);

		if (cap_set_proc(cap)!=0) {
			ap_log_error (APLOG_MARK, APLOG_ERR, 0, NULL, "%s CRITICAL ERROR %s:cap_set_proc failed after setuid", MODULE_NAME, __func__);
			retval = HTTP_FORBIDDEN;
		}
		cap_free(cap);
	}

	return retval;
}


static void register_hooks (apr_pool_t *p)
{
	UNUSED(p);

	ap_hook_post_config (ruid_init, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_child_init (ruid_child_init, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_post_read_request(ruid_setup, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_header_parser(ruid_uiiii, NULL, NULL, APR_HOOK_FIRST);
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
