
/*
 * Copyright (C) 2010 Valery Kholodkov
 *
 * NOTE: Some small fragments have been copied from original nginx log module due to exports problem.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>
#include <syslog.h>

#define NGX_SYSLOG_SEVERITY_INFO        6

typedef struct ngx_http_log_op_s  ngx_http_log_op_t;

typedef u_char *(*ngx_http_log_op_run_pt) (ngx_http_request_t *r, u_char *buf,
    ngx_http_log_op_t *op);

typedef size_t (*ngx_http_log_op_getlen_pt) (ngx_http_request_t *r,
    uintptr_t data);


struct ngx_http_log_op_s {
    size_t                      len;
    ngx_http_log_op_getlen_pt   getlen;
    ngx_http_log_op_run_pt      run;
    uintptr_t                   data;
};

typedef struct {
    ngx_str_t                   name;
#if defined nginx_version && nginx_version >= 7018
    ngx_array_t                *flushes;
#endif
    ngx_array_t                *ops;        /* array of ngx_http_log_op_t */
} ngx_http_log_fmt_t;

typedef struct {
    ngx_array_t                 formats;    /* array of ngx_http_log_fmt_t */
    ngx_uint_t                  combined_used; /* unsigned  combined_used:1 */
} ngx_http_log_main_conf_t;

typedef struct {
    ngx_str_t                   name;
    ngx_uint_t                  number;
} ngx_syslog_severity_t;

typedef struct {
    ngx_array_t                *endpoints;
} ngx_http_syslog_main_conf_t;

typedef struct {
    ngx_http_log_fmt_t          *format;
    ngx_uint_t                   severity;
    unsigned                     off;
} ngx_http_syslog_conf_t;

static void *ngx_http_syslog_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_syslog_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_syslog_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

static char *ngx_http_syslog_set_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_syslog_set_priority(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_syslog_init(ngx_conf_t *cf);
static char* ngx_syslog_init_conf(ngx_cycle_t *cycle, void *conf);

static ngx_int_t ngx_http_syslog_init_process(ngx_cycle_t *cycle);
static void ngx_http_syslog_exit_process(ngx_cycle_t *cycle);

static ngx_command_t  ngx_http_syslog_commands[] = {

    { ngx_string("access_syslog"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_HTTP_LMT_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE1,
      ngx_http_syslog_set_log,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("syslog_priority"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_syslog_set_priority,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_syslog_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_syslog_init,                  /* postconfiguration */

    ngx_http_syslog_create_main_conf,      /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_syslog_create_loc_conf,       /* create location configration */
    ngx_http_syslog_merge_loc_conf         /* merge location configration */
};

extern ngx_module_t  ngx_http_log_module;

ngx_module_t  ngx_http_syslog_module = {
    NGX_MODULE_V1,
    &ngx_http_syslog_module_ctx,           /* module context */
    ngx_http_syslog_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_syslog_init_process,          /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_http_syslog_exit_process,          /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_syslog_severity_t ngx_syslog_severities[] = {
    { ngx_string("emerg"),      0 },
    { ngx_string("alert"),      1 },
    { ngx_string("crit"),       2 },
    { ngx_string("err"),        3 },
    { ngx_string("warning"),    4 },
    { ngx_string("notice"),     5 },
    { ngx_string("info"),       6 },
    { ngx_string("debug"),      7 },

    { ngx_null_string, 0 }
};

ngx_int_t
ngx_http_syslog_handler(ngx_http_request_t *r)
{
    u_char                   *line, *p;
    size_t                    len;
    ngx_uint_t                i;
    ngx_http_log_fmt_t        *format;
    ngx_http_log_op_t         *op;
    ngx_http_syslog_conf_t    *slcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http syslog handler");

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_syslog_module);

    if(slcf->off || slcf->format == NULL) {
        return NGX_OK;
    }

    format = slcf->format;

#if defined nginx_version && nginx_version >= 7018
    ngx_http_script_flush_no_cacheable_variables(r, format->flushes);
#endif

    len = 0;
    op = format->ops->elts;
    for (i = 0; i < format->ops->nelts; i++) {
        if (op[i].len == 0) {
            len += op[i].getlen(r, op[i].data);

        } else {
            len += op[i].len;
        }
    }

#if defined nginx_version && nginx_version >= 7003
    line = ngx_pnalloc(r->pool, len + 1);
#else
    line = ngx_palloc(r->pool, len + 1);
#endif
    if (line == NULL) {
        return NGX_ERROR;
    }

    p = line;

    for (i = 0; i < format->ops->nelts; i++) {
        p = op[i].run(r, p, &op[i]);
    }

    *p++ = '\0';

    syslog(slcf->severity, "%s", line);

    return NGX_OK;
}

static ngx_int_t
ngx_syslog_handler(ngx_log_t *log, u_char *buf, size_t len)
{
    u_char   errstr[NGX_MAX_ERROR_STR], *p;

    p = ngx_cpymem(errstr, buf,
        len >= NGX_MAX_ERROR_STR ? NGX_MAX_ERROR_STR - 1 : len);

    *p++ = '\0';

    syslog(LOG_CRIT, "%s", errstr);

    return NGX_OK;
}

static void *
ngx_http_syslog_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_syslog_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_syslog_main_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    return conf;
}

static void *
ngx_http_syslog_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_syslog_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_syslog_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->severity = NGX_CONF_UNSET_UINT;

    return conf;
}

static char *
ngx_http_syslog_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_syslog_conf_t *prev = parent;
    ngx_http_syslog_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->severity,
                              prev->severity, NGX_SYSLOG_SEVERITY_INFO);

    if(conf->format != NULL || conf->off) {
        return NGX_CONF_OK;
    }

    conf->format = prev->format;
    conf->off = prev->off;

    return NGX_CONF_OK;
}

static char *
ngx_http_syslog_set_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_syslog_conf_t      *slcf = conf;

    ngx_uint_t                   i;
    ngx_str_t                   *value, name;
    ngx_http_log_fmt_t          *fmt;
    ngx_http_log_main_conf_t    *lmcf;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        slcf->off = 1;
        return NGX_CONF_OK;
    }

    if (slcf->format != NULL) {
        return "is duplicate";
    }

    lmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_log_module);

    if(lmcf == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "syslog module requires log module to be compiled in");
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts > 1) {
        name = value[1];

        if (ngx_strcmp(name.data, "combined") == 0) {
            lmcf->combined_used = 1;
        }
    } else {
        name.len = sizeof("combined") - 1;
        name.data = (u_char *) "combined";
        lmcf->combined_used = 1;
    }

    fmt = lmcf->formats.elts;
    for (i = 0; i < lmcf->formats.nelts; i++) {
        if (fmt[i].name.len == name.len
            && ngx_strcasecmp(fmt[i].name.data, name.data) == 0)
        {
            slcf->format = &fmt[i];
            goto done;
        }
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "unknown log format \"%V\"", &name);
    return NGX_CONF_ERROR;

done:
    return NGX_CONF_OK;
}

static char *
ngx_http_syslog_set_priority(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_syslog_conf_t     *slcf = conf;
    ngx_str_t                  *value;
    ngx_syslog_severity_t      *s;

    value = cf->args->elts;

    s = ngx_syslog_severities;

    while(s->name.data != NULL) {
        if(ngx_strncmp(s->name.data, value[1].data, s->name.len) == 0)
            break;

        s++;
    }

    if(s->name.data != NULL) {
        slcf->severity = s->number;
    }
    else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unknown severity \"%V\"", &value[2]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_syslog_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t    *cmcf;
    ngx_http_syslog_main_conf_t  *smcf;
    ngx_http_handler_pt          *h;

    smcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_syslog_module);
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_syslog_handler;

    return NGX_OK;
}

static ngx_int_t
ngx_http_syslog_init_process(ngx_cycle_t *cycle)
{
    openlog("nginx", LOG_NDELAY, LOG_DAEMON);

    return NGX_OK;
}

static void
ngx_http_syslog_exit_process(ngx_cycle_t *cycle)
{
    closelog();
}
