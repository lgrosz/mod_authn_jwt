#include "first.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <jwt.h>

#include "plugin.h"

#include "base.h"
#include "array.h"
#include "fdevent.h"
#include "log.h"
#include "buffer.h"
#include "request.h"
#include "http_header.h"
#include "mod_auth_api.h"

typedef struct {
    jwt_checker_t *jwt_checker;
    jwk_set_t *jwk_set;
} mod_authn_jwt_opts;

typedef struct {
    mod_authn_jwt_opts *opts;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
    plugin_config conf;
} plugin_data;


static handler_t mod_authn_jwt_check_bearer(request_st *r, void *p_d, const struct http_auth_require_t *require, const struct http_auth_backend_t *backend);

INIT_FUNC(mod_authn_jwt_init) {
    static http_auth_scheme_t http_auth_scheme_bearer =
        { "bearer", mod_authn_jwt_check_bearer, NULL };

    static http_auth_backend_t http_auth_backend_jwt =
        { "jwt", NULL, NULL, NULL };

    plugin_data *p = ck_calloc(1, sizeof(plugin_data));

    /* register bearer scheme */
    http_auth_scheme_bearer.p_d = p;
    http_auth_scheme_set(&http_auth_scheme_bearer);

    /* register jwt backend */
    http_auth_backend_jwt.p_d = p;
    http_auth_backend_set(&http_auth_backend_jwt);

    return p;
}

FREE_FUNC(mod_authn_jwt_cleanup) {
    plugin_data * const p = p_d;
    if (NULL == p->cvlist) return;
    /* (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1], used = p->nconfig; i < used; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            if (cpv->vtype != T_CONFIG_LOCAL || NULL == cpv->v.v) continue;
            switch (cpv->k_id) {
              case 0: /* auth.backend.jwt.opts */
                {
                    const mod_authn_jwt_opts * const opts = cpv->v.v;
                    jwt_checker_free(opts->jwt_checker);
                    if (opts->jwk_set)
                        jwks_free(opts->jwk_set);
                }
                break;
              default:
                break;
            }
        }
    }
}

static void mod_authn_jwt_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* auth.backend.jwt.opts */
        if (cpv->vtype != T_CONFIG_LOCAL) break;
        pconf->opts = cpv->v.v;
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_authn_jwt_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_authn_jwt_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

static void mod_authn_jwt_patch_config(request_st * const r, plugin_data * const p) {
    p->conf = p->defaults; /* copy small struct instead of memcpy() */
    /*memcpy(&p->conf, &p->defaults, sizeof(plugin_config));*/
    for (int i = 1, used = p->nconfig; i < used; ++i) {
        if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
            mod_authn_jwt_merge_config(&p->conf, p->cvlist+p->cvlist[i].v.u2[0]);
    }
}

__attribute_cold__
__attribute_noinline__
static int
mod_authn_jwt_perror(log_error_st * const errh, const int errnum, const char * const label, const char * const value)
{
    errno = errnum;
    log_perror(errh, __FILE__, __LINE__, "Failed to %s %s", label, value);
    return errnum;
}

static mod_authn_jwt_opts *
mod_authn_jwt_parse_opts(const array * const list, log_error_st * const errh)
{
    jwt_checker_t *jwt_checker = NULL;
    const data_unset *du;
    int rc;
    jwt_alg_t alg;
    jwk_set_t *jwk_set = NULL;
    const jwk_item_t *jwk_item;
    const char *keyfile = NULL;

    du = array_get_element_klen(list, CONST_STR_LEN("algorithm"));
    if (!du || du->type != TYPE_STRING
        || (alg = jwt_str_alg(((const data_string *)du)->value.ptr)) == JWT_ALG_INVAL) {
        log_error(errh, __FILE__, __LINE__, "Invalid or missing auth.backend.jwt.opts \"algorithm\"");
        return NULL;
    }

    jwt_checker = jwt_checker_new();
    if (NULL == jwt_checker) {
        mod_authn_jwt_perror(errh, 0, "create", "jwt_checker");
        return NULL;
    }

    // No config is good config, I suppose
    rc = 0;

    for (uint32_t i = 0; i < list->used; ++i) {
        du = list->data[i];
        if (0 == strcmp(du->key.ptr, "algorithm"))
            continue; /*(already handled above)*/
        else if (0 == strcmp(du->key.ptr, "exp-leeway")
                 && (rc = config_plugin_value_to_int32(du, -1)) != -1) {
            rc = jwt_checker_time_leeway(jwt_checker, JWT_CLAIM_EXP, rc);
        }
        else if (0 == strcmp(du->key.ptr, "nbf-leeway")
                 && (rc = config_plugin_value_to_int32(du, -1)) != -1) {
            rc = jwt_checker_time_leeway(jwt_checker, JWT_CLAIM_NBF, rc);
        }
        else if (0 == strcmp(du->key.ptr, "audience") && du->type == TYPE_STRING) {
            rc = jwt_checker_claim_set(jwt_checker, JWT_CLAIM_AUD, ((const data_string *)du)->value.ptr);
        }
        else if (0 == strcmp(du->key.ptr, "issuer") && du->type == TYPE_STRING) {
            rc = jwt_checker_claim_set(jwt_checker, JWT_CLAIM_ISS, ((const data_string *)du)->value.ptr);
        }
        else if (0 == strcmp(du->key.ptr, "subject") && du->type == TYPE_STRING) {
            rc = jwt_checker_claim_set(jwt_checker, JWT_CLAIM_SUB, ((const data_string *)du)->value.ptr);
        }
        else if (0 == strcmp(du->key.ptr, "keyfile") && du->type == TYPE_STRING) {
            keyfile = ((const data_string *)du)->value.ptr;
            jwk_set = jwks_create_fromfile(keyfile);
            if (NULL == jwk_set) {
                if (jwks_error(jwk_set)) {
                    // This is really bad, just get out
                    log_error(errh, __FILE__, __LINE__, "Failed to load jwks \"%s\"", jwks_error_msg(jwk_set));
                    rc = -1;
                    break;
                }

                // TODO check for, notify of, and discard erroneous keys
            }

            // Use last key in the key set.. mostly because I have no idea how
            // LibJWT wants me to choose this considering there is no way to
            // query the set size...
            // Iterate through the array until you hit a NULL item
            jwk_item = NULL;
            for (struct { size_t i; jwk_item_t *item; } d = { 0, jwks_item_get(jwk_set, 0) }; d.item != NULL; d.item = jwks_item_get(jwk_set, ++d.i)) {
                jwk_item = d.item;
            }

            rc = jwt_checker_setkey(jwt_checker, alg, jwk_item);
            if (0 != rc) {
                mod_authn_jwt_perror(errh, rc, "set key", jwt_checker_error_msg(jwt_checker));
                break;
            }
        }
        else {
            log_error(errh, __FILE__, __LINE__, "Invalid syntax for auth.backend.jwt.opts \"%s\"", du->key.ptr);
            rc = -1;
            break;
        }
    }

    if (0 != rc) {
        jwt_checker_free(jwt_checker);
        return NULL;
    }

    mod_authn_jwt_opts * const opts = ck_calloc(1, sizeof(*opts));
    opts->jwt_checker = jwt_checker;
    opts->jwk_set = jwk_set;
    return opts;
}

SETDEFAULTS_FUNC(mod_authn_jwt_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("auth.backend.jwt.opts"),
        T_CONFIG_ARRAY_KVANY,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_authn_jwt"))
        return HANDLER_ERROR;

    /* process and validate config directives
     * (init i to 0 if global context; to 1 to skip empty global context) */
    for (int i = !p->cvlist[0].v.u2[1]; i < p->nconfig; ++i) {
        config_plugin_value_t *cpv = p->cvlist + p->cvlist[i].v.u2[0];
        for (; -1 != cpv->k_id; ++cpv) {
            switch (cpv->k_id) {
              case 0: /* auth.backend.jwt.opts */
                cpv->v.v = mod_authn_jwt_parse_opts(cpv->v.a, srv->errh);
                if (NULL == cpv->v.v) return HANDLER_ERROR;
                cpv->vtype = T_CONFIG_LOCAL;
                break;
              default:/* should not happen */
                break;
            }
        }
    }

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id)
            mod_authn_jwt_merge_config(&p->defaults, cpv);
    }

    return HANDLER_GO_ON;
}

/*
 * auth schemes
 */

__attribute_noinline__
static void
mod_authn_jwt_www_authenticate(request_st * const r, const struct http_auth_require_t * const require, const char * const error)
{
    /* [RFC-6750 3.1](https://datatracker.ietf.org/doc/html/rfc6750#section-3.1) */

    buffer * const b =
      http_header_response_set_ptr(r, HTTP_HEADER_WWW_AUTHENTICATE,
                                   CONST_STR_LEN("WWW-Authenticate"));
    buffer_append_str3(b,
      CONST_STR_LEN("Bearer realm=\""),
      BUF_PTR_LEN(require->realm),
      CONST_STR_LEN("\", charset=\"UTF-8\""));

    if (error)
        buffer_append_str3(b,
          CONST_STR_LEN(", error=\""),
          error, strlen(error),
          CONST_STR_LEN("\""));
}

__attribute_cold__
__attribute_noinline__
static handler_t
mod_authn_jwt_send_400_bad_request (request_st * const r, const struct http_auth_require_t * const require, const char * const error)
{
    /* a field was missing or invalid */
    r->http_status = 400; /* Bad Request */
    r->handler_module = NULL;
    mod_authn_jwt_www_authenticate(r, require, error);
    return HANDLER_FINISHED;
}

static handler_t
mod_authn_jwt_send_401_unauthorized(request_st * const r, const struct http_auth_require_t * const require, const char * const error)
{
    r->http_status = 401; /* Unauthorized */
    r->handler_module = NULL;
    mod_authn_jwt_www_authenticate(r, require, error);
    return HANDLER_FINISHED;
}

__attribute_cold__
static handler_t
mod_authn_jwt_send_500_server_error (request_st * const r)
{
    r->http_status = 500; /* Internal Server Error */
    r->handler_module = NULL;
    return HANDLER_FINISHED;
}

static const char *
remove_url_scheme(const char *url)
{
    if (NULL == url) {
        return NULL;
    }

    const char *scheme_end = strstr(url, "://");

    // remove valid scheme
    if (scheme_end && scheme_end != url) {
        return scheme_end + 3;
    }

    return url;
}

static int
mod_authn_jwt_set_remote_user (jwt_t *jwt, jwt_config_t * jwt_config)
{
    jwt_value_t sub_val;
    jwt_value_t iss_val;
    jwt_value_error_t err;
    request_st * r;

    if (NULL == jwt_config) {
        return 1;
    }

    r = jwt_config->ctx;

    jwt_set_GET_STR(&sub_val, "sub");
    err = jwt_claim_get(jwt, &sub_val);
    if (err == JWT_VALUE_ERR_NOEXIST)
        return 0;
    else if (err != JWT_VALUE_ERR_NONE) {
        return 1;
    }

    jwt_set_GET_STR(&iss_val, "iss");
    err = jwt_claim_get(jwt, &iss_val);
    if (err != JWT_VALUE_ERR_NOEXIST && err != JWT_VALUE_ERR_NONE) {
        return 1;
    }

    // TODO add config option to specify label to retrieve for REMOTE_USER
    /* Apache mod_auth_openidc doc defaults REMOTE_USER to "[sub]@[iss]" */
    const char *sub = remove_url_scheme(sub_val.str_val);
    if (NULL == sub) return 0;
    const char *iss = remove_url_scheme(iss_val.str_val);
    if (!iss)
        http_auth_setenv(r, sub, strlen(sub), CONST_STR_LEN("Bearer"));
    else {
        buffer * const tb = r->tmp_buf;
        buffer_clear(tb);
        buffer_append_str3(tb,sub,strlen(sub),"@",1,iss,strlen(iss));
        http_auth_setenv(r, BUF_PTR_LEN(tb), CONST_STR_LEN("Bearer"));
    }

    return 0;
}

static handler_t
mod_authn_jwt_bearer(request_st * const r, void *p_d, const http_auth_require_t * const require, const char * const token)
{
    plugin_data *p = (plugin_data *)p_d;
    mod_authn_jwt_patch_config(r, p);
    const mod_authn_jwt_opts * const opts = p->conf.opts;
    if (NULL == opts)
        return mod_authn_jwt_send_500_server_error(r); /*(misconfigured)*/

    if (jwt_checker_setcb(opts->jwt_checker, mod_authn_jwt_set_remote_user, r))
        return mod_authn_jwt_send_500_server_error(r);

    /* (jwt_checker_t *) is reusable but is not thread-safe or reentrant.
     * If shared between threads, use mutex around (jwt_checker_t *) */
    /*pthread_mutex_lock(...)*//* or simpler ticket lock or even atomics */
    int rc = jwt_checker_verify(opts->jwt_checker, token);
    /*pthread_mutex_unlock(...)*/

    if (0 != rc) {
        buffer * const tb = r->tmp_buf;
        buffer_copy_string_len(tb, CONST_STR_LEN("invalid_token"));
        if (r->conf.log_response_header) { /*(debugging)*/
            buffer_append_string_len(tb,
              CONST_STR_LEN("\", error_description=\""));
            buffer_append_string(tb, jwt_checker_error_msg(opts->jwt_checker));
        }
        mod_authn_jwt_send_401_unauthorized(r, require, tb->ptr);
    }

    return (0 == rc) ? HANDLER_GO_ON : HANDLER_FINISHED;
}

static handler_t
mod_authn_jwt_check_bearer(request_st *r, void *p_d, const struct http_auth_require_t *require, const struct http_auth_backend_t *backend)
{
    UNUSED(backend);
    const buffer * const vb =
      http_header_request_get(r, HTTP_HEADER_AUTHORIZATION,
                              CONST_STR_LEN("Authorization"));
    if (NULL == vb)
        return mod_authn_jwt_send_401_unauthorized(r, require, NULL);
    if (!buffer_eq_icase_ssn(vb->ptr, CONST_STR_LEN("Bearer ")))
        return mod_authn_jwt_send_400_bad_request(r, require, "invalid_request");

    /* TODO Here is where we can do authentication caching */

    return mod_authn_jwt_bearer(r, p_d, require, vb->ptr+sizeof("Bearer ")-1);
}


__attribute_cold__
__declspec_dllexport__
int mod_authn_jwt_plugin_init(plugin *p);
int mod_authn_jwt_plugin_init(plugin *p) {
    p->version     = LIGHTTPD_VERSION_ID;
    p->name        = "authn_jwt";
    p->init        = mod_authn_jwt_init;
    p->cleanup     = mod_authn_jwt_cleanup;
    p->set_defaults= mod_authn_jwt_set_defaults;

    return 0;
}
