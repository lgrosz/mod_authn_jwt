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
    jwt_valid_t *jwt_valid;
    const buffer *keyfile;
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
                jwt_valid_free(cpv->v.v);
                break;
              case 1: /* auth.backend.jwt.keyfile */
                buffer_free(cpv->v.v);
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
        pconf->jwt_valid = cpv->v.v;
        break;
      case 1: /* auth.backend.jwt.keyfile */
        if (cpv->vtype != T_CONFIG_LOCAL) break;
        pconf->keyfile = cpv->v.v;
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

static jwt_valid_t *
mod_authn_jwt_parse_opts(const array * const opts, log_error_st * const errh)
{
    jwt_valid_t *jwt_valid = NULL;
    const data_unset *du;
    int rc;
    jwt_alg_t alg;

    du = array_get_element_klen(opts, CONST_STR_LEN("algorithm"));
    if (!du || du->type != TYPE_STRING
        || (alg = jwt_str_alg(((const data_string *)du)->value.ptr)) == JWT_ALG_INVAL) {
        log_error(errh, __FILE__, __LINE__, "Invalid or missing auth.backend.jwt.opts \"algorithm\"");
        return NULL;
    }

    rc = jwt_valid_new(&jwt_valid, alg);
    if (0 != rc) {
        mod_authn_jwt_perror(errh, rc, "create", "jwt_valid");
        return NULL;
    }

    for (uint32_t i = 0; i < opts->used; ++i) {
        du = opts->data[i];
        if (0 == strcmp(du->key.ptr, "algorithm"))
            continue; /*(already handled above)*/
        else if (0 == strcmp(du->key.ptr, "exp-leeway")
                 && (rc = config_plugin_value_to_int32(du, -1)) != -1) {
          #ifdef HAVE_JWT_VALID_SET_EXP_LEEWAY
            jwt_valid_set_exp_leeway(jwt_valid, rc);
          #endif
        }
        else if (0 == strcmp(du->key.ptr, "nbf-leeway")
                 && (rc = config_plugin_value_to_int32(du, -1)) != -1) {
          #ifdef HAVE_JWT_VALID_SET_NBF_LEEWAY
            jwt_valid_set_nbf_leeway(jwt_valid, rc);
          #endif
        }
        else if (0 == strcmp(du->key.ptr, "claims") && du->type == TYPE_ARRAY
                 && array_is_kvany(&((const data_array *)du)->value)) {
            const array * const claims = &((const data_array *)du)->value;
            for (uint32_t j = 0; j < claims->used; ++j) {
                du = claims->data[j];
                rc = 0;
                if (du->type == TYPE_STRING)
                    rc = jwt_valid_add_grant(jwt_valid, du->key.ptr, ((const data_string *)du)->value.ptr);
                else if (du->type == TYPE_INTEGER)
                    rc = jwt_valid_add_grant_int(jwt_valid, du->key.ptr, ((const data_integer *)du)->value);
                else
                    log_notice(errh, __FILE__, __LINE__, "Unsupported type, ignoring claim %s", du->key.ptr);
                if (0 != rc) {
                    mod_authn_jwt_perror(errh, rc, "add claim", du->key.ptr);
                    break;
                }
            }
            if (0 != rc)
                break;
        }
        else if (0 == strcmp(du->key.ptr, "json-claims") && du->type == TYPE_ARRAY
                 && array_is_vlist(&((const data_array *)du)->value)) {
            const array * const json_claims = &((const data_array *)du)->value;
            for (uint32_t j = 0; j < json_claims->used; ++j) {
                const data_string * const ds = (const data_string *)json_claims->data[j];
                rc = jwt_valid_add_grants_json(jwt_valid, ds->value.ptr);
                if (0 != rc) {
                    mod_authn_jwt_perror(errh, rc, "add json claim", ds->value.ptr);
                    break;
                }
            }
            if (0 != rc)
                break;
        }
        else {
            log_error(errh, __FILE__, __LINE__, "Invalid syntax for auth.backend.jwt.opts \"%s\"", du->key.ptr);
            rc = -1;
            break;
        }
    }

    if (0 != rc) {
        jwt_valid_free(jwt_valid);
        return NULL;
    }

    return jwt_valid;
}

SETDEFAULTS_FUNC(mod_authn_jwt_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("auth.backend.jwt.opts"),
        T_CONFIG_ARRAY_KVANY,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.jwt.keyfile"),
        T_CONFIG_STRING,
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
              case 1: /* auth.backend.jwt.keyfile */
                if (buffer_is_blank(cpv->v.b))
                    cpv->v.v = buffer_init();
                else {
                    off_t lim = 1*1024*1024; /*(arbitrary limit: 1 MB file; expect < 10 KB)*/
                    char *data = fdevent_load_file(cpv->v.b->ptr, &lim, srv->errh, malloc, free);
                    if (NULL == data)
                        return HANDLER_ERROR;
                    buffer * const b = buffer_init();
                    b->ptr = data;
                    b->used = (uint32_t)lim+1;
                    cpv->v.v = b;
                }
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

static void
mod_authn_jwt_set_remote_user (request_st * const r, jwt_t * const jwt)
{
    // TODO add config option to specify label to retrieve for REMOTE_USER
    /* Apache mod_auth_openidc doc defaults REMOTE_USER to "[sub]@[iss]" */
    const char *sub = jwt_get_grant(jwt, "sub");
    if (NULL == sub) return;
    const char *iss = jwt_get_grant(jwt, "iss");
    if (!iss)
        http_auth_setenv(r, sub, strlen(sub), CONST_STR_LEN("Bearer"));
    else {
        if (0 == strncmp(iss, "https://", sizeof("https://")-1))
            iss += sizeof("https://")-1;
        buffer * const tb = r->tmp_buf;
        buffer_clear(tb);
        buffer_append_str3(tb,sub,strlen(sub),"@",1,iss,strlen(iss));
        http_auth_setenv(r, BUF_PTR_LEN(tb), CONST_STR_LEN("Bearer"));
    }
}

static handler_t
mod_authn_jwt_bearer(request_st * const r, void *p_d, const http_auth_require_t * const require, const char * const token)
{
    plugin_data *p = (plugin_data *)p_d;
    mod_authn_jwt_patch_config(r, p);
    if (NULL == p->conf.keyfile || NULL == p->conf.jwt_valid)
        return mod_authn_jwt_send_500_server_error(r); /*(misconfigured)*/

    jwt_t *jwt = NULL;
    const buffer * const kb = p->conf.keyfile;
    int rc = jwt_decode(&jwt, token, (const unsigned char *)BUF_PTR_LEN(kb));
    if (0 != rc)
        return mod_authn_jwt_send_401_unauthorized(r, require,
          r->conf.log_response_header /*(debugging)*/
            ? "invalid_token\", error_description=\"malformed"
            : "invalid_token");

    /* (jwt_valid_t *) is reusable but is not thread-safe or reentrant.
     * If shared between threads, use mutex around (jwt_valid_t *) */
    /*pthread_mutex_lock(...)*//* or simpler ticket lock or even atomics */
    jwt_valid_t * const jwt_valid = p->conf.jwt_valid;
    jwt_valid_set_now(jwt_valid, (time_t)log_epoch_secs);
    rc = jwt_validate(jwt, jwt_valid);
    /*pthread_mutex_unlock(...)*/

    if (0 == rc) {
        mod_authn_jwt_set_remote_user(r, jwt);
    }
    else {
        buffer * const tb = r->tmp_buf;
        buffer_copy_string_len(tb, CONST_STR_LEN("invalid_token"));

        if (r->conf.log_response_header) { /*(debugging)*/
            buffer_append_string_len(tb,
              CONST_STR_LEN("\", error_description=\""));
          #ifdef HAVE_JWT_EXCEPTION_STR /* user must define for compilation */
            /* jwt_exception_str() added in jwt v1.17.0; not in older vers */
            char *errstr = jwt_exception_str(rc);
            buffer_append_string(tb, errstr);
            jwt_free_str(errstr);
          #else
            if (rc & JWT_VALIDATION_ERROR)
                buffer_append_str2(tb, CONST_STR_LEN("general failures"),
                                       CONST_STR_LEN("; "));
            if (rc & JWT_VALIDATION_ALG_MISMATCH)
                buffer_append_str2(tb, CONST_STR_LEN("algorithm mismatch"),
                                       CONST_STR_LEN("; "));
            if (rc & (JWT_VALIDATION_EXPIRED|JWT_VALIDATION_TOO_NEW))
                buffer_append_str2(tb, CONST_STR_LEN("expired or too new"),
                                       CONST_STR_LEN("; "));
            if (rc & JWT_VALIDATION_GRANT_MISSING)
                buffer_append_str2(tb, CONST_STR_LEN("grant missing"),
                                       CONST_STR_LEN("; "));
            if (rc & (JWT_VALIDATION_GRANT_MISMATCH
                     |JWT_VALIDATION_ISS_MISMATCH
                     |JWT_VALIDATION_SUB_MISMATCH
                     |JWT_VALIDATION_AUD_MISMATCH))
                buffer_append_str2(tb, CONST_STR_LEN("grant mismatch"),
                                       CONST_STR_LEN("; "));
            buffer_truncate(tb, buffer_clen(tb)-2); /*(remove final "; ")*/
          #endif
        }

        mod_authn_jwt_send_401_unauthorized(r, require, tb->ptr);
    }

    jwt_free(jwt);

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
