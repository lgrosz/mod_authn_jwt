#include "first.h"

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
    const buffer *keyfile;
    jwt_alg_t alg;
    unsigned int exp_leeway;
    unsigned int nbf_leeway;
    const buffer *issuer;
    const buffer *subject;
    const buffer *audience;
    const array *claims;
    const array *json_claims;
} plugin_config;

typedef struct {
    PLUGIN_DATA;
    plugin_config defaults;
    plugin_config conf;
} plugin_data;


static handler_t mod_auth_check_bearer(request_st *r, void *p_d, const struct http_auth_require_t *require, const struct http_auth_backend_t *backend);

static handler_t mod_authn_jwt_bearer(request_st *r, void *p_d, const http_auth_require_t *require, const buffer *token, const char *pswd);

INIT_FUNC(mod_authn_jwt_init) {
    static http_auth_scheme_t http_auth_scheme_bearer =
        { "bearer", mod_auth_check_bearer, NULL };

    /* NOTE Since http_auth_backend_t is limited to basic and digest handlers,
     * the bearer handler will just be assigned as the "basic" handler. It's
     * implementation will assume that the "user" parameter will be a token */
    static http_auth_backend_t http_auth_backend_jwt =
        { "jwt", mod_authn_jwt_bearer, NULL, NULL };

    plugin_data *p = ck_calloc(1, sizeof(plugin_data));

    /* register bearer scheme */
    http_auth_scheme_bearer.p_d = p;
    http_auth_scheme_set(&http_auth_scheme_bearer);

    /* register jwt backend */
    http_auth_backend_jwt.p_d = p;
    http_auth_backend_set(&http_auth_backend_jwt);

    return p;
}

static void mod_authn_jwt_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* auth.backend.jwt.keyfile */
        pconf->keyfile = cpv->v.b;
        break;
      case 1: /* auth.backend.jwt.algorithm */
        if (cpv->vtype != T_CONFIG_LOCAL) break;
        pconf->alg = cpv->v.u;
        break;
      case 2: /* auth.backend.jwt.exp-leeway */
        pconf->exp_leeway = cpv->v.u;
        break;
      case 3: /* auth.backend.jwt.nbf-leeway */
        pconf->nbf_leeway = cpv->v.u;
        break;
      case 4: /* auth.backend.jwt.issuer */
        pconf->issuer = cpv->v.b;
        break;
      case 5: /* auth.backend.jwt.subject */
        pconf->subject = cpv->v.b;
        break;
      case 6: /* auth.backend.jwt.audience */
        pconf->audience = cpv->v.b;
        break;
      case 7: /* auth.backend.jwt.claims */
        pconf->claims = cpv->v.a;
        break;
      case 8: /* auth.backend.jwt.json_claims */
        pconf->json_claims = cpv->v.a;
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

static jwt_alg_t mod_authn_jwt_process_algorithm(const char * const algstr, server * const srv);

SETDEFAULTS_FUNC(mod_authn_jwt_set_defaults) {
    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("auth.backend.jwt.keyfile"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.jwt.algorithm"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.jwt.exp-leeway"),
        T_CONFIG_INT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.jwt.nbf-leeway"),
        T_CONFIG_INT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.jwt.issuer"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.jwt.subject"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.jwt.audience"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.jwt.claims"),
        T_CONFIG_ARRAY_KVANY,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("auth.backend.jwt.json-claims"),
        T_CONFIG_ARRAY,
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
                case 0: /* auth.backend.jwt.keyfile */
                    if (buffer_is_blank(cpv->v.b))
                        cpv->v.b = NULL;
                    break;
                case 1: /* auth.backend.jwt.algorithm */
                    cpv->v.u = mod_authn_jwt_process_algorithm(cpv->v.b->ptr, srv);
                    cpv->vtype = T_CONFIG_LOCAL;
                    break;
                case 2: /* auth.backend.jwt.exp-leeway */
                case 3: /* auth.backend.jwt.nbf-leeway */
                    break;
                case 4: /* auth.backend.jwt.issuer */
                    if (buffer_is_blank(cpv->v.b))
                        cpv->v.b = NULL;
                    break;
                case 5: /* auth.backend.jwt.subject */
                    if (buffer_is_blank(cpv->v.b))
                        cpv->v.b = NULL;
                    break;
                case 6: /* auth.backend.jwt.audience */
                    if (buffer_is_blank(cpv->v.b))
                        cpv->v.b = NULL;
                    break;
                case 7: /* auth.backend.jwt.claims */
                       break;
                case 8: /* auth.backend.jwt.json_claims */
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

static jwt_alg_t mod_authn_jwt_process_algorithm(const char * const algstr, server * const srv)
{
    jwt_alg_t alg = jwt_str_alg(algstr);

    if (JWT_ALG_INVAL == alg) {
        log_notice(srv->errh, __FILE__, __LINE__, "Could not process algorithm :%s", algstr);
    }

    return alg;
}

/*
 * auth schemes
 */

__attribute_cold__
__attribute_noinline__
static handler_t
mod_auth_send_400_bad_request (request_st * const r)
{
    /* a field was missing or invalid */
    r->http_status = 400; /* Bad Request */
    r->handler_module = NULL;
    return HANDLER_FINISHED;
}

__attribute_noinline__
static handler_t
mod_auth_send_401_unauthorized_bearer(request_st * const r, const buffer * const realm)
{
    log_notice(r->conf.errh, __FILE__, __LINE__, "Unauthorized bearer");

    r->http_status = 401;
    r->handler_module = NULL;

    /* TODO See [RFC-6750 3.1](https://datatracker.ietf.org/doc/html/rfc6750#section-3.1) */

    /* TODO *MAY* include a realm */
    /* TODO *SHOULD* include error, description, and uri */

    buffer_append_str3(
            http_header_response_set_ptr(r, HTTP_HEADER_WWW_AUTHENTICATE,
            CONST_STR_LEN("WWW-Authenticate")),
            CONST_STR_LEN("Bearer realm=\""),
            BUF_PTR_LEN(realm),
            CONST_STR_LEN("\", charset=\"UTF-8\""));
    return HANDLER_FINISHED;
}

__attribute_cold__
static handler_t
mod_auth_bearer_misconfigured (request_st * const r, const struct http_auth_backend_t * const backend)
{
    if (NULL == backend)
        log_error(r->conf.errh, __FILE__, __LINE__,
          "auth.backend not configured for %s", r->uri.path.ptr);
    else
        log_error(r->conf.errh, __FILE__, __LINE__,
          "auth.require \"method\" => \"...\" is invalid "
          "(try \"bearer\"?) for %s", r->uri.path.ptr);

    r->http_status = 500;
    r->handler_module = NULL;
    return HANDLER_FINISHED;
}

static handler_t
mod_auth_check_bearer(request_st *r, void *p_d, const struct http_auth_require_t *require, const struct http_auth_backend_t *backend)
{
    UNUSED(p_d);

    if (backend == NULL || backend->basic == NULL)
        return mod_auth_bearer_misconfigured(r, backend);

    /* Parse token from authorization header */
    const buffer * const vb =
        http_header_request_get(r, HTTP_HEADER_AUTHORIZATION,
                CONST_STR_LEN("Authorization"));

    if (NULL == vb)
        return mod_auth_send_401_unauthorized_bearer(r, require->realm);

    if (!buffer_eq_icase_ssn(vb->ptr, CONST_STR_LEN("Bearer ")))
        return mod_auth_send_400_bad_request(r);

    /* TODO Here is where we can do authentication caching */

    const buffer token = { vb->ptr + sizeof("Bearer ")-1,
                           buffer_clen(vb) - (sizeof("Bearer ")-1) + 1, 0 };
    handler_t rc = backend->basic(r, backend->p_d, require, &token, "");

    switch (rc) {
        case HANDLER_GO_ON:
        case HANDLER_WAIT_FOR_EVENT:
        case HANDLER_FINISHED:
            break;
        default:
            /* TODO
             * - include "error" attribute and give correct codes
             *   - invalid_request
             *   - invalid_token
             *   - insufficient_scope
             * - include "error_description" attribute (developer-readable)
             * - include "error_uri" attribute (human-readable)
             *
             * We probably need to check plugin data or similar for this operation
             */
            rc = mod_auth_send_401_unauthorized_bearer(r, require->realm);
            break;
    }

    return rc;
}

handler_t mod_authn_jwt_bearer(request_st *r, void *p_d, const http_auth_require_t *require, const buffer *token, const char *pswd)
{
    UNUSED(require);
    UNUSED(pswd);

    plugin_data *p = (plugin_data *)p_d;
    mod_authn_jwt_patch_config(r, p);

    handler_t rc = HANDLER_ERROR;
    unsigned int keylength = 0;
    unsigned char *keyhandle = NULL;

    if (p->conf.keyfile) {
        off_t lim = 1*1024*1024; /*(arbitrary limit: 1 MB file; expect < 10 KB)*/
        keyhandle = fdevent_load_file(p->conf.keyfile, &lim, r->conf.errh, malloc, free);
        if (NULL == keyhandle)
            return HANDLER_ERROR;
        keylength = (unsigned int)lim;
    }

    /* Read token into jwt_t */
    jwt_t *jwt = NULL;
    if (0 != jwt_decode(&jwt, token->ptr, keyhandle, keylength) || jwt == NULL) {
        log_error(r->conf.errh, __FILE__, __LINE__, "Failed to decode jwt: %s", token->ptr);
        free(keyhandle);
        goto jwt_finish;
    }
    free(keyhandle);

    jwt_valid_t *jwt_valid = NULL;

    if (0 != jwt_valid_new(&jwt_valid, p->conf.alg) || jwt_valid == NULL) {
        log_error(r->conf.errh, __FILE__, __LINE__, "Failed to create jwt_valid");
        goto jwt_valid_finish;
    }

    // TODO These fields should be propogated as error data to the client
    unsigned int errno;

    errno = jwt_valid_set_exp_leeway(jwt_valid, p->conf.exp_leeway);
    if (0 != errno) {
        log_error(r->conf.errh, __FILE__, __LINE__, "Failed to set exp_leeway to %d: %s", p->conf.exp_leeway, jwt_exception_str(errno));
        goto jwt_valid_finish;
    }

    errno = jwt_valid_set_nbf_leeway(jwt_valid, p->conf.nbf_leeway);
    if (0 != errno) {
        log_error(r->conf.errh, __FILE__, __LINE__, "Failed to set nbf_leeway to %d: %s", p->conf.nbf_leeway, jwt_exception_str(errno));
        goto jwt_valid_finish;
    }

    if (NULL != p->conf.issuer) {
        errno = jwt_valid_add_grant(jwt_valid, "iss", p->conf.issuer->ptr);
        if (0 != errno) {
            log_error(r->conf.errh, __FILE__, __LINE__, "Failed to set issuer to %s: %s", p->conf.issuer->ptr, jwt_exception_str(errno));
            goto jwt_valid_finish;
        }
    }

    if (NULL != p->conf.subject) {
        errno = jwt_valid_add_grant(jwt_valid, "iss", p->conf.subject->ptr);
        if (0 != errno) {
            log_error(r->conf.errh, __FILE__, __LINE__, "Failed to set subject to %s: %s", p->conf.subject->ptr, jwt_exception_str(errno));
            goto jwt_valid_finish;
        }
    }

    if (NULL != p->conf.audience) {
        errno = jwt_valid_add_grant(jwt_valid, "iss", p->conf.audience->ptr);
        if (0 != errno) {
            log_error(r->conf.errh, __FILE__, __LINE__, "Failed to set audience to %s: %s", p->conf.audience->ptr, jwt_exception_str(errno));
            goto jwt_valid_finish;
        }
    }

    errno = jwt_valid_set_now(jwt_valid, time(NULL));
    if (0 != errno) {
        log_error(r->conf.errh, __FILE__, __LINE__, "Failed to set now: %s", jwt_exception_str(errno));
        goto jwt_valid_finish;
    }

    const array *claims = p->conf.claims;
    for (uint32_t i = 0; NULL != claims && i < claims->used; ++i) {
        const data_unset * const du = claims->data[i];

        const buffer * const claim = &du->key;
        const data_type_t type = du->type;

        if (type == TYPE_STRING) {
            const data_string * const ds = (const data_string *)du;

            errno = jwt_valid_add_grant(jwt_valid, claim->ptr, (&ds->value)->ptr);
            if (0 != errno) {
                log_error(r->conf.errh, __FILE__, __LINE__, "Failed to add claim %s => %s: %s", claim->ptr, (&ds->value)->ptr, jwt_exception_str(errno));
                goto jwt_valid_finish;
            }
        } else if (type == TYPE_INTEGER) {
            const data_integer * const di = (const data_integer *)du;
            errno = jwt_valid_add_grant_int(jwt_valid, claim->ptr, di->value);
            if (0 != errno) {
                log_error(r->conf.errh, __FILE__, __LINE__, "Failed to add claim %s => %d: %s", claim->ptr, di->value, jwt_exception_str(errno));
                goto jwt_valid_finish;
            }
        } else {
            log_notice(r->conf.errh, __FILE__, __LINE__, "Unsupported type, ignoring claim", claim->ptr);
        }
    }

    const array *json_claims = p->conf.json_claims;
    for (uint32_t i = 0; NULL != json_claims && i < json_claims->used; ++i) {
        const data_unset * const du = json_claims->data[i];
        const data_type_t type = du->type;

        if (type == TYPE_STRING) {
            const data_string * const ds = (const data_string *)du;

            log_notice(r->conf.errh, __FILE__, __LINE__, "Add json claim: %s", (&ds->value)->ptr);

            errno = jwt_valid_add_grants_json(jwt_valid, (&ds->value)->ptr);
            if (0 != errno) {
                log_error(r->conf.errh, __FILE__, __LINE__, "Failed to add json claim %s: %s", (&ds->value)->ptr, jwt_exception_str(errno));
                goto jwt_valid_finish;
            }
        } else {
            log_notice(r->conf.errh, __FILE__, __LINE__, "JSON claims must be string, value ignored...");
        }
    }

    errno = jwt_validate(jwt, jwt_valid);
    if (0 != errno) {
        log_error(r->conf.errh, __FILE__, __LINE__, "Failed to validate jwt %s: %s", token->ptr, jwt_exception_str(errno));
        goto jwt_valid_finish;
    }

    log_notice(r->conf.errh, __FILE__, __LINE__, "Valid JWT: %s", token->ptr);
    rc = HANDLER_GO_ON;

jwt_valid_finish:
    jwt_valid_free(jwt_valid);

jwt_finish:
    jwt_free(jwt);

    return rc;
}

__attribute_cold__
__declspec_dllexport__
int mod_authn_jwt_plugin_init(plugin *p);
int mod_authn_jwt_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "authn_jwt";
	p->init        = mod_authn_jwt_init;
	p->set_defaults= mod_authn_jwt_set_defaults;

	return 0;
}
