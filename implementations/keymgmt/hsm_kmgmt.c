#include "internal/deprecated.h"

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/proverr.h>
#include "crypto/bn.h"
#include "crypto/ec.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "internal/param_build_set.h"

#ifndef FIPS_MODULE
# ifndef OPENSSL_NO_SM2
#  include "crypto/sm2.h"
# endif
#endif

static OSSL_FUNC_keymgmt_new_fn ec_newdata;
static OSSL_FUNC_keymgmt_gen_init_fn ec_gen_init;
static OSSL_FUNC_keymgmt_gen_set_template_fn ec_gen_set_template;
static OSSL_FUNC_keymgmt_gen_set_params_fn ec_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn ec_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_fn ec_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn ec_gen_cleanup;
static OSSL_FUNC_keymgmt_load_fn ec_load;
static OSSL_FUNC_keymgmt_free_fn ec_freedata;
static OSSL_FUNC_keymgmt_get_params_fn ec_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn ec_gettable_params;
static OSSL_FUNC_keymgmt_set_params_fn ec_set_params;
static OSSL_FUNC_keymgmt_settable_params_fn ec_settable_params;
static OSSL_FUNC_keymgmt_has_fn ec_has;
static OSSL_FUNC_keymgmt_match_fn ec_match;
static OSSL_FUNC_keymgmt_validate_fn ec_validate;
static OSSL_FUNC_keymgmt_import_fn ec_import;
static OSSL_FUNC_keymgmt_import_types_fn ec_import_types;
static OSSL_FUNC_keymgmt_export_fn ec_export;
static OSSL_FUNC_keymgmt_export_types_fn ec_export_types;
static OSSL_FUNC_keymgmt_query_operation_name_fn ec_query_operation_name;
static OSSL_FUNC_keymgmt_dup_fn ec_dup;

static OSSL_FUNC_keymgmt_new_fn sm2_newdata;
static OSSL_FUNC_keymgmt_gen_init_fn sm2_gen_init;
static OSSL_FUNC_keymgmt_gen_fn sm2_gen;
static OSSL_FUNC_keymgmt_get_params_fn sm2_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn sm2_gettable_params;
static OSSL_FUNC_keymgmt_settable_params_fn sm2_settable_params;
static OSSL_FUNC_keymgmt_import_fn sm2_import;
static OSSL_FUNC_keymgmt_query_operation_name_fn sm2_query_operation_name;
static OSSL_FUNC_keymgmt_validate_fn sm2_validate;




const OSSL_DISPATCH ossl_ec_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))ec_newdata },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))ec_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
      (void (*)(void))ec_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))ec_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))ec_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))ec_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))ec_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))ec_load },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))ec_freedata },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))ec_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))ec_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*) (void))ec_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*) (void))ec_settable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))ec_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))ec_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))ec_validate },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))ec_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))ec_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))ec_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))ec_export_types },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
      (void (*)(void))ec_query_operation_name },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))ec_dup },
    { 0, NULL }
};

#ifndef FIPS_MODULE
# ifndef OPENSSL_NO_SM2
const OSSL_DISPATCH ossl_hsm_sm2_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))sm2_newdata },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))sm2_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
      (void (*)(void))ec_gen_set_template },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))ec_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))ec_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))sm2_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))ec_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))sm2_load },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))ec_freedata },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))sm2_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))sm2_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*) (void))ec_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*) (void))sm2_settable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))ec_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))ec_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))sm2_validate },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))sm2_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))ec_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))ec_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))ec_export_types },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
      (void (*)(void))sm2_query_operation_name },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))ec_dup },
    { 0, NULL }
};