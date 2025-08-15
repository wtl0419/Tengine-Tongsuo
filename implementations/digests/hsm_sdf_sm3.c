#include "internal/deprecated.h"
#include <openssl/crypto.h>
#include <openssl/sm3.h>
#include <openssl/proverr.h>
#include "prov/digestcommon.h"
#include "prov/implementations.h"
#include "prov/provider_ctx.h"
#include "prov/piico_define.h"
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define SR_SUCCESSFULLY 0
#define CHECK_SDF_RET(ret, msg) do { \
    if ((ret) != SR_SUCCESSFULLY) { \
        fprintf(stderr, "%s failed with error code: %d\n", msg, (ret)); \
    } \
} while(0)

/* SDF 函数指针声明 */
typedef int (*SDF_OpenDevice_fn)(void** phDeviceHandle);
typedef int (*SDF_CloseDevice_fn)(void* hDeviceHandle);
typedef int (*SDF_OpenSession_fn)(void* hDeviceHandle, void** phSessionHandle);
typedef int (*SDF_CloseSession_fn)(void* hSessionHandle);
typedef int (*SDF_HashInit_fn)(void* hSessionHandle, unsigned int uiAlgID, void* pucPublicKey, unsigned char* pucID, unsigned int uiIDLength);
typedef int (*SDF_HashUpdate_fn)(void* hSessionHandle, unsigned char* pucData, unsigned int uiDataLength);
typedef int (*SDF_HashFinal_fn)(void* hSessionHandle, unsigned char* pucHash, unsigned int* puiHashLength);

/* HSM SM3 摘要上下文 */
typedef struct {
    void* hDevice;
    void* hSession;
    // 由于我们使用硬件，因此不需要软件的 SM3_CTX
} HSM_SM3_DIGEST_CTX;

/* 动态库和 SDF 函数的全局变量 */
static void* h_lib = NULL;
static SDF_OpenDevice_fn pfn_SDF_OpenDevice = NULL;
static SDF_CloseDevice_fn pfn_SDF_CloseDevice = NULL;
static SDF_OpenSession_fn pfn_SDF_OpenSession = NULL;
static SDF_CloseSession_fn pfn_SDF_CloseSession = NULL;
static SDF_HashInit_fn pfn_SDF_HashInit = NULL;
static SDF_HashUpdate_fn pfn_SDF_HashUpdate = NULL;
static SDF_HashFinal_fn pfn_SDF_HashFinal = NULL;

/*
 * 只加载一次动态库和函数指针。
 * 这比在 newctx 中重复调用更好。
 */
static int load_sdf_functions() {
    if (h_lib != NULL) return 1;
    h_lib = dlopen("libpiico_cc.so", RTLD_LAZY);
    if (h_lib == NULL) {
        fprintf(stderr, "Error loading libpiico_cc.so: %s\n", dlerror());
        return 0;
    }
    pfn_SDF_OpenDevice = (SDF_OpenDevice_fn)dlsym(h_lib, "SDF_OpenDevice");
    pfn_SDF_CloseDevice = (SDF_CloseDevice_fn)dlsym(h_lib, "SDF_CloseDevice");
    pfn_SDF_OpenSession = (SDF_OpenSession_fn)dlsym(h_lib, "SDF_OpenSession");
    pfn_SDF_CloseSession = (SDF_CloseSession_fn)dlsym(h_lib, "SDF_CloseSession");
    pfn_SDF_HashInit = (SDF_HashInit_fn)dlsym(h_lib, "SDF_HashInit");
    pfn_SDF_HashUpdate = (SDF_HashUpdate_fn)dlsym(h_lib, "SDF_HashUpdate");
    pfn_SDF_HashFinal = (SDF_HashFinal_fn)dlsym(h_lib, "SDF_HashFinal");
    if (!pfn_SDF_OpenDevice || !pfn_SDF_CloseDevice || !pfn_SDF_OpenSession ||
        !pfn_SDF_CloseSession || !pfn_SDF_HashInit || !pfn_SDF_HashUpdate || !pfn_SDF_HashFinal) {
        fprintf(stderr, "Error: One or more SDF digest functions not found.\n");
        dlclose(h_lib);
        h_lib = NULL;
        return 0;
    }
    return 1;
}

static void unload_sdf_functions() {
    if (h_lib != NULL) {
        dlclose(h_lib);
        h_lib = NULL;
    }
}

/* -------------------- 提供程序函数定义 -------------------- */

/* newctx - 分配并返回一个新的、未初始化的上下文。 */
static void* hsm_sm3_newctx(void* prov_ctx) {
    if (!ossl_prov_is_running()) return NULL;
    HSM_SM3_DIGEST_CTX* ctx = OPENSSL_zalloc(sizeof(*ctx));
    printf("entering hsm_sm3_newctx with ctx: %p\n", ctx);
    return ctx;
}

/* init - 初始化上下文以进行新的摘要操作。 */
static int hsm_sm3_internal_init(void* vctx, ossl_unused const OSSL_PARAM params[]) {
    HSM_SM3_DIGEST_CTX* ctx = (HSM_SM3_DIGEST_CTX*)vctx;
    printf("entering HSM_SM3_Init_internal_init with ctx: %p\n", ctx);

    if (!ossl_prov_is_running()) return 0;
    if (!load_sdf_functions()) return 0;

    // 检查硬件是否已打开。如果已打开，则仅重新初始化哈希。
    if (ctx->hSession != NULL) {
        return pfn_SDF_HashInit(ctx->hSession, SGD_SM3, NULL, NULL, 0) == SR_SUCCESSFULLY;
    }

    // 如果未打开，则初始化硬件。
    if (pfn_SDF_OpenDevice(&ctx->hDevice) != SR_SUCCESSFULLY) {
        return 0;
    }
    if (pfn_SDF_OpenSession(ctx->hDevice, &ctx->hSession) != SR_SUCCESSFULLY) {
        pfn_SDF_CloseDevice(ctx->hDevice);
        return 0;
    }
    return pfn_SDF_HashInit(ctx->hSession, SGD_SM3, NULL, NULL, 0) == SR_SUCCESSFULLY;
}

/* update - 将数据馈送到摘要操作中。 */
static int hsm_sm3_update(void* vctx, const void* data, size_t len) {
    HSM_SM3_DIGEST_CTX* ctx = (HSM_SM3_DIGEST_CTX*)vctx;
    if (!ossl_prov_is_running()) return 0;
    int ret = pfn_SDF_HashUpdate(ctx->hSession, (unsigned char*)data, len);
    printf("entering SM3_Update with data length: %zu\n", len);
    return ret == SR_SUCCESSFULLY;
}

/* final - 最终化摘要并返回结果。 */
static int hsm_sm3_internal_final(void* vctx, unsigned char* out, size_t* outl, size_t outsz) {
    HSM_SM3_DIGEST_CTX* ctx = (HSM_SM3_DIGEST_CTX*)vctx;
    if (!ossl_prov_is_running()) return 0;
    unsigned int hash_len;
    int ret = pfn_SDF_HashFinal(ctx->hSession, out, &hash_len);
    if (ret != SR_SUCCESSFULLY) return 0;
    *outl = hash_len;
    printf("entering hsm_sm3_internal_final with outsz: %zu\n", outsz);
    return 1;
}

/* freectx - 释放上下文并释放硬件资源。 */
static void hsm_sm3_freectx(void* vctx) {
    HSM_SM3_DIGEST_CTX* ctx = (HSM_SM3_DIGEST_CTX*)vctx;
    if (ctx != NULL) {
        if (ctx->hSession != NULL) pfn_SDF_CloseSession(ctx->hSession);
        if (ctx->hDevice != NULL) pfn_SDF_CloseDevice(ctx->hDevice);
        OPENSSL_clear_free(ctx, sizeof(*ctx));
    }
    unload_sdf_functions();
    printf("entering hsm_sm3_freectx with ctx: %p\n", vctx);
}

/* dupctx - 复制上下文。 */
static void* hsm_sm3_dupctx(void* ctx) {
    HSM_SM3_DIGEST_CTX* in = (HSM_SM3_DIGEST_CTX*)ctx;
    HSM_SM3_DIGEST_CTX* ret = ossl_prov_is_running() ? OPENSSL_malloc(sizeof(*ret)) : NULL;
    if (ret != NULL) *ret = *in;
    printf("entering hsm_sm3_dupctx with ctx: %p\n", ctx);
    return ret;
}

/* get_params - 检索算法参数。 */
static int hsm_sm3_get_params(OSSL_PARAM params[]) {
    printf("entering hsm_sm3_get_params\n");
    return ossl_digest_default_get_params(params, SM3_CBLOCK, SM3_DIGEST_LENGTH, 0);
}

static const OSSL_PARAM* hsm_sm3_gettable_params_fn(ossl_unused void* provctx) {
    return ossl_digest_default_gettable_params(provctx);
}

/* SM3 函数的调度表 */
const OSSL_DISPATCH ossl_hsm_sm3_functions[] = {
    { OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))hsm_sm3_newctx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void))hsm_sm3_internal_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))hsm_sm3_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void))hsm_sm3_internal_final },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))hsm_sm3_freectx },
    { OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))hsm_sm3_dupctx },
    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))hsm_sm3_get_params },
    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))hsm_sm3_gettable_params_fn },
    { 0, NULL }
};