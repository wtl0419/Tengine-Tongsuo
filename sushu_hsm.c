#include <string.h>
#include <stdio.h>
#include <openssl/opensslconf.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "prov/bio.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"
#include "prov/implementations.h"
#include "prov/names.h"
#include "prov/provider_util.h"
#include "prov/seeding.h"
#include "internal/nelem.h"

#define ALGC(NAMES, FUNC, CHECK) { { NAMES, "provider=sushuHsm", FUNC }, CHECK }
#define ALG(NAMES, FUNC) ALGC(NAMES, FUNC, NULL)

static OSSL_FUNC_provider_gettable_params_fn sushu_hsm_gettable_params;
static OSSL_FUNC_provider_get_params_fn sushu_hsm_get_params;
static OSSL_FUNC_provider_query_operation_fn sushu_hsm_query_operation;
// Provider 内部的上下文结构体，用于保存Provider的状态和数据
typedef struct sushu_hsm_prov_ctx_st {
    OSSL_LIB_CTX* libctx;
    // 其他PCIe硬件相关的句柄、配置等
    void* sushu_hsm_device_handle;
} SUSHU_HSM_PROV_CTX;

// 前向声明 Provider 提供的算法分发表
const OSSL_ALGORITHM_CAPABLE sushu_hsm_cipher_functions[] = {
    ALG(PROV_NAMES_SM4_CBC, ossl_hsm_sm4cbc_functions),
    ALG(PROV_NAMES_SM4_ECB, ossl_hsm_sm4ecb_functions),


    { { NULL, NULL, NULL }, NULL }
}; // 示例：PCIe 加速的对称密码算法

static OSSL_ALGORITHM sushu_hsm_exported_ciphers[OSSL_NELEM(sushu_hsm_cipher_functions)];


const OSSL_ALGORITHM sushu_hsm_digest_functions[] = {

    { PROV_NAMES_SM3, "provider=sushuHsm", ossl_hsm_sm3_functions },
    { NULL, NULL, NULL }
};
static const OSSL_ALGORITHM sushu_hsm_asym_cipher[] = {

    { PROV_NAMES_SM2, "provider=sushuHsm", ossl_hsm_sm2_asym_cipher_functions },
    { NULL, NULL, NULL }
};
static const OSSL_ALGORITHM sushu_hsm_keymgmt_functions[] = {
    { PROV_NAMES_SM2, "provider=sushuHsm", ossl_hsm_sm2_keymgmt_functions, PROV_DESCS_SM2},
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM sushu_hsm_signature_functions[] = {
    { PROV_NAMES_SM2, "provider=sushuHsm", ossl_hsm_sm2_signature_functions },
    { NULL, NULL, NULL }
};
static const OSSL_ALGORITHM sushu_hsm_store[] = {
#define STORE(name, _fips, func_table)                           \
    { name, "provider=sushuHsm,fips=" _fips, (func_table) },

#include "stores.inc"
    { NULL, NULL, NULL }
#undef STORE
};
static const OSSL_ALGORITHM sushu_hsm_encoder[] = {
#define ENCODER_PROVIDER "sushuHsm"
#include "encoders.inc"
    { NULL, NULL, NULL }
#undef ENCODER_PROVIDER
};

static const OSSL_ALGORITHM sushu_hsm_decoder[] = {
#define DECODER_PROVIDER "sushuHsm"
#include "decoders.inc"
    { NULL, NULL, NULL }
#undef DECODER_PROVIDER
};
static const OSSL_PARAM sushu_hsm_gettable_provider_params[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    // 如果有自定义参数，也要在这里声明
    // OSSL_PARAM_DEFN("device-id", OSSL_PARAM_INT, NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM* sushu_hsm_gettable_params(void* provctx) {
    return sushu_hsm_gettable_provider_params;
}
static int sushu_hsm_get_params(void* provctx, OSSL_PARAM params[])
{
    OSSL_PARAM* p;

    // 获取 Provider 名称
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "sushuHsm Provider"))
        return 0; // 如果设置失败，返回0表示失败

    // 获取 Provider 版本
    // 这里可以使用当前的OpenSSL版本字符串，或者如果你有PCIe Provider自己的版本号
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR))
        return 0;

    // 获取 Provider 构建信息（可选，可以使用OpenSSL的完整版本字符串）
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
        return 0;

    // 获取 Provider 状态（是否正在运行）
    // ossl_prov_is_running() 是一个通用函数，检查Provider是否处于活跃状态
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, ossl_prov_is_running()))
        return 0;

    // 如果你有PCIe Provider特有的参数，也可以在这里提供。
    // 例如，假设你有一个内部的PCIe设备ID：
    // PCIE_PROV_CTX *ctx = (PCIE_PROV_CTX *)provctx; // 如果需要访问provctx
    // p = OSSL_PARAM_locate(params, "device-id"); // 自定义参数名称
    // if (p != NULL && !OSSL_PARAM_set_int(p, ctx->device_id))
    //     return 0;

    return 1; // 成功设置所有请求的参数
}
// Provider 的 Teardown 函数 (卸载时调用)
static void sushu_hsm_teardown(void* provctx) {
    SUSHU_HSM_PROV_CTX* ctx = (SUSHU_HSM_PROV_CTX*)provctx;
    // 清理硬件句柄，释放资源
    if (ctx->sushu_hsm_device_handle != NULL) {
        // sushu_hsm_close_device(ctx->pcie_device_handle); // 假设的关闭函数
    }
    ossl_prov_ctx_free(ctx); // 释放 Provider 上下文
}
static const OSSL_DISPATCH sushu_hsm_provider_dispatch_table[] = {
        { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))sushu_hsm_teardown },
        { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))sushu_hsm_query_operation },
        { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))sushu_hsm_gettable_params },
        { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))sushu_hsm_get_params },
        { 0, NULL }
};
// Provider 的查询操作函数 (实现 OSSL_FUNC_PROVIDER_QUERY_OPERATION)
static const OSSL_ALGORITHM* sushu_hsm_query_operation(void* provctx, int operation_id, int* no_cache) {
    // 根据 operation_id 返回对应的算法列表
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_CIPHER:
        return sushu_hsm_exported_ciphers; // 返回对称密码算法列表
    case OSSL_OP_DIGEST:
        return sushu_hsm_digest_functions; // 返回散列算法列表
    case OSSL_OP_ASYM_CIPHER:
        return sushu_hsm_asym_cipher;
    case OSSL_OP_KEYMGMT:
        return sushu_hsm_keymgmt_functions;
    case OSSL_OP_SIGNATURE:
        return sushu_hsm_signature_functions;
    //case OSSL_OP_ENCODER:
    //    return sushu_hsm_encoder;
    //case OSSL_OP_DECODER:
    //    return sushu_hsm_decoder;
    case OSSL_OP_STORE:
        return sushu_hsm_store;
        // ... 其他操作，如 KDF, RAND 等
    }
    return NULL;
}
// Provider 的入口点函数，在 Provider 被加载时由 OpenSSL 核心调用
// 这个函数指针会在 ossl_predefined_providers 数组中被引用
int ossl_sushu_hsm_provider_init(const OSSL_CORE_HANDLE* handle,
    const OSSL_DISPATCH* in,
    const OSSL_DISPATCH** out,
    void** provctx)
{
    SUSHU_HSM_PROV_CTX* sushu_hsm_ctx;

    // 1. 从核心库接收服务 (BIO, Seeding, Error Handling等)
    // 确保你的 Provider 能够使用核心库的 I/O、内存和随机数服务
    if (!ossl_prov_bio_from_dispatch(in)
        || !ossl_prov_seeding_from_dispatch(in)
        // ... 其他从核心库获取的服务
        ) {
        return 0;
    }

    // 2. 存储核心库提供的其他通用函数
    OSSL_FUNC_core_get_libctx_fn* c_get_libctx = NULL;
    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_LIBCTX:
            c_get_libctx = OSSL_FUNC_core_get_libctx(in);
            break;
            // ... 处理其他你需要的核心函数，例如错误报告，线程启动等
        }
    }
    if (c_get_libctx == NULL) {
        return 0; // 必需函数未获取到
    }

    // 3. 创建 Provider 私有上下文
    if ((*provctx = ossl_prov_ctx_new()) == NULL) {
        return 0;
    }
    sushu_hsm_ctx = OPENSSL_zalloc(sizeof(*sushu_hsm_ctx)); // 分配你自己的PCIe上下文
    if (sushu_hsm_ctx == NULL) {
        ossl_prov_ctx_free(*provctx);
        *provctx = NULL;
        return 0;
    }
    ossl_prov_ctx_set0_handle(*provctx, handle);
    ossl_prov_ctx_set0_libctx(*provctx, (OSSL_LIB_CTX*)c_get_libctx(handle));

    // 4. 初始化硬件 (如果需要)
    // pcie_ctx->pcie_device_handle = pcie_init_device(); // 假设的硬件初始化函数
    // if (pcie_ctx->pcie_device_handle == NULL) {
    //     // ... 错误处理
    //     pcie_teardown(*provctx);
    //     return 0;
    // }

    *out = sushu_hsm_provider_dispatch_table; // 返回Provider的核心功能分发表
    ossl_prov_cache_exported_algorithms(sushu_hsm_cipher_functions, sushu_hsm_exported_ciphers);
    return 1;
}