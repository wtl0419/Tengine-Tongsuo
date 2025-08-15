#include <stdio.h>    // For printf, fprintf
#include <stdlib.h>   // For malloc, free, exit
#include <string.h>   // For memcpy, memset
#include <dlfcn.h>    // For dlopen, dlsym, dlclose, dlerror
#include <openssl/err.h> // For OpenSSL error handling
# include <openssl/types.h>
#include <openssl/proverr.h>
#include "hsm_sdf_sm1.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "prov/piico_define.h"
#include <string.h>

#define CHECK_SDF_RET(ret, msg) do { \
    if ((ret) != 0) { \
        fprintf(stderr, "%s failed with error code: %d\n", msg, (ret)); \
    } \
} while(0)
// Global variables for dynamic library and function pointers
static void* h_lib = NULL;
static SDF_OpenDevice_fn pfn_SDF_OpenDevice = NULL;
static SDF_CloseDevice_fn pfn_SDF_CloseDevice = NULL;
static SDF_OpenSession_fn pfn_SDF_OpenSession = NULL;
static SDF_CloseSession_fn pfn_SDF_CloseSession = NULL;
static SDF_GenerateRandom_fn pfn_SDF_GenerateRandom = NULL;
static SDF_GenerateKeyWithKEK_fn pfn_SDF_GenerateKeyWithKEK = NULL;
static SDF_ImportKey_fn pfn_SDF_ImportKey = NULL;
static SDF_DestroyKey_fn pfn_SDF_DestroyKey = NULL;
static SDF_Encrypt_fn pfn_SDF_Encrypt = NULL;
static SDF_Decrypt_fn pfn_SDF_Decrypt = NULL;

void* hDevice = NULL;
void* hSession = NULL;
void* hKey = NULL;
// Function to load all required SDF functions from the dynamic library
static int load_sdf_functions() {
    h_lib = dlopen("libpiico_cc.so", RTLD_LAZY);
    if (h_lib == NULL) {
        fprintf(stderr, "Error loading libpiico_cc.so: %s\n", dlerror());
        return 0;
    }

    pfn_SDF_OpenDevice = (SDF_OpenDevice_fn)dlsym(h_lib, "SDF_OpenDevice");
    pfn_SDF_CloseDevice = (SDF_CloseDevice_fn)dlsym(h_lib, "SDF_CloseDevice");
    pfn_SDF_OpenSession = (SDF_OpenSession_fn)dlsym(h_lib, "SDF_OpenSession");
    pfn_SDF_CloseSession = (SDF_CloseSession_fn)dlsym(h_lib, "SDF_CloseSession");
    pfn_SDF_GenerateRandom = (SDF_GenerateRandom_fn)dlsym(h_lib, "SDF_GenerateRandom");
    pfn_SDF_GenerateKeyWithKEK = (SDF_GenerateKeyWithKEK_fn)dlsym(h_lib, "SDF_GenerateKeyWithKEK");
    pfn_SDF_ImportKey = (SDF_ImportKey_fn)dlsym(h_lib, "SDF_ImportKey");
    pfn_SDF_DestroyKey = (SDF_DestroyKey_fn)dlsym(h_lib, "SDF_DestroyKey");
    pfn_SDF_Encrypt = (SDF_Encrypt_fn)dlsym(h_lib, "SDF_Encrypt");
    pfn_SDF_Decrypt = (SDF_Decrypt_fn)dlsym(h_lib, "SDF_Decrypt");

    if (!pfn_SDF_OpenDevice || !pfn_SDF_CloseDevice || !pfn_SDF_OpenSession || !pfn_SDF_CloseSession ||
        !pfn_SDF_GenerateRandom || !pfn_SDF_ImportKey || !pfn_SDF_DestroyKey || !pfn_SDF_Encrypt ||
        !pfn_SDF_Decrypt) {
        fprintf(stderr, "Error: One or more SDF functions not found in the library.\n");
        dlclose(h_lib);
        h_lib = NULL;
        return 0;
    }
    return 1;
}
// Function to unload the dynamic library
static void unload_sdf_functions() {
    if (h_lib != NULL) {
        dlclose(h_lib);
        h_lib = NULL;
    }
}
static void cleanup(void* hDevice, void* hSession, void* hKey,
    unsigned char* ciphertext, unsigned char* decryptedtext) {
    if (hKey != NULL) {
        pfn_SDF_DestroyKey(hSession, hKey);
        printf("Key destroyed.\n");
    }
    if (hSession != NULL) {
        pfn_SDF_CloseSession(hSession);
        printf("Session closed.\n");
    }
    if (hDevice != NULL) {
        pfn_SDF_CloseDevice(hDevice);
        printf("Device closed.\n");
    }
    unload_sdf_functions();
    printf("SDF functions unloaded.\n");
}

// --- 1. newctx 函数实现 (对应 OSSL_FUNC_CIPHER_NEWCTX) ---
static void* hsm_sm1_cbc_newctx(void* provctx) {
    SUSHU_HSM_SM1_CTX* ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ossl_cipher_generic_initkey(ctx, SGD_SM1_CBC_KBITS, SGD_SM1_CBC_BLOCK_SIZE, SGD_SM1_CBC_IVLEN, SGD_SM1_CBC, 0, NULL, provctx);
     // Load the dynamic library
    if (!load_sdf_functions()) {
        return 1;
    }
    int ret = 0;
    unsigned int encrypted_key_len = 16;
    // Step 1: Open the SDF device
    ret = pfn_SDF_OpenDevice(&hDevice);
    CHECK_SDF_RET(ret, "SDF_OpenDevice");

    printf("Device opened successfully. Device handle: %p\n", hDevice);

    // Step 2: Open a session with the device
    ret = pfn_SDF_OpenSession(hDevice, &hSession);
    CHECK_SDF_RET(ret, "SDF_OpenSession");

    printf("Session opened successfully. Session handle: %p\n", hSession);    

   
    return ctx;
}
static void* hsm_sm1_ecb_newctx(void* provctx) {
    SUSHU_HSM_SM1_CTX* ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ossl_cipher_generic_initkey(ctx, SGD_SM1_ECB_KBITS, SGD_SM1_ECB_BLOCK_SIZE, SGD_SM1_ECB_IVLEN, SGD_SM1_ECB, 0, NULL, provctx);
    // Load the dynamic library
    if (!load_sdf_functions()) {
        return 1;
    }
    int ret = 0;
    unsigned int encrypted_key_len = 16;
    // Step 1: Open the SDF device
    ret = pfn_SDF_OpenDevice(&hDevice);
    CHECK_SDF_RET(ret, "SDF_OpenDevice");

    printf("Device opened successfully. Device handle: %p\n", hDevice);

    // Step 2: Open a session with the device
    ret = pfn_SDF_OpenSession(hDevice, &hSession);
    CHECK_SDF_RET(ret, "SDF_OpenSession");

    printf("Session opened successfully. Session handle: %p\n", hSession);


    return ctx;
}

// --- 2. freectx 函数实现 (对应 OSSL_FUNC_CIPHER_FREECTX) ---
static void hsm_freectx(void* vctx) {
    
    SUSHU_HSM_SM1_CTX* ctx = (SUSHU_HSM_SM1_CTX*)vctx;

    ossl_cipher_generic_reset_ctx((PROV_CIPHER_CTX*)vctx);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}
// --- 3. dupctx 函数实现 (对应 OSSL_FUNC_CIPHER_DUPCTX) ---
static void* hsm_dupctx(void* ctx) {

    SUSHU_HSM_SM1_CTX* in = (SUSHU_HSM_SM1_CTX*)ctx;
    SUSHU_HSM_SM1_CTX* ret;

    if (!ossl_prov_is_running())
        return NULL;

    ret = OPENSSL_malloc(sizeof(*ret));
    if (ret == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    in->base.hw->copyctx(&ret->base, &in->base);

    return ret;
}
// --- 4. einit 函数实现 (对应 OSSL_FUNC_CIPHER_ENCRYPT_INIT) ---
// 该函数会被 ossl_cipher_generic_einit 间接调用
static int hsm_einit(void* vctx, const unsigned char* key, size_t keylen,
    const unsigned char* iv, size_t ivlen, const OSSL_PARAM params[]) {
    int ret;
    ossl_cipher_generic_einit(vctx, key, keylen, iv, ivlen, params);
    if(key != NULL) {
        ret = pfn_SDF_ImportKey(hSession, key, keylen, &hKey);
        CHECK_SDF_RET(ret, "SDF_ImportKey");

        printf("Generated and imported key successfully. Key handle: %p\n", hKey);
	}
    return 1;
}

// --- 5. dinit 函数实现 (对应 OSSL_FUNC_CIPHER_DECRYPT_INIT) ---
// 该函数会被 ossl_cipher_generic_dinit 间接调用
static int hsm_dinit(void* vctx, const unsigned char* key, size_t keylen,
    const unsigned char* iv, size_t ivlen, const OSSL_PARAM params[]) {
    int ret;
    ossl_cipher_generic_dinit(vctx, key, keylen, iv, ivlen, params);
    if (key != NULL) {
        ret = pfn_SDF_ImportKey(hSession, key, keylen, &hKey);
        CHECK_SDF_RET(ret, "SDF_ImportKey");
        printf("Generated and imported key successfully. Key handle: %p\n", hKey);
	}
    return 1;
}
static int hsm_sm1_cbc_update(void* vctx, unsigned char* out,
    int* outl, size_t outsize, const unsigned char* in, int inl)
{
    PROV_CIPHER_CTX* ctx = (PROV_CIPHER_CTX*)vctx;
    int ret;
    int success = 0;
    if (ctx->enc == 1)
    {
        printf("Starting encryption...\n");
        ret = pfn_SDF_Encrypt(hSession, hKey, SGD_SM1_CBC, ctx->iv, in, inl, out, outl);
        CHECK_SDF_RET(ret, "SDF_Encrypt");
        printf("Encryption successful. Ciphertext length: %d\n", *outl);
    }
    else if(ctx->enc == 0)
    {
        printf("Starting decryption...\n");
        ret = pfn_SDF_Decrypt(hSession, hKey, SGD_SM1_CBC, ctx->iv, in, inl, out, outl);
        CHECK_SDF_RET(ret, "SDF_Decrypt");

        printf("Decryption successful. Decrypted length: %d\n", *outl);
    }
    else
    {
        fprintf(stderr, "Invalid operation mode.\n");
        return 0;
	}
	success = ret == 0 ? 1 : 0;
    return success;
}
static int hsm_sm1_ecb_update(void* vctx, unsigned char* out,
    int* outl, size_t outsize, const unsigned char* in, int inl)
{
    PROV_CIPHER_CTX* ctx = (PROV_CIPHER_CTX*)vctx;
    int ret;
    int success = 0;
    if (ctx->enc == 1)
    {
        printf("Starting encryption...\n");
        ret = pfn_SDF_Encrypt(hSession, hKey, SGD_SM1_ECB, ctx->iv, in, inl, out, outl);
        CHECK_SDF_RET(ret, "SDF_Encrypt");
        printf("Encryption successful. Ciphertext length: %d\n", *outl);
    }
    else if (ctx->enc == 0)
    {
        printf("Starting decryption...\n");
        ret = pfn_SDF_Decrypt(hSession, hKey, SGD_SM1_ECB, ctx->iv, in, inl, out, outl);
        CHECK_SDF_RET(ret, "SDF_Decrypt");

        printf("Decryption successful. Decrypted length: %d\n", *outl);
    }
    else
    {
        fprintf(stderr, "Invalid operation mode.\n");
        return 0;
    }
    success = ret == 0 ? 1 : 0;
    return success;
}
static int hsm_final(void* vctx, unsigned char* out, size_t* outl, size_t outsize)
{
    *outl = 0;
    PROV_CIPHER_CTX* ctx = (PROV_CIPHER_CTX*)vctx;
    // 我们可以添加一个简单的打印，来表明操作已经完成。
    if (ctx->enc == 1) {
        printf("encrypt success!\n");
    }
    else if (ctx->enc == 0) {
        printf("decrypt success!\n");
    }

    // 返回1表示成功。
    return 1;
}
// --- 6. get_params 函数实现 (对应 OSSL_FUNC_CIPHER_GET_PARAMS) ---
// 该函数会被 ossl_cipher_generic_get_params 间接调用
static int hsm_get_params(OSSL_PARAM params[]) {
    // 这个函数通常用于返回算法的固定参数，如块大小、IV长度等
    // 这些参数通常在Provider的OSSL_ALGORITHM定义中提供，这里只是一个示例
    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 16)) return 0; // SM4密钥长度16字节

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 16)) return 0; // SM4 IV长度16字节

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 16)) return 0; // SM4块大小16字节

    return 1;
}

// --- 7. get_ctx_params 函数实现 (对应 OSSL_FUNC_CIPHER_GET_CTX_PARAMS) ---
// 该函数会被 ossl_cipher_generic_get_ctx_params 间接调用
static int hsm_get_ctx_params(void* vctx, OSSL_PARAM params[]) {
    PROV_CIPHER_CTX* ctx = (PROV_CIPHER_CTX*)vctx;
    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->ivlen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->pad)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL
        && !OSSL_PARAM_set_octet_ptr(p, &ctx->oiv, ctx->ivlen)
        && !OSSL_PARAM_set_octet_string(p, &ctx->oiv, ctx->ivlen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL
        && !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->ivlen)
        && !OSSL_PARAM_set_octet_string(p, &ctx->iv, ctx->ivlen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_NUM);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->num)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keylen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS_MAC);
    if (p != NULL
        && !OSSL_PARAM_set_octet_ptr(p, ctx->tlsmac, ctx->tlsmacsize)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return 1;
}

// --- 8. gettable_ctx_params 函数实现 (对应 OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS) ---
// 该函数会被 ossl_cipher_generic_gettable_ctx_params 间接调用
static const OSSL_PARAM* hsm_gettable_ctx_params(void* provctx) {
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_DEFN(OSSL_CIPHER_PARAM_IV, OSSL_PARAM_OCTET_STRING, NULL, 0),
        OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}
const OSSL_DISPATCH ossl_hsm_sm1cbc_functions[] = {
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))hsm_einit },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))hsm_dinit },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))hsm_sm1_cbc_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))hsm_final },
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))ossl_cipher_generic_cipher },
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))hsm_sm1_cbc_newctx },
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))hsm_dupctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))hsm_freectx },
    { OSSL_FUNC_CIPHER_GET_PARAMS,(void (*)(void))hsm_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))ossl_cipher_generic_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))hsm_get_ctx_params },  
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))hsm_gettable_ctx_params }, 
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,(void (*)(void))ossl_cipher_generic_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))ossl_cipher_generic_settable_ctx_params },
    { 0, NULL }
};
const OSSL_DISPATCH ossl_hsm_sm1ecb_functions[] = {
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))hsm_einit },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))hsm_dinit },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))hsm_sm1_ecb_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))hsm_final },
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))ossl_cipher_generic_cipher },
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))hsm_sm4_ecb_newctx },
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))hsm_dupctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))hsm_freectx },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))hsm_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))ossl_cipher_generic_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))hsm_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))hsm_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))ossl_cipher_generic_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))ossl_cipher_generic_settable_ctx_params },
    { 0, NULL }
};