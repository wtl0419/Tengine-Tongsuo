#include "internal/deprecated.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "crypto/sm2.h"
#include "prov/provider_ctx.h"
#include "prov/implementations.h"
#include "prov/provider_util.h"
#include "prov/piico_define.h"
#include "prov/piico_error.h"
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* SDF 函数指针声明 */
typedef int (*SDF_OpenDevice_fn)(void** phDeviceHandle);
typedef int (*SDF_CloseDevice_fn)(void* hDeviceHandle);
typedef int (*SDF_OpenSession_fn)(void* hDeviceHandle, void** phSessionHandle);
typedef int (*SDF_CloseSession_fn)(void* hSessionHandle);
typedef int (*SDF_GenerateKeyPair_ECC_fn)(void* hSessionHandle, unsigned int uiAlgID, unsigned int uiKeyBits, ECCrefPublicKey* pucPublicKey, ECCrefPrivateKey* pucPrivateKey);
typedef int (*SDF_ExternalEncrypt_ECC_fn)(void* hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey* pucPublicKey, unsigned char* pucData, unsigned int uiDataLength, ECCCipher* pucEncData);
typedef int (*SDF_ExternalDecrypt_ECC_fn)(void* hSessionHandle, unsigned int uiAlgID, ECCrefPrivateKey* pucPrivateKey, ECCCipher* pucEncData, unsigned char* pucData, unsigned int* puiDataLength);
typedef int (*SDF_GenerateRandom_fn)(void* hSessionHandle, unsigned int uiLength, unsigned char* pucRandom);

/* 动态库和 SDF 函数的全局变量 */
static void* h_lib = NULL;
static SDF_OpenDevice_fn pfn_SDF_OpenDevice = NULL;
static SDF_CloseDevice_fn pfn_SDF_CloseDevice = NULL;
static SDF_OpenSession_fn pfn_SDF_OpenSession = NULL;
static SDF_CloseSession_fn pfn_SDF_CloseSession = NULL;
static SDF_GenerateKeyPair_ECC_fn pfn_SDF_GenerateKeyPair_ECC = NULL;
static SDF_ExternalEncrypt_ECC_fn pfn_SDF_ExternalEncrypt_ECC = NULL;
static SDF_ExternalDecrypt_ECC_fn pfn_SDF_ExternalDecrypt_ECC = NULL;


static OSSL_FUNC_asym_cipher_newctx_fn hsm_sm2_newctx;
static OSSL_FUNC_asym_cipher_encrypt_init_fn hsm_sm2_init;
static OSSL_FUNC_asym_cipher_encrypt_fn hsm_sm2_asym_encrypt;
static OSSL_FUNC_asym_cipher_decrypt_init_fn hsm_sm2_init;
static OSSL_FUNC_asym_cipher_decrypt_fn hsm_sm2_asym_decrypt;
static OSSL_FUNC_asym_cipher_freectx_fn hsm_sm2_freectx;
static OSSL_FUNC_asym_cipher_dupctx_fn hsm_sm2_dupctx;
static OSSL_FUNC_asym_cipher_get_ctx_params_fn hsm_sm2_get_ctx_params;
static OSSL_FUNC_asym_cipher_gettable_ctx_params_fn hsm_sm2_gettable_ctx_params;
static OSSL_FUNC_asym_cipher_set_ctx_params_fn hsm_sm2_set_ctx_params;
static OSSL_FUNC_asym_cipher_settable_ctx_params_fn hsm_sm2_settable_ctx_params;
#define SR_SUCCESSFULLY 0
#define CHECK_SDF_RET(ret, msg) do { \
    if ((ret) != SR_SUCCESSFULLY) { \
        ERR_raise(ERR_LIB_PROV, PROV_R_OPERATION_FAILED); \
        fprintf(stderr, "%s failed with error code: %d\n", msg, (ret)); \
    } \
} while(0)

/* SM2 非对称密码的上下文 */
typedef struct {
    OSSL_LIB_CTX* libctx;
    EC_KEY* key;
    PROV_DIGEST md;
    void* hDevice;
    void* hSession;
    ECCrefPublicKey ecc_pk;
    ECCrefPrivateKey ecc_sk;
} HSM_PROV_SM2_CTX;

/* 动态加载和卸载函数 */
static int load_sm2_sdf_functions() {
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
    pfn_SDF_ExternalEncrypt_ECC = (SDF_ExternalEncrypt_ECC_fn)dlsym(h_lib, "SDF_ExternalEncrypt_ECC");
    pfn_SDF_ExternalDecrypt_ECC = (SDF_ExternalDecrypt_ECC_fn)dlsym(h_lib, "SDF_ExternalDecrypt_ECC");
    if (!pfn_SDF_OpenDevice || !pfn_SDF_CloseDevice || !pfn_SDF_OpenSession ||
        !pfn_SDF_CloseSession || !pfn_SDF_ExternalEncrypt_ECC || !pfn_SDF_ExternalDecrypt_ECC) {
        fprintf(stderr, "Error: One or more SDF functions not found.\n");
        dlclose(h_lib);
        h_lib = NULL;
        return 0;
    }
    return 1;
}

static void unload_sm2_sdf_functions() {
    if (h_lib != NULL) {
        dlclose(h_lib);
        h_lib = NULL;
    }
}
static void* hsm_sm2_newctx(void* provctx)
{
    HSM_PROV_SM2_CTX* psm2ctx = OPENSSL_zalloc(sizeof(HSM_PROV_SM2_CTX));
    if (psm2ctx == NULL) return NULL;
    psm2ctx->libctx = PROV_LIBCTX_OF(provctx);
    psm2ctx->hDevice = NULL;
    psm2ctx->hSession = NULL;
    return psm2ctx;
}
static void print_hex(const char* label, const unsigned char* data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}
// 新增辅助函数：互换字节数组的前后两块
static void swap_halves(unsigned char* data, size_t len) {
    if (len % 2 != 0) return; // 长度必须为偶数
    size_t half = len / 2;
    unsigned char* temp = (unsigned char*)malloc(half);
    if (temp == NULL) return;

    memcpy(temp, data, half);
    memmove(data, data + half, half);
    memcpy(data + half, temp, half);
    free(temp);
}
static int hsm_sm2_init(void* vpsm2ctx, void* vkey, const OSSL_PARAM params[])
{
    HSM_PROV_SM2_CTX* psm2ctx = (HSM_PROV_SM2_CTX*)vpsm2ctx;
    const EC_POINT* pub_point = NULL;
    const BIGNUM* priv_key = NULL;
	printf("entering hsm_sm2_init with psm2ctx: %p, vkey: %p\n", psm2ctx, vkey);
    if (psm2ctx == NULL || vkey == NULL || !EC_KEY_up_ref(vkey))
        return 0;
    EC_KEY_free(psm2ctx->key);
    psm2ctx->key = vkey;
    if (!load_sm2_sdf_functions()) return 0;

    // 打开设备和会话
    if (pfn_SDF_OpenDevice(&psm2ctx->hDevice) != SR_SUCCESSFULLY) return 0;
    if (pfn_SDF_OpenSession(psm2ctx->hDevice, &psm2ctx->hSession) != SR_SUCCESSFULLY) {
        pfn_SDF_CloseDevice(psm2ctx->hDevice);
        return 0;
    }
    // 从 EC_KEY 中提取公钥和私钥并转换为 SDF 格式
    pub_point = EC_KEY_get0_public_key(psm2ctx->key);
    priv_key = EC_KEY_get0_private_key(psm2ctx->key);

    // 公钥转换
    if (pub_point != NULL) {
        const EC_GROUP* group = EC_KEY_get0_group(psm2ctx->key);
        BIGNUM* bn_x = BN_new();
        BIGNUM* bn_y = BN_new();

        if (!EC_POINT_get_affine_coordinates(group, pub_point, bn_x, bn_y, NULL)) {
            BN_free(bn_x);
            BN_free(bn_y);
            return 0;
        }

        psm2ctx->ecc_pk.bits = BN_num_bits(bn_x);
        BN_bn2bin(bn_x, psm2ctx->ecc_pk.x);
        BN_bn2bin(bn_y, psm2ctx->ecc_pk.y);

        BN_free(bn_x);
        BN_free(bn_y);
    }

    // 私钥转换
    if (priv_key != NULL) {
        psm2ctx->ecc_sk.bits = BN_num_bits(priv_key);
        BN_bn2bin(priv_key, psm2ctx->ecc_sk.K);
    }
	printf("private key bits: %d\n", psm2ctx->ecc_sk.bits);
    print_hex("Private Key (vk.K)", psm2ctx->ecc_sk.K, 64);
    print_hex("Public Key X (pk.x)", psm2ctx->ecc_pk.x, 64);
    print_hex("Public Key Y (pk.y)", psm2ctx->ecc_pk.y, 64);
    // 假设密钥数据总长64位，即8个字节。如果你的ECCref_MAX_LEN是64，这里需要调整
    swap_halves(psm2ctx->ecc_pk.x, 64);
    swap_halves(psm2ctx->ecc_pk.y, 64);
    swap_halves(psm2ctx->ecc_sk.K, 64);
    // ---------------------------------

    print_hex("Private Key (vk.K)", psm2ctx->ecc_sk.K, 64);
    print_hex("Public Key X (pk.x)", psm2ctx->ecc_pk.x, 64);
    print_hex("Public Key Y (pk.y)", psm2ctx->ecc_pk.y, 64);

    return 1;
}

static const EVP_MD* hsm_sm2_get_md(HSM_PROV_SM2_CTX* psm2ctx)
{
    const EVP_MD* md = ossl_prov_digest_md(&psm2ctx->md);
    const char* prop_query = "provider=sushuHsm";
    if (md == NULL) {
        md = ossl_prov_digest_fetch(&psm2ctx->md, psm2ctx->libctx, "SM3", prop_query);
    }
    printf("entering hsm_sm2_get_md with md: %p\n", md);
    return md;
}

static int hsm_sm2_asym_encrypt(void* vpsm2ctx, unsigned char* out, size_t* outlen,
    size_t outsize, const unsigned char* in,
    size_t inlen)
{
    HSM_PROV_SM2_CTX* psm2ctx = (HSM_PROV_SM2_CTX*)vpsm2ctx;
    const EVP_MD* md = hsm_sm2_get_md(psm2ctx);
    ECCCipher* eccEnData = NULL;
    int ret;
	printf("entering hsm_sm2_asym_encrypt\n");
    if (md == NULL)
        return 0;

    if (out == NULL) {
        if (!ossl_sm2_ciphertext_size(psm2ctx->key, md, inlen, outlen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
            return 0;
        }
        size_t required_size = sizeof(ECCCipher) + inlen;
        *outlen = required_size;
        return 1;
    }
    eccEnData = OPENSSL_malloc(sizeof(ECCCipher) + inlen);
    if (eccEnData == NULL) return 0;

    ret = pfn_SDF_ExternalEncrypt_ECC(psm2ctx->hSession, SGD_SM2_3, &psm2ctx->ecc_pk,
        (unsigned char*)in, inlen, eccEnData);
    if (ret != SR_SUCCESSFULLY) {
        OPENSSL_free(eccEnData);
        return 0;
    }

    size_t encrypted_len = sizeof(ECCCipher) + eccEnData->L;
    if (outsize < encrypted_len) {
        *outlen = encrypted_len;
        OPENSSL_free(eccEnData);
        return 0;
    }

    memcpy(out, eccEnData, encrypted_len);
    *outlen = encrypted_len;

    OPENSSL_free(eccEnData);
    return 1;
}

static int hsm_sm2_asym_decrypt(void* vpsm2ctx, unsigned char* out, size_t* outlen,
    size_t outsize, const unsigned char* in,
    size_t inlen)
{
    HSM_PROV_SM2_CTX* psm2ctx = (HSM_PROV_SM2_CTX*)vpsm2ctx;
    ECCCipher* eccEnData = (ECCCipher*)in;
    unsigned int temp_len;

    if (psm2ctx == NULL || in == NULL) return 0;
    if (out == NULL) {
        *outlen = eccEnData->L;
        //if (!ossl_sm2_plaintext_size(in, inlen, outlen)) return 0;
        return 1;
    }

    int ret = pfn_SDF_ExternalDecrypt_ECC(psm2ctx->hSession, SGD_SM2_3, &psm2ctx->ecc_sk, eccEnData, out, &temp_len);
    if (ret != SR_SUCCESSFULLY) return 0;
    *outlen = temp_len;

    return 1;
}

static void hsm_sm2_freectx(void* vpsm2ctx)
{
    HSM_PROV_SM2_CTX* psm2ctx = (HSM_PROV_SM2_CTX*)vpsm2ctx;
	printf("entering hsm_sm2_freectx\n");
    EC_KEY_free(psm2ctx->key);
    ossl_prov_digest_reset(&psm2ctx->md);

    OPENSSL_free(psm2ctx);
}

static void* hsm_sm2_dupctx(void* vpsm2ctx)
{
    HSM_PROV_SM2_CTX* srcctx = (HSM_PROV_SM2_CTX*)vpsm2ctx;
    HSM_PROV_SM2_CTX* dstctx;
	printf("entering hsm_sm2_dupctx\n");
    dstctx = OPENSSL_zalloc(sizeof(*srcctx));
    if (dstctx == NULL)
        return NULL;

    *dstctx = *srcctx;
    if (dstctx->key != NULL && !EC_KEY_up_ref(dstctx->key)) {
        OPENSSL_free(dstctx);
        return NULL;
    }

    if (!ossl_prov_digest_copy(&dstctx->md, &srcctx->md)) {
        hsm_sm2_freectx(dstctx);
        return NULL;
    }

    return dstctx;
}

static int hsm_sm2_get_ctx_params(void* vpsm2ctx, OSSL_PARAM* params)
{
    HSM_PROV_SM2_CTX* psm2ctx = (HSM_PROV_SM2_CTX*)vpsm2ctx;
    OSSL_PARAM* p;
	printf("entering hsm_sm2_get_ctx_params\n");
    if (vpsm2ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_DIGEST);
    if (p != NULL) {
        const EVP_MD* md = ossl_prov_digest_md(&psm2ctx->md);

        if (!OSSL_PARAM_set_utf8_string(p, md == NULL ? ""
            : EVP_MD_get0_name(md)))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM* hsm_sm2_gettable_ctx_params(ossl_unused void* vpsm2ctx,
    ossl_unused void* provctx)
{
	printf("entering hsm_sm2_gettable_ctx_params\n");
    return known_gettable_ctx_params;
}

static int hsm_sm2_set_ctx_params(void* vpsm2ctx, const OSSL_PARAM params[])
{
    HSM_PROV_SM2_CTX* psm2ctx = (HSM_PROV_SM2_CTX*)vpsm2ctx;
	printf("entering hsm_sm2_set_ctx_params\n");
    if (psm2ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    if (!ossl_prov_digest_load_from_params(&psm2ctx->md, params,
        psm2ctx->libctx))
        return 0;

    return 1;
}

static const OSSL_PARAM known_settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_ENGINE, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM* hsm_sm2_settable_ctx_params(ossl_unused void* vpsm2ctx,
    ossl_unused void* provctx)
{
	printf("entering hsm_sm2_settable_ctx_params\n");
    return known_settable_ctx_params;
}

const OSSL_DISPATCH ossl_hsm_sm2_asym_cipher_functions[] = {
    { OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))hsm_sm2_newctx },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, (void (*)(void))hsm_sm2_init },
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (void (*)(void))hsm_sm2_asym_encrypt },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, (void (*)(void))hsm_sm2_init },
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))hsm_sm2_asym_decrypt },
    { OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))hsm_sm2_freectx },
    { OSSL_FUNC_ASYM_CIPHER_DUPCTX, (void (*)(void))hsm_sm2_dupctx },
    { OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,
      (void (*)(void))hsm_sm2_get_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS,
      (void (*)(void))hsm_sm2_gettable_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,
      (void (*)(void))hsm_sm2_set_ctx_params },
    { OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS,
      (void (*)(void))hsm_sm2_settable_ctx_params },
    { 0, NULL }
};