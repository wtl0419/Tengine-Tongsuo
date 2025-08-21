/*
 * Copyright 2020-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * ECDSA low level APIs are deprecated for public use, but still ok for
 * internal use - SM2 implemetation uses ECDSA_size() function.
 */
#include "internal/deprecated.h"

#include <string.h> /* memcpy */
#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/dsa.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/sm3.h>
#include "internal/nelem.h"
#include "internal/sizes.h"
#include "internal/cryptlib.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "crypto/ec.h"
#include "crypto/sm2.h"
#include "prov/der_sm2.h"
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "prov/piico_define.h"
#include "prov/piico_error.h"

#define SR_SUCCESSFULLY 0
#define ECCref_MAX_LEN 64

static OSSL_FUNC_signature_newctx_fn sm2sig_newctx;
static OSSL_FUNC_signature_sign_init_fn sm2sig_signature_init;
static OSSL_FUNC_signature_verify_init_fn sm2sig_signature_init;
static OSSL_FUNC_signature_sign_fn sm2sig_sign;
static OSSL_FUNC_signature_verify_fn sm2sig_verify;
static OSSL_FUNC_signature_digest_sign_init_fn sm2sig_digest_signverify_init;
static OSSL_FUNC_signature_digest_sign_update_fn sm2sig_digest_signverify_update;
static OSSL_FUNC_signature_digest_sign_final_fn sm2sig_digest_sign_final;
static OSSL_FUNC_signature_digest_verify_init_fn sm2sig_digest_signverify_init;
static OSSL_FUNC_signature_digest_verify_update_fn sm2sig_digest_signverify_update;
static OSSL_FUNC_signature_digest_verify_final_fn sm2sig_digest_verify_final;
static OSSL_FUNC_signature_freectx_fn sm2sig_freectx;
static OSSL_FUNC_signature_dupctx_fn sm2sig_dupctx;
static OSSL_FUNC_signature_get_ctx_params_fn sm2sig_get_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn sm2sig_gettable_ctx_params;
static OSSL_FUNC_signature_set_ctx_params_fn sm2sig_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn sm2sig_settable_ctx_params;
static OSSL_FUNC_signature_get_ctx_md_params_fn sm2sig_get_ctx_md_params;
static OSSL_FUNC_signature_gettable_ctx_md_params_fn sm2sig_gettable_ctx_md_params;
static OSSL_FUNC_signature_set_ctx_md_params_fn sm2sig_set_ctx_md_params;
static OSSL_FUNC_signature_settable_ctx_md_params_fn sm2sig_settable_ctx_md_params;

/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 * We happen to know that our KEYMGMT simply passes EC structures, so
 * we use that here too.
 */
typedef struct {
    OSSL_LIB_CTX *libctx;
    char *propq;
    EC_KEY *ec;

    /*
     * Flag to termine if the 'z' digest needs to be computed and fed to the
     * hash function.
     * This flag should be set on initialization and the compuation should
     * be performed only once, on first update.
     */
    unsigned int flag_compute_z_digest : 1;

    char mdname[OSSL_MAX_NAME_SIZE];

    /* The Algorithm Identifier of the combined signature algorithm */
    unsigned char aid_buf[OSSL_MAX_ALGORITHM_ID_SIZE];
    unsigned char *aid;
    size_t  aid_len;

    /* main digest */
    EVP_MD *md;
    EVP_MD_CTX *mdctx;
    size_t mdsize;

    /* SM2 ID used for calculating the Z value */
    unsigned char *id;
    size_t id_len;
    ECCrefPublicKey ecc_pk;
    ECCrefPrivateKey ecc_vk;
    void* hDevice;
    void* hSession;
    void* hHashSession;
} PROV_SM2_CTX;
// SDF 函数指针类型定义
typedef int (*SDF_OpenDevice_fn)(void** phDeviceHandle);
typedef int (*SDF_CloseDevice_fn)(void* hDeviceHandle);
typedef int (*SDF_OpenSession_fn)(void* hDeviceHandle, void** phSessionHandle);
typedef int (*SDF_CloseSession_fn)(void* hSessionHandle);
typedef int (*SDF_GenerateRandom_fn)(void* hSessionHandle, unsigned int uiLength, unsigned char* pucRandom);
typedef int (*SDF_ExternalSign_ECC_fn)(void* hSessionHandle, unsigned int uiAlgID, void* pucPrivateKey, unsigned char* pucData, unsigned int uiDataLength, void* pucSignature);
typedef int (*SDF_ExternalVerify_ECC_fn)(void* hSessionHandle, unsigned int uiAlgID, void* pucPublicKey, unsigned char* pucDataInput, unsigned int uiInputLength, void* pucSignature);
typedef int (*SDF_HashInit_fn)(void* hSessionHandle, unsigned int uiAlgID, void* pucPublicKey, unsigned char* pucID, unsigned int uiIDLength);
typedef int (*SDF_HashUpdate_fn)(void* hSessionHandle, unsigned char* pucData, unsigned int uiDataLength);
typedef int (*SDF_HashFinal_fn)(void* hSessionHandle, unsigned char* pucHash, unsigned int* puiHashLength);

// SDF函数指针
static void* h_lib = NULL;
static SDF_OpenDevice_fn pfn_SDF_OpenDevice = NULL;
static SDF_CloseDevice_fn pfn_SDF_CloseDevice = NULL;
static SDF_OpenSession_fn pfn_SDF_OpenSession = NULL;
static SDF_CloseSession_fn pfn_SDF_CloseSession = NULL;
static SDF_ExternalSign_ECC_fn pfn_SDF_ExternalSign_ECC = NULL;
static SDF_ExternalVerify_ECC_fn pfn_SDF_ExternalVerify_ECC = NULL;
static SDF_GenerateRandom_fn pfn_SDF_GenerateRandom = NULL;
static SDF_HashInit_fn pfn_SDF_HashInit = NULL;
static SDF_HashUpdate_fn pfn_SDF_HashUpdate = NULL;
static SDF_HashFinal_fn pfn_SDF_HashFinal = NULL;

// 动态加载和卸载函数
static int load_sm2_sdf_functions() {
    if (h_lib != NULL) return 1;
    h_lib = dlopen("libpiico_cc.so", RTLD_LAZY);
    if (h_lib == NULL) return 0;
    pfn_SDF_OpenDevice = (SDF_OpenDevice_fn)dlsym(h_lib, "SDF_OpenDevice");
    pfn_SDF_CloseDevice = (SDF_CloseDevice_fn)dlsym(h_lib, "SDF_CloseDevice");
    pfn_SDF_OpenSession = (SDF_OpenSession_fn)dlsym(h_lib, "SDF_OpenSession");
    pfn_SDF_CloseSession = (SDF_CloseSession_fn)dlsym(h_lib, "SDF_CloseSession");
    pfn_SDF_ExternalSign_ECC = (SDF_ExternalSign_ECC_fn)dlsym(h_lib, "SDF_ExternalSign_ECC");
    pfn_SDF_ExternalVerify_ECC = (SDF_ExternalVerify_ECC_fn)dlsym(h_lib, "SDF_ExternalVerify_ECC");
    pfn_SDF_GenerateRandom = (SDF_GenerateRandom_fn)dlsym(h_lib, "SDF_GenerateRandom");
    pfn_SDF_HashInit = (SDF_HashInit_fn)dlsym(h_lib, "SDF_HashInit");
    pfn_SDF_HashUpdate = (SDF_HashUpdate_fn)dlsym(h_lib, "SDF_HashUpdate");
    pfn_SDF_HashFinal = (SDF_HashFinal_fn)dlsym(h_lib, "SDF_HashFinal");
    return (pfn_SDF_OpenDevice && pfn_SDF_CloseDevice && pfn_SDF_OpenSession && pfn_SDF_CloseSession &&
        pfn_SDF_ExternalSign_ECC && pfn_SDF_ExternalVerify_ECC && pfn_SDF_GenerateRandom &&
        pfn_SDF_HashInit && pfn_SDF_HashUpdate && pfn_SDF_HashFinal);
}

static void unload_sm2_sdf_functions() {
    if (h_lib != NULL) {
        dlclose(h_lib);
        h_lib = NULL;
    }
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
static void print_hex(const char* label, const unsigned char* data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}
// 辅助函数：将EC_KEY中的公钥/私钥转换为SDF格式
static int convert_key_to_sdf_format(PROV_SM2_CTX* ctx) {
    const EC_POINT* pub_point = EC_KEY_get0_public_key(ctx->ec);
    const BIGNUM* priv_key = EC_KEY_get0_private_key(ctx->ec);

    int key_len_bytes = EC_GROUP_get_degree(EC_KEY_get0_group(ctx->ec)) / 8;
    if (key_len_bytes <= 0) return 0;

    // 公钥转换
    if (pub_point != NULL) {
        const EC_GROUP* group = EC_KEY_get0_group(ctx->ec);
        BIGNUM* bn_x = BN_new();
        BIGNUM* bn_y = BN_new();
        if (!EC_POINT_get_affine_coordinates(group, pub_point, bn_x, bn_y, NULL)) {
            BN_free(bn_x); BN_free(bn_y); return 0;
        }
        ctx->ecc_pk.bits = key_len_bytes * 8;
        if (BN_bn2binpad(bn_x, ctx->ecc_pk.x, key_len_bytes) <= 0) { BN_free(bn_x); BN_free(bn_y); return 0; }
        if (BN_bn2binpad(bn_y, ctx->ecc_pk.y, key_len_bytes) <= 0) { BN_free(bn_x); BN_free(bn_y); return 0; }
        BN_free(bn_x); BN_free(bn_y);
    }

    // 私钥转换
    if (priv_key != NULL) {
        ctx->ecc_vk.bits = key_len_bytes * 8;
        if (BN_bn2binpad(priv_key, ctx->ecc_vk.K, key_len_bytes) <= 0) return 0;
    }
    print_hex("Private Key (vk.K)", ctx->ecc_vk.K, 64);
    print_hex("Public Key X (pk.x)", ctx->ecc_pk.x, 64);
    print_hex("Public Key Y (pk.y)", ctx->ecc_pk.y, 64);
    swap_halves(ctx->ecc_pk.x, 64);
    swap_halves(ctx->ecc_pk.y, 64);
    swap_halves(ctx->ecc_vk.K, 64);
    print_hex("Private Key (vk.K)", ctx->ecc_vk.K, 64);
    print_hex("Public Key X (pk.x)", ctx->ecc_pk.x, 64);
    print_hex("Public Key Y (pk.y)", ctx->ecc_pk.y, 64);
    return 1;
}
static void print_ECCSignature(const ECCSignature* sig)
{
    if (sig == NULL) {
        printf("ECCSignature is NULL.\n");
        return;
    }

    // 打印 r 数组
    printf("r: ");
    for (int i = 0; i < ECCref_MAX_LEN; i++) {
        printf("%02x", sig->r[i]);
    }
    printf("\n");

    // 打印 s 数组
    printf("s: ");
    for (int i = 0; i < ECCref_MAX_LEN; i++) {
        printf("%02x", sig->s[i]);
    }
    printf("\n");
}
static void print_signature(const unsigned char* sig, size_t siglen) {
    if (sig == NULL || siglen == 0) {
        printf("Signature is NULL or has zero length.\n");
        return;
    }

    printf("Signature data (length %zu):\n", siglen);
    for (size_t i = 0; i < siglen; i++) {
        printf("%02x", sig[i]);
        if ((i + 1) % 32 == 0) {
            printf("\n"); // 每32字节换行
        }
    }
    printf("\n");
}
static int sm2sig_set_mdname(PROV_SM2_CTX *psm2ctx, const char *mdname)
{

    if (psm2ctx->md == NULL) /* We need an SM3 md to compare with */
        psm2ctx->md = EVP_MD_fetch(psm2ctx->libctx, psm2ctx->mdname,
            "provider=sushuHsm");
    if (psm2ctx->md == NULL)
        return 0;
	printf("entry hsm_sm2sig_set_mdname with mdname %s\n", mdname);
    if (mdname == NULL)
        return 1;

    if (strlen(mdname) >= sizeof(psm2ctx->mdname)
        || !EVP_MD_is_a(psm2ctx->md, mdname)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST, "digest=%s",
                       mdname);
        return 0;
    }

    OPENSSL_strlcpy(psm2ctx->mdname, mdname, sizeof(psm2ctx->mdname));
    return 1;
}

static void *sm2sig_newctx(void *provctx, const char *propq)
{
    PROV_SM2_CTX *ctx = OPENSSL_zalloc(sizeof(PROV_SM2_CTX));
	printf("entry hsm_sm2sig_newctx with provctx %p, propq %s\n", provctx, propq);
    if (ctx == NULL)
        return NULL;

    ctx->libctx = PROV_LIBCTX_OF(provctx);
    if (propq != NULL && (ctx->propq = OPENSSL_strdup(propq)) == NULL) {
        OPENSSL_free(ctx);
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ctx->mdsize = SM3_DIGEST_LENGTH;
    strcpy(ctx->mdname, OSSL_DIGEST_NAME_SM3);
    return ctx;
}

static int sm2sig_signature_init(void *vpsm2ctx, void *ec,
                                 const OSSL_PARAM params[])
{
    PROV_SM2_CTX* ctx = (PROV_SM2_CTX*)vpsm2ctx;
    if (!ossl_prov_is_running() || ctx == NULL) return 0;

    if (ec != NULL) {
        if (!EC_KEY_up_ref(ec)) return 0;
        EC_KEY_free(ctx->ec);
        ctx->ec = ec;
    }
    if (ctx->ec == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (!load_sm2_sdf_functions()) return 0;
    if (pfn_SDF_OpenDevice(&ctx->hDevice) != SR_SUCCESSFULLY) return 0;
    if (pfn_SDF_OpenSession(ctx->hDevice, &ctx->hSession) != SR_SUCCESSFULLY) {
        pfn_SDF_CloseDevice(ctx->hDevice);
        return 0;
    }
    //if (pfn_SDF_OpenSession(ctx->hDevice, &ctx->hHashSession) != SR_SUCCESSFULLY) {
    //    pfn_SDF_CloseDevice(ctx->hDevice);
    //    return 0;
    //}
    if (!convert_key_to_sdf_format(ctx)) {
        pfn_SDF_CloseSession(ctx->hSession);
        pfn_SDF_CloseDevice(ctx->hDevice);
        return 0;
    }
    return 1;
}

static int sm2sig_sign(void* vpsm2ctx, unsigned char* sig, size_t* siglen,
    size_t sigsize, const unsigned char* tbs, size_t tbslen)
{
    PROV_SM2_CTX* ctx = (PROV_SM2_CTX*)vpsm2ctx;
    int ret;
    ECCSignature ecc_sig;

    if (sig == NULL) {
        *siglen = ECCref_MAX_LEN * 2; // SM2签名总长度为128字节
        return 1;
    }

    if (sigsize < ECCref_MAX_LEN * 2) return 0;
    if (ctx == NULL || ctx->hSession == NULL) return 0;

    // 调用SDF接口进行签名
    ret = pfn_SDF_ExternalSign_ECC(ctx->hSession, SGD_SM2_1, &ctx->ecc_vk, (unsigned char*)tbs, tbslen, &ecc_sig);
    if (ret != SR_SUCCESSFULLY) return 0;

    // 将SDF签名结果(R和S)复制到输出缓冲区
    //压缩签名长度，由于铜锁SSL最大支持siglen为72字节，SDF接口输出出来为128字节
    //签名的r和s前32字节全部为0，所以截去前32字节，保留后32字节作为签名结果
    memcpy(sig, ecc_sig.r+32, ECCref_MAX_LEN/2);
    memcpy(sig + ECCref_MAX_LEN/2, ecc_sig.s+32, ECCref_MAX_LEN/2);
    
    print_ECCSignature(&ecc_sig);
    *siglen = ECCref_MAX_LEN;
    print_signature(sig, *siglen);
    return 1;
}

static int sm2sig_verify(void* vpsm2ctx, const unsigned char* sig, size_t siglen,
    const unsigned char* tbs, size_t tbslen)
{
    PROV_SM2_CTX* ctx = (PROV_SM2_CTX*)vpsm2ctx;
    int ret;
    ECCSignature ecc_sig;

    if (ctx == NULL || ctx->hSession == NULL) return 0;
    print_signature(sig, 64);
    printf("entry hsm_sm2sig_verify with sig %p, siglen %zu, tbs %p, tbslen %zu\n",
		sig, siglen, tbs, tbslen);
    // 检查签名长度，确保与SM2签名总长一致
    if (siglen != ECCref_MAX_LEN) {
        // ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SIGNATURE);
        return 0;
    }

    // 从输入缓冲区中提取R和S
    //重新填充截去的前32字节的0
    memset(ecc_sig.r, 0, ECCref_MAX_LEN / 2);
    memset(ecc_sig.s, 0, ECCref_MAX_LEN / 2);
    memcpy(ecc_sig.r+32, sig, ECCref_MAX_LEN/2);
    memcpy(ecc_sig.s+32, sig + ECCref_MAX_LEN/2, ECCref_MAX_LEN/2);
    print_ECCSignature(&ecc_sig);

    // 调用SDF接口进行验签
    ret = pfn_SDF_ExternalVerify_ECC(ctx->hSession, SGD_SM2_1, &ctx->ecc_pk, (unsigned char*)tbs, tbslen, &ecc_sig);
    if (ret != SR_SUCCESSFULLY) return 0;

    return 1;
}

static void free_md(PROV_SM2_CTX *ctx)
{
    EVP_MD_CTX_free(ctx->mdctx);
    EVP_MD_free(ctx->md);
    ctx->mdctx = NULL;
    ctx->md = NULL;
}

static int sm2sig_digest_signverify_init(void *vpsm2ctx, const char *mdname,
                                         void *ec, const OSSL_PARAM params[])
{
    PROV_SM2_CTX *ctx = (PROV_SM2_CTX *)vpsm2ctx;
    int md_nid;
    WPACKET pkt;
    int ret = 0;
    printf("entry hsm sm2sig_digest_signverify_init with vpsm2ctx %p, mdname %s, ec %p, params %p\n",
		vpsm2ctx, mdname, ec, params);
    /* This default value must be assigned before it may be overridden */
    ctx->flag_compute_z_digest = 1;

    if (!sm2sig_signature_init(vpsm2ctx, ec, params)
        || !sm2sig_set_mdname(ctx, mdname))
        return ret;

    if (ctx->mdctx == NULL) {
        ctx->mdctx = EVP_MD_CTX_new();
        if (ctx->mdctx == NULL)
            goto error;
    }

    md_nid = EVP_MD_get_type(ctx->md);

    /*
     * We do not care about DER writing errors.
     * All it really means is that for some reason, there's no
     * AlgorithmIdentifier to be had, but the operation itself is
     * still valid, just as long as it's not used to construct
     * anything that needs an AlgorithmIdentifier.
     */
    ctx->aid_len = 0;
    if (WPACKET_init_der(&pkt, ctx->aid_buf, sizeof(ctx->aid_buf))
        && ossl_DER_w_algorithmIdentifier_SM2_with_MD(&pkt, -1, ctx->ec, md_nid)
        && WPACKET_finish(&pkt)) {
        WPACKET_get_total_written(&pkt, &ctx->aid_len);
        ctx->aid = WPACKET_get_curr(&pkt);
    }
    WPACKET_cleanup(&pkt);


    //if (!EVP_DigestInit_ex2(ctx->mdctx, ctx->md, params))
    //    goto error;
    if (pfn_SDF_HashInit(ctx->hSession, SGD_SM3, &ctx->ecc_pk, ctx->id, ctx->id_len) != SR_SUCCESSFULLY) {
        goto error;
    }
    ret = 1;

 error:
    return ret;
}

static int sm2sig_compute_z_digest(PROV_SM2_CTX *ctx)
{
    uint8_t *z = NULL;
    int ret = 1;
	printf("entry hsm_sm2sig_compute_z_digest with ctx %p\n", ctx);
    if (ctx->flag_compute_z_digest) {
        /* Only do this once */
        ctx->flag_compute_z_digest = 0;

        if ((z = OPENSSL_zalloc(ctx->mdsize)) == NULL
            /* get hashed prefix 'z' of tbs message */
            || !ossl_sm2_compute_z_digest(z, ctx->md, ctx->id, ctx->id_len,
                                          ctx->ec)
            || !EVP_DigestUpdate(ctx->mdctx, z, ctx->mdsize)
            || pfn_SDF_HashUpdate(ctx->hSession, (unsigned char*)z, ctx->mdsize))
            ret = 0;
        printf("hsm sm2sig_compute_z_digest with z %p, mdsize %zu, id %p, id_len %zu\n",
            z, ctx->mdsize, ctx->id, ctx->id_len);
        OPENSSL_free(z);
    }

    return ret;
}

int sm2sig_digest_signverify_update(void *vpsm2ctx, const unsigned char *data,
                                    size_t datalen)
{
    PROV_SM2_CTX *psm2ctx = (PROV_SM2_CTX *)vpsm2ctx;
    printf("entry hsm sm2sig_digest_signverify_update\n");
    if (psm2ctx == NULL || psm2ctx->mdctx == NULL)
        return 0;

    int ret = !pfn_SDF_HashUpdate(psm2ctx->hSession, (unsigned char*)data, datalen);
    return ret;
}

int sm2sig_digest_sign_final(void *vpsm2ctx, unsigned char *sig, size_t *siglen,
                             size_t sigsize)
{
    PROV_SM2_CTX *psm2ctx = (PROV_SM2_CTX *)vpsm2ctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    int ret;
    printf("entry hsm sm2sig_digest_sign_final\n");
    if (psm2ctx == NULL || psm2ctx->mdctx == NULL)
        return 0;

    /*
     * If sig is NULL then we're just finding out the sig size. Other fields
     * are ignored. Defer to sm2sig_sign.
     */
    if (sig != NULL) {
        ret = pfn_SDF_HashFinal(psm2ctx->hSession, (unsigned char*)digest, &dlen);
        if (ret != 0)
            return 0;
    }

    return sm2sig_sign(vpsm2ctx, sig, siglen, sigsize, digest, (size_t)dlen);
}


int sm2sig_digest_verify_final(void *vpsm2ctx, const unsigned char *sig,
                               size_t siglen)
{
    PROV_SM2_CTX *psm2ctx = (PROV_SM2_CTX *)vpsm2ctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;
    int ret;
    printf("entry hsm sm2sig_digest_verify_final\n");
    ret = pfn_SDF_HashFinal(psm2ctx->hSession, digest, &dlen);
    if (ret != 0)
        return 0;

    return sm2sig_verify(vpsm2ctx, sig, siglen, digest, (size_t)dlen);
}

static void sm2sig_freectx(void *vpsm2ctx)
{
    PROV_SM2_CTX *ctx = (PROV_SM2_CTX *)vpsm2ctx;
	printf("entry hsm sm2sig_freectx with vpsm2ctx %p\n", vpsm2ctx);
    if (ctx != NULL) {
        if (ctx->hSession != NULL) pfn_SDF_CloseSession(ctx->hSession);
        if (ctx->hDevice != NULL) pfn_SDF_CloseDevice(ctx->hDevice);
        EC_KEY_free(ctx->ec);
        OPENSSL_free(ctx);
    }
	printf("hsm sm2sig_freectx completed\n");
}

static void *sm2sig_dupctx(void *vpsm2ctx)
{
    PROV_SM2_CTX *srcctx = (PROV_SM2_CTX *)vpsm2ctx;
    PROV_SM2_CTX *dstctx;

	printf("entry hsm sm2sig_dupctx with vpsm2ctx %p\n", vpsm2ctx);
    dstctx = OPENSSL_zalloc(sizeof(*srcctx));
    if (dstctx == NULL)
        return NULL;

    *dstctx = *srcctx;
    srcctx->hDevice = NULL;
	srcctx->hSession = NULL;
    dstctx->ec = NULL;
    dstctx->md = NULL;
    dstctx->mdctx = NULL;

    if (srcctx->ec != NULL && !EC_KEY_up_ref(srcctx->ec))
        goto err;
    dstctx->ec = srcctx->ec;

    if (srcctx->md != NULL && !EVP_MD_up_ref(srcctx->md))
        goto err;
    dstctx->md = srcctx->md;

    if (srcctx->mdctx != NULL) {
        dstctx->mdctx = EVP_MD_CTX_new();
        if (dstctx->mdctx == NULL
                || !EVP_MD_CTX_copy_ex(dstctx->mdctx, srcctx->mdctx))
            goto err;
    }

    if (srcctx->id != NULL) {
        dstctx->id = OPENSSL_malloc(srcctx->id_len);
        if (dstctx->id == NULL)
            goto err;
        dstctx->id_len = srcctx->id_len;
        memcpy(dstctx->id, srcctx->id, srcctx->id_len);
    }

    return dstctx;
 err:
    sm2sig_freectx(dstctx);
    return NULL;
}

static int sm2sig_get_ctx_params(void *vpsm2ctx, OSSL_PARAM *params)
{
    PROV_SM2_CTX *psm2ctx = (PROV_SM2_CTX *)vpsm2ctx;
    OSSL_PARAM *p;
    printf("entry hsm sm2sig_get_ctx_params\n");
    if (psm2ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL
        && !OSSL_PARAM_set_octet_string(p, psm2ctx->aid, psm2ctx->aid_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, psm2ctx->mdsize))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, psm2ctx->md == NULL
                                                    ? psm2ctx->mdname
                                                    : EVP_MD_get0_name(psm2ctx->md)))
        return 0;

    return 1;
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *sm2sig_gettable_ctx_params(ossl_unused void *vpsm2ctx,
                                                    ossl_unused void *provctx)
{
	printf("entry hsm sm2sig_gettable_ctx_params\n");
    return known_gettable_ctx_params;
}

static int sm2sig_set_ctx_params(void *vpsm2ctx, const OSSL_PARAM params[])
{
    PROV_SM2_CTX *psm2ctx = (PROV_SM2_CTX *)vpsm2ctx;
    const OSSL_PARAM *p;
    size_t mdsize;
    printf("entry hsm sm2sig_set_ctx_params with vpsm2ctx\n");
    if (psm2ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_SM2_ZA);
    if (p != NULL) {
        char *v = NULL;

        if (!OSSL_PARAM_get_utf8_string(p, &v, 0))
            return 0;

        /*
         * If 'sm2-za:no' is specified, omit computing the z digest
         */
        if (OPENSSL_strcasecmp(v, "no") == 0)
            psm2ctx->flag_compute_z_digest = 0;

        OPENSSL_free(v);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DIST_ID);
    if (p != NULL) {
        void *tmp_id = NULL;
        size_t tmp_idlen = 0;

        /*
         * If the 'z' digest has already been computed, the ID is set too late
         */
        if (!psm2ctx->flag_compute_z_digest)
            return 0;

        if (p->data_size != 0
            && !OSSL_PARAM_get_octet_string(p, &tmp_id, 0, &tmp_idlen))
            return 0;
        OPENSSL_free(psm2ctx->id);
        psm2ctx->id = tmp_id;
        psm2ctx->id_len = tmp_idlen;
    }

    /*
     * The following code checks that the size is the same as the SM3 digest
     * size returning an error otherwise.
     * If there is ever any different digest algorithm allowed with SM2
     * this needs to be adjusted accordingly.
     */
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p != NULL && (!OSSL_PARAM_get_size_t(p, &mdsize)
                      || mdsize != psm2ctx->mdsize))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL) {
        char *mdname = NULL;

        if (!OSSL_PARAM_get_utf8_string(p, &mdname, 0))
            return 0;
        if (!sm2sig_set_mdname(psm2ctx, mdname)) {
            OPENSSL_free(mdname);
            return 0;
        }
        OPENSSL_free(mdname);
    }

    return 1;
}

static const OSSL_PARAM known_settable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_DIST_ID, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_SM2_ZA, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *sm2sig_settable_ctx_params(ossl_unused void *vpsm2ctx,
                                                    ossl_unused void *provctx)
{
	printf("entry hsm sm2sig_settable_ctx_params\n");
    return known_settable_ctx_params;
}

static int sm2sig_get_ctx_md_params(void *vpsm2ctx, OSSL_PARAM *params)
{
    PROV_SM2_CTX *psm2ctx = (PROV_SM2_CTX *)vpsm2ctx;
	printf("entry hsm sm2sig_get_ctx_md_params with vpsm2ctx %p\n", vpsm2ctx);
    if (psm2ctx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_get_params(psm2ctx->mdctx, params);
}

static const OSSL_PARAM *sm2sig_gettable_ctx_md_params(void *vpsm2ctx)
{
    PROV_SM2_CTX *psm2ctx = (PROV_SM2_CTX *)vpsm2ctx;
	printf("entry hsm sm2sig_gettable_ctx_md_params with vpsm2ctx %p\n", vpsm2ctx);
    if (psm2ctx->md == NULL)
        return 0;

    return EVP_MD_gettable_ctx_params(psm2ctx->md);
}

static int sm2sig_set_ctx_md_params(void *vpsm2ctx, const OSSL_PARAM params[])
{
    PROV_SM2_CTX *psm2ctx = (PROV_SM2_CTX *)vpsm2ctx;
    printf("entry hsm sm2sig_set_ctx_md_params\n");
    if (psm2ctx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_set_params(psm2ctx->mdctx, params);
}

static const OSSL_PARAM *sm2sig_settable_ctx_md_params(void *vpsm2ctx)
{
    PROV_SM2_CTX *psm2ctx = (PROV_SM2_CTX *)vpsm2ctx;
	printf("entry hsm sm2sig_settable_ctx_md_params with vpsm2ctx %p\n", vpsm2ctx);
    if (psm2ctx->md == NULL)
        return 0;

    return EVP_MD_settable_ctx_params(psm2ctx->md);
}

const OSSL_DISPATCH ossl_hsm_sm2_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))sm2sig_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))sm2sig_signature_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))sm2sig_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))sm2sig_signature_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))sm2sig_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))sm2sig_digest_signverify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
      (void (*)(void))sm2sig_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
      (void (*)(void))sm2sig_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))sm2sig_digest_signverify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))sm2sig_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))sm2sig_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))sm2sig_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))sm2sig_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))sm2sig_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))sm2sig_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))sm2sig_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))sm2sig_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
      (void (*)(void))sm2sig_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
      (void (*)(void))sm2sig_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
      (void (*)(void))sm2sig_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
      (void (*)(void))sm2sig_settable_ctx_md_params },
    { 0, NULL }
};
