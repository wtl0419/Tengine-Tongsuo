#include <stdio.h>    // For printf, fprintf
#include <stdlib.h>   // For malloc, free, exit
#include <string.h>   // For memcpy, memset
#include <dlfcn.h>    // For dlopen, dlsym, dlclose, dlerror
#include <openssl/err.h> // For OpenSSL error handling
# include <openssl/types.h>
#include <openssl/proverr.h>
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "prov/piico_define.h"
#include <string.h>
#include "prov/ciphercommon.h"
#include "crypto/sm4.h"
#include "crypto/sm4_platform.h"

#define SGD_SM4_CBC_KBITS                  128 //��Կ����Ϊ128λ     
#define SGD_SM4_CBC_BLOCK_SIZE             128 //SM4���鳤��Ϊ16�ֽ�
#define SGD_SM4_CBC_IVLEN                  128 //IV����Ϊ16�ֽ�

#define SGD_SM4_ECB_KBITS                  128 //��Կ����Ϊ128λ     
#define SGD_SM4_ECB_BLOCK_SIZE             128 //SM4���鳤��Ϊ16�ֽ�
#define SGD_SM4_ECB_IVLEN                  128 //IV����Ϊ16�ֽ�
#define SM4_BLOCK_SIZE                     16
//SDF����ָ������
typedef int (*SDF_OpenDevice_fn)(void** phDeviceHandle);
typedef int (*SDF_CloseDevice_fn)(void* hDeviceHandle);
typedef int (*SDF_OpenSession_fn)(void* hDeviceHandle, void** phSessionHandle);
typedef int (*SDF_CloseSession_fn)(void* hSessionHandle);
typedef int (*SDF_GenerateRandom_fn)(void* hSessionHandle, unsigned int uiLength, unsigned char* pucRandom);
typedef int (*SDF_GenerateKeyWithKEK_fn)(void* hSessionHandle, unsigned int uiKeyBits, unsigned int uiAlgID, unsigned int uiKEKIndex, unsigned char* pucKey, unsigned int* puiKeyLength, void** phKeyHandle);
typedef int (*SDF_ImportKey_fn)(void* hSessionHandle, unsigned char* pucKey, unsigned int uiKeyLength, void** phKeyHandle);
typedef int (*SDF_DestroyKey_fn)(void* hSessionHandle, void* hKeyHandle);
typedef int (*SDF_Encrypt_fn)(void* hSessionHandle, void* hKeyHandle, unsigned int uiAlgID, unsigned char* pucIV, unsigned char* pucData, unsigned int uiDataLength, unsigned char* pucEncData, unsigned int* puiEncDataLength);
typedef int (*SDF_Decrypt_fn)(void* hSessionHandle, void* hKeyHandle, unsigned int uiAlgID, unsigned char* pucIV, unsigned char* pucEncData, unsigned int uiEncDataLength, unsigned char* pucData, unsigned int* puiDataLength);

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


typedef struct sushu_hsm_encrypt_ctx_st {
    PROV_CIPHER_CTX base;
    union {
        OSSL_UNION_ALIGN;
        SM4_KEY ks;
    } ks;
    void* hDevice;
    void* hSession;
    void* hKey;
} SUSHU_HSM_ENCRYPT_CTX;
const PROV_CIPHER_HW* ossl_prov_cipher_hw_sm4_cbc(size_t keybits);
const PROV_CIPHER_HW* ossl_prov_cipher_hw_sm4_ecb(size_t keybits);

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

// --- 1. newctx ����ʵ�� (��Ӧ OSSL_FUNC_CIPHER_NEWCTX) ---
static void* hsm_sm4_cbc_newctx(void* provctx) {
    SUSHU_HSM_ENCRYPT_CTX* ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ossl_cipher_generic_initkey(&ctx->base, SGD_SM4_CBC_KBITS, SGD_SM4_CBC_BLOCK_SIZE, SGD_SM4_CBC_IVLEN, SGD_SM4_CBC, 0, ossl_prov_cipher_hw_sm4_cbc(SGD_SM4_CBC_KBITS), provctx);
     // Load the dynamic library
    if (!load_sdf_functions()) {
        return 1;
    }
    int ret = 0;
    unsigned int encrypted_key_len = 16;
    // Step 1: Open the SDF device
    ret = pfn_SDF_OpenDevice(&ctx->hDevice);
    CHECK_SDF_RET(ret, "SDF_OpenDevice");

    printf("Device opened successfully. Device handle: %p\n", ctx->hDevice);

    // Step 2: Open a session with the device
    ret = pfn_SDF_OpenSession(ctx->hDevice, &ctx->hSession);
    CHECK_SDF_RET(ret, "SDF_OpenSession");

    printf("Session opened successfully. Session handle: %p\n", ctx->hSession);

   
    return ctx;
}
static void* hsm_sm4_ecb_newctx(void* provctx) {
    SUSHU_HSM_ENCRYPT_CTX* ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    ossl_cipher_generic_initkey(&ctx->base, SGD_SM4_ECB_KBITS, SGD_SM4_ECB_BLOCK_SIZE, SGD_SM4_ECB_IVLEN, SGD_SM4_ECB, 0, ossl_prov_cipher_hw_sm4_ecb(SGD_SM4_ECB_KBITS), provctx);
    // Load the dynamic library
    if (!load_sdf_functions()) {
        return 1;
    }
    int ret = 0;
    unsigned int encrypted_key_len = 16;
    // Step 1: Open the SDF device
    ret = pfn_SDF_OpenDevice(&ctx->hDevice);
    CHECK_SDF_RET(ret, "SDF_OpenDevice");

    printf("Device opened successfully. Device handle: %p\n", ctx->hDevice);

    // Step 2: Open a session with the device
    ret = pfn_SDF_OpenSession(ctx->hDevice, &ctx->hSession);
    CHECK_SDF_RET(ret, "SDF_OpenSession");

    printf("Session opened successfully. Session handle: %p\n", ctx->hSession);


    return ctx;
}

// --- 2. freectx ����ʵ�� (��Ӧ OSSL_FUNC_CIPHER_FREECTX) ---
static void hsm_freectx(void* vctx) {
    SUSHU_HSM_ENCRYPT_CTX* ctx = (SUSHU_HSM_ENCRYPT_CTX*)vctx;
    if (ctx == NULL) return;

    ossl_cipher_generic_reset_ctx((PROV_CIPHER_CTX*)vctx);
    if (ctx->hKey != NULL) {
        pfn_SDF_DestroyKey(ctx->hSession, ctx->hKey);
    }
    if (ctx->hSession != NULL) {
        pfn_SDF_CloseSession(ctx->hSession);
    }
    if (ctx->hDevice != NULL) {
        pfn_SDF_CloseDevice(ctx->hDevice);
    }
    OPENSSL_clear_free(ctx, sizeof(*ctx));
}
// --- 3. dupctx ����ʵ�� (��Ӧ OSSL_FUNC_CIPHER_DUPCTX) ---
static void* hsm_dupctx(void* ctx) {

    SUSHU_HSM_ENCRYPT_CTX* in = (SUSHU_HSM_ENCRYPT_CTX*)ctx;
    SUSHU_HSM_ENCRYPT_CTX* ret;

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
// --- 4. einit ����ʵ�� (��Ӧ OSSL_FUNC_CIPHER_ENCRYPT_INIT) ---
// �ú����ᱻ ossl_cipher_generic_einit ��ӵ���
static int hsm_einit(void* vctx, const unsigned char* key, size_t keylen,
    const unsigned char* iv, size_t ivlen, const OSSL_PARAM params[]) {
    int ret;
    SUSHU_HSM_ENCRYPT_CTX* ctx = (SUSHU_HSM_ENCRYPT_CTX*)vctx;
    ossl_cipher_generic_einit(ctx, key, keylen, iv, ivlen, params);
    if(key != NULL) {
        ret = pfn_SDF_ImportKey(ctx->hSession, key, keylen, &ctx->hKey);
        CHECK_SDF_RET(ret, "SDF_ImportKey");

        printf("Generated and imported key successfully. Key handle: %p\n", ctx->hKey);
	}
    return 1;
}

// --- 5. dinit ����ʵ�� (��Ӧ OSSL_FUNC_CIPHER_DECRYPT_INIT) ---
// �ú����ᱻ ossl_cipher_generic_dinit ��ӵ���
static int hsm_dinit(void* vctx, const unsigned char* key, size_t keylen,
    const unsigned char* iv, size_t ivlen, const OSSL_PARAM params[]) {
    int ret;
    SUSHU_HSM_ENCRYPT_CTX* ctx = (SUSHU_HSM_ENCRYPT_CTX*)vctx;
    ossl_cipher_generic_dinit(ctx, key, keylen, iv, ivlen, params);
    if (key != NULL) {
        ret = pfn_SDF_ImportKey(ctx->hSession, key, keylen, &ctx->hKey);
        CHECK_SDF_RET(ret, "SDF_ImportKey");
        printf("Generated and imported key successfully. Key handle: %p\n", ctx->hKey);
	}
    return 1;
}
static void print_hex_dump(const unsigned char* in, size_t inl) {
    size_t i;
    for (i = 0; i < inl; i++) {
        // ��ʮ�����Ƹ�ʽ��ӡÿ���ֽڣ����Ϊ2������ǰ�油0
        printf("%02X ", in[i]);

        // ÿ16���ֽڻ��У������Ķ�
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    // ��ӡ�������������У�����
    if (i % 16 != 0) {
        printf("\n");
    }
}
#define SM4_BLOCK_SIZE 16
#define SSL3_VERSION 0x0300
#define SM3_MAC_SIZE 32

// �޸ĺ�� hsm_sm4_cbc_update ����
static int hsm_sm4_cbc_update(void* vctx, unsigned char* out,
    size_t* outl, size_t outsize, const unsigned char* in, size_t inl)
{
    SUSHU_HSM_ENCRYPT_CTX* ctx = (SUSHU_HSM_ENCRYPT_CTX*)vctx;
    int ret;
    int success = 0;

    // outlen ���ڸ���ʵ������ĳ���
    size_t outlen = outsize;

    if (ctx->base.enc == 1)
    {
        printf("Starting encryption...\n");
        printf("--- �����ܵ�ԭʼ���� ---\n");
        // in��ʱ���� [������Ϣ] + [MAC]
        print_hex_dump(in, inl);
        printf("---------------------------\n");

        unsigned char* full_data_to_encrypt = NULL;
        size_t full_len = 0;
        unsigned char padval;
        size_t padnum;
        unsigned char explicit_iv[SM4_BLOCK_SIZE];

        // 1. ����һ�������16�ֽ�IV
        if (RAND_bytes(explicit_iv, SM4_BLOCK_SIZE) <= 0) {
            return -1; // ���������ʧ��
        }

        // 2. ������Ҫ�����ֽ���
        padnum = SM4_BLOCK_SIZE - (inl % SM4_BLOCK_SIZE);
        if (padnum == 0)
            padnum = SM4_BLOCK_SIZE;

        // 3. �������ռ������ݵ��ܳ���: [IV] + [����+MAC] + [���]
        full_len = SM4_BLOCK_SIZE + inl + padnum;
        full_data_to_encrypt = (unsigned char*)malloc(full_len);
        if (!full_data_to_encrypt) {
            return -1; // �ڴ����ʧ��
        }

        // 4. ��װ���ݰ�
        // �����ɵ����IV���Ƶ���ͷ
        memcpy(full_data_to_encrypt, explicit_iv, SM4_BLOCK_SIZE);
        // ����ԭʼ���� (����+MAC) ��IV֮��
        memcpy(full_data_to_encrypt + SM4_BLOCK_SIZE, in, inl);

        // 5. ��� TLS ���
        if (ctx->base.tlsversion == SSL3_VERSION) {
            padval = (unsigned char)(padnum - 1);
            if (padnum > 1) {
                memset(full_data_to_encrypt + SM4_BLOCK_SIZE + inl, 0, padnum - 1);
            }
            full_data_to_encrypt[SM4_BLOCK_SIZE + inl + padnum - 1] = padval;
        }
        else {
            padval = (unsigned char)(padnum - 1);
            memset(full_data_to_encrypt + SM4_BLOCK_SIZE + inl, padval, padnum);
        }

        // 6. ���ü��ܺ������������IV���������ݰ�
        ret = pfn_SDF_Encrypt(ctx->hSession, ctx->hKey, SGD_SM4_CBC,
            ctx->base.iv, full_data_to_encrypt, full_len, out, &outlen);

        *outl = outlen;
        free(full_data_to_encrypt);

        CHECK_SDF_RET(ret, "SDF_Encrypt");
        printf("Encryption successful. Ciphertext length: %zu\n", *outl);
    }
    else if (ctx->base.enc == 0)
    {
        printf("Starting decryption...\n");
        // 'in' �����ģ�'out' �����ڴ�����ĺ� MAC �Ļ�������
        ret = pfn_SDF_Decrypt(ctx->hSession, ctx->hKey, SGD_SM4_CBC,
            ctx->base.iv, in, inl, out, &outlen);
        CHECK_SDF_RET(ret, "SDF_Decrypt");

        printf("--- ���ܺ����� ---\n");
        // ���ܺ�����ݽṹ�ǣ�[IV] + [����+MAC] + [���]
        print_hex_dump(out, outlen);
        printf("---------------------------\n");

        if (ret == 0) {
            // �ڽ���ģʽ�£�outlen �ǽ��ܺ���ܳ��ȣ�����IV�����ġ�MAC�����
            // removetlsfixed ���� MAC �� IV ���ܴ�С
            if (outlen <= ctx->base.removetlsfixed) {
                printf("Error: Decrypted length too small to contain MAC and IV.\n");
                return 0;
            }

            size_t mac_size = ctx->base.tlsmacsize;
            size_t total_len_without_pad;

            // TLS ȥ����߼�����䳤�� = ���һ���ֽڵ�ֵ + 1
            int padding_len = out[outlen - 1] + 1;

            // ��֤���
            if (padding_len <= 0 || padding_len > ctx->base.blocksize || padding_len > outlen) {
                printf("Error: Invalid TLS padding length.\n");
                return 0;
            }
            for (int i = 1; i <= padding_len; ++i) {
                if (out[outlen - i] != (unsigned char)(padding_len - 1)) {
                    printf("Error: Invalid TLS padding value.\n");
                    return 0;
                }
            }

            total_len_without_pad = outlen - padding_len;

            // �� MAC ��ַ���������Ľṹ���е�ָ��
            // MACλ�����ĵĺ��棬����ָ��ƫ������Ҫ�����Ŀ�ʼ���㣬
            // ע��������Ҫ����IV�ĳ��ȡ�
            ctx->base.tlsmac = out + SM4_BLOCK_SIZE + (total_len_without_pad - SM4_BLOCK_SIZE) - mac_size;
            ctx->base.alloced = 0;

            // �������յ�������ȣ�ֻ�������Ĳ���
            *outl = (total_len_without_pad - SM4_BLOCK_SIZE) - mac_size;
        }

        printf("Decryption successful. Decrypted length: %zu\n", *outl);
    }

    success = (ret == 0) ? 1 : 0;
    return success;
}
// �޸ĺ�� hsm_sm4_ecb_update ����
static int hsm_sm4_ecb_update(void* vctx, unsigned char* out,
    size_t* outl, size_t outsize, const unsigned char* in, size_t inl)
{
    SUSHU_HSM_ENCRYPT_CTX* ctx = (SUSHU_HSM_ENCRYPT_CTX*)vctx;
    int ret;
    int success = 0;

    // outlen ���ڸ���ʵ������ĳ���
    size_t outlen = outsize;

    if (ctx->base.enc == 1)
    {
        printf("Starting encryption...\n");
        printf("--- �����ܵ�ԭʼ���� ---\n");
        // in��ʱ���� [������Ϣ] + [MAC]
        print_hex_dump(in, inl);
        printf("---------------------------\n");

        unsigned char* full_data_to_encrypt = NULL;
        size_t full_len = 0;
        unsigned char padval;
        size_t padnum;
        unsigned char explicit_iv[SM4_BLOCK_SIZE];

        // 1. ����һ�������16�ֽ�IV
        if (RAND_bytes(explicit_iv, SM4_BLOCK_SIZE) <= 0) {
            return -1; // ���������ʧ��
        }

        // 2. ������Ҫ�����ֽ���
        padnum = SM4_BLOCK_SIZE - (inl % SM4_BLOCK_SIZE);
        if (padnum == 0)
            padnum = SM4_BLOCK_SIZE;

        // 3. �������ռ������ݵ��ܳ���: [IV] + [����+MAC] + [���]
        full_len = SM4_BLOCK_SIZE + inl + padnum;
        full_data_to_encrypt = (unsigned char*)malloc(full_len);
        if (!full_data_to_encrypt) {
            return -1; // �ڴ����ʧ��
        }

        // 4. ��װ���ݰ�
        // �����ɵ����IV���Ƶ���ͷ
        memcpy(full_data_to_encrypt, explicit_iv, SM4_BLOCK_SIZE);
        // ����ԭʼ���� (����+MAC) ��IV֮��
        memcpy(full_data_to_encrypt + SM4_BLOCK_SIZE, in, inl);

        // 5. ��� TLS ���
        if (ctx->base.tlsversion == SSL3_VERSION) {
            padval = (unsigned char)(padnum - 1);
            if (padnum > 1) {
                memset(full_data_to_encrypt + SM4_BLOCK_SIZE + inl, 0, padnum - 1);
            }
            full_data_to_encrypt[SM4_BLOCK_SIZE + inl + padnum - 1] = padval;
        }
        else {
            padval = (unsigned char)(padnum - 1);
            memset(full_data_to_encrypt + SM4_BLOCK_SIZE + inl, padval, padnum);
        }

        // 6. ���ü��ܺ������������IV���������ݰ�
        ret = pfn_SDF_Encrypt(ctx->hSession, ctx->hKey, SGD_SM4_ECB,
            ctx->base.iv, full_data_to_encrypt, full_len, out, &outlen);

        *outl = outlen;
        free(full_data_to_encrypt);

        CHECK_SDF_RET(ret, "SDF_Encrypt");
        printf("Encryption successful. Ciphertext length: %zu\n", *outl);
    }
    else if (ctx->base.enc == 0)
    {
        printf("Starting decryption...\n");
        // 'in' �����ģ�'out' �����ڴ�����ĺ� MAC �Ļ�������
        ret = pfn_SDF_Decrypt(ctx->hSession, ctx->hKey, SGD_SM4_ECB,
            ctx->base.iv, in, inl, out, &outlen);
        CHECK_SDF_RET(ret, "SDF_Decrypt");

        printf("--- ���ܺ����� ---\n");
        // ���ܺ�����ݽṹ�ǣ�[IV] + [����+MAC] + [���]
        print_hex_dump(out, outlen);
        printf("---------------------------\n");

        if (ret == 0) {
            // �ڽ���ģʽ�£�outlen �ǽ��ܺ���ܳ��ȣ�����IV�����ġ�MAC�����
            // removetlsfixed ���� MAC �� IV ���ܴ�С
            if (outlen <= ctx->base.removetlsfixed) {
                printf("Error: Decrypted length too small to contain MAC and IV.\n");
                return 0;
            }

            size_t mac_size = ctx->base.tlsmacsize;
            size_t total_len_without_pad;

            // TLS ȥ����߼�����䳤�� = ���һ���ֽڵ�ֵ + 1
            int padding_len = out[outlen - 1] + 1;

            // ��֤���
            if (padding_len <= 0 || padding_len > ctx->base.blocksize || padding_len > outlen) {
                printf("Error: Invalid TLS padding length.\n");
                return 0;
            }
            for (int i = 1; i <= padding_len; ++i) {
                if (out[outlen - i] != (unsigned char)(padding_len - 1)) {
                    printf("Error: Invalid TLS padding value.\n");
                    return 0;
                }
            }

            total_len_without_pad = outlen - padding_len;

            // �� MAC ��ַ���������Ľṹ���е�ָ��
            // MACλ�����ĵĺ��棬����ָ��ƫ������Ҫ�����Ŀ�ʼ���㣬
            // ע��������Ҫ����IV�ĳ��ȡ�
            ctx->base.tlsmac = out + SM4_BLOCK_SIZE + (total_len_without_pad - SM4_BLOCK_SIZE) - mac_size;
            ctx->base.alloced = 0;

            // �������յ�������ȣ�ֻ�������Ĳ���
            *outl = (total_len_without_pad - SM4_BLOCK_SIZE) - mac_size;
        }

        printf("Decryption successful. Decrypted length: %zu\n", *outl);
    }

    success = (ret == 0) ? 1 : 0;
    return success;
}
static int hsm_final(void* vctx, unsigned char* out, size_t* outl, size_t outsize)
{
    *outl = 0;
    SUSHU_HSM_ENCRYPT_CTX* ctx = (SUSHU_HSM_ENCRYPT_CTX*)vctx;
    // ���ǿ������һ���򵥵Ĵ�ӡ�������������Ѿ���ɡ�
    if (ctx->base.enc == 1) {
        printf("encrypt success!\n");
    }
    else if (ctx->base.enc == 0) {
        printf("decrypt success!\n");
    }

    // ����1��ʾ�ɹ���
    return 1;
}
// --- 6. get_params ����ʵ�� (��Ӧ OSSL_FUNC_CIPHER_GET_PARAMS) ---
// �ú����ᱻ ossl_cipher_generic_get_params ��ӵ���
static int hsm_get_params(OSSL_PARAM params[]) {
    // �������ͨ�����ڷ����㷨�Ĺ̶�����������С��IV���ȵ�
    // ��Щ����ͨ����Provider��OSSL_ALGORITHM�������ṩ������ֻ��һ��ʾ��
    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 16)) return 0; // SM4��Կ����16�ֽ�

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 16)) return 0; // SM4 IV����16�ֽ�

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 16)) return 0; // SM4���С16�ֽ�

    return 1;
}

// --- 7. get_ctx_params ����ʵ�� (��Ӧ OSSL_FUNC_CIPHER_GET_CTX_PARAMS) ---
// �ú����ᱻ ossl_cipher_generic_get_ctx_params ��ӵ���
static int hsm_get_ctx_params(void* vctx, OSSL_PARAM params[]) {
    SUSHU_HSM_ENCRYPT_CTX* ctx = (SUSHU_HSM_ENCRYPT_CTX*)vctx;
    OSSL_PARAM* p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->base.ivlen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->base.pad)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL
        && !OSSL_PARAM_set_octet_ptr(p, &ctx->base.oiv, ctx->base.ivlen)
        && !OSSL_PARAM_set_octet_string(p, &ctx->base.oiv, ctx->base.ivlen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL
        && !OSSL_PARAM_set_octet_ptr(p, &ctx->base.iv, ctx->base.ivlen)
        && !OSSL_PARAM_set_octet_string(p, &ctx->base.iv, ctx->base.ivlen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_NUM);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->base.num)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->base.keylen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS_MAC);
    if (p != NULL
        && !OSSL_PARAM_set_octet_ptr(p, ctx->base.tlsmac, ctx->base.tlsmacsize)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return 1;
}

// --- 8. gettable_ctx_params ����ʵ�� (��Ӧ OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS) ---
// �ú����ᱻ ossl_cipher_generic_gettable_ctx_params ��ӵ���
static const OSSL_PARAM* hsm_gettable_ctx_params(void* provctx) {
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_DEFN(OSSL_CIPHER_PARAM_IV, OSSL_PARAM_OCTET_STRING, NULL, 0),
        OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}
const OSSL_DISPATCH ossl_hsm_sm4cbc_functions[] = {
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))hsm_einit },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))hsm_dinit },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))hsm_sm4_cbc_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))hsm_final },
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))ossl_cipher_generic_cipher },
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))hsm_sm4_cbc_newctx },
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
const OSSL_DISPATCH ossl_hsm_sm4ecb_functions[] = {
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))hsm_einit },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))hsm_dinit },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))hsm_sm4_ecb_update },
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