#include "prov/ciphercommon.h"
#include "crypto/sm4.h"
#include "crypto/sm4_platform.h"

#define SGD_SM4_CBC_KBITS                  128 //密钥长度为128位     
#define SGD_SM4_CBC_BLOCK_SIZE             128 //SM4分组长度为16字节
#define SGD_SM4_CBC_IVLEN                  128 //IV长度为16字节

#define SGD_SM4_ECB_KBITS                  128 //密钥长度为128位     
#define SGD_SM4_ECB_BLOCK_SIZE             128 //SM4分组长度为16字节
#define SGD_SM4_ECB_IVLEN                  128 //IV长度为16字节

//SDF函数指针类型
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

typedef struct sushu_hsm_encrypt_ctx_st {
    PROV_CIPHER_CTX base;
    union {
        OSSL_UNION_ALIGN;
        SM4_KEY ks;
    } ks;
} SUSHU_HSM_ENCRYPT_CTX;

typedef struct {
    PROV_CIPHER_CTX base;
    
} HSM_PROV_CTX;

const PROV_CIPHER_HW* ossl_prov_cipher_hw_sm4_cbc(size_t keybits);
const PROV_CIPHER_HW* ossl_prov_cipher_hw_sm4_ecb(size_t keybits);
