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

#define ALGC(NAMES, FUNC, CHECK) { { NAMES, "provider=default", FUNC }, CHECK }
#define ALG(NAMES, FUNC) ALGC(NAMES, FUNC, NULL)

static OSSL_FUNC_provider_gettable_params_fn sushu_hsm_gettable_params;
static OSSL_FUNC_provider_get_params_fn sushu_hsm_get_params;
static OSSL_FUNC_provider_query_operation_fn sushu_hsm_query_operation;
// Provider �ڲ��������Ľṹ�壬���ڱ���Provider��״̬������
typedef struct sushu_hsm_prov_ctx_st {
    OSSL_LIB_CTX* libctx;
    // ����PCIeӲ����صľ�������õ�
    void* sushu_hsm_device_handle;
} SUSHU_HSM_PROV_CTX;

// ǰ������ Provider �ṩ���㷨�ַ���
const OSSL_ALGORITHM_CAPABLE sushu_hsm_cipher_functions[] = {
    ALG(PROV_NAMES_SM4_CBC, ossl_hsm_encrypt_functions),
    ALG(PROV_NAMES_HSM_SDF_CIPHER, ossl_hsm_encrypt_functions)
}; // ʾ����PCIe ���ٵĶԳ������㷨
const OSSL_ALGORITHM sushu_hsm_digest_functions[] = {

#ifndef OPENSSL_NO_SM3
    { PROV_NAMES_SM3, "provider=sushu_hsm", ossl_sm3_functions },
#endif /* OPENSSL_NO_SM3 */
    { NULL, NULL, NULL }
};
static const OSSL_PARAM sushu_hsm_gettable_provider_params[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    // ������Զ��������ҲҪ����������
    // OSSL_PARAM_DEFN("device-id", OSSL_PARAM_INT, NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM* sushu_hsm_gettable_params(void* provctx) {
    return sushu_hsm_gettable_provider_params;
}
static int sushu_hsm_get_params(void* provctx, OSSL_PARAM params[])
{
    OSSL_PARAM* p;

    // ��ȡ Provider ����
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL sushu hsm Provider"))
        return 0; // �������ʧ�ܣ�����0��ʾʧ��

    // ��ȡ Provider �汾
    // �������ʹ�õ�ǰ��OpenSSL�汾�ַ����������������PCIe Provider�Լ��İ汾��
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR))
        return 0;

    // ��ȡ Provider ������Ϣ����ѡ������ʹ��OpenSSL�������汾�ַ�����
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
        return 0;

    // ��ȡ Provider ״̬���Ƿ��������У�
    // ossl_prov_is_running() ��һ��ͨ�ú��������Provider�Ƿ��ڻ�Ծ״̬
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, ossl_prov_is_running()))
        return 0;

    // �������PCIe Provider���еĲ�����Ҳ�����������ṩ��
    // ���磬��������һ���ڲ���PCIe�豸ID��
    // PCIE_PROV_CTX *ctx = (PCIE_PROV_CTX *)provctx; // �����Ҫ����provctx
    // p = OSSL_PARAM_locate(params, "device-id"); // �Զ����������
    // if (p != NULL && !OSSL_PARAM_set_int(p, ctx->device_id))
    //     return 0;

    return 1; // �ɹ�������������Ĳ���
}
// Provider �� Teardown ���� (ж��ʱ����)
static void sushu_hsm_teardown(void* provctx) {
    SUSHU_HSM_PROV_CTX* ctx = (SUSHU_HSM_PROV_CTX*)provctx;
    // ����Ӳ��������ͷ���Դ
    if (ctx->sushu_hsm_device_handle != NULL) {
        // sushu_hsm_close_device(ctx->pcie_device_handle); // ����Ĺرպ���
    }
    ossl_prov_ctx_free(ctx); // �ͷ� Provider ������
}
static const OSSL_DISPATCH sushu_hsm_provider_dispatch_table[] = {
        { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))sushu_hsm_teardown },
        { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))sushu_hsm_query_operation },
        { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))sushu_hsm_gettable_params },
        { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))sushu_hsm_get_params },
        { 0, NULL }
};
// Provider �Ĳ�ѯ�������� (ʵ�� OSSL_FUNC_PROVIDER_QUERY_OPERATION)
static const OSSL_ALGORITHM* sushu_hsm_query_operation(void* provctx, int operation_id, int* no_cache) {
    // ���� operation_id ���ض�Ӧ���㷨�б�
    switch (operation_id) {
    case OSSL_OP_CIPHER:
        return sushu_hsm_cipher_functions; // ���ضԳ������㷨�б�
    case OSSL_OP_DIGEST:
        return sushu_hsm_digest_functions; // ����ɢ���㷨�б�
        // ... ������������ KDF, RAND ��
    }
    return NULL;
}
// Provider ����ڵ㺯������ Provider ������ʱ�� OpenSSL ���ĵ���
// �������ָ����� ossl_predefined_providers �����б�����
int ossl_sushu_hsm_provider_init(const OSSL_CORE_HANDLE* handle,
    const OSSL_DISPATCH* in,
    const OSSL_DISPATCH** out,
    void** provctx)
{
    SUSHU_HSM_PROV_CTX* sushu_hsm_ctx;

    // 1. �Ӻ��Ŀ���շ��� (BIO, Seeding, Error Handling��)
    // ȷ����� Provider �ܹ�ʹ�ú��Ŀ�� I/O���ڴ�����������
    if (!ossl_prov_bio_from_dispatch(in)
        || !ossl_prov_seeding_from_dispatch(in)
        // ... �����Ӻ��Ŀ��ȡ�ķ���
        ) {
        return 0;
    }

    // 2. �洢���Ŀ��ṩ������ͨ�ú���
    OSSL_FUNC_core_get_libctx_fn* c_get_libctx = NULL;
    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_LIBCTX:
            c_get_libctx = OSSL_FUNC_core_get_libctx(in);
            break;
            // ... ������������Ҫ�ĺ��ĺ�����������󱨸棬�߳�������
        }
    }
    if (c_get_libctx == NULL) {
        return 0; // ���躯��δ��ȡ��
    }

    // 3. ���� Provider ˽��������
    if ((*provctx = ossl_prov_ctx_new()) == NULL) {
        return 0;
    }
    sushu_hsm_ctx = OPENSSL_zalloc(sizeof(*sushu_hsm_ctx)); // �������Լ���PCIe������
    if (sushu_hsm_ctx == NULL) {
        ossl_prov_ctx_free(*provctx);
        *provctx = NULL;
        return 0;
    }
    ossl_prov_ctx_set0_handle(*provctx, handle);
    ossl_prov_ctx_set0_libctx(*provctx, (OSSL_LIB_CTX*)c_get_libctx(handle));

    // 4. ��ʼ��Ӳ�� (�����Ҫ)
    // pcie_ctx->pcie_device_handle = pcie_init_device(); // �����Ӳ����ʼ������
    // if (pcie_ctx->pcie_device_handle == NULL) {
    //     // ... ������
    //     pcie_teardown(*provctx);
    //     return 0;
    // }

    *out = sushu_hsm_provider_dispatch_table; // ����Provider�ĺ��Ĺ��ַܷ���

    return 1;
}