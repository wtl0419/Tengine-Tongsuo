#ifndef HEADER_ERROR_H
#define HEADER_ERROR_H

///////////////////////国密标准错误返回////////////////////////////////////
#define SDR_OK                  0x0
#define SDR_UNKNOWERR           0x01000001
#define SDR_NOTSUPPORT          0x01000002
#define SDR_COMMFAIL            0x01000003
#define SDR_HARDFAIL            0x01000004
#define SDR_OPENDEVICE          0x01000005
#define SDR_OPENSESSION         0x01000006
#define SDR_PARDENY             0x01000007
#define SDR_KEYNOTEXIST         0x01000008
#define SDR_ALGNOTSUPPORT       0x01000009
#define SDR_ALGMODNOTSUPPORT    0x0100000A
#define SDR_PKOPERR             0x0100000B
#define SDR_SKOPERR             0x0100000C
#define SDR_SIGNERR             0x0100000D
#define SDR_VERIFYERR           0x0100000E
#define SDR_SYMOPERR            0x0100000F
#define SDR_STEPERR             0x01000010
#define SDR_FILESIZEERR         0x01000011
#define SDR_FILENOEXIST         0x01000012
#define SDR_FILEOFSERR          0x01000013
#define SDR_KEYTYPEERR          0x01000014
#define SDR_KEYERR              0x01000015

//user defined error
#define SDR_FILENOROOM          0x0100001F
#define SDR_FILEEXIST           0x01000020
#define SDR_POPEDOMERR          0x01000021
#define SDR_KEYISEMPTYERR       0x01000022
#define SDR_INITCardERR         0x01000023

///////////////////////////////////////////////////////////////////////////
/* 密码卡驱动程序返回值 */
#define SR_SUCCESSFULLY                 SDR_OK          /* 函数返回成功 */
#define SR_CANNOT_OPEN_DEVICE           0x80000001      /* 无法打开设备 */
#define SR_INVALID_PARAMETER            0x80000002      /* 参数错误 */
#define SR_WRITE_TO_DEVICE              0x80000003      /* 写往内核错误 */
#define SR_CANNOT_RESETCARD             0x80000004      /* 卡不能复位 */
#define SR_CANNOT_CLEAN_MODULE          0x80000005      /* 模块不能卸载 */ 
#define SR_WRITE_TIMEOUT                0x80000006      /* 写超时错误 */
#define SR_READ_TIMEOUT                 0x80000007      /* 读超时错误 */
#define SR_RETURN_ERROR                 0x80000008      /* 从卡中返回数据有误 */
#define SR_GENERAL_ERROR                0x80000009      /* 未知的错误 */
#define SR_VERIFY_FAILURE               0x8000000a      /* 未通过验证 */
#define SR_FUNCTION_NOT_SUPPLIED        0x8000000b      /* 此函数暂不提供 */
#define SR_PARAMETER_LENGTH_ERROR       0x8000000c      /* 参数长度错误 */
#define SR_HOST_MEMORY                  0x8000000d      /* 内存错误 */
#define SR_ID_OUTRANGE                  0x8000000e      /* ID超出范围 */
#define SR_RSA_KEYLEN_ERROR             0x8000000f      /* RSA密钥长度错误 */
#define SR_SMALL_BUFFER                 0x80000010      /* 缓冲区不足 */
#define SR_INVALID_PINLEN               0x80000011      /* 无效的PIN口令长度 */
#define SR_INVALID_FLAG                 0x80000012      /* 无效的FLAG标识 */
#define SR_INVALID_KEYLEN               0x80000013      /* 密钥长度有误 */
#define SR_BLOCK_ENCRY_DATALENGTH       0x80000014      /* 分组加密数据长度错误 */
#define SR_BLOCK_DECRY_DATALENGTH       0x80000015      /* 分组解密数据长度错误 */
#define SR_SESSION_OUTRANGE             0x80000016      /* SKID超出范围 */
#define SR_DATALEN_OUTRANGE             0x80000017      /* 数据超出范围 */
#define SR_INVALID_DATALEN              0x80000018      /* 无效的数据长度 */
#define SR_INVALID_HOST                 0x80000019      /* 无效的主机 */
#define SR_INVALID_MKID                 0x8000001a      /* 无效的MKID */
#define SR_DEVICE_BUSYING               0x8000001b      /* 设备忙 */
#define SR_TOO_MANY_COMUCATION_DEVICE   0x8000001c      /* 同时通信的设备太多，产生的SK大于768 */
#define SR_INSUFFICIENT_MEMORY          0x8000001d      /* 存不足 */
#define SR_RSA_OUT_DATA                 0x8000001e      /* RSA算法中数据长度超过128Bytes */
#define SR_READ_FROM_DEVICE             0x8000001f      /* 从内核读出错误 */
#define SR_INVALID_RSA_VK               0x80000020      /* 表示私钥未曾注入，或者注入的私钥错误 */
#define SR_RSA_KEY_ERROR                0x80000021      /* 其它操作加密的程序未释放某些资源而出错 */
#define SR_TIME_OUT                     0x80000022      /* 超时错误 */
#define SR_NOT_SUPPORT_OSVERSOIN        0x80000023      /* 不支持此版本的操作系统 */
#define SR_COMMAND_IC_ERROR             0x80000024      /* IC卡命令字错误 */
#define SR_CANNOT_OPEN_IC               0x80000025      /* 不能打开IC卡 */
#define SR_SESSION_KEY_LEN_ERR          0x80000026      /* 会话密钥长度错误，必须为16 */
#define SR_ECC_DATA_LEN_ERR             0x80000027      /* ECC 加解密数据长度错误*/
#define SR_KEY_INDEX_ERR                0x80000028      /* KEY 索引值错误 */

#define SR_RSA_ERASEPADDING_ERR         0x80000029
#define SR_RSA_PADDING_ERR              0x8000002a
#define SR_ECC_DECRYPT_ERR              0x8000002b
#define SR_NOT_SUPPORT_ALGORITHM        0x8000002c
#define SR_RETURN_LENGTH_ERR            0x8000002d
#define SR_NOT_SUPPORT_TYPE             0x8000002e




/* 卡内返回 */
/////////////////////////////////////////////////////////////////////////////////////
#define CCR_SUCCESS                         0x00000000
#define CCR_LENGTH_WRONG                    0x00000001            //格式长度错误
#define CCR_UNKNOWN_ALG                     0x00000005            //未知算法
#define CCR_UNKNOWN_MODE                    0x00000006            //未知算法模式
#define CCR_FLASH_OVER                      0x00000002            //FLASH溢出 (offset+inlen)>=0x1000   
#define CCR_FLASH_FAN_ERROR                 0x00000003            //使用了不可用的扇区
#define CCR_FLASH_OFFSET_ERROR              0x00000004
#define CCR_NO_ICCARD                       0x00000007            //无IC卡
#define CCR_IC_ERROR                        0x00000008            //IC返回数据错
#define CCR_ECC_FAIL                        0x00000009            //ECC操作失败
#define CCR_ECC_VERIFY_FAIL                 0x0000000A            //ECC验证失败
#define CCR_ECC_PARA_ERR                    0x0000000B            //ECC参数错
#define CCR_ECC_ENCRYPT_FAIL                0x0000000C
#define CCR_ECC_DECRYPT_FAIL                0x0000000D
#define CCR_ECC_KEYAGREEMENT_FAIL           0x0000000E
#define    CCR_HASH_INIT_FAIL               0x0000000F
#define CCR_HASH_FAIL                       0x00000010
#define CCR_FLASH_WRITE_ERR                 0x00000012            //
#define CCR_ERASEPADDING_FAIL               0x00000013                      //
#define CCR_FLASH_CHECK_FAIL                0x00000014
#define CCR_FLASH_READ_ERR                  0x00000015 

#define CCR_UKEY_FAIL                       0x00000201
#define CCR_UKEY_UNKOWNERR                  0x00000202
#define CCR_UKEY_NOTSUPPORTYETERR           0x00000203
#define CCR_UKEY_FILEERR                    0x00000204
#define CCR_UKEY_INVALIDHANDLEERR           0x00000205
#define CCR_UKEY_INVALIDPARAMERR            0x00000206
#define CCR_UKEY_READFILEERR                0x00000207
#define CCR_UKEY_WRITEFILEERR               0x00000208
#define CCR_UKEY_NAMELENERR                 0x00000209
#define CCR_UKEY_KEYUSAGEERR                0x0000020A
#define CCR_UKEY_MODULUSLENERR              0x0000020B
#define CCR_UKEY_NOTINITIALIZEERR           0x0000020C
#define CCR_UKEY_OBJERR                     0x0000020D
#define CCR_UKEY_MEMORYERR                  0x0000020E
#define CCR_UKEY_TIMEOUTERR                 0x0000020F
#define CCR_UKEY_INDATALENERR               0x00000210
#define CCR_UKEY_INDATAERR                  0x00000211
#define CCR_UKEY_GENRANDERR                 0x00000212
#define CCR_UKEY_HASHOBJERR                 0x00000213
#define CCR_UKEY_HASHERR                    0x00000214
#define CCR_UKEY_GENRSAKEYERR               0x00000215
#define CCR_UKEY_RSAMODULUSLENERR           0x00000216
#define CCR_UKEY_CSPIMPRTPUBKEYERR          0x00000217
#define CCR_UKEY_RSAENCERR                  0x00000218
#define CCR_UKEY_RSADECERR                  0x00000219
#define CCR_UKEY_HASHNOTEQUALERR            0x0000021A
#define CCR_UKEY_KEYNOTFOUNTERR             0x0000021B
#define CCR_UKEY_CERTNOTFOUNTERR            0x0000021C
#define CCR_UKEY_NOTEXPORTERR               0x0000021D
#define CCR_UKEY_DECRYPTPADERR              0x0000021E
#define CCR_UKEY_MACLENERR                  0x0000021F
#define CCR_UKEY_BUFFER_TOO_SMALL           0x00000220
#define CCR_UKEY_KEYINFOTYPEERR             0x00000221
#define CCR_UKEY_NOT_EVENTERR               0x00000222
#define CCR_UKEY_DEVICE_REMOVED             0x00000223
#define CCR_UKEY_PIN_INCORRECT              0x00000224
#define CCR_UKEY_PIN_LOCKED                 0x00000225
#define CCR_UKEY_PIN_INVALID                0x00000226
#define CCR_UKEY_PIN_LEN_RANGE              0x00000227
#define CCR_UKEY_USER_ALREADY_LOGGED_IN     0x00000228
#define CCR_UKEY_USER_PIN_NOT_INITIALIZED   0x00000229
#define CCR_UKEY_USER_TYPE_INVALID          0x0000022A
#define CCR_UKEY_APPLICATION_NAME_INVALID   0x0000022B
#define CCR_UKEY_APPLICATION_EXISTS         0x0000022C
#define CCR_UKEY_USER_NOT_LOGGED_IN         0x0000022D
#define CCR_UKEY_APPLICATION_NOT_EXISTS     0x0000022E
#define CCR_UKEY_FILE_ALREADY_EXIST         0x0000022F
#define CCR_UKEY_NO_ROOM                    0x00000230
#define CCR_UKEY_FILE_NOT_EXIST             0x00000231
#define CCR_UKEY_REACH_MAX_CONTAINER_COUNT  0x00000232

#define CCR_INDEX_OUT_OF_RANGE                  0x00001001            //数值超出范围
#define CCR_PIN_CHECK_ERR                       0x00001002            //
#define CCR_RSA_DATALEN_ERR                     0x00001003            //RSA数据长度错误
#define CCR_CMD_FAIL                            0x00000001            //失败返回
#define CCR_SESSION_KEY_EMPTY                   0x00001004            //会话密钥句柄已经分配完毕
  
#define CCR_SECTOR_OUT_OF_RANGE                 0x00001006            //扇区编号越界（0～23） 
#define CCR_SESSION_KEY_OUT_OF_RANGE            0x00001007            //SESSION编号越界（0～127）
#define CCR_SESSION_KEY_IS_EMPTY                0x00001008            //SESSION KEY 为空
#define CCR_CMD_ERR                             0x00001009            //无效的命令字
#define CCR_PRIVATE_KEY_ACCESSRIGHT_VERIFY_ERR  0x00001010            //PIN 校验失败
#define CCR_RSA_PRIVATE_KEY_FLAG_ERR            0x00001011            //无效的RSA私钥类型。
#define CCR_KEY_IS_EMPTY                        0x00001012            //无效的RSA私钥类型。
#define CCR_AUTHORITY_ERR                       0x00001013            //权限验证错误
#define CCR_PARAMETER_ERR                       0x00001016

#define CCR_WEAK_PIN_CHECK_ERR                  0x00002001        //PIN码校验错误
#define CCR_CHECK_DATA_ERR                      0x00002006        //数据校验失败
#define CCR_GEN_SM2_KEYPAIR_FAIL                0x00002007        //ECC获取密钥对
#define CCR_NO_ADMIN_PERMITION                  0x00002008        //未获得管员权限
#define CCR_SM2_KEY_INDEX_ERR                   0x0000200C
#define CCR_BAKUP_UKEY_ERR                      0x0000200E        //备份卡的类型错误
#define CCR_KEK_INDEX_ERR                       0x0000200F        //
#define CCR_RESTORE_PROTECTKEY_NOT_EXIST        0x00002010        //没有恢复PPK
#define CCR_DEVICEKEY_NOT_PREPARED              0x00002015        //未初始化
#define CCR_BAKUP_PROTECTKEY_NOT_EXIST          0x00002016        //PPK未产生
#define CCR_PERMISSION_FAIL                     0x00002019        //权限错误
#define CCR_UKEY_CHECK_ERR                      0x000020A1        //IC卡校验错误
#define CCR_KEY_PAIRE_EMPTY                     0x00002050
#define CCR_USER_NOT_READY                      0x00002051
#define CCR_CARD_STATUS_ERR                     0x00002053
#define CCR_UKEY_REPEAT                         0x00002054
#define CCR_CMD_CANNOT_EXEC_AT_CURRUNT_STATUS   0x00002063



unsigned char *pii_strerror(int iErrCode);

#endif
