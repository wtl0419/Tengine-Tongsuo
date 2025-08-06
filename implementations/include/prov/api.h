#ifdef __cplusplus
extern "C"{
#endif

#include "piico_define.h"
#include "piico_error.h"

//GM/T 0018===================================================================
//打开设备
int  SDF_OpenDevice(
		void **phDeviceHandle);

//关闭设备
int SDF_CloseDevice(
		void *hDeviceHandle);

//打开会话
int SDF_OpenSession(
		void *hDeviceHandle,
		void **phSessionHandle);

//关闭会话
int SDF_CloseSession(
		void *hSessionHandle);

//获取设备信息
int SDF_GetDeviceInfo (
		void *hSessionHandle,
		DEVICEINFO *pstDeviceInfo);

//获取随机数
int SDF_GenerateRandom(
		void * hSessionHandle, 
		unsigned int   uiLength,
		unsigned char *pucRandom);

//获取私钥权限
int SDF_GetPrivateKeyAccessRight(
		void *hSessionHandle,
		unsigned int  uiKeyIndex,
		unsigned char *pucPassword,
		unsigned int  uiPwdLength);

//释放私钥权限
int SDF_ReleasePrivateKeyAccessRight(
		void *hSessionHandle,
		unsigned int  uiKeyIndex);

//导出ECC签名公钥
int SDF_ExportSignPublicKey_ECC(
		void * hSessionHandle,
		unsigned int  uiKeyIndex,	
		ECCrefPublicKey *pucPublicKey);

//导出ECC加密公钥
int SDF_ExportEncPublicKey_ECC(
		void * hSessionHandle,
		unsigned int  uiKeyIndex,
		ECCrefPublicKey *pucPublicKey);

//产生ECC密钥对并导出
int SDF_GenerateKeyPair_ECC(
		void * hSessionHandle,
		unsigned int  uiAlgID,
		unsigned int  uiKeyBits,
		ECCrefPublicKey *pucPublicKey,
		ECCrefPrivateKey *pucPrivateKey);

//产生会话密钥并使用内部加密公钥加密导出
int SDF_GenerateKeyWithIPK_ECC (
		void * hSessionHandle,
		unsigned int uiIPKIndex,
		unsigned int uiKeyBits,	
		ECCCipher *pucKey,
		void * *phKeyHandle);

//产生会话密钥并使用外部公钥加密导出
int SDF_GenerateKeyWithEPK_ECC (
		void * hSessionHandle,
		unsigned int uiKeyBits,
		unsigned int uiAlgID,
		ECCrefPublicKey *pucPublicKey,
		ECCCipher *pucKey,
		void * *phKeyHandle);

//内部加密私钥解密并导入会话密钥
int SDF_ImportKeyWithISK_ECC (
		void * hSessionHandle,
		unsigned int uiISKIndex,
		ECCCipher *pucKey,
		void * *phKeyHandle);

//ECC数字信封转换
int SDF_ExchangeDigitEnvelopeBaseOnECC(
		void * hSessionHandle,
		unsigned int uiKeyIndex,
		unsigned int uiAlgID,
		ECCrefPublicKey *pucPublicKey,
		ECCCipher *pucEncDataIn,
		ECCCipher *pucEncDataOut);

//生成密钥协商参数并输出
int SDF_GenerateAgreementDataWithECC(
		void * hSessionHandle,
		unsigned int uiISKIndex,
		unsigned int uiKeyBits,
		unsigned char *pucSponsorID,
		unsigned int uiSponsorIDLength,
		ECCrefPublicKey *pucSponsorPublicKey,
		ECCrefPublicKey *pucSponsorTmpPublicKey,
		void **phAgreementHandle);

//计算会话密钥
int SDF_GenerateKeyWithECC(
		void * hSessionHandle,
		unsigned char *pucResponseID,
		unsigned int uiResponseIDLength,
		ECCrefPublicKey *pucResponsePublicKey,
		ECCrefPublicKey *pucResponseTmpPublicKey,
		void * hAgreementHandle,
		void **phKeyHandle);
		
//产生协商数据并计算会话密钥		
int SDF_GenerateAgreementDataAndKeyWithECC(
		void * hSessionHandle,
		unsigned int uiISKIndex,
		unsigned int uiKeyBits,
		unsigned char *pucResponseID,
		unsigned int uiResponseIDLength,
		unsigned char *pucSponseID,
		unsigned int uiSponseIDLength,
		ECCrefPublicKey *pucSponsorPublicKey,
		ECCrefPublicKey *pucSponsorTmpPublicKey,
		ECCrefPublicKey *pucResponsePublicKey,
		ECCrefPublicKey *pucResponseTmpPublicKey,
		void **phKeyHandle);


//产生会话密钥并使用KEK加密导出
int SDF_GenerateKeyWithKEK (
		void * hSessionHandle,
		unsigned int uiKeyBits,
		unsigned int  uiAlgID,
		unsigned int uiKEKIndex,
		unsigned char *pucKey,
		unsigned int *puiKeyLength, 
		void **phKeyHandle);

//KEK解密导入会话密钥
int SDF_ImportKeyWithKEK(
		void * hSessionHandle,
		unsigned int uiAlgID,
		unsigned int uiKEKIndex,
		unsigned char *pucKey,
		unsigned int puiKeyLength,
		void **phKeyHandle);

//导入明文状态会话密钥
int SDF_ImportKey (
		void * hSessionHandle,
		unsigned char *pucKey,
		unsigned int uiKeyLength,
		void *  *phKeyHandle);

//销毁会话密钥
int SDF_DestroyKey (
		void * hSessionHandle, 
		void * hKeyHandle);

//外部ECC公钥验证
int SDF_ExternalVerify_ECC(
		void * hSessionHandle,
		unsigned int uiAlgID,
		ECCrefPublicKey *pucPublicKey,
		unsigned char *pucDataInput,
		unsigned int  uiInputLength,
		ECCSignature *pucSignature);

//内部ECC私钥签名
int SDF_InternalSign_ECC(
		void * hSessionHandle,
		unsigned int  uiISKIndex,
		unsigned char *pucData,
		unsigned int  uiDataLength,
		ECCSignature *pucSignature);

//内部ECC公钥验证
int SDF_InternalVerify_ECC(
		void *  hSessionHandle,
		unsigned int  uiISKIndex,
		unsigned char *pucData,
		unsigned int  uiDataLength,
		ECCSignature *pucSignature);

//外部ECC公钥加密
int SDF_ExternalEncrypt_ECC(
		void * hSessionHandle,
		unsigned int uiAlgID,
		ECCrefPublicKey *pucPublicKey,
		unsigned char *pucData,
		unsigned int uiDataLength,
		ECCCipher *pucEncData);

//对称加密
int SDF_Encrypt(
		void * hSessionHandle,
		void * hKeyHandle,
		unsigned int uiAlgID,	
		unsigned char *pucIV,
		unsigned char *pucData,
		unsigned int uiDataLength,
		unsigned char *pucEncData,
		unsigned int  *puiEncDataLength);

//对称解密
int SDF_Decrypt (
		void * hSessionHandle,
		void * hKeyHandle,
		unsigned int uiAlgID,
		unsigned char *pucIV,
		unsigned char *pucEncData,
		unsigned int  uiEncDataLength,	
		unsigned char *pucData,
		unsigned int *puiDataLength);

//mac
int SDF_CalculateMAC(
		void * hSessionHandle,
		void * hKeyHandle,
		unsigned int uiAlgID,
		unsigned char *pucIV,
		unsigned char *pucData,
		unsigned int uiDataLength,
		unsigned char *pucMAC,
		unsigned int *puiMACLength);

//杂凑初始化
int SDF_HashInit(
		void * hSessionHandle,
		unsigned int uiAlgID,
		ECCrefPublicKey *pucPublicKey,
		unsigned char *pucID,
		unsigned int uiIDLength);

//杂凑Update
int SDF_HashUpdate(
		void * hSessionHandle,
		unsigned char *pucData,
		unsigned int uiDataLength);

//杂凑结束
int SDF_HashFinal(
		void * hSessionHandle,
		unsigned char *pucHash,
		unsigned int *puiHashLength);

//删除文件
int SDF_CreateFile(
		void * hSessionHandle,
		unsigned char *pucFileName,
		unsigned int uiNameLen,
		unsigned int uiFileSize);

//读文件
int SDF_ReadFile(
		void * hSessionHandle,
		unsigned char *pucFileName,
		unsigned int uiNameLen,
		unsigned int uiOffset,
		unsigned int *puiFileLength,
		unsigned char *pucBuffer);

//写文件
int SDF_WriteFile(
		void * hSessionHandle,
		unsigned char *pucFileName,
		unsigned int uiNameLen,
		unsigned int uiOffset,
		unsigned int uiFileLength,
		unsigned char *pucBuffer);

//删除文件
int SDF_DeleteFile(
		void * hSessionHandle,
		unsigned char *pucFileName,
		unsigned int uiNameLen);
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////
////自定义函数

//外部ECC私钥解密
int SDF_ExternalDecrypt_ECC(
			void * hSessionHandle,
			unsigned int uiAlgID,
			ECCrefPrivateKey *pucPrivateKey,
			ECCCipher *pucEncData,
			unsigned char *pucData,
			unsigned int  *puiDataLength);

//外部ECC私钥签名			
int SDF_ExternalSign_ECC(
			void * hSessionHandle,
			unsigned int uiAlgID,
			ECCrefPrivateKey *pucPrivateKey,
			unsigned char *pucData,
			unsigned int  uiDataLength,
			ECCSignature *pucSignature);

//内部ECC私钥加密
int SDF_InternalEncrypt_ECC(
			void *hSessionHandle,
			unsigned int uiIPKIndex,
			unsigned int uiAlgID,
			unsigned char *pucData,
			unsigned int uiDataLength,
			ECCCipher *pucEncData);

//内部ECC私钥解密
int SDF_InternalDecrypt_ECC(
			void *hSessionHandle,
			unsigned int uiISKIndex,
			unsigned int uiAlgID,
			ECCCipher *pucEncData,
			unsigned char *pucData,
			unsigned int *puiDataLength);	
				
//销毁密钥协商参数句柄
int SPII_DestroyAgreementHandle(
		void * pSessionHandle,
		void * phAgreementHandle);

//注册用户
int SPII_Regsvr(
		void * pSessionHandle,
		unsigned int Ukeyflag,
		unsigned char *Password,
		unsigned int PasswordLength,
		ECCrefPublicKey  *enpk,
		ECCrefPublicKey  *signpk,
		unsigned int UserID);
		
//登录第一步		
int SPII_LoadinStepF(
			void * pSessionHandle,
			unsigned int Ukeyflag,
			unsigned char *Password,
			unsigned int PasswordLength,
			ECCrefPublicKey  *enpk,
			ECCrefPublicKey  *entpk,
			ECCCipher *enR,
			ECCCipher *enmk);
			
//登录第二步	
int SPII_LoadinStepS(
			void * pSessionHandle,
			unsigned int Ukeyflag,
			unsigned char *Password,
			unsigned int PasswordLength,
			ECCSignature  *signR,
			ECCCipher *enmk);

//口令方式登录用户
int SPII_LoadinWithPassword(
                	void * pSessionHandle,
                	unsigned char *Password,
                	unsigned int PasswordLength,
                	unsigned int UserID);
			
//恢复第一步
int SPII_GenerateTmpPK(
			void * pSessionHandle ,
			ECCrefPublicKey *pucPublicKey);
			
//恢复导入备份保护密钥
int SPII_RestoreBK(
			void * pSessionHandle,
			unsigned int Ukeyflag,
			unsigned char *Password,
			unsigned int PasswordLen,
			ECCCipher *Enbk);											//恢复1中，获得的临时公钥加密的备份保护密钥分量

//备份导出备份保护密钥
int SPII_BackUpBK(
			void * pSessionHandle,			//IN 设备句柄
			unsigned int    UkeyFlag,			// IN 注册Ukey形式（0内在线Ukey，1外离线Ukey）
			unsigned char *Password,			//IN Ukey的口令，UkeyFlag=0时有效
			unsigned int  PasswordLen,		//IN Ukey的口令长度，UKeyFlag=0时有效
			unsigned int    UkeyNun,			//IN （1\2\3）表示三组合成备份保护密钥bk的分量
			ECCrefPublicKey  *pk,			//IN 备份密钥Ukey的加密公钥
			ECCCipher	*Enpk);		//Out 备份密钥Ukey加密的备份保护密钥分量

//备份导出ECC加密密钥对			
int SPII_BackUpECCEnc(
			void * hSessionHandle,
			unsigned int keyIndex,
			unsigned char *EncECCKeyPair,
			unsigned int *EncECCKeyPairLength);
			
//备份导出ECC签名密钥对			
int SPII_BackUpECCSign(
			void * hSessionHandle,
			unsigned int keyIndex,
			unsigned char *EncECCKeyPair,
			unsigned int *EncECCKeyPairLength);

//备份导出KEK密钥
int SPII_BackUpKEK(
			void * pSessionHandle,
			unsigned int keyIndex,
			unsigned char *EncKEK,
			unsigned int *EncKEKLength);
			
//恢复ECC加密密钥对
int SPII_RestoreECCEnc(
			void * pSessionHandle,
			unsigned int keyIndex,
			unsigned char *EncECCKeyPair,
			unsigned int EncECCKeyPairLength);
			
//恢复ECC签名密钥对
int SPII_RestoreECCSign(
			void * pSessionHandle,
			unsigned int keyIndex,
			unsigned char *EncECCKeyPair,
			unsigned int EncECCKeyPairLength);

//恢复KEK密钥
int SPII_RestoreKEK(
			void * pSessionHandle, 
			unsigned int uiKEKIndex,
            unsigned char *EncKEK, 
			unsigned int EncKEKLength);

//初始化密钥空间
int SPII_Init_KeyContainer(
			void * phDeviceHandle,
			unsigned int KeyIndex);

//初始化密钥空间
int SPII_Init_KeyContainerWithPrivateKeyAccessRight(
			void * phDeviceHandle,
			unsigned int KeyIndex,
			unsigned char *pucPassword,
			unsigned int  uiPwdLength);			

//初始化置零设备
int SPII_Init_Device(
			void * phDeviceHandle);

//获取设备状态
int  SPII_GetDeviceStatus(
			void * phDeviceHandle,
			unsigned short *CardStatus,
			unsigned short *PermissionStatus);

//状态转换：初始化状态-〉就绪状态
int  SPII_ISTORS(
			void * phDeviceHandle);

//状态转换：就绪状态-〉初始化状态
int  SPII_RSTOIS(
			void * phDeviceHandle);

//状态转换：出厂状态-〉初始化状态
int  SPII_FSTOIS(
			void * phDeviceHandle);

//获取最后错误信息
int SPII_GetErrorInfo(void * hSessionHandle);

//修改密钥权限码
int SPII_ChangePrivateKeyAccessRight(
			void *  hSessionHandle,
			unsigned int  uiKeyIndex,
			unsigned char *oldpucPassword,
			unsigned int uioldPwdlength,
			unsigned char *newpucPassword,
			unsigned int  uiPwdLength);

//复位密码卡
int SPII_ResetModule(
			void * phDeviceHandle);
			
//初始化文件系统
int SPII_Init_FileSystem(
			void * hSessionHandle);

//产生并存储ECC加密密钥对
int SPII_GenerateEncKeyPair_ECC(
			void * hSessionHandle,
			unsigned int uiKeyIndex);

//产生并存储ECC签名密钥对
int SPII_GenerateSignKeyPair_ECC(
			void * hSessionHandle,
			unsigned int uiKeyIndex);

//产生并存储KEK密钥对
int SPII_GenerateKEK(
			void * hSessionHandle,
			unsigned int uiKeyIndex,
			unsigned int byteslen);

//对称算法外送密钥解密
int SPII_DecryptEx(
			void * hSessionHandle,
			unsigned char *endata,
			int enlen,
			unsigned char *keybuf,
			int keylen,
			unsigned char *IV,
			int IVLen,
			int uiAlgID,
			unsigned char *data,
			int *len);

//对称算法外送密钥加密
int SPII_EncryptEx(
			void * hSessionHandle,
			unsigned char *data,
			int len,
			unsigned char *keybuf,
			int keylen,
			unsigned char *IV,
			int IVLen,
			int uiAlgID,
			unsigned char *endata,
			int *enlen);

//导入加密ECC密钥对
int SPII_NVELOPEDKEY(
			void * hSessionHandle,
			unsigned int uiKeyIndex,
			unsigned int ulAsymmAlgID,
			unsigned int ulSymmAlgID,
			ECCCipher          *ECCCipherBlob,
			ECCrefPublicKey     *PubKey,
			unsigned char *cbEncryptedPriKey,
			unsigned int cbEncryptedPriKeylen);
	
int SPII_ImportKey_KEK(
	HANDLE hSessionHandle,
	unsigned int uiKEKIndex,
	unsigned char *pucKey,
	unsigned int uiKeyLength);

int SPII_ExportKey_KEK(
	HANDLE hSessionHandle,
	unsigned int uiKEKIndex,
	unsigned char *pucKey,
	unsigned int * uiKeyLength);

int SPII_GetChallenger(
                HANDLE hSessionHandle,
                unsigned char *Challenger,
                unsigned int *ChallengerLength);

int SPII_Authentiation(
                HANDLE hSessionHandle,
                unsigned char *Challenger,
                unsigned int ChallengerLength,
                unsigned char *Pin,
                unsigned int Pinlength);

int SPII_SM3Hmac(HANDLE pSessionHandle,
		unsigned char *key,
		unsigned int keylength,
		unsigned char *input ,
		unsigned int inputlength,
		unsigned char *output,
		unsigned int *outputlength);

int SPII_LoopTest(HANDLE hDeviceHandle, unsigned char * in, unsigned int inlen, unsigned char * out, unsigned int * outlen);



int SPII_ModifyPin(
		HANDLE pSessionHandle,
		unsigned char *pOldPin,
		unsigned int nOldPinLen,	
		unsigned char *pNewPin,	
		unsigned int nNewPinLen	
);

////////////////////////////////////////////////////////////////////////////////
#ifdef __cplusplus
}
#endif
