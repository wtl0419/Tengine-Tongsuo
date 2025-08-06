#ifndef HEADER_DEFINE_H
#define HEADER_DEFINE_H

#ifndef USERTYPE
#define USERTYPE

typedef unsigned char     S_BYTE;
typedef unsigned char     S_UCHAR;
typedef unsigned int      S_UINT;
typedef unsigned long     S_ULONG;
typedef unsigned short    S_USHORT;
typedef char   	S_CHAR;
typedef int     S_INT;
typedef long    S_LONG;
typedef short   S_SHORT;
typedef void    S_VOID;
typedef void*	HANDLE;
#endif

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef OPTIONAL
#define OPTIONAL
#endif

#define RSA_NONE_ID			0x00
#define RSA_SIGN_ID			0x01		//签名公私钥ID
#define RSA_ENCRYPT_ID			0x02		//加密公私钥ID
///////SCB2 
#ifdef  A1H2
#define SGD_SM1_ECB	0x00000001
#define SGD_SM1_CBC	0x00000001
#define SGD_SM1_CFB	0x00000001
#define SGD_SM1_OFB	0x00000001
#define SGD_SM1_MAC	0x00000001
#else
#define SGD_SM1_ECB	0x00000101
#define SGD_SM1_CBC	0x00000102
#define SGD_SM1_CFB	0x00000104
#define SGD_SM1_OFB	0x00000108
#define SGD_SM1_MAC	0x00000110
#endif
/////////SSF33

#define SGD_SSF33_ECB	0x00000201
#define SGD_SSF33_CBC	0x00000202
#define SGD_SSF33_CFB	0x00000204
#define SGD_SSF33_OFB	0x00000208
#define SGD_SSF33_MAC	0x00000210
//////////
#define SGD_SM4_ECB    0x00000401
#define SGD_SM4_CBC    0x00000402
#define SGD_SM4_CFB    0x00000404
#define SGD_SM4_OFB    0x00000408
#define SGD_SM4_MAC	   0x00000410

#define SGD_SM7_ECB 0x00004001
#define SGD_SM7_CBC 0x00004002
#define SGD_SM7_CFB 0x00004004
#define SGD_SM7_OFB 0x00004008
#define SGD_SM7_MAC 0x00004010

#define SGD_DES_ECB    0x00001001
#define SGD_DES_CBC    0x00001002
#define SGD_DES_CFB    0x00001004
#define SGD_DES_OFB    0x00001008
#define SGD_DES_MAC    0x00001010


#define SGD_3DES_ECB    0x00002001
#define SGD_3DES_CBC    0x00002002
#define SGD_3DES_CFB    0x00002004
#define SGD_3DES_OFB    0x00002008
#define SGD_3DES_MAC    0x00002010

#define SGD_RSA		0x00010000
#define SGD_SM2		0x00020100
#define SGD_SM2_1	0x00020200
#define SGD_SM2_2	0x00020400
#define SGD_SM2_3	0x00020800


#define SGD_SM9_1 0x00040100			//签名
#define SGD_SM9_2 0x00040200			//密钥交换
#define SGD_SM9_4 0x00040400			//密钥封装
#define SGD_SM9_8 0x00040800			//加密
#define SGD_SM9_8_ECB 0x00040801		//加密ECB加密模式
#define SGD_SM9_8_CBC 0x00040802		//加密CBC加密模式
#define SGD_SM9_8_CFB 0x00040804		//加密CFB加密模式
#define SGD_SM9_8_OFB 0x00040808		//加密OFB加密模式

#define SGD_SM3		0x00000001
#define SGD_SHA1	0x00000002
#define SGD_SHA256	0x00000004
#define SGD_SHA512	0x00000008

#define  SUPPER_ADMIN 1
#define   ADMIN             2
#define   ASSISTANT1     3
#define   ASSISTANT2     4


#define ECCref_MAX_BITS 512
#define ECCref_MAX_LEN ((ECCref_MAX_BITS+7)/8)
#define MAX_DATALEN	3584

#define KEKEY_MAX_INDEX 128
#define KEKEY_MIN_INDEX 1

#define RSAref_MAX_BITS    2048

#define RSAref_MAX_LEN     ((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS   ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN    ((RSAref_MAX_PBITS + 7)/ 8)

#define SM9ref_MAX_BITS			256 
#define SM9ref_MAX_LEN			((SM9ref_MAX_BITS+7) / 8)

#define  KEYPAIR_MAX_INDEX                      511
#define  KEYPAIR_MIN_INDEX			0
#define SM3_HASH_BYTE_SIZE  32
//#define MAX_PUID_LEN				1024
#define KEK_MAX_INDEX				(511)

#define SIGN_MAST_KEYPAIR				1
#define ENC_MAST_KEYPAIR				2
#define SIGN_USER_KEYPAIR				3
#define ENC_USER_KEYPAIR				4


typedef	struct _S_ICFILEINFO{
	unsigned short 	nFileID;	//文件标识符
	unsigned short	nDirID;		//目录标识符
	unsigned short	nFileLength;	//文件长度
	unsigned char	nFileType;	//文件类型
} S_ICFILEINFO;

typedef struct RSArefPublicKey_st
{
	unsigned int  bits;
	unsigned char m[RSAref_MAX_LEN];
	unsigned char e[RSAref_MAX_LEN];
} RSArefPublicKey;


typedef struct RSArefPrivateKey_st
{
	unsigned  int  bits;
	unsigned char m[RSAref_MAX_LEN];
	unsigned char e[RSAref_MAX_LEN];
	unsigned char d[RSAref_MAX_LEN];
	unsigned char prime[2][RSAref_MAX_PLEN];
	unsigned char pexp[2][RSAref_MAX_PLEN];
	unsigned char coef[RSAref_MAX_PLEN];
} RSArefPrivateKey;

typedef struct ECCrefPublicKey_st
{
	unsigned int  bits;
	unsigned char x[ECCref_MAX_LEN];
	unsigned char y[ECCref_MAX_LEN];
}ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st
{
	unsigned int  bits;
	unsigned char K[ECCref_MAX_LEN];
	
}ECCrefPrivateKey;

typedef struct ECCCipher_st
{
	unsigned char x[ECCref_MAX_LEN];
	unsigned char y[ECCref_MAX_LEN];
	unsigned char M[32];
	unsigned int  L;
	unsigned char C[1];
	
}ECCCipher;

typedef struct ECCSignature_st
{
	unsigned char r[ECCref_MAX_LEN];
	unsigned char s[ECCref_MAX_LEN];
}ECCSignature;

typedef struct DeviceInfo_st
{
		unsigned char IssuerName[40];//设备生产厂商名称
		unsigned char DeviceName[16];//设备型号
		unsigned char DeviceSerial[16];//设备编号，包含：日期（8字符）、批次号（3字符）、流水号（5字符）
		unsigned int  DeviceVersion;//密码设备内部软件的版本号
		unsigned int  StandardVersion;//密码设备支持的接口规范版本号
		unsigned int  AsymAlgAbility[2];//前4字节表示支持的算法,表示方法为非对称算法标识按位或的结果；
	                               //后4字节表示算法的最大模长，表示方法为支持的模长按位或的结果
		unsigned int  SymAlgAbility;//所有支持的对称算法，表示方法为对称算法标识按位或运算结果
		unsigned int  HashAlgAbility;//所有支持的杂凑算法，表示方法为杂凑算法标识按位或运算结果
		unsigned int  BufferSize; //支持的最大文件存储空间（单位字节）

}DEVICEINFO;

typedef struct SDF_ENVELOPEDKEYBLOB
{
	unsigned long       ulAsymmAlgID;
	unsigned long       ulSymmAlgID;
	ECCCipher          ECCCipherBlob;
	ECCrefPublicKey     PubKey;
	unsigned char 	cbEncryptedPriKey[64];
}ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;

typedef struct SDF_RSAENVELOPEDKEYBLOB
{
	unsigned long       ulAsymmAlgID;
	unsigned long       ulSymmAlgID;
	unsigned char       RSAcipherBlob[256];
	RSArefPublicKey     PubKey;
	unsigned char 	    cbEncryptedPriKey[896];
}RSAENVELOPEDKEYBLOB, *PRSAENVELOPEDKEYBLOB;

typedef struct SM9refSignMastPrivateKey_st
{
	unsigned int  bits;
	unsigned char s[SM9ref_MAX_LEN];	
} SM9SignMastPrivateKey;

typedef struct SM9refSignMastPublicKey_st
{
	unsigned int  compressType;						//只支持4模式
unsigned int  bits;
	unsigned char xa[SM9ref_MAX_LEN];	
unsigned char xb[SM9ref_MAX_LEN];
unsigned char ya[SM9ref_MAX_LEN];
unsigned char yb[SM9ref_MAX_LEN];
} SM9SignMastPublicKey;

typedef struct SM9refEncMastPrivateKey_st
{
	unsigned int  bits;
	unsigned char s[SM9ref_MAX_LEN];	
} SM9EncMastPrivateKey;

typedef struct SM9refEncMastPublicKey_st
{
	unsigned int  bits;
	unsigned char x[SM9ref_MAX_LEN];	
unsigned char y[SM9ref_MAX_LEN];
} SM9EncMastPublicKey;

typedef struct SM9refUserSignPrivateKey_st
{
	unsigned int  bits;
	unsigned char x[SM9ref_MAX_LEN];	
unsigned char y[SM9ref_MAX_LEN];
} SM9UserSignPrivateKey;

typedef struct SM9refUserEncPrivateKey_st
{
	unsigned int  compressType;									//只支持4模式
	unsigned int  bits;
	unsigned char xa[SM9ref_MAX_LEN];	
unsigned char xb[SM9ref_MAX_LEN];
unsigned char ya[SM9ref_MAX_LEN];
unsigned char yb[SM9ref_MAX_LEN];
} SM9UserEncPrivateKey;

typedef struct SM9refCipher_st
{
	unsigned int  enType;
	unsigned char x[SM9ref_MAX_LEN];	
unsigned char y[SM9ref_MAX_LEN];
	unsigned char h[SM9ref_MAX_LEN];
unsigned int  L;
unsigned char C[1];
} SM9Cipher;

typedef struct SM9refSignature_st
{
	unsigned char h[SM9ref_MAX_LEN];
	unsigned char x[SM9ref_MAX_LEN];	
unsigned char y[SM9ref_MAX_LEN];
} SM9Signature;

typedef struct SM9refKeyPackage_st
{
	unsigned char x[SM9ref_MAX_LEN];	
unsigned char y[SM9ref_MAX_LEN];
} SM9KeyPackage;

typedef struct SM9refPairEncEnvelopedKey_st
{
	unsigned int   version;
	unsigned int   symmAlgID;
	unsigned int   aSymmAlgID;					//SGD_SM4_ECB
	unsigned int   bits;
	unsigned char  encryptedPriKey [128];
	SM9EncMastPublicKey encMastPubKey;
unsigned int  userIDLen;
unsigned char userID[1024];
SM9Cipher pairCipher;
} SM9PairEncEnvelopedKey;

typedef struct SM9refPairSignEnvelopedKey_st
{
	unsigned int   version;
	unsigned int   symmAlgID; 
	unsigned int   aSymmAlgID;
	unsigned int   bits;
	unsigned char  encryptedPriKey [64];
	SM9SignMastPublicKey  encMastPubKey;
unsigned int  userIDLen;
unsigned char userID[1024];
SM9Cipher pairCipher;
} SM9PairSignEnvelopedKey;


#endif
