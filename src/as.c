/*
 ============================================================================
 Name        : as.c
 Author      : lsc
 Version     :
 Copyright   : R & D Center of Internet of Things Security
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include "as.h"

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

static int count = 1;  //作用：测试as运行fill_certificate_auth_resp_packet函数的次数

//访问user_table时要使用的信号量
pthread_mutex_t user_table_mutex;

/*************************************************

 Function:    // init_server_socket
 Description: // 初始化asu(扮演服务器角色)的server_socket
 Calls:       // socket API
 Called By:   // main();
 Input:	     //	无
 Output:      //	无
 Return:      // server_socket
 Others:      //

 *************************************************/
int init_server_socket()
{
	struct sockaddr_in server_addr;

	// 接收缓冲区
	int nRecvBuf = 32 * 1024; //设置为32K
	//发送缓冲区
	int nSendBuf = 32 * 1024; //设置为32K

	bzero(&server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htons(INADDR_ANY );
	server_addr.sin_port = htons(CHAT_SERVER_PORT);

	int server_socket = socket(AF_INET, SOCK_STREAM, 0);

	setsockopt(server_socket, SOL_SOCKET, SO_RCVBUF, (const BYTE *) &nRecvBuf,
			sizeof(int));
	setsockopt(server_socket, SOL_SOCKET, SO_SNDBUF, (const BYTE *) &nSendBuf,
			sizeof(int));

	if (server_socket < 0)
	{
		printf("Create Socket Failed!");
		exit(1);
	}

	if (bind(server_socket, (struct sockaddr*) &server_addr,
			sizeof(server_addr)))
	{
		printf("Server Bind Port : %d Failed!", CHAT_SERVER_PORT);
		exit(1);
	}

	if (listen(server_socket, 5))
	{
		printf("Server Listen Failed!");
		exit(1);
	}
	return server_socket;
}

int send_to_peer(int new_server_socket, BYTE *send_buffer, int send_len)
{

	int length = send(new_server_socket, send_buffer, send_len, 0);
//	printf("---- send %d bytes -----\n",length);
	printf("---------发送 %d 字节数据！---------\n", length);
	if (length < 0)
	{
		printf("Socket Send Data Failed Or Closed\n");
		close(new_server_socket);
		return FALSE;
	} else
		return TRUE;
}

int recv_from_peer(int new_server_socket, BYTE *recv_buffer, int recv_len)
{
	int length = recv(new_server_socket, recv_buffer, recv_len, MSG_WAITALL);

	if (length < 0)
	{
		printf("Receive Data From Server Failed\n");
		return FALSE;
	} else if (length < recv_len)
	{
		printf("Receive data from server less than required, %d bytes.\n",
				length);
		return FALSE;
	} else if (length > recv_len)
	{
		printf("Receive data from server more than required.\n");
		return FALSE;
	} else
	{
//		printf("receive data succeed, %d bytes.\n",length);
		printf("---------接收数据成功, 接收 %d 字节数据！---------\n", length);
		return TRUE;
	}

}



BOOL writeCertFile(int userID, BYTE buf[], int len)
{
	FILE *fp;
	char certname[40];
	memset(certname, '\0', sizeof(certname));//初始化certname,以免后面写入乱码到文件中

	if (userID == 0)
		sprintf(certname, "./cacert/cacert.pem");
	else if (userID == 1)
		//sprintf(certname, "./cert/usercert%d.pem", userID);
		sprintf(certname, "./cert/camerareceive.pem");
	else if (userID == 2)
		sprintf(certname, "./cert/nvrreceive.pem");
	//printf("cert file name: %s\n", certname);

	fp = fopen(certname, "w");
	if (fp == NULL)
	{
		printf("open cert file failed!\n");
		return FALSE;
	}

	fwrite(buf, 1, len, fp);
	printf("数字证书长度是 %d 字节\n", len);
	fclose(fp);
	printf("完成数字证书写入操作!\n");

	return TRUE;
}










/*************************************************

 Function:    // getpubkeyfromcert
 Description: // 从数字证书(PEM文件)中读取公钥
 Calls:       // openssl中读PEM文件的API
 Called By:   // fill_certificate_auth_resp_packet
 Input:	     //	用户证书的用户名certnum
 Output:      //	数字证书公钥
 Return:      // EVP_PKEY *pubKey
 Others:      // 用户证书的用户名certnum最好是用字符串形式，但是目前是int值，有待改进

 *************************************************/
EVP_PKEY *getpubkeyfromcert(int certnum)
{
	EVP_PKEY *pubKey;

	BIO * key = NULL;
	X509 * Cert = NULL; //X509证书结构体，保存CA证书
	key = BIO_new(BIO_s_file());

	char certname[60];
	memset(certname, '\0', sizeof(certname)); //初始化certname,以免后面写如乱码到文件中
	if (certnum == 0)
		sprintf(certname, "./cacerts/cacert.pem");
	else
		sprintf(certname, "./cert/usercert%d.pem", certnum);

	BIO_read_filename(key, certname);
	if (!PEM_read_bio_X509(key, &Cert, 0, NULL ))
	{
		/* Error 读取证书失败！*/
		printf("读取证书失败!\n");
		return NULL ;
	}

	pubKey = EVP_PKEY_new();
	//获取证书公钥
	pubKey = X509_get_pubkey(Cert);
	return pubKey;
}

/*************************************************

 Function:    // verify_sign
 Description: // 验证数字签名
 Calls:       // openssl验证签名的API
 Called By:   // fill_certificate_auth_resp_packet
 Input:	     //	input---待验证签名的整个数据包
 sign_input_len---待验证签名的有效数据字段的长度，并非整个input长度
 sign_value---签名字段
 sign_output_len---签名字段的长度
 pubKey---验证签名所使用的公钥
 Output:      //	验证签名结果，TRUE or FALSE
 Return:      // TRUE or FALSE
 Others:      // 注意sign_input_len字段并非整个input长度，这一点今后如果感觉不合适再修改

 *************************************************/

BOOL verify_sign(BYTE *input, int sign_input_len, BYTE * sign_value,
		unsigned int sign_output_len, EVP_PKEY * pubKey)
{
	EVP_MD_CTX mdctx;		 //摘要算法上下文变量

	EVP_MD_CTX_init(&mdctx); //初始化摘要上下文

	BYTE sign_input_buffer[10000];

	memcpy(sign_input_buffer, input, sign_input_len); //sign_inputLength为签名算法输入长度，为所传入分组的除签名字段外的所有字段

	if (!EVP_VerifyInit_ex(&mdctx, EVP_md5(), NULL))	//验证初始化，设置摘要算法，一定要和签名一致。
	{
		printf("EVP_VerifyInit_ex err\n");
//		EVP_PKEY_free(pubKey);//pubkey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
		return FALSE;
	}

	if (!EVP_VerifyUpdate(&mdctx, sign_input_buffer, sign_input_len))//验证签名（摘要）Update
	{
		printf("err\n");
//		EVP_PKEY_free(pubKey);//pubkey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
		return FALSE;
	}

	if (!EVP_VerifyFinal(&mdctx, sign_value, sign_output_len, pubKey))//验证签名（摘要）Update
	{
		printf("EVP_Verify err\n");
//		EVP_PKEY_free(pubKey);//pubkey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
		return FALSE;
	}
//	else
//	{
//		printf("验证签名正确!!!\n");
//	}
	//释放内存
//	EVP_PKEY_free(pubKey);//pubkey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
	EVP_MD_CTX_cleanup(&mdctx);
	return TRUE;
}

/*************************************************

 Function:    // X509_Cert_Verify
 Description: // X509证书验证
 Calls:       // openssl证书验证指令verify
 Called By:   // fill_certificate_auth_resp_packet
 Input:	     //	aecertnum---AE(NVR)数字证书编号
 asuecertnum---ASUE(摄像机或NVR客户端)数字证书编号
 Output:      //	AE和ASUE数字证书的验证结果
 Return:      // 宏AE_OK_ASUE_OK or AE_OK_ASUE_ERROR or AE_ERROR_ASUE_OK or AE_ERROR_ASUE_ERROR
 Others:      // 关于证书验证操作既可以使用verify指令，也可以使用X509_verify_cert函数来实现，但是目前测试着使用X509_verify_cert函数总是出错，还有待于进一步研究

 *************************************************/

int X509_Cert_Verify(int aecertnum, int asuecertnum)
{
	char tempcmd[200];
	FILE* fp;
	int i,j;

	char * ERRresult = "error";
	char * pae = NULL;
	char * pasue = NULL;

	//验证AE证书
	memset(tempcmd, '\0', sizeof(tempcmd)); //初始化buf,以免后面写如乱码到文件中
//	sprintf(tempcmd,
//			"openssl verify -CAfile ./cacert/cacert.pem -verbose ./cert/usercert%d.pem > X509_Cert_Verify_AE.txt",
//			aecertnum);
	sprintf(tempcmd,
			"openssl verify -CAfile ./cacert/cacert.pem -verbose ./cert/nvrreceive.pem > X509_Cert_Verify_AE.txt",
			aecertnum);

	system(tempcmd);
	memset(tempcmd, '\0', sizeof(tempcmd)); //初始化buf,以免后面写如乱码到文件中
	fp = fopen("X509_Cert_Verify_AE.txt", "rb");
	if (NULL == fp)
	{
		printf("reading the cert file failed!\n");
	}
	i = fread(tempcmd, 1, 200, fp);
	if (i != 0)
	{
		pae = strstr(tempcmd, ERRresult);
	}

	if ((i != 0) && (NULL == pae))
//	if (NULL == pae)
//		printf("验证AE证书正确！\n");
		printf("认证服务器验证网络硬盘录像机数字证书合法有效！\n");
	else
	{
//		printf("证书AE验证错误！\n");
		printf("认证服务器验证网络硬盘录像机数字证书非法无效！\n");
//		printf("错误信息：%s\n", tempcmd);
	}
	fclose(fp);

	//验证ASUE证书
	memset(tempcmd, '\0', sizeof(tempcmd)); //初始化buf,以免后面写如乱码到文件中
	sprintf(tempcmd,
			"openssl verify -CAfile ./cacert/cacert.pem -verbose ./cert/camerareceive.pem > X509_Cert_Verify_ASUE.txt",
			asuecertnum);
	system(tempcmd);
	memset(tempcmd, '\0', sizeof(tempcmd)); //初始化buf,以免后面写如乱码到文件中
	fp = fopen("X509_Cert_Verify_ASUE.txt", "rb");
	if (NULL == fp)
	{
		printf("reading the cert file failed!\n");
	}
	j = fread(tempcmd, 1, 200, fp);
	if (j != 0)
	{
		pasue = strstr(tempcmd, ERRresult);
	}


	if ((j != 0) && (NULL == pasue))
//	if (NULL == pasue)
//		printf("ASU验证ASUE证书正确！\n");
		printf("认证服务器验证摄像机数字证书合法有效！\n");
	else
	{
//		printf("ASU证书ASUE验证错误！\n");
		printf("认证服务器验证摄像机数字证书非法无效！\n");
		printf("摄像机数字证书验证错误信息：%s", tempcmd);
	}
	fclose(fp);

//	printf("ASU验证AE、ASUE证书结束!!!\n");
	printf("认证服务器完成网络硬盘录像机、摄像机数字证书验证操作，“三元对等身份认证”过程结束\n");
	printf("认证服务器开始封装【证书认证响应分组】(认证服务器->网络硬盘录像机)\n");

	if ((NULL == pae) && (i != 0) && (NULL == pasue) && (j != 0))
		return AE_OK_ASUE_OK;      //AE和ASUE证书验证都正确
	else if (((NULL == pae) && (i != 0)) && (((NULL != pasue) && (j != 0)) || ((NULL == pasue) && (j == 0))))
		return AE_OK_ASUE_ERROR;   //AE证书验证正确，ASUE证书验证错误
	else if (((NULL != pae) && (i != 0)) || (((NULL == pae) && (i == 0)) && ((NULL == pasue) && (j != 0))))
		return AE_ERROR_ASUE_OK;   //AE证书验证错误，ASUE证书验证正确
	else if ((((NULL != pae) && (i != 0)) || ((NULL == pae) && (i == 0))) && (((NULL != pasue) && (j != 0)) || ((NULL == pasue) && (j == 0))))
		return AE_ERROR_ASUE_ERROR;   //AE证书验证错误，ASUE证书验证错误
//	else
//		return AE_ERROR_ASUE_ERROR;
}

/*************************************************

 Function:    // getprivkeyfromprivkeyfile
 Description: // CA(驻留在ASU中)从cakey.pem中提取CA的私钥，以便后续进行ASU的签名
 Calls:       // openssl读取私钥PEM文件相关函数
 Called By:   // fill_certificate_auth_resp_packet
 Input:	     //	无
 Output:      //	CA(驻留在ASU中)的私钥
 Return:      // EVP_PKEY *privKey
 Others:      //

 *************************************************/

EVP_PKEY * getprivkeyfromprivkeyfile(int userID)
{
	EVP_PKEY * privKey;
	FILE* fp;
	RSA* rsa;

	char keyname[40];

	if (userID == 0)
		sprintf(keyname, "./private/cakey.pem");                   //asu密钥文件
	else
		sprintf(keyname, "./private/userkey%d.pem", userID);       //ae或asue密钥文件
	fp = fopen(keyname, "r");

	if (NULL == fp)
	{
		fprintf(stderr, "Unable to open %s for RSA priv params\n",
				"./pricate/cakey.pem");
		return NULL ;
	}

	rsa = RSA_new();
	if ((rsa = PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL )) == NULL )
	{
		fprintf(stderr, "Unable to read private key parameters\n");
		return NULL ;
	}
	fclose(fp);

	// print
//	printf("Content of CA's Private key PEM file\n");
//	RSA_print_fp(stdout, rsa, 0);
//	printf("\n");

	privKey = EVP_PKEY_new();
	if (EVP_PKEY_set1_RSA(privKey, rsa) != 1) //保存RSA结构体到EVP_PKEY结构体
	{
		printf("EVP_PKEY_set1_RSA err\n");
		RSA_free(rsa);
		return NULL ;
	}
	else
	{
		RSA_free(rsa);
		return privKey;
	}
}

/*************************************************

 Function:    // gen_sign
 Description: // 生成数字签名
 Calls:       // openssl生成签名的API
 Called By:   // fill_certificate_auth_resp_packet
 Input:	     //	input---待生成签名的整个数据包(分组)
 sign_input_len---待生成签名的有效数据字段的长度，并非整个input长度
 sign_value---保存生成的字段
 sign_output_len---生成的签名字段的长度
 privKey---生成签名所使用的私钥
 Output:      //	生成签名操作结果，TRUE or FALSE
 Return:      // TRUE or FALSE
 Others:      // 注意sign_input_len字段并非整个input长度，这一点今后如果感觉不合适再修改

 *************************************************/

BOOL gen_sign(BYTE * input, int sign_input_len, BYTE * sign_value,
		unsigned int *sign_output_len, EVP_PKEY * privKey)
{
	EVP_MD_CTX mdctx;						//摘要算法上下文变量

	unsigned int temp_sign_len;
	unsigned int i;
	BYTE sign_input_buffer[10000];

	memcpy(sign_input_buffer, input, sign_input_len); //sign_inputLength为签名算法输入长度，为所传入分组的除签名字段外的所有字段

	//以下是计算签名代码
	EVP_MD_CTX_init(&mdctx);				//初始化摘要上下文

	if (!EVP_SignInit_ex(&mdctx, EVP_md5(), NULL))	//签名初始化，设置摘要算法，本例为MD5
	{
		printf("err\n");
//		EVP_PKEY_free (privKey);//privKey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
		return FALSE;
	}

	if (!EVP_SignUpdate(&mdctx, sign_input_buffer, sign_input_len))	//计算签名（摘要）Update
	{
		printf("err\n");
//		EVP_PKEY_free (privKey);//privKey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同;
		return FALSE;
	}

	if (!EVP_SignFinal(&mdctx, sign_value, &temp_sign_len, privKey))	//签名输出
	{
		printf("err\n");
//		EVP_PKEY_free (privKey);//privKey只是作为参数传进来，其清理内存留给其调用者完成，这一点与参考程序不同
		return FALSE;
	}

	*sign_output_len = temp_sign_len;

//	printf("签名值是: \n");
//	for (i = 0; i < * sign_output_len; i++)
//	{
//		if (i % 16 == 0)
//			printf("\n%08xH: ", i);
//		printf("%02x ", sign_value[i]);
//	}
//	printf("\n");
	//清理内存
	EVP_MD_CTX_cleanup(&mdctx);
	return TRUE;
}

BOOL getCertData(int userID, BYTE buf[], int *len)
{
	FILE *fp;
	char certname[40];
	memset(certname, '\0', sizeof(certname));	//初始化certname,以免后面写如乱码到文件中

	if (userID == 0)
		sprintf(certname, "./cacert/cacert.pem");
	else
		sprintf(certname, "./cert/usercert%d.pem", userID);       //eclipse调试或运行

//	printf("cert file name: %s\n", certname);

	fp = fopen(certname, "rb");
	if (fp == NULL )
	{
		printf("reading the cert file failed!\n");
		return FALSE;
	}
	*len = fread(buf, 1, 5000, fp);
//	printf("cert's length is %d\n", *len);
	fclose(fp);
//	printf("将证书保存到缓存buffer成功!\n");

	return TRUE;
}

/*************************************************

 Function:    // fill_certificate_auth_resp_packet
 Description: // 按照认证协议中的证书认证响应分组格式来填充分组
 Calls:       // getpubkeyfromcert，verify_sign，X509_Cert_Verify，getprivkeyfromprivkeyfile，gen_sign
 Called By:   // fill_certificate_auth_resp_packet
 Input:	     //	input---待生成签名的整个数据包(分组)
 sign_input_len---待生成签名的有效数据字段的长度，并非整个input长度
 sign_value---保存生成的字段
 sign_output_len---生成的签名字段的长度
 privKey---生成签名所使用的私钥
 Output:      //	生成签名操作结果，TRUE or FALSE
 Return:      // TRUE or FALSE
 Others:      //

 *************************************************/

int fill_certificate_auth_resp_packet(certificate_auth_requ *recv_certificate_auth_requ_buffer,
		                              certificate_auth_resp *send_certificate_auth_resp_buffer)
{
	//certificate_auth_resp certificate_auth_resp_buffer;    //待填充及发送的证书认证响应分组
	EVP_PKEY *aepubKey = NULL;
//	BYTE *pTmp = NULL;
//	int aepubkeyLen;
//	int i;
	int CertVerifyResult;
	//BYTE deraepubkey[1024];

	EVP_PKEY * privKey;
	int asue_ID = 1;
	int ae_ID = 2;

	BYTE cervalresasusign[1024];			     //保存ASU服务器对证书验证结果字段的签名值的数组
	unsigned int cervalresasusignlen;           //保存ASU服务器对证书验证结果字段的签名值数组的长度

	BYTE cerauthrespasusign[1024];			 //保存ASU服务器对整个证书认证响应分组(除本字段外)的签名值的数组
	unsigned int cerauthrespasusignlen;    //保存ASU服务器对整个证书认证响应分组(除本字段外)的签名值数组的长度

	BYTE cert_buffer[5000];
	int cert_len = 0;
	int aecertcheck, asuecertcheck;

	//2号证书文件-ae数字证书文件，
	//今后需要根据recv_certificate_auth_requ_buffer->staasuecer.cer_identify字段值来提取证书文件的编号等信息
	aepubKey = getpubkeyfromcert(2);
	if (aepubKey == NULL )
	{
		printf("getpubkeyfromcert.....failed!\n");
		return FALSE;
	}

//	//打印ae公钥，可删除-----begin------
//	pTmp = deraepubkey;
//	//把证书公钥转换为DER编码的数据，以方便打印(aepubkey结构体不方便打印)
//	aepubkeyLen = i2d_PublicKey(aepubKey, &pTmp);
//	printf("ae's PublicKey is: \n");
//	for (i = 0; i < aepubkeyLen; i++)
//	{
//		printf("%02x", deraepubkey[i]);
//	}
//	printf("\n");
//	//打印ae公钥，可删除--------end-------

	//验证AE(NVR)的签名
	if (verify_sign((BYTE *) recv_certificate_auth_requ_buffer,
			sizeof(certificate_auth_requ) - sizeof(sign_attribute),
			recv_certificate_auth_requ_buffer->aesign.sign.data,
			recv_certificate_auth_requ_buffer->aesign.sign.length, aepubKey))
	{
		printf("认证服务器验证网络硬盘录像机的【证书认证请求分组】签名字段正确!!!\n");
		EVP_PKEY_free(aepubKey);
	}
	else
		return FALSE;

	//填充wai_packet_head
	send_certificate_auth_resp_buffer->wai_packet_head.version = 1;
	send_certificate_auth_resp_buffer->wai_packet_head.type = 1;
	send_certificate_auth_resp_buffer->wai_packet_head.subtype = CERTIFICATE_AUTH_RESP;
	send_certificate_auth_resp_buffer->wai_packet_head.reserved = 0;
	send_certificate_auth_resp_buffer->wai_packet_head.length = sizeof(certificate_auth_resp);
	send_certificate_auth_resp_buffer->wai_packet_head.packetnumber = 4;
	send_certificate_auth_resp_buffer->wai_packet_head.fragmentnumber = 0;
	send_certificate_auth_resp_buffer->wai_packet_head.identify = 0;

	//填充ADDID
	bzero((send_certificate_auth_resp_buffer->addid.mac1),
			sizeof(send_certificate_auth_resp_buffer->addid.mac1));
	bzero((send_certificate_auth_resp_buffer->addid.mac2),
			sizeof(send_certificate_auth_resp_buffer->addid.mac2));

	//填充证书验证结果字段
	send_certificate_auth_resp_buffer->cervalidresult.type = 2; /* 证书验证结果属性类型 (2)*/
	send_certificate_auth_resp_buffer->cervalidresult.length = sizeof(certificate_valid_result);
	memcpy(send_certificate_auth_resp_buffer->cervalidresult.random1,
			recv_certificate_auth_requ_buffer->aechallenge,
			sizeof(recv_certificate_auth_requ_buffer->aechallenge));
	memcpy(send_certificate_auth_resp_buffer->cervalidresult.random2,
			recv_certificate_auth_requ_buffer->asuechallenge,
			sizeof(recv_certificate_auth_requ_buffer->asuechallenge));

	//ASU读取自己保存的证书文件夹中的ASUE证书，并与接收到的证书认证请求分组中的ASUE证书字段比对是否一致，若一致将证书认证请求分组中的ASUE证书字段复制到证书认证响应分组中的证书认证结果结构体中的相应字段
	memset(cert_buffer, 0, sizeof(cert_buffer));
	if (!getCertData(1, cert_buffer, &cert_len)) //先读取ASUE证书，"./newcerts/usercert1.pem"
	{
		printf("将ASUE证书保存到缓存buffer失败!");
		return FALSE;
	}

	writeCertFile(asue_ID, (BYTE *)recv_certificate_auth_requ_buffer->staasuecer.cer_X509, (int)recv_certificate_auth_requ_buffer->staasuecer.cer_length);
	writeCertFile(ae_ID, (BYTE *)recv_certificate_auth_requ_buffer->staaecer.cer_X509, (int)recv_certificate_auth_requ_buffer->staaecer.cer_length);

	asuecertcheck = strncmp((char *) cert_buffer,(char *) (recv_certificate_auth_requ_buffer->staasuecer.cer_X509),cert_len);
	if (asuecertcheck == 0)
	{
		memcpy(&(send_certificate_auth_resp_buffer->cervalidresult.certificate1),
			   &(recv_certificate_auth_requ_buffer->staasuecer),
			   sizeof(certificate));
	}

	//ASU读取自己保存的证书文件夹中的AE证书，并与接收到的证书认证请求分组中的AE证书字段比对是否一致，若一致将证书认证请求分组中的AE证书字段复制到证书认证响应分组中的证书认证结果结构体中的相应字段
	memset(cert_buffer, 0, sizeof(cert_buffer));
	if (!getCertData(2, cert_buffer, &cert_len)) //先读取AE证书，"./newcerts/usercert2.pem"
	{
		printf("将AE证书保存到缓存buffer失败!");
		return FALSE;
	}

	aecertcheck = strncmp((char *) cert_buffer,(char *) (recv_certificate_auth_requ_buffer->staaecer.cer_X509),cert_len);
	if (aecertcheck == 0)
	{
		memcpy(&(send_certificate_auth_resp_buffer->cervalidresult.certificate2),&(recv_certificate_auth_requ_buffer->staaecer),sizeof(certificate));
	}

	if ((asuecertcheck == 0) && (aecertcheck == 0))
	{
		//验证AE和ASUE的数字证书
		//X509_Cert_Verify(int aecertnum, int asuecertnum)
		//aecertnum = 2;asuecertnum = 1
		//今后需要根据recv_certificate_auth_requ_buffer->staasuecer.cer_identify字段值来提取证书文件的编号等信息
		CertVerifyResult = X509_Cert_Verify(2, 1);
		//根据证书验证结果来设置send_certificate_auth_resp_buffer->cervalidresult.cerresult1和send_certificate_auth_resp_buffer->cervalidresult.cerresult2字段值
		//证书验证结果除了有效和无效大的分类外，还应有具体的说明，这一点有待细化修改！
		if (CertVerifyResult == AE_OK_ASUE_OK)
		{
			send_certificate_auth_resp_buffer->cervalidresult.cerresult1 = 0; //ASUE证书验证正确有效
			send_certificate_auth_resp_buffer->cervalidresult.cerresult2 = 0; //AE证书验证正确有效
		}
	}
	else if ((asuecertcheck != 0) && (aecertcheck == 0))
	{
		CertVerifyResult = X509_Cert_Verify(2, 1);
		//根据证书验证结果来设置send_certificate_auth_resp_buffer->cervalidresult.cerresult1和send_certificate_auth_resp_buffer->cervalidresult.cerresult2字段值
		//证书验证结果除了有效和无效大的分类外，还应有具体的说明，这一点有待细化修改！
		if (CertVerifyResult == AE_OK_ASUE_ERROR)
		{
			send_certificate_auth_resp_buffer->cervalidresult.cerresult1 = 1; //ASUE证书验证错误无效
			send_certificate_auth_resp_buffer->cervalidresult.cerresult2 = 0; //AE证书验证正确有效
		}

	}
	else if ((asuecertcheck == 0) && (aecertcheck != 0))
	{
		CertVerifyResult = X509_Cert_Verify(2, 1);
		//根据证书验证结果来设置send_certificate_auth_resp_buffer->cervalidresult.cerresult1和send_certificate_auth_resp_buffer->cervalidresult.cerresult2字段值
		//证书验证结果除了有效和无效大的分类外，还应有具体的说明，这一点有待细化修改！
		if (CertVerifyResult == AE_ERROR_ASUE_OK)
		{
			send_certificate_auth_resp_buffer->cervalidresult.cerresult1 = 0; //ASUE证书验证正确有效
			send_certificate_auth_resp_buffer->cervalidresult.cerresult2 = 1; //AE证书验证错误无效
		}

	}
	else if ((asuecertcheck != 0) && (aecertcheck != 0))
	{
		CertVerifyResult = X509_Cert_Verify(2, 1);
		//根据证书验证结果来设置send_certificate_auth_resp_buffer->cervalidresult.cerresult1和send_certificate_auth_resp_buffer->cervalidresult.cerresult2字段值
		//证书验证结果除了有效和无效大的分类外，还应有具体的说明，这一点有待细化修改！
		if (CertVerifyResult == AE_ERROR_ASUE_ERROR)
		{
			send_certificate_auth_resp_buffer->cervalidresult.cerresult1 = 1; //ASUE证书验证正确有效
			send_certificate_auth_resp_buffer->cervalidresult.cerresult2 = 1; //AE证书验证错误无效
		}
	}

	//ASU使用CA的私钥(cakey.pem)来生成对证书验证结果字段的签名和对整个证书认证响应分组(除本字段外)的签名
	privKey = getprivkeyfromprivkeyfile(0); //0号密钥文件-CA(驻留在asu中)的密钥文件 "./private/cakey.pem"
	if (NULL == privKey)
	{
		printf("getprivkeyitsself().....failed!\n");
	}

	//ASU服务器对证书验证结果字段的签名
	if (!gen_sign((BYTE *) &(send_certificate_auth_resp_buffer->cervalidresult),
			sizeof(send_certificate_auth_resp_buffer->cervalidresult),
			cervalresasusign, &cervalresasusignlen, privKey))
	{
		printf("ASU服务器对证书验证结果字段的签名失败！");
	}
	send_certificate_auth_resp_buffer->cervalresasusign.sign.length =
			cervalresasusignlen;
	memcpy(send_certificate_auth_resp_buffer->cervalresasusign.sign.data,
			cervalresasusign, cervalresasusignlen);

	//ASU服务器对整个证书认证响应分组(除本字段外)的签名
	if (!gen_sign((BYTE *) send_certificate_auth_resp_buffer,
			send_certificate_auth_resp_buffer->wai_packet_head.length
					- sizeof(send_certificate_auth_resp_buffer->cerauthrespasusign),
			cerauthrespasusign, &cerauthrespasusignlen, privKey))
	{
		printf("ASU服务器对整个证书认证响应分组(除本字段外)的签名失败！");
	}
	send_certificate_auth_resp_buffer->cerauthrespasusign.sign.length =
			cerauthrespasusignlen;
	memcpy(send_certificate_auth_resp_buffer->cerauthrespasusign.sign.data,
			cerauthrespasusign, cerauthrespasusignlen);

	EVP_PKEY_free(privKey);

	//利用全局变量count来打印ASU中的fill_certificate_auth_resp_packet函数运行的次数，该部分打印如感觉没必要可删除
	printf("认证服务器中的【证书认证响应分组】生成函数运行的次数为第%d次！\n", count);

	printf("*******************\n");
	count++;

	return TRUE;

}

void process_request(int client_ae_socket, BYTE * recv_buffer,int recv_buffer_len)
{
	certificate_auth_resp send_certificate_auth_resp_buffer;

	certificate_auth_requ recv_certificate_auth_requ_buffer;

	BYTE subtype;
	BYTE send_buffer[15000];

	subtype = *(recv_buffer + 3);   //WAI协议分组基本格式包头的第三个字节是分组的subtype字段，用来区分不同的分组

	switch (subtype)
	{
	case CERTIFICATE_AUTH_REQU:
		bzero((BYTE *) &send_certificate_auth_resp_buffer,
				sizeof(send_certificate_auth_resp_buffer));
		bzero((BYTE *) &recv_certificate_auth_requ_buffer,
				sizeof(recv_certificate_auth_requ_buffer));
		memcpy(&recv_certificate_auth_requ_buffer, recv_buffer,
				sizeof(certificate_auth_requ));

		if (!(fill_certificate_auth_resp_packet(
				&recv_certificate_auth_requ_buffer,
				&send_certificate_auth_resp_buffer)))
		{
			printf("fill certificate auth resp packet failed!\n");
		}
		memcpy(send_buffer, &send_certificate_auth_resp_buffer,sizeof(certificate_auth_resp));
		break;
//	case XXX:其他case留作以后通信分组使用
//		XXX---其他case处理语句
//		break;
	}
	send_to_peer(client_ae_socket, send_buffer, sizeof(certificate_auth_resp));
}

void * talk_to_ae(void * new_asu_server_socket_to_client_ae)
{
	int recv_buffer_len;
	int new_asu_server_socket = (int) new_asu_server_socket_to_client_ae;

	BYTE recv_buffer[15000];

	memset(recv_buffer, 0, sizeof(recv_buffer));

//	printf("sizeof(certificate_auth_requ)=%d\n",sizeof(certificate_auth_requ));
	recv_buffer_len = recv_from_peer(new_asu_server_socket, recv_buffer,
			sizeof(certificate_auth_requ));

	//recv_buffer_len = recv(new_asu_server_socket, recv_buffer,sizeof(recv_buffer), 0);//MSG_WAITALL

//	printf("\n-----------------\n");
	/*

	 printf("server receive %d data from client!!!!!!!\n",recv_buffer_len);

	 if (recv_buffer_len == 9586)
	 {
	 printf("服务器接收到客户端%d字节的有效证书认证请求分组数据包\n", recv_buffer_len);
	 }
	 */
	printf("*******************\n");

	if (recv_buffer_len < 0)
	{
		printf("Server Recieve Data Failed!\n");
		close(new_asu_server_socket);
		pthread_exit(NULL );
	}
	if (recv_buffer_len == 0)
	{
		close(new_asu_server_socket);
		pthread_exit(NULL );
	}

	process_request(new_asu_server_socket, recv_buffer, recv_buffer_len);

	close(new_asu_server_socket);
	pthread_exit(NULL );

}

int main(int argc, char **argv)
{
	OpenSSL_add_all_algorithms();

	//**************************************演示清单第二部分WAPI的WAI认证过程演示 begin***************************************************
	pthread_mutex_init(&user_table_mutex, NULL );
	int asu_server_socket = init_server_socket();

	pthread_t child_thread;
	pthread_attr_t child_thread_attr;
	pthread_attr_init(&child_thread_attr);
	pthread_attr_setdetachstate(&child_thread_attr, PTHREAD_CREATE_DETACHED);

	while (1)
	{
		struct sockaddr_in client_addr;
		socklen_t length = sizeof(client_addr);
		int new_asu_server_socket = accept(asu_server_socket,
				(struct sockaddr*) &client_addr, &length);
		if (new_asu_server_socket < 0)
		{
			printf("Server Accept Failed!\n");
			break;
		}
		if (pthread_create(&child_thread, &child_thread_attr, talk_to_ae,
				(void *) new_asu_server_socket) < 0)
			printf("pthread_create Failed : %s\n", strerror(errno));
	}
	//**************************************演示清单第二部分WAPI的WAI认证过程演示 end***************************************************
	return 0;
}

