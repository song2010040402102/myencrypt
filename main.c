#include <unistd.h>
#include <termios.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <string.h>
#include <readline/readline.h>
#include <readline/history.h>

#define OBJECT_MAX 64
#define PASSWD_MAX 256

#define TTY_TIP_ED (g_bDecode? "解密":"加密") //加密解密提示

#define BEGIN_TTY_PASSWD struct termios initial_settings, new_settings;\
	FILE* in = fopen("/dev/tty", "r");\
if(in)\
{\
	tcgetattr(fileno(in), &initial_settings);\
	new_settings = initial_settings;\
	new_settings.c_lflag &= ~ECHO;\
	tcsetattr(fileno(in), TCSANOW, &new_settings);\
}

#define END_TTY_PASSWD  if(in)\
{\
	tcsetattr(fileno(in), TCSANOW, &initial_settings);\
}\

//加密信息，写入加密文件头
typedef struct _encrypt_info
{
	unsigned char type; //文件类型，0：目录，1：文件
	char passwd[PASSWD_MAX]; //密码

}ENCRYPT_INFO, *PENCRYPT_INFO;

bool g_bDecode = false; //是否解密 

//判断一个文件是文件还是目录
bool IsDir(const char *file)
{
	if(!file)
	  return false;

	struct stat st;
	stat(file, &st);
	if(S_ISDIR(st.st_mode))
	  return true;
	return false;
}

//判断输入的文件/目录是否存在
bool IsLegalAndExist(const char *file)
{
	if(!file)
	  return false;

	if(IsDir(file))
	{
		//判断目录是否存在
		if(opendir(file))
		  return true;		
	}
	else
	{
		//判断文件是否存在
		if(access(file, F_OK) == 0)
		  return true;
	}
	return false;
}

void PreprocessObject(char *object)
{
	if(!object)
	  return;
	
	//去除末尾的空格
	int len = strlen(object)-1;
	while(len >= 0)
	{
		if(object[len] == ' ')
		  object[len--] = '\0';
		else
		  break;
	}

	//替换用户名
	if(object[0] == '~')
	{		
		char *home = getenv("HOME");
		if(home)
		{
			char temp[PATH_MAX] = {0};
			strcpy(temp, &object[1]);
			strcpy(object, home);
			strcat(object, temp);
		}
	}
}

//读取密码信息
bool ReadEncryptInfo(const char *file, ENCRYPT_INFO *pEncryptInfo)
{
	if(!file || !pEncryptInfo)
	  return false;

	FILE *pFile = fopen(file, "r");
	if(pFile)
	{
		int nRead = fread(pEncryptInfo, sizeof(ENCRYPT_INFO), 1, pFile);
		if(nRead == 1)
		{
			fclose(pFile);
			return true;
		}
		fclose(pFile);
	}

	return false;
}

//写入加密信息
bool WriteEncryptInfo(const char *file, ENCRYPT_INFO *pEncryptInfo)
{
	if(!file || !pEncryptInfo)
	  return false;

	FILE *pFile = fopen(file, "w");
	if(pFile)
	{
		int nWrite = fwrite(pEncryptInfo, sizeof(ENCRYPT_INFO), 1, pFile);
		if(nWrite == 1)
		{
			fclose(pFile);
			return true;
		}
		fclose(pFile);
	}
	return false;
}

//判断是否已经存在加密对象
bool IsExistForDstObj(const char *object, char *dstObject, bool bEncrypt)
{
	if(bEncrypt)
	{
		strcpy(dstObject, object);
		strcat(dstObject, ".me");
	}
	else
	{
		strcpy(dstObject, object);
		strcat(dstObject, ".em");
	}
	return IsLegalAndExist(dstObject);
}

//自动补全的输入
char *gets_ex(char *s)
{
	if(!s)
	  return NULL;

	char *ret = NULL;
	ret = readline("");
	if(ret)
	{
		if(*ret)
		{
			add_history(ret);			
		}
		strcpy(s, ret);
		free(ret);
		return s;
	}
	return NULL;
}

//打包文件
void PackFile(const char *file1, char *file2)
{
	if(!file1 || !file2)
	  return;

	char command[1024] = {0};
	sprintf(command, "tar -cf %s %s", file2, file1);
	printf("system command: %s\n", command);
	int ret = system(command);
	if(WIFSIGNALED(ret) && (WTERMSIG(ret) == SIGINT || WTERMSIG(ret) == SIGQUIT))
	{
		//如果子进程接受到终止命令则结束当前进程
		_exit(ret);
	}
}

//解包文件
void UnpackFile(const char *file1, char *file2)
{
	if(!file1 || !file2)
	  return;

	char command[1024] = {0};
	sprintf(command, "tar -xf %s", file1);
	printf("system command: %s\n", command);
	int ret = system(command);
	if(WIFSIGNALED(ret) && (WTERMSIG(ret) == SIGINT || WTERMSIG(ret) == SIGQUIT))
	{
		//如果子进程接受到终止命令则结束当前进程
		_exit(ret);
	}
}

//加密对象
void EncryptObject(const char *object1, const char *object2, const ENCRYPT_INFO *pEncryptInfo, bool bEncrypt)
{
	if(!object1 || !object2 || !pEncryptInfo)
	  return;

	FILE *file1 = fopen(object1, "r");
	FILE *file2 = fopen(object2, "w");
	if(!file1 || !file2)
	{
		printf("warning: %s -> %s encrypt failed\n", object1, object2);
		return;
	}

	if(bEncrypt)
	{
		//写入加密信息
		fwrite(pEncryptInfo, sizeof(ENCRYPT_INFO), 1, file2);
	}
	else
	{
		//读取加密信息
		ENCRYPT_INFO encrypt_info;
		memset(&encrypt_info, 0, sizeof(ENCRYPT_INFO));
		fread(&encrypt_info, sizeof(ENCRYPT_INFO), 1, file1);
		if(strcmp(encrypt_info.passwd, pEncryptInfo->passwd) != 0)
		{
			printf("warning: %s password wrong\n", object1);
			goto EndEncrypt;
		}
	}

	while(1)
	{
		int nRead = 0, nWrite = 0;
		char buf[1024] = {0};

		//读取1K的数据
		while(1)
		{
			int n = fread(buf+nRead, 1, 1024-nRead, file1);
			nRead += n;
			if(nRead == 1024 || n == 0)
			{
				break;
			}
		}
		if(nRead == 0)
		{
			//文件指针到达文件尾部则退出
			break;
		}

		//与密码去异或
		int index = 0;
		int nPsdLen = strlen(pEncryptInfo->passwd);
		for(;index < nRead; index++)
		{
			buf[index] ^= pEncryptInfo->passwd[index%nPsdLen];
		}

		//写入加密后的数据
		while(1)
		{
			int n = fwrite(buf+nWrite, 1, nRead-nWrite, file2);
			nWrite += n;
			if(nWrite == nRead)
			{
				break;
			}
			if(n == 0)
			{
				printf("warning: %s, write wrong\n", object2);
				goto EndEncrypt;
			}
		}
	}

EndEncrypt:
	fclose(file1);
	fclose(file2);
}

//加密目录
void EncryptDir(char *dir, char *passwd, bool bEncrypt)
{
	if(!dir || !passwd)
	  return;

	//先判断是否已存在加密后的文件
	char dstDir[PATH_MAX] = {0};
	if(IsExistForDstObj(dir, dstDir, bEncrypt))
	{
		printf("warning: %s, existed, will be ignored\n", dstDir);
		return;
	}

	//构造临时对象
	char tempObject[PATH_MAX] = {0}; 
	sprintf(tempObject, "/tmp/%d.tar", (int)time(NULL));

	//构造加密信息
	ENCRYPT_INFO encrypt_info;
	encrypt_info.type = 0;
	strcpy(encrypt_info.passwd, passwd);
	if(bEncrypt)
	{
		//如果是加密目录，则先打包后加密

		//打包目录
		PackFile(dir, tempObject);

		//加密打包文件
		EncryptObject(tempObject, dstDir,&encrypt_info, bEncrypt);

		//删除打包文件
		unlink(tempObject);
	}
	else
	{
		//如果是解密目录，则先解密后解包

		//解密打包文件
		EncryptObject(dir, tempObject, &encrypt_info, bEncrypt);		

		//解包目录
		UnpackFile(tempObject, dstDir);

		//删除解密后的打包文件
		unlink(tempObject);
	}
}

//加密文件
void EncryptFile(const char *file, const char *passwd, bool bEncrypt)
{
	if(!file || !passwd)
	  return;

	//先判断是否已存在加密后的文件
	char dstFile[PATH_MAX] = {0};
	if(IsExistForDstObj(file, dstFile, bEncrypt))
	{
		printf("warning: %s, existed, will be ignored\n", dstFile);
		return;
	}

	//加密文件
	ENCRYPT_INFO encrypt_info;
	encrypt_info.type = 1;
	strcpy(encrypt_info.passwd, passwd);
	EncryptObject(file, dstFile, &encrypt_info, bEncrypt);
}

//批量加密/解密
void DoEncrypt(char (*object)[PATH_MAX], int nCount, char *passwd, bool bEncrypt)
{
	if(!object || nCount <= 0 || !passwd)
	  return;

	int index = 0;
	for(;index < nCount; index++)
	{
		printf("%s, encrypting...\n", object[index]);
		if(IsDir(object[index]))
		{
			if(bEncrypt)
			{
				EncryptDir(object[index], passwd, bEncrypt);
			}
			else
			{
				printf("warning: %s, invalid object for decoding\n", object[index]);
				continue;
			}
		}				
		else
		{
			if(bEncrypt)
			{
				EncryptFile(object[index], passwd, bEncrypt);
			}
			else
			{
				ENCRYPT_INFO encrypt_info;
				memset(&encrypt_info, 0, sizeof(ENCRYPT_INFO));
				ReadEncryptInfo(object[index], &encrypt_info);
				if(encrypt_info.type == 0)
				{
					EncryptDir(object[index], passwd, bEncrypt);
				}
				else
				{
					EncryptFile(object[index], passwd, bEncrypt);
				}
			}
		}
	}
}

//打印版本信息
void PrintVerInfo()
{
	printf("myEncrypt1.0\n");
}

int main(int argc, char *argv[])
{	
	int nCount = 0; //要加密/解密的对象个数
	char object[OBJECT_MAX][PATH_MAX] = {0}; //要加密/解密的对象列表
	char passwd[PASSWD_MAX] = {0};	//密码

	bool bPrintVer = false; //是否打印版本信息

	int opt = 0;
	while((opt = getopt(argc, argv, ":p:dv")) != -1)
	{
		switch(opt)
		{
		  case 'p':
			  strcpy(passwd, optarg);
			  break;
		  case 'd':
			  g_bDecode = true;
			  break;
		  case 'v':
			  bPrintVer = true;
			  break;
		  case ':':
			  printf("warning: option -%c need a value!\n", optopt);
			  break;
		  case '?':
			  printf("warning: unknown option %c\n", optopt);
			  break;
		  default:
			  printf("warning: unknown option %c\n", opt);
			  break;

		}
	}

	if(bPrintVer)
	{
		PrintVerInfo();	
	}

	//从命令行获取有效的加密/解密的对象
	int index = optind;
	for(; index < argc; index++)
	{
		if(nCount >= OBJECT_MAX)
		{
			printf("warning: 已超出最大%s的数量, %d\n", TTY_TIP_ED, OBJECT_MAX);
			break;
		}

		//判断文件名或路径名是否有效并存在
		if(IsLegalAndExist(argv[index]))
		{
			strcpy(object[nCount++], argv[index]);
		}
		else
		{
			printf("warning: %s, a invalid filename or directory, will be ignored\n", argv[index]);
		}
	}

	if(nCount == 0)
	{
		//如果用户在命令行没有输入有效的文件名或目录，则提示用户继续输入
		printf("请输入要%s的文件或目录，多个文件或目录请分行输入，确定请输入回车\n", TTY_TIP_ED);
		while(1)
		{
			char cInput[PATH_MAX] = {0};
			if(!gets_ex(cInput))
			{
				printf("warning: system function-gets failed, will be ignored\n");
				continue;
			}

			if(cInput[0] == '\0')
			{
				//输入回车则退出当前输入循环
				break;
			}

			if(nCount >= OBJECT_MAX)
			{
				printf("warning: 已超出最大%s的数量, %d\n", TTY_TIP_ED, OBJECT_MAX);
			}
			else
			{
				PreprocessObject(cInput);
				if(IsLegalAndExist(cInput))
				{
					strcpy(object[nCount++], cInput);
				}
				else
				{
					printf("warning: %s, a invalid filename or directory, will be ignored\n", cInput);
				}
			}
		}		
	}

	if(nCount == 0)
	{
		//如果依然没有有效的加密/解密的对象，则退出程序
		printf("error: 未获取到有效的%s文件或目录\n", TTY_TIP_ED);
		return 0;
	}

	if(g_bDecode)
	{
		//如果是解密，则判断被解密的对象密码是否一致
		int nValidIndex[OBJECT_MAX] = {0};
		ENCRYPT_INFO encrypt_info;
		memset(&encrypt_info, 0, sizeof(ENCRYPT_INFO));
		int index = 0;
		for(;index < nCount; index++)
		{
			if(ReadEncryptInfo(object[index], &encrypt_info))
			{
				break;
			}
			else
			{
				nValidIndex[index] = 1;
				printf("warning: %s, invalid file format, will be ignored\n", object[index]);				
			}
		}
		for(;index < nCount; index++)
		{
			ENCRYPT_INFO temp_encry_info;
			memset(&temp_encry_info, 0, sizeof(ENCRYPT_INFO));
			if(ReadEncryptInfo(object[index], &temp_encry_info))
			{
				if(strcmp(temp_encry_info.passwd, encrypt_info.passwd))
				{
					nValidIndex[index] = 1;
					printf("warning: %s, password of the file is different from previous files, will be ignored\n", object[index]);
				}
			}
			else
			{
				nValidIndex[index] = 1;
				printf("warning: %s, invalid file format, will be ignored\n", object[index]);				
			}
		}

		int tempIndex = 0;
		for(index = 0; index < nCount; index++)
		{
			if(nValidIndex[index] == 0)
			{
				if(index > tempIndex)
				{
					strcpy(object[tempIndex], object[index]);
				}
				tempIndex++;
			}
		}
		nCount = tempIndex;
		if(nCount == 0)
		{
			printf("error: 没有有效格式的被解密文件或目录\n");
			return 0;
		}
	}

	if(strlen(passwd) == 0)
	{		
		//如果用户在命令行没有输入密码，则提示输入密码
		if(g_bDecode)
		{
			//如果是解密，则提示输入密码一次
			int nAllowTimes = 0;
			while(1)
			{
				printf("请输入要%s的密码:", TTY_TIP_ED);

				//屏蔽回显
				BEGIN_TTY_PASSWD
					char cInput[PASSWD_MAX] = {0};
				if(!gets(cInput))
				{
					END_TTY_PASSWD
						printf("\nwarning: system function-gets failed, will be ignored\n");
					continue;
				}
				printf("\n");
				END_TTY_PASSWD
					ENCRYPT_INFO encrypt_info;
				memset(&encrypt_info, 0, sizeof(ENCRYPT_INFO));
				ReadEncryptInfo(object[0], &encrypt_info);
				if(strcmp(cInput, encrypt_info.passwd))
				{
					if(++nAllowTimes >= 10)
					{
						//暂且不做文件锁定的处理
						printf("密码连续输入错误已10次，请24h后重试\n");
						return 0;
					}
					printf("您输入的密码不正确，请重新输入\n");
				}
				else
				{
					strcpy(passwd, cInput);
					break;
				}
			}

		}
		else
		{
			//如果是加密，则提示输入密码两次
			printf("请输入要%s的密码:", TTY_TIP_ED);
			char pwd1[PASSWD_MAX] = {0}, pwd2[PASSWD_MAX] = {0};
			BEGIN_TTY_PASSWD
			gets(pwd1);
			printf("\n请再次输入要%s的密码:", TTY_TIP_ED);
			gets(pwd2);
			printf("\n");
			END_TTY_PASSWD
				if(strcmp(pwd1, pwd2) == 0)
				{
					strcpy(passwd, pwd1);
				}
				else
				{
					printf("error: 两次输入的密码不一致\n");
					return 0;
				}
		}
	}
	else
	{
		if(g_bDecode)
		{
			ENCRYPT_INFO encrypt_info;
			memset(&encrypt_info, 0, sizeof(ENCRYPT_INFO));
			ReadEncryptInfo(object[0], &encrypt_info);
			if(strcmp(passwd, encrypt_info.passwd))
			{
				printf("error: 密码错误\n");
				return 0;
			}
		}
	}

	DoEncrypt(object, nCount, passwd, !g_bDecode);
	return 0;

}
