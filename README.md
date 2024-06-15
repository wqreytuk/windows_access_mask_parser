access rigth 一共只有32bit 就是4bytes


https://learn.microsoft.com/en-us/windows/win32/secauthz/access-mask-format


![image](https://github.com/wqreytuk/windows_access_mask_parser/assets/48377190/8fa203ca-842f-4849-af3a-b405cf7a0473)



最左边的4bit是通用访问权限
GR\GW\GE\GA

紧跟着3bit是保留位


再紧跟着是针对SACL的访问权限

https://learn.microsoft.com/en-us/windows/win32/secauthz/sacl-access-right

是否拥有这个权限，表示是否拥有对这个对象的SACL进行修改的权限   DACL  SACL     SACL仅用来audit，和DACL不一样

DACL才是真正用来控制权限的


然后再往后8bit 是标准访问权限   适用于大多数object

再往后是object specific access right  针对不同的对象类型，这些权限标志位拥有不同的涵义


我们现在只需要解析FILEOBJECT的访问权限

```c


#include <Windows.h>
#include <stdio.h>

int main(int argc,char* argv[])
{
	DWORD am = 0x80100080;
	char* decodedAM = (char*)malloc(0x1000);
	memset(decodedAM, 0, 0x1000);

	// Generic Access Rigths
	if (am & 0b10000000000000000000000000000000) {
		char gr[] = " | GenericRead";
		strcat(decodedAM, gr);
	}
	if (am & 0b01000000000000000000000000000000) {
		char gr[] = " | GenericWrite";
		strcat(decodedAM, gr);
	}
	if (am & 0b00100000000000000000000000000000) {
		char gr[] = " | GenericExecute";
		strcat(decodedAM, gr);
	}
	if (am & 0b00010000000000000000000000000000) {
		char gr[] = " | GenericAll";
		strcat(decodedAM, gr);
	}

	// standard rigths
	// 其实标准访问权限只有5个
// #define DELETE                           (0x00010000L)
// #define READ_CONTROL                     (0x00020000L)
// #define WRITE_DAC                        (0x00040000L)
// #define WRITE_OWNER                      (0x00080000L)
// #define SYNCHRONIZE                      (0x00100000L)

	if (am & DELETE) {
		char gr[] = " | DELETE";
		strcat(decodedAM, gr);
	}
	if (am & READ_CONTROL) {
		char gr[] = " | READ_CONTROL";
		strcat(decodedAM, gr);
	}
	if (am & WRITE_DAC) {
		char gr[] = " | WRITE_DAC";
		strcat(decodedAM, gr);
	}
	if (am & WRITE_OWNER) {
		char gr[] = " | WRITE_OWNER";
		strcat(decodedAM, gr);
	}
	if (am & SYNCHRONIZE) {
		char gr[] = " | SYNCHRONIZE";
		strcat(decodedAM, gr);
	}

	// file object specific rights
	// 针对文件的权限定义
// #define FILE_READ_DATA            ( 0x0001 )    // file & pipe
// #define FILE_WRITE_DATA           ( 0x0002 )    // file & pipe
// #define FILE_APPEND_DATA          ( 0x0004 )    // file
// #define FILE_READ_EA              ( 0x0008 )    // file & directory
// #define FILE_WRITE_EA             ( 0x0010 )    // file & directory
// #define FILE_EXECUTE              ( 0x0020 )    // file
// #define FILE_READ_ATTRIBUTES      ( 0x0080 )    // all
// #define FILE_WRITE_ATTRIBUTES     ( 0x0100 )    // all

	if (am & FILE_READ_DATA) {
		char gr[] = " | FILE_READ_DATA";
		strcat(decodedAM, gr);
	}
	if (am & FILE_WRITE_DATA) {
		char gr[] = " | FILE_WRITE_DATA";
		strcat(decodedAM, gr);
	}
	if (am & FILE_APPEND_DATA) {
		char gr[] = " | FILE_APPEND_DATA";
		strcat(decodedAM, gr);
	}
	if (am & FILE_READ_EA) {
		char gr[] = " | FILE_READ_EA";
		strcat(decodedAM, gr);
	}
	if (am & FILE_WRITE_EA) {
		char gr[] = " | FILE_WRITE_EA";
		strcat(decodedAM, gr);
	}
	if (am & FILE_EXECUTE) {
		char gr[] = " | FILE_EXECUTE";
		strcat(decodedAM, gr);
	}
	if (am & FILE_READ_ATTRIBUTES) {
		char gr[] = " | FILE_READ_ATTRIBUTES";
		strcat(decodedAM, gr);
	}
	if (am & FILE_WRITE_ATTRIBUTES) {
		char gr[] = " | FILE_WRITE_ATTRIBUTES";
		strcat(decodedAM, gr);
	}


	printf("%s\n", decodedAM);
}
```
