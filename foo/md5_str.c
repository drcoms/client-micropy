#include "md5.h"
#include <stdlib.h>
#include <string.h>

char* md5(char* str) 
{
    unsigned char* buf = (unsigned char*)malloc(32);
    memset(buf, 0, 32);
    MD5_CTX foo;
    MD5_Init(&foo);
    MD5_Update(&foo, str, 4);
    MD5_Final(buf, &foo);
    return 0;
}

