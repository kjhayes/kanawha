
#include <netdb.h>

const char *
gai_strerror(int errcode)
{
    switch(errcode)
    {
    case EAI_ADDRFAMILY:
        return "EAI_ADDRFAMILY";
    case EAI_AGAIN:
        return "EAI_AGAIN";
    case EAI_BADFLAGS:
        return "EAI_BADFLAGS";
    case EAI_FAIL:
        return "EAI_FAIL";
    case EAI_FAMILY:
        return "EAI_FAMILY";
    case EAI_MEMORY:
        return "EAI_MEMORY";
    case EAI_NODATA:
        return "EAI_NODATA";
    case EAI_NONAME:
        return "EAI_NONAME";
    case EAI_SERVICE:
        return "EAI_SERVICE";
    case EAI_SOCKTYPE:
        return "EAI_SOCKTYPE";
    case EAI_SYSTEM:
        return "EAI_SYSTEM";
    default:
        return "EAI_UNKNOWN";
    }
}
