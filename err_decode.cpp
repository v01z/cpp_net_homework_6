#include "main.h"

//-----------------------------------------------------------------------------

const char *get_last_error()
{
#if defined(_WIN32)
    static char message[256] = {};

    FormatMessage(
            FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,
                0, WSAGetLastError(), 0, message, 256, 0);

    char *new_line = strchr(message, '\n');

    if(new_line) *new_line = 0;

    return message;

#else
    return strerror(errno);
#endif
}

//-----------------------------------------------------------------------------
