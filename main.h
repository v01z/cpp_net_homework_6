#ifndef MAIN_H
#define MAIN_H

#if defined(_WIN32)
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>

#endif


#if defined(_WIN32)
#define ISVALIDSOCKET(s) ((s) != INVALID_SOCKET)
#define CLOSESOCKET(s) closesocket(s)

#else
#define ISVALIDSOCKET(s) ((s) >= 0)
#define CLOSESOCKET(s) close(s)
#define SOCKET int
#endif


#include <string.h>
#include <iostream>
#include <vector>


#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

//------------------------------------------------------------------------------

struct server_params{
    const char* hostname = 0;
    const char* port = 0;
};

//------------------------------------------------------------------------------

struct login{
    std::string user;
    std::string pass;
};

//------------------------------------------------------------------------------

const char* get_last_error();

//-----------------------------------------------------------------------------

#endif //MAIN_H