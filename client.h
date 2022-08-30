
#ifndef HOMEWORK_NET_6_CLIENT_H
#define HOMEWORK_NET_6_CLIENT_H

#include "main.h"

//-----------------------------------------------------------------------------

class Client{
public:
    virtual void get_file() = 0;
    virtual ~Client(){};
};

//-----------------------------------------------------------------------------

class HttpsDownloader: public Client{
private:
    const server_params* server_;
    const login* login_;
    const char* request_;
    SSL_CTX *ssl_context_;
    SSL *ssl_;
    SOCKET socket_;

    bool ssl_init();

    void divide_stream_buffers(std::string&, std::vector<char>&,
            const char*, size_t, bool&)const;

    [[nodiscard]] inline const std::string get_filename_from_path
        (const std::string&)const;

    void send_request()const;
    void get_response()const;

public:
    void get_file() override;

    explicit HttpsDownloader(const server_params*, const login*, const char*);
    ~HttpsDownloader();
};

//------------------------------------------------------------------------------

#endif //HOMEWORK_NET_6_CLIENT_H
