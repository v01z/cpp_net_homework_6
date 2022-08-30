
#ifndef HOMEWORK_NET_6_SERVER_H
#define HOMEWORK_NET_6_SERVER_H

#include "main.h"
#include <list>
#include <memory>

//------------------------------------------------------------------------------

class Server{
public:
    virtual void run() = 0;
    virtual ~Server(){};
};

//------------------------------------------------------------------------------

#define MAX_REQUEST_SIZE 2047
#define AUTH_FILE "auth.txt"

//------------------------------------------------------------------------------

struct client_info {
    socklen_t address_length;
    struct sockaddr_storage address;
    SOCKET socket;
    SSL *ssl;
    char request[MAX_REQUEST_SIZE + 1];
    int received;
    login auth_data;

    client_info();
};

//------------------------------------------------------------------------------

using ci_ptr = std::shared_ptr<client_info>;

class HttpsStorage: public Server{
private:
    std::list<ci_ptr> clients_;
    SSL_CTX *ssl_context_;
    SOCKET socket_;
    std::vector<login> logins_;

    bool ssl_init();

    const ci_ptr get_client();
    void drop_client(ci_ptr);
    [[nodiscard]] const std::string get_client_address(const ci_ptr)const;

    fd_set wait_on_clients();
    const std::string get_content_type(const std::string&);
    bool is_auth_OK(ci_ptr);

    void serve_resource(ci_ptr , const std::string&);
    void send_400(ci_ptr);
    void send_401(ci_ptr);
    void send_404(ci_ptr);

    void freeing_ci_list();
public:
    explicit HttpsStorage(const char*, const char*);
    HttpsStorage() = delete;
    ~HttpsStorage();

    void run() override;
};

//------------------------------------------------------------------------------

#endif //HOMEWORK_NET_6_SERVER_H
