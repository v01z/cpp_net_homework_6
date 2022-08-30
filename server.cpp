#include <thread>
#include <fstream>
#include "server.h"
#include <sstream>

//------------------------------------------------------------------------------

client_info::client_info():
    address_length{},
    address{},
    socket{ -1 },
    ssl{},
    request{},
    received{},
    auth_data{}//,
    {}

//------------------------------------------------------------------------------

//------------------------------------------------------------------------------

HttpsStorage::HttpsStorage(const char* host, const char* port):
    clients_{}, ssl_context_{ nullptr }, socket_{ -1 }, logins_{}
{
    std::cout << "Checking logins database (" << AUTH_FILE << ")..";
    std::ifstream auth_file{AUTH_FILE };
    if(!auth_file.is_open())
    {
        std::cerr << "Couldnt open file " << AUTH_FILE
                  << std::endl;
        std::exit(1);
    }

    std::stringstream file_stream;
    file_stream << auth_file.rdbuf();

    while(file_stream.good())
    {
        std::string username, password;
        file_stream >> username >> password;
        logins_.push_back({username, password});
    }
    std::cout << ".. OK\n";

    std::cout << "Configuring local address...\n";
    struct addrinfo hints{};
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo *bind_address;
    if(getaddrinfo(host, port, &hints, &bind_address))
    {
        std::cerr << "getaddrinfo() failed. "
            << get_last_error() << std::endl;
        std::exit(2);
    }

    std::cout << "Creating socket...\n";
    socket_ = socket(bind_address->ai_family,
                           bind_address->ai_socktype, bind_address->ai_protocol);
    if (!ISVALIDSOCKET(socket_)) {
        std::cerr <<  "socket() failed.\n" << get_last_error();
        std::exit(3);
    }

    std::cout << "Binding socket to local address...\n";
    if (bind(socket_,
             bind_address->ai_addr, bind_address->ai_addrlen)) {
        std::cerr << "bind() failed. \n" << get_last_error();
        CLOSESOCKET(socket_);
        std::exit(4);
    }
    freeaddrinfo(bind_address);

    std::cout << "Listening...\n";
    if (listen(socket_, 10) < 0) {
        std::cerr << "listen() failed. (%d)\n" << get_last_error();
        CLOSESOCKET(socket_);
        std::exit(5);
    }

    if(!ssl_init())
    {
        CLOSESOCKET(socket_);
        std::exit(6);
    }
}

//------------------------------------------------------------------------------

bool HttpsStorage::ssl_init() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ssl_context_ = SSL_CTX_new(TLS_server_method());
    if (!ssl_context_) {
        std::cerr << "SSL_CTX_new() failed.\n";
        return false;
    }

    if (!SSL_CTX_use_certificate_file(ssl_context_, "cert.pem" , SSL_FILETYPE_PEM)
        || !SSL_CTX_use_PrivateKey_file(ssl_context_, "key.pem", SSL_FILETYPE_PEM)) {
        std::cerr <<  "SSL_CTX_use_certificate_file() failed.\n";
        ERR_print_errors_fp(stderr);

        SSL_CTX_free(ssl_context_);
        return false;
    }
    return true;
}

//------------------------------------------------------------------------------

const ci_ptr HttpsStorage::get_client() {

    ci_ptr new_client{ new client_info{} };
    if (!new_client) {
        std::cerr << "Out of memory.\n";
        freeing_ci_list();
        std::exit(7);
    }

    new_client->address_length = sizeof(new_client->address);

    clients_.push_back(new_client);

    return new_client;
}

//------------------------------------------------------------------------------

void HttpsStorage::drop_client(ci_ptr client) {
    SSL_shutdown(client->ssl);
    CLOSESOCKET(client->socket);
    SSL_free(client->ssl);

    clients_.remove(client);
}

//------------------------------------------------------------------------------

[[nodiscard]] const std::string HttpsStorage::get_client_address(const  ci_ptr client)const {
    static char host_name_buff[NI_MAXHOST];
    static char service_name_buff[NI_MAXSERV];

    getnameinfo((struct sockaddr*)&client->address, client->address_length,
        host_name_buff, NI_MAXHOST, service_name_buff,
        NI_MAXSERV, NI_NUMERICHOST);

    return std::string(host_name_buff) + ":" + std::string(service_name_buff);
}

//------------------------------------------------------------------------------

fd_set HttpsStorage::wait_on_clients() {
    fd_set reads;
    FD_ZERO(&reads);
    FD_SET(socket_, &reads);
    SOCKET max_socket = socket_;

    for (const auto &elem : clients_)
    {
        FD_SET(elem->socket, &reads);
        if(elem->socket > max_socket)
            max_socket = elem->socket;
    }

    if (select(max_socket+1, &reads,
    nullptr, nullptr, nullptr) < 0) {
        std::cerr << "select() failed.\n" << get_last_error();
        freeing_ci_list();
        std::exit(8);
    }

    return reads;
}

//------------------------------------------------------------------------------

void HttpsStorage::send_400(ci_ptr client){
    const char *c400 = "HTTP/1.1 400 Bad Request\r\n"
                       "Connection: close\r\n"
                       "Content-Length: 11\r\n\r\nBad Request";
    SSL_write(client->ssl, c400, strlen(c400));
    drop_client(client);
}

//------------------------------------------------------------------------------

void HttpsStorage::send_401(ci_ptr  client){
    const char *c401 = "HTTP/1.1 401 Unauthorized\r\n"
                       "Connection: close\r\n"
                       "Content-Length: 12\r\n\r\nUnauthorized";
    SSL_write(client->ssl, c401, strlen(c401));
    drop_client(client);
}

//------------------------------------------------------------------------------

void HttpsStorage::send_404(ci_ptr client){
    const char *c404 = "HTTP/1.1 404 Not Found\r\n"
                       "Connection: close\r\n"
                       "Content-Length: 9\r\n\r\nNot Found";
    SSL_write(client->ssl, c404, strlen(c404));
    drop_client(client);
}

//------------------------------------------------------------------------------

bool HttpsStorage::is_auth_OK(ci_ptr client) {

    const std::string auth_pattern{ "Authorization: " };
    const std::string request { std::string(client->request) };

    size_t start_pos = request.find(auth_pattern);
    if(start_pos == std::string::npos) return false;

    std::string auth_str_line{ request.substr(start_pos,
        request.length() - start_pos) };

    size_t end_pos = auth_str_line.find("\r\n");
    if(end_pos == std::string::npos) return false;

    auth_str_line = auth_str_line.substr(0, end_pos);

    size_t colon_pos = auth_str_line.find_last_of(":");
    if(colon_pos == std::string::npos) return false;

    client->auth_data.user = auth_str_line.substr(auth_pattern.length(),
    colon_pos - auth_pattern.length());

    client->auth_data.pass = auth_str_line.substr(colon_pos + 1,
        end_pos - auth_str_line.length() - client->auth_data.user.length() - 1);

    for (const auto &elem : logins_)
        if((elem.user == client->auth_data.user) &&
                (elem.pass == client->auth_data.pass) )
            return true;

    return false;
}

//------------------------------------------------------------------------------

const std::string HttpsStorage::get_content_type(const std::string& path) {

    size_t last_dot = path.rfind(".");
    if (last_dot != std::string::npos) {
        if (std::string(path, last_dot, path.length()) == ".css")
            return std::string("text/css");
        if (std::string(path, last_dot, path.length()) == ".gif")
            return std::string("image/gif");
        if (std::string(path, last_dot, path.length()) == ".htm")
            return std::string("text/html");
        if (std::string(path, last_dot, path.length()) == ".html")
            return std::string("text/html");
        if (std::string(path, last_dot, path.length()) == ".ico")
            return std::string("image/x-icon");
        if (std::string(path, last_dot, path.length()) == ".jpeg")
            return std::string("image/jpeg");
        if (std::string(path, last_dot, path.length()) == ".jpg")
            return std::string("image/jpeg");
        if (std::string(path, last_dot, path.length()) == ".js")
            return std::string("application/javascript");
        if (std::string(path, last_dot, path.length()) == ".json")
            return std::string("application/json");
        if (std::string(path, last_dot, path.length()) == ".png")
            return std::string("image/png");
        if (std::string(path, last_dot, path.length()) == ".pdf")
            return std::string("application/pdf");
        if (std::string(path, last_dot, path.length()) == ".svg")
            return std::string("image/svg+xml");
        if (std::string(path, last_dot, path.length()) == ".txt")
            return std::string("text/plain");
    }

    return "application/octet-stream";
}

//------------------------------------------------------------------------------

void HttpsStorage::serve_resource(ci_ptr client, const std::string& full_path){

    std::cout << "serve_resource " << get_client_address(client)
    << " " << full_path << std::endl;

    if (full_path.length() > 100){
        send_400(client);
        return;
    }

#if defined(_WIN32)
    char *p = full_path;
    while (*p) {
        if (*p == '/') *p = '\\';
        ++p;
    }
#endif
        FILE *fp = fopen(full_path.data(), "rb");

        if (!fp) {
            std::cout << "Cannot open " << full_path << std::endl;
            send_404(client);
            return;
        }

        fseek(fp, 0L, SEEK_END);
        size_t content_length = ftell(fp);
        rewind(fp);

        std::string header { "HTTP/1.1 200 OK\r\n" };

        header.append("Connection: close\r\n");

        header.append("Content-Length: "
        + std::to_string(content_length) + "\r\n");

        header.append("Content-Type: " + get_content_type(full_path) + "\r\n");

        header.append("\r\n");

        SSL_write(client->ssl, header.c_str(), header.length());

#define BSIZE 1024
        char buffer[BSIZE];

        size_t sent_size{};

        int r = fread(buffer, 1, BSIZE, fp);

        sent_size += r;

        std::cout << "Sending requested file " << full_path << " to "
            << get_client_address(client) << std::endl;
        while (r) {
            SSL_write(client->ssl, buffer, r);
            r = fread(buffer, 1, BSIZE, fp);
            sent_size += r;
        }
        std::cout << "File " << full_path << " has been sent to "
            << get_client_address(client) << ". Size: " << sent_size << " bytes.\n";

        fclose(fp);
        drop_client(client);
}

//------------------------------------------------------------------------------

void HttpsStorage::run() {

    if(ssl_context_ == nullptr)
        return;
    if(socket_ < 0)
        return;

    while(true) {

        fd_set reads;
        reads = wait_on_clients();

        if (FD_ISSET(socket_, &reads)) {
            ci_ptr client = get_client();

            client->socket = accept(socket_,
                                    (struct sockaddr*) &(client->address),
                                    &(client->address_length));

            if (!ISVALIDSOCKET(client->socket)) {
                std::cerr << "accept() failed.\n"
                    << get_last_error() << std::endl;

                return;
            }

            client->ssl = SSL_new(ssl_context_);
            if (!client->ssl) {
                std::cerr << "SSL_new() failed.\n";
                return;
            }

            SSL_set_fd(client->ssl, client->socket);
            if (SSL_accept(client->ssl) != 1) {
                //SSL_get_error(client->ssl, SSL_accept(...));
                ERR_print_errors_fp(stderr);
                drop_client(client);
            } else {
                std::cout << "\nNew connection from "
                       << get_client_address(client) << std::endl;
                std::cout << "SSL connection using "
                    << SSL_get_cipher(client->ssl) << std::endl;
            }
        }

        std::list<ci_ptr>::iterator client = clients_.begin();
        while(client != clients_.end() && clients_.size() > 0)
        {

            if (FD_ISSET((*client)->socket, &reads)) {

                if (MAX_REQUEST_SIZE == (*client)->received) {
                    send_400(*client);
                    client++;
                    continue;
                }

                int bytes_read = SSL_read((*client)->ssl,
                                          (*client)->request + (*client)->received,
                                 MAX_REQUEST_SIZE - (*client)->received);

                if (bytes_read < 1) {
                    std::cout << "Unexpected disconnect from "
                           << get_client_address(*client) << std::endl;
                    drop_client(*client);

                } else {
                    (*client)->received += bytes_read;
                    (*client)->request[(*client)->received] = 0;

                    char *header_end = strstr((*client)->request, "\r\n\r\n");
                    if (header_end) {
                        *header_end = 0;

                        std::cout << "\nGot client request from "
                            << get_client_address(*client) << ":\n"
                                << (*client)->request << std::endl << std::endl;

                        if(!is_auth_OK(*client)) {
                            std::cout << "Caught unauthorized access from "
                                << get_client_address(*client) << std::endl;
                            send_401(*client);
                        }
                        else {

                            if (!strncmp("GET @exit_server@", (*client)->request, 17)) {
                                std::cout << "\nGot stop command from client\n";;

                                return;
                            }

                            if (strncmp("GET /", (*client)->request, 5)) {
                                send_400(*client);
                            } else {
                                char *path = (*client)->request + 4;
                                char *end_path = strstr(path, " ");
                                if (!end_path) {
                                    send_400(*client);
                                } else {
                                    *end_path = 0;

                                    std::thread service_thread([=]() {
                                        serve_resource(*client, std::string(path));
                                    });
                                    service_thread.detach();
                                }
                            }
                        } //ifAuthOK()
                    } //if (q)
                }
            } //if FD_ISSET(client..
            client++;
        }//while(client)
    } //while(true)
}

//------------------------------------------------------------------------------

void HttpsStorage::freeing_ci_list() {
    for (auto &connected_client: clients_)
    {
        SSL_shutdown(connected_client->ssl);
        SSL_free(connected_client->ssl);
        CLOSESOCKET(connected_client->socket);
        connected_client.reset();
    }

    SSL_CTX_free(ssl_context_);
    CLOSESOCKET(socket_);
}
//------------------------------------------------------------------------------

HttpsStorage::~HttpsStorage(){
    freeing_ci_list();
}

//------------------------------------------------------------------------------

int main(int argc, char** argv){

#if defined(_WIN32)
    WSADATA d;
    if (WSAStartup(MAKEWORD(2, 2), &d)) {
        std::cerr << "Failed to initialize.\n");
        return 1;
    }
#endif

    const char* host = "localhost";
    const char* port = "51511";

    if (argc == 2 && !strcmp(argv[1], "--help"))
    {
        std::cout << "Usage: <local address> <port>\n";
        return 0;
    }

    if (argc == 3)
    {
        host = argv[1];
        port = argv[2];
    }
    else
        std::cout << "Using default parameters: <"
            << host << ">:<" << port << ">" << std::endl;

    HttpsStorage server{host, port };
    server.run();

#if defined(_WIN32)
    WSACleanup();
#endif

    std::cout << "Finished.\n";
};

//------------------------------------------------------------------------------
