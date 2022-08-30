#include "client.h"
#include "cassert"

//------------------------------------------------------------------------------

void HttpsDownloader::get_file() {
    std::cout << "\nSending request to peer..\n";
    send_request();

    std::cout << "\nGetting server response..\n";
    get_response();
}

//------------------------------------------------------------------------------

HttpsDownloader::HttpsDownloader(const server_params* server, const login* login, const char* request):
    server_{ server },
    login_{ login },
    request_{ request },
    ssl_context_{ nullptr },
    ssl_{ nullptr },
    socket_{ -1 }
{
    std::cout << "Configuring remote address...\n";
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *peer_address;
    if (getaddrinfo(server_->hostname, server_->port, &hints, &peer_address)) {
        std::cerr << "getaddrinfo() failed. " << get_last_error() << std::endl;
        exit(1);
    }

    std::cout << "Remote address is: ";
    char address_buffer[100];
    char service_buffer[100];
    getnameinfo(peer_address->ai_addr, peer_address->ai_addrlen,
                address_buffer, sizeof(address_buffer),
                service_buffer, sizeof(service_buffer),
                NI_NUMERICHOST);
    std::cout << address_buffer << ":" << service_buffer << std::endl;

    std::cout << "Creating socket...\n";
    socket_ = socket(peer_address->ai_family,
                    peer_address->ai_socktype, peer_address->ai_protocol);
    if (!ISVALIDSOCKET(socket_)) {
        std::cerr << "socket() failed. " << get_last_error() << std::endl;
        freeaddrinfo(peer_address);
        exit(2);
    }

    std::cout << "Connecting...\n";
    if (connect(socket_,
                peer_address->ai_addr, peer_address->ai_addrlen)) {
        std::cerr << "connect() failed. " << get_last_error() << std::endl;
        freeaddrinfo(peer_address);
        CLOSESOCKET(socket_);
        exit(3);
    }
    freeaddrinfo(peer_address);

    std::cout << "Connected.\n\n";

    if(!ssl_init())
    {
        CLOSESOCKET(socket_);
        exit(4);
    }
}

//------------------------------------------------------------------------------

bool HttpsDownloader::ssl_init() {
    if (socket_ == -1)
        return false;
    if(server_->hostname == nullptr)
        return false;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ssl_context_ = SSL_CTX_new(TLS_client_method());
    if (!ssl_context_) {
        std::cerr << "SSL_CTX_new() failed.\n";
        return false;
    }

    ssl_ = SSL_new(ssl_context_);
    if (!ssl_) {
        std::cerr << "SSL_new() failed.\n";
        SSL_CTX_free(ssl_context_);
        return false;
    }

    if (!SSL_set_tlsext_host_name(ssl_, server_->hostname)) {
        std::cerr <<  "SSL_set_tlsext_host_name() failed.\n";
        ERR_print_errors_fp(stderr);
        SSL_free(ssl_);
        SSL_CTX_free(ssl_context_);
        return false;
    }

    SSL_set_fd(ssl_, socket_);
    if (SSL_connect(ssl_) == -1) {
        std::cerr <<  "SSL_connect() failed.\n";
        ERR_print_errors_fp(stderr);
        SSL_free(ssl_);
        SSL_CTX_free(ssl_context_);
        return false;
    }

    std::cout << "SSL/TLS using " << SSL_get_cipher(ssl_) << std::endl;


    X509 *cert = SSL_get_peer_certificate(ssl_);
    if (!cert) {
        std::cerr << "SSL_get_peer_certificate() failed.\n";
        SSL_free(ssl_);
        SSL_CTX_free(ssl_context_);
        return false;
    }

    char *tmp;
    if ((tmp = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0))) {
        std::cout << "Subject: " << tmp << std::endl;
        OPENSSL_free(tmp);
    }

    if ((tmp = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0))) {
        std::cout << "Issuer: " << tmp << std::endl;
        OPENSSL_free(tmp);
    }

    X509_free(cert);

    return true;
}

//------------------------------------------------------------------------------

HttpsDownloader::~HttpsDownloader() {
    SSL_shutdown(ssl_);
    CLOSESOCKET(socket_);
    SSL_free(ssl_);
    SSL_CTX_free(ssl_context_);
}

//------------------------------------------------------------------------------

void HttpsDownloader::send_request() const {
    std::string header_str{ "GET " + std::string(request_) +  " HTTP/1.1\r\n"};

    header_str.append("Host: " + std::string(server_->hostname) + ":"
        + std::string(server_->port) + "\r\n");
    header_str.append("Authorization: " + std::string(login_->user) + ":"
                      + std::string(login_->pass) + "\r\n");
    header_str.append("Connection: close\r\n");
    header_str.append("User-Agent: https_client\r\n");
    header_str.append("\r\n");

    SSL_write(ssl_, header_str.c_str(), header_str.length());
    std::cout << "Sent Headers:\n" << header_str;
}

//------------------------------------------------------------------------------

void HttpsDownloader::divide_stream_buffers(std::string &header, std::vector<char> &body,
                                            const char* buff, size_t size, bool &gotHeader) const
{
    size_t i{};
    for(; i < size; i++)
    {
        if(!gotHeader)
        {
            header.push_back(buff[i]);

            //strlen("\r\n\r\n") == 4
            if(header.length() > 4 && std::string(header, header.length() - 4, 4) == "\r\n\r\n")
            {
                assert(buff[i] == '\n');
                gotHeader = true;
                i++;
                break;
            }
        }
        else
            body.emplace_back(buff[i]);
    }
    if(gotHeader)
    {
        for(; i < size; i++)
            body.push_back(buff[i]);
    }
}

//------------------------------------------------------------------------------

[[nodiscard]] inline const std::string HttpsDownloader::get_filename_from_path
    (const std::string &path)const {
        return path.substr(path.find_last_of("/\\") + 1);
}

//------------------------------------------------------------------------------

void HttpsDownloader::get_response()const{

    char buffer[2048];
    std::string header_str{};
    std::vector<char> body_vec{};
    bool isHeaderGot{};

    size_t progress{};
    const std::string file_name{get_filename_from_path(request_) };

    std::cout << "Downloading " << file_name << ", wait please..\n";
    while(true) {
        int bytes_received = SSL_read(ssl_, buffer, sizeof(buffer));
        if (bytes_received < 1) {
            std::cout << "\nConnection closed by peer.\n";
            break;
        }
        divide_stream_buffers(header_str, body_vec,
                        buffer, bytes_received, isHeaderGot);

        //30 - it's just a magic number to beautify console output
        if(progress > 30) {
            std::cout << "\r*";
            progress = 0;
        }
        progress++;
        std::cout << ".";
    } //end while(true)

    std::cout << "\nGot HTTP-Header from server:\n" << header_str;

    if((body_vec.empty()) ||
        (header_str.find("HTTP/1.1 200 OK\r\n") == std::string::npos))
        return;

    FILE *fp = fopen(file_name.c_str(), "wb");

    if(!fp){
        std::cerr << "Can't create file.\n";
        return;
    }

    fwrite(body_vec.data(), body_vec.size(), 1, fp);

    std::cout << "File " << file_name << " has been downloaded and saved.\n";

    fclose(fp);
}

//------------------------------------------------------------------------------

int main(int argc, char** argv){
#if defined(_WIN32)
    WSADATA d;
    if (WSAStartup(MAKEWORD(2, 2), &d)) {
        std::cerr << "Failed to initialize WinSock library.\n";
        return 1;
    }
#endif

    if (argc < 6 || argc > 7)
    {
        std::cerr << "Usage:\n" <<
            "To get a file:\n" << argv[0] << " <server> <port> <user> "
                << "<password> <file-to-get>\n"
            "To stop a server:\n" << argv[0] << "<server> <port> <user> "
                << "<password> @exit_server@\n";

        return 1;
    }

    const server_params server { argv[1], argv[2] };
    const login login_params { argv[3], argv[4] };

    //./client localhost 51511 user puser /etc/passwd
    //./client localhost 51511 user puser @exit_server@

    HttpsDownloader client {&server, &login_params, argv[5] };

    client.get_file();

#if defined(_WIN32)
    WSACleanup();
#endif

    std::cout << "\nFinished.\n";
    return 0;
}

//------------------------------------------------------------------------------
