#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>
#include <map>
#include <thread>
#include <chrono>
#include <fstream>
#include <sys/time.h>
#include <sys/select.h>
#include <poll.h>

#define PORT 12350
#define BUF_SIZE 2048

using namespace std;

void error(const char *msg) {
    perror(msg);
    exit(1);
}

// Define a map to store sessions
map<string, SSL_SESSION *> sessionCache;

int generate_session_ticket(SSL *ssl, void *arg) {
    // Code to generate a session ticket
    return 1; // Return 1 on success, 0 on error
}

SSL_TICKET_RETURN decrypt_session_ticket(SSL *ssl, SSL_SESSION *ss,
                                         const unsigned char *keyname,
                                         size_t keyname_length,
                                         SSL_TICKET_STATUS status,
                                         void *arg) {
    // Code to decrypt a session ticket
    return SSL_TICKET_RETURN_USE; // Return appropriate status based on the result
}

int validate_session_ticket_cb(SSL *ssl, unsigned char *ticket, int ticketlen, unsigned char *sess_ctx) {
    // Your implementation here
    return 1; // Return 1 for valid ticket or 0 for invalid ticket
}

// Function to cache an SSL session
void cache_session(const string& sessionID, SSL_SESSION* session) {
    sessionCache[sessionID] = session;
}

// Function to retrieve cached session
SSL_SESSION *get_cached_session(const string &sessionID) {
    // Check if session ID exists in the cache
    for (const auto& pair : sessionCache) {
        cout << "Session ID: " << pair.first << ", SSL_SESSION Address: " << pair.second << endl;
    }
    if (sessionCache.find(sessionID) != sessionCache.end()) {
        // Session found, return the session data
        return sessionCache[sessionID];
    } else {
        // Session not found
        return nullptr;
    }
}

// Function to save session cache to a file
void save_session_cache(const std::string& filename) {
    std::ofstream outfile(filename);
    for (const auto& pair : sessionCache) {
        outfile << pair.first << " " << reinterpret_cast<uintptr_t>(pair.second) << std::endl;
    }
    outfile.close();
}

// Function to load session cache from a file
void load_session_cache(const std::string& filename) {
    std::ifstream infile(filename);
    if (infile.is_open()) {
        std::string sessionID;
        uintptr_t sessionPtr;
        while (infile >> sessionID >> sessionPtr) {
            SSL_SESSION* session = reinterpret_cast<SSL_SESSION*>(sessionPtr);
            sessionCache[sessionID] = session;
        }
        infile.close();
    }
}

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
    // Generate a random cookie
    memcpy(cookie, "cookie",6);
    *cookie_len = 6; // Set the cookie length

    return 1; // Success
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {

    // Return 1 if the cookie is valid, 0 otherwise
    return 1; // Valid cookie
}


SSL_CTX *create_client_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    method = DTLSv1_2_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256");
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT);
    return ctx;
}

SSL_CTX *create_server_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    method = DTLSv1_2_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx,string cert,string key)
{
    
    if (SSL_CTX_use_certificate_file(ctx, cert.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key.c_str(), SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int verify_the_certificate(SSL *ssl)
{
    int result;
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert == nullptr)
    {
        ERR_print_errors_fp(stderr);
        cout << "\nCertificate Not Given by Peer" << endl;
        abort();
    }
    if (cert)
    {
        cout << "\n";
        X509_NAME_print_ex_fp(stdout, X509_get_subject_name(cert), 0, XN_FLAG_ONELINE);
    }
    int err = SSL_get_verify_result(ssl);
    if (err != X509_V_OK)
    {
        ERR_print_errors_fp(stderr);
        const char *err_string = X509_verify_cert_error_string(err);
        printf("\nCertificate Not Valid : %s\n", err_string);
        abort();
    }
    result = err;

    return result;
}

void server() {
    // Server implementation
    int chat_hello=0;
    int chat_start_ssl =0;
    int server_fd;
    int client_fd;
    char send_buffer[BUF_SIZE];
    char recieve_buffer[BUF_SIZE];
    struct timeval timeout;
    X509* cert;
    X509* peer_cert;
    SSL *ssl;
    SSL_CTX *ctx;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_size;
    char buf[BUF_SIZE];

    struct timeval tv;
    tv.tv_sec = 5; // Timeout in seconds
    tv.tv_usec = 0;
    
    // Create a UDP socket
    if ((server_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
        error("Error opening socket");
        abort();
    }

    // Set socket options to receive with timeout
    if (setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("Error setting socket timeout");
        close(server_fd);
        abort();
    }

    // Set socket options to allow address reuse
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("Setsockopt failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Fill server address structure
    memset((char *)&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("172.31.0.3");
    server_addr.sin_port = htons(PORT); 


    // Bind the socket to the server address
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        error("Binding failed");
        close(server_fd);
        abort();
    }

    client_addr_size = sizeof(client_addr);

    cout << "Server is waiting for incoming connections...\n";
    cout<<endl;
    while(1)
    {
        
        memset(recieve_buffer, 0, BUF_SIZE);
        int bytes_received = recvfrom(server_fd, recieve_buffer, BUF_SIZE, 0, (struct sockaddr *)&client_addr, &client_addr_size);
        if (bytes_received < 0) {
            string message(recieve_buffer);
            // cout<<message<<endl;
            if(message == "chat_close")
            {
                cout<<"Connection Terminated by Client: Bye"<<endl; 
                memset(&client_addr, 0, sizeof(client_addr));
                continue;
            }

            string clientIP = inet_ntoa(client_addr.sin_addr);
            if ((errno == EWOULDBLOCK || errno == EAGAIN )&& (clientIP != "0.0.0.0")) {
                // Timeout occurred, handle accordingly
                // cout<<inet_ntoa(client_addr.sin_addr)<<endl;
                cout << "Timeout: No message received from client, Packet might be lost\n";
                memset(&client_addr, 0, sizeof(client_addr));
                continue; // Optionally continue waiting for messages or handle the timeout
            } else {
                continue;
            }
        }
        // cout<<inet_ntoa(client_addr.sin_addr)<<endl;

        string message(recieve_buffer);
        if(message == "chat_close")
        {
            cout<<"Connection Terminated by Client: Bye"<<endl; 
            memset(&client_addr, 0, sizeof(client_addr));
            continue;
        }
        if(message == "chat_hello")
        {
            chat_hello=1;
        }
        cout<<endl;
        cout<<"Client: "<<message<<endl;
        string reply1 = "chat_ok_reply";
        cout<<"You: "<<reply1<<endl;
        reply1 += '\0';

        sendto(server_fd, reply1.c_str(), reply1.length()+1, 0, (struct sockaddr *)&client_addr, client_addr_size);
        memset(recieve_buffer, 0, BUF_SIZE);
        bytes_received = recvfrom(server_fd, recieve_buffer, BUF_SIZE, 0, (struct sockaddr *)&client_addr, &client_addr_size);
        if (bytes_received < 0) {
        if ((errno == EWOULDBLOCK || errno == EAGAIN )) {
            // Timeout occurred, handle accordingly
            cout<<endl;
            string s = "chat_close";
            cout<<"You: chat_close"<<endl;
            cout<<endl;

            cout << "Timeout: No message received from client, Packet might be lost\n";
            cout<<"Terminating the connection"<<endl;
            cout<<endl;

            s += '\0';

            sendto(server_fd, s.c_str(), s.length()+1, 0, (struct sockaddr *)&client_addr, client_addr_size);
            memset(&client_addr, 0, sizeof(client_addr));
            // sleep(20);
            continue;
        } else {
            perror("Error receiving message");
            close(server_fd);
            abort();
        }
        }
        message = string(recieve_buffer);

        if(message == "chat_close")
        {
            cout<<"Connection Terminated by Client: Bye"<<endl; 
            memset(&client_addr, 0, sizeof(client_addr));
            continue;
        }
    
        if(message == "chat_START_SSL")
        {
            tv.tv_sec = 0;
            if (setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
                perror("Error removing socket timeout");
                close(server_fd);
                exit(EXIT_FAILURE);
            }
            
            cout<<"Client: "<<message<<endl;
            string reply2 = "chat_START_SSL_ACK";
            reply2 += '\0';
            cout<<"You: "<<reply2<<endl;
            int send_result = sendto(server_fd, reply2.c_str(), strlen(reply2.c_str())+1, 0, (struct sockaddr *)&client_addr, client_addr_size);
            if (send_result <= 0) {
                perror("sendto failed");
                abort();
            }

            SSL_library_init();
            ctx = create_server_context();
            // SSL_CTX_sess_set_new_cb(ctx, ex);
            SSL_CTX_set_security_level(ctx,1);
            SSL_CTX_set_cipher_list(ctx, "ALL:NULL:eNULL:aNULL");
            // SSL_CTX_set_session_ticket_cb(ctx, generate_session_ticket, decrypt_session_ticket, NULL);
            SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
            // SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TICKET);
            SSL_CTX_set_session_id_context(ctx, (const unsigned char *)"DTLS", strlen("DTLS"));
            configure_context(ctx, "/root/bob/bob.pem", "/root/bob/bob_private_key.pem");//put server certificates file names
            SSL_CTX_load_verify_locations(ctx, "/root/bob/chainOfTrust.pem", NULL);
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER , NULL);
            SSL_CTX_set_mode(ctx,SSL_MODE_AUTO_RETRY);
            SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
            SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);
            // Set client address for SSL connection
            BIO *bio = BIO_new_dgram(server_fd, BIO_CLOSE);

            /* Set and activate timeouts */
            timeout.tv_sec = 5;
            timeout.tv_usec = 0;
            BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
            // BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &client_addr);
            
            ssl = SSL_new(ctx);
            // Create SSL structure
            if (!ssl) {

                ERR_print_errors_fp(stderr);
                close(server_fd);
                SSL_CTX_free(ctx);
                exit(EXIT_FAILURE);
            }
            SSL_set_bio(ssl, bio, bio);
            if (DTLSv1_listen(ssl, (BIO_ADDR*)&client_addr) <= 0) { //SSL_accept(ssl) <= 0 DTLSv1_2_listen(ssl, (BIO_ADDR*)&client_addr) <= 0
                cout<<"Handshake Message might be lost"<<endl;
                ERR_print_errors_fp(stderr);
                SSL_shutdown(ssl);
                // close(server_fd);
                SSL_CTX_free(ctx);
                memset(&client_addr, 0, sizeof(client_addr));
                continue;
                // exit(EXIT_FAILURE);
            }
            else{ 
                cout<<"SSL/TLS pipe successful"<<endl;
                if (SSL_accept(ssl) <= 0) {
                    cout << "Failed to accept incoming DTLS connection" << endl;
                    unsigned long err_code = SSL_get_error(ssl, -1); // Get SSL error code
                    switch (err_code) {
                        case SSL_ERROR_SSL:
                            // A failure in the SSL library occurred, often due to protocol error.
                            // Retrieve the detailed reason from the error queue.
                            {
                                unsigned long lib_err = ERR_get_error();
                                switch (ERR_GET_REASON(lib_err)) {
                                    case SSL_R_NO_SHARED_CIPHER:
                                        std::cerr << "No shared cipher could be selected." << std::endl;
                                        break;
                                    // Add more cases as needed
                                    default:
                                        std::cerr << "SSL error, reason: " << ERR_reason_error_string(lib_err) << std::endl;
                                }
                            }
                            // Add more cases as needed for other SSL_ERROR_ constants
                        default:
                            cerr << "SSL_accept error, code: " << err_code << endl;
                    }
                    ERR_print_errors_fp(stderr);
                    SSL_shutdown(ssl);
                    close(server_fd);
                    SSL_CTX_free(ctx);
                    exit(EXIT_FAILURE);
                }
                
                STACK_OF(SSL_CIPHER) *client_ciphers = SSL_get_client_ciphers(ssl);
                if (client_ciphers) {
                    STACK_OF(SSL_CIPHER) *server_ciphers = SSL_CTX_get_ciphers(SSL_get_SSL_CTX(ssl));
                    
                    if (server_ciphers) {
                        // Iterate through the client's supported cipher suites
                        for (int i = 0; i < sk_SSL_CIPHER_num(client_ciphers); i++) {
                            const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(client_ciphers, i);
                            const char *cipher_name = SSL_CIPHER_get_name(cipher);
                            bool supported = false;
                            cout<<cipher_name<<endl;
                            
                            // Iterate through the server's configured cipher suites
                            for (int j = 0; j < sk_SSL_CIPHER_num(server_ciphers); j++) {
                                const SSL_CIPHER *server_cipher = sk_SSL_CIPHER_value(server_ciphers, j);
                                const char *server_cipher_name = SSL_CIPHER_get_name(server_cipher);
                                
                                // Check if the client's cipher suite matches a server's configured cipher suite
                                if (strcmp(cipher_name, server_cipher_name) == 0) {
                                    supported = true;
                                    break; // Match found, exit the loop
                                }
                            }
                            
                            // Check if the client's cipher suite is supported by the server
                            if (supported) {
                                // Cipher suite is supported by both client and server
                                // Do something
                                cout<<"\vclient and server are compatible with cipher suits"<<endl;
                                break;
                            } else {
                                // Cipher suite is not supported by the server
                                cout<<"client and server are not compatible with cipher suits\n"<<endl;
                                const char *error_msg = "Error: Mismatched Cipher Suite";
                                SSL_write(ssl, error_msg, strlen(error_msg));
                                memset(&client_addr, 0, sizeof(client_addr));
                                continue;
                            }
                        }
                    } else {
                        cout<<"server_ciphers is NULL"<<endl;
                        const char *error_msg = "chat_close";
                        SSL_write(ssl, error_msg, strlen(error_msg));
                        memset(&client_addr, 0, sizeof(client_addr));
                        continue;
                    }
                } else {
                    cout<<"client_ciphers is NULL"<<endl;
                    const char *error_msg = "chat_close";
                    SSL_write(ssl, error_msg, strlen(error_msg));
                    memset(&client_addr, 0, sizeof(client_addr));
                    continue;
                }

                // Check if session was resumed
                if (SSL_session_reused(ssl)) {
                    cout << "Session Resumed" << endl;
                } else {
                    cout << "New Session" << endl;
                }

                SSL_SESSION *session = SSL_get1_session(ssl);

                peer_cert = SSL_get_peer_certificate(ssl);
                if(peer_cert != nullptr)
                {
                    cout<<endl;
                }
                else
                {
                    cout<<"h"<<endl;
                    ERR_print_errors_fp(stderr);
                    SSL_free(ssl);
                    SSL_CTX_free(ctx);
                    abort();
                }
                int result = verify_the_certificate(ssl);
                if(result == X509_V_OK)
                {
                    cout<<"\nClient Certificate Valid\n\n";
                    chat_start_ssl = 1;
                }
            }
        }
        else{

            cout<<"\nStarting unsecure communication over UDP"<<endl;
            cout<<"\nClient: ";
            cout<<message;
            cout<<endl;

            struct pollfd fds[2]; // Two file descriptors for bidirectional communication
            fds[0].fd = server_fd; // Server's socket for receiving
            fds[0].events = POLLIN;
            fds[1].fd = fileno(stdin); // Standard input for sending
            fds[1].events = POLLIN;


            while (true)
            {
                if (poll(fds, 2, -1) > 0) {

                    if (fds[0].revents & POLLIN) {
                    char receive_message[BUF_SIZE];
                    memset(receive_message, 0, BUF_SIZE);
                    recvfrom(server_fd, receive_message, BUF_SIZE, 0, (struct sockaddr *)&client_addr, (socklen_t *)sizeof(client_addr));
                    if ((strncmp(receive_message, "chat_close", 10)) == 0)
                    {
                        cout << "Connection terminated by Client\n";
                        break;
                    }
                    cout << "Client: " << receive_message<<"\n";
                    }

                    if (fds[1].revents & POLLIN) {

                        char message_buffer[BUF_SIZE];
                        string s;
                        getline(cin, s);
                        int n = s.size();
                        for (int i = 0; i < n; i++)
                        {
                            message_buffer[i] = s[i];
                        }
                        message_buffer[n] = '\0';
                        sendto(server_fd, message_buffer, strlen(message_buffer) + 1, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
                        if ((strncmp(message_buffer, "chat_close", 10)) == 0)
                        {
                            cout << "Connection Terminated\n";
                            break;
                        }
                    }
                }  
            }
        }

        if((chat_hello== 1) && (chat_start_ssl ==1))
        {

            struct pollfd fds[2]; // Two file descriptors for bidirectional communication
            fds[0].fd = server_fd; // Server's socket for receiving
            fds[0].events = POLLIN;
            fds[1].fd = fileno(stdin); // Standard input for sending
            fds[1].events = POLLIN;

            while (true) {
                if (poll(fds, 2, -1) > 0) {
                    if (fds[0].revents & POLLIN) {
                        char receive_buffer[BUF_SIZE];
                        int bytes_received = SSL_read(ssl, receive_buffer, BUF_SIZE);
                        if (bytes_received <= 0) {
                            ERR_print_errors_fp(stderr);
                            break;
                        }
                        receive_buffer[bytes_received] = '\0';
                        cout << "Client: " << receive_buffer << std::endl;
                        if (string(receive_buffer) == "chat_close") {
                            string m = "Connection terminated from Client";
                            cout << m << endl;
                            SSL_write(ssl, m.c_str(), m.length());
                            break;
                        }
                       
                    }
                    if (fds[1].revents & POLLIN) {
                        string s;
                        getline(cin, s);
                        int n = s.size();
                        SSL_write(ssl, s.c_str(), n);
                        if (s == "chat_close") {
                            cout << "Connection terminated by server" << endl;
                            break;
                        }
                    }
                }
            }
        }
        else if ((chat_hello== 1) && (chat_start_ssl ==0)){

            memset(&client_addr, 0, sizeof(client_addr));
            // sleep(20);
            continue;

        }
        else{
            cout<<"No chat_hello recieved!!"<<endl;
            cout<<"\nConnection Not Established\n"<<endl;
            SSL_free(ssl);    
            SSL_CTX_free(ctx);
            close(server_fd);
            abort();
        }

    }
    cout<<"exit";
    close(server_fd);

}

int client(const char *hostname)
{

    X509 *cert;
    X509 *peer_cert;
    SSL_CTX *ctx;
    SSL *ssl;
    struct timeval timeout;

    int tls_flag = 0;
    int communication_flag = 0;

    int client_sd;
    char send_buffer[BUF_SIZE];
    char receive_buffer[BUF_SIZE];
    struct hostent *host;

    struct sockaddr_in server_addr;

    load_session_cache("session_cache.txt");

    struct timeval tv;
    tv.tv_sec = 10; // Timeout in seconds
    tv.tv_usec = 0;


    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    ctx = create_client_context();
    // SSL_CTX_set_session_ticket_cb(ctx, generate_session_ticket, decrypt_session_ticket, NULL);
    SSL_CTX_set_security_level(ctx,1);
    // SSL_CTX_sess_set_new_cb(ctx, external_cache);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT); // Enable session caching
    SSL_CTX_set_session_id_context(ctx, (const unsigned char *)"DTLS", strlen("DTLS")); // Set session ID context

    if ((host = gethostbyname(hostname)) == NULL)
    {
        perror(hostname);
        abort();
    }

    if ((client_sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
        cerr << "Failed to create socket" << std::endl;
        abort();
    }
    
    // Set socket options to receive with timeout
    if (setsockopt(client_sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("Error setting socket timeout");
        close(client_sd);
        abort();
    }

    bzero(&server_addr, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = *(long *)(host->h_addr);

    cout << "\nClient Socket Created\n"
         << endl;
    // sleep(10);
    cout << "You: chat_hello" << endl;
    connect(client_sd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in));
    sendto(client_sd, "chat_hello\0", strlen("chat_hello\0") + 1, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
    int bytes_received = recvfrom(client_sd, receive_buffer, BUF_SIZE, 0, (struct sockaddr *)&server_addr, (socklen_t *)sizeof(server_addr));
    if (bytes_received < 0) {
        if ((errno == EWOULDBLOCK || errno == EAGAIN )) {
            // Timeout occurred, handle accordingly
            cout<<endl;
            cout<<"You: chat_close"<<endl;
            cout<<endl;
            cout<< "Timeout: No message received from server, Packet might be lost\n";
            cout<<"Terminating the connection"<<endl;
            cout<<endl;
            sendto(client_sd, "chat_close\0", strlen("chat_close\0") + 1, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
            close(client_sd);
            abort(); 
        }
    }
    if(string(receive_buffer) == "chat_close")
    {
        cout<<"Server: chat_close"<<endl;
        cout<<endl;
        cout<<"Connection Terminated by Server"<<endl; 
        close(client_sd);
        abort();
    }

    cout << "Server: " << string(receive_buffer) << endl;
    if ((strncmp(receive_buffer, "chat_ok_reply", 13)) == 0)
    {
        communication_flag = 1;
    }
    
    cout << "You: chat_START_SSL" << endl;
    // sleep(10);
    sendto(client_sd, "chat_START_SSL\0", strlen("chat_START_SSL\0") + 1, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
    bytes_received = recvfrom(client_sd, receive_buffer, BUF_SIZE, 0, (struct sockaddr *)&server_addr, (socklen_t *)sizeof(server_addr));
    if (bytes_received < 0) {
        if ((errno == EWOULDBLOCK || errno == EAGAIN )) {
            // Timeout occurred, handle accordingly
            cout<<endl;
            cout<<"You: chat_close"<<endl;
            cout<<endl;
            cout << "Timeout: No message received from server, Packet might be lost\n";
            cout<<"Terminating the connection"<<endl;
            cout<<endl;

            sendto(client_sd, "chat_close\0", strlen("chat_close\0") + 1, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
            close(client_sd);
            abort(); 
        } 
    }
    if(string(receive_buffer) == "chat_close")
    {
        cout<<"Server: chat_close"<<endl;
        cout<<endl;
        cout<<"Connection Terminated by Server"<<endl; 
        close(client_sd);
        abort();
    }
    tv.tv_sec = 0;
    if (setsockopt(client_sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            perror("Error removing socket timeout");
            close(client_sd);
            exit(EXIT_FAILURE);
    }
    cout << "Server: " << string(receive_buffer) << endl;
    if ((strncmp(receive_buffer, "chat_START_SSL_ACK", 18)) == 0)
    {

        if (SSL_CTX_use_certificate_file(ctx, "/root/alice/alice.pem", SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, "/root/alice/alice_private_key.pem", SSL_FILETYPE_PEM) <= 0)
        {
            cout << "\nKey file not valid" << endl;
            ERR_print_errors_fp(stderr);
            abort();
        }
        if (!SSL_CTX_check_private_key(ctx))
        {
            cout << "\nKey not match with certificate file" << endl;
            abort();
        }

        ssl = SSL_new(ctx); 

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

        SSL_CTX_load_verify_locations(ctx, "/root/alice/chainOfTrust.pem", NULL);

        if (ssl == nullptr)
        {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            close(client_sd);
            abort();
        }

        //

        SSL_set_fd(ssl, client_sd);

        // Check if there is a cached session for resumption
        // SSL_SESSION *cached_session = get_cached_session("example_session_id"); // Implement this function to retrieve cached session
        // if (cached_session != nullptr) {
        //     cout<<"hi1"<<endl;
        //     cout<<SSL_session_reused(ssl)<<endl;
        //     cout<<cached_session<<endl;
        //     cout<<"12"<<endl;
        //     if(!ssl) cout<<"null"<<endl;
        //     if(!cached_session) cout<<"null2"<<endl;
        //     // SSL_SESSION_set1_id_context(cached_session, (const unsigned char *)&"DTLS", sizeof("DTLS"));
        //     SSL_set_session(ssl, (SSL_SESSION *)cached_session); // Set the cached session for resumption
        // }
        // // cout<<"hi"<<endl;
        

        // if (SSL_session_reused(ssl)) {
        //     cout << "Session Resumed" << endl;
        // } else {
        // cout << "New Session" << endl;
        // }  

        // Create a datagram BIO
        // BIO *bio = BIO_new_dgram(client_sd, BIO_CLOSE);
        // if (!bio) {
        //     // Handle error
        //     return -1;
        // }

        // // Set the timeout for the BIO
        // struct timeval tv;
        // tv.tv_sec = 2; // 5-second timeout
        // tv.tv_usec = 0;
        // if (BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &tv) <= 0) {
        //     // Handle error
        //     BIO_free(bio);
        //     return -1;
        // }
        // SSL_set_bio(ssl, bio, bio);

        int retval = SSL_connect(ssl);

        // SSL_SESSION *session = SSL_get1_session(ssl);
        //     // Check if the SSL_SESSION object is not null before calling SSL_SESSION_up_ref
        // if (session != nullptr) {
        //     cout<<"1"<<endl;
        //     SSL_SESSION_up_ref(session);  // Increment reference count
        //     // Use the SSL_SESSION object or perform other operations
        // }
        // cache_session("example_session_id", session);
        // save_session_cache("session_cache.txt");

        // if(session){
        //     SSL_SESSION_free(session);
        // }

        SSL_SESSION *session = SSL_get_session(ssl);

        if (session != NULL) {
            // Check if the session is resumable
            if (SSL_SESSION_is_resumable(session)) {
                printf("Session is resumable.\n");
            } else {
                printf("Session is not resumable.\n");
            }
        } else {
            printf("Session is NULL.\n");
        }

        if (retval <= 0)
        {
            switch (SSL_get_error(ssl, retval))
            {
            case SSL_ERROR_ZERO_RETURN:
                fprintf(stderr, "SSL_connect failed with SSL_ERROR_ZERO_RETURN\n");
                break;
            case SSL_ERROR_WANT_READ:
                fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_READ\n");
                break;
            case SSL_ERROR_WANT_WRITE:
                fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_WRITE\n");
                break;
            case SSL_ERROR_WANT_CONNECT:
                fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_CONNECT\n");
                break;
            case SSL_ERROR_WANT_ACCEPT:
                fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_ACCEPT\n");
                break;
            case SSL_ERROR_WANT_X509_LOOKUP:
                fprintf(stderr, "SSL_connect failed with SSL_ERROR_WANT_X509_LOOKUP\n");
                break;
            case SSL_ERROR_SYSCALL:
                fprintf(stderr, "SSL_connect failed with SSL_ERROR_SYSCALL\n");
                break;
            case SSL_ERROR_SSL:
                fprintf(stderr, "SSL_connect failed with SSL_ERROR_SSL\n");
                break;
            default:
                fprintf(stderr, "SSL_connect failed with unknown error\n");
                break;
            }

            ERR_print_errors_fp(stderr);
            abort();
        }
        else
        {
            int result = verify_the_certificate(ssl);
            if (result == X509_V_OK)
            {
                cout << "\nServer Certificate Valid\n";
                tls_flag = 1;
            }
        }
    }


    if ((communication_flag == 1) && (tls_flag == 1))
    {
        cout << "SSL/TLS pipe successful\n";
        cout<<endl;
        struct pollfd fds[2]; // Two file descriptors for bidirectional communication
        fds[0].fd = client_sd; // Client's socket for receiving
        fds[0].events = POLLIN;
        fds[1].fd = fileno(stdin); // Standard input for sending
        fds[1].events = POLLIN;

        while (true) {
            if (poll(fds, 2, -1) > 0) {
                if (fds[0].revents & POLLIN) {
                    char message_buffer[BUF_SIZE];
                    int bytes_received = SSL_read(ssl, message_buffer, BUF_SIZE);
                    message_buffer[bytes_received] = '\0';
                    cout << "Server: " << message_buffer << std::endl;
                    if ((strncmp(message_buffer, "chat_close", 10)) == 0)
                    {
                        cout << "\nConnection Terminated from Server\n"<< endl;
                        // cout<<"Attempting for resumption"<<endl;
                        // SSL_SESSION *cached_session =  SSL_get1_session(ssl);; // Implement this function to retrieve cached session
                        // if (cached_session != nullptr) {
                        //     SSL_shutdown(ssl);
                        //     SSL_free(ssl);
                        //     close(client_sd);

                        //     client_sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                        //     ssl = SSL_new(ctx);
                        //     SSL_set_session(ssl,cached_session);
                        //     if(SSL_connect(ssl)<0) 
                        //     {
                        //         cout<<"Exiting"<<endl;
                        //         break;
                        //     }
                        // }
                        break;
                    }
                }
                if (fds[1].revents & POLLIN) {
                    string s;
                    getline(cin, s);
                    int n = s.size();
                    SSL_write(ssl, s.c_str(), n);
                    if (s== "chat_close")
                    {
                        cout << "\nConnection Terminated\n"<< endl;
                        break;
                    }
                }
            }
        }

    }
    else if ((communication_flag == 1) && (tls_flag == 0))
    {
        cout<<"\nStarting unsecure communication over UDP"<<endl;
        struct pollfd fds[2]; // Two file descriptors for bidirectional communication
        fds[0].fd = client_sd; // Client's socket for receiving
        fds[0].events = POLLIN;
        fds[1].fd = fileno(stdin); // Standard input for sending
        fds[1].events = POLLIN;
        while (true)
        {
            if (poll(fds, 2, -1) > 0) {

                if (fds[0].revents & POLLIN) {
                    char receive_message[BUF_SIZE];
                    memset(receive_message, 0, BUF_SIZE);
                    recvfrom(client_sd, receive_message, BUF_SIZE, 0, (struct sockaddr *)&server_addr, (socklen_t *)sizeof(server_addr));
                    if ((strncmp(receive_message, "chat_close", 10)) == 0)
                    {
                        cout << "Connection terminated from Server\n";
                        break;
                    }
                    cout << "Server: " << receive_message << "\n";
                }

                if (fds[1].revents & POLLIN) {
                    char message_buffer[BUF_SIZE];
                    string s;
                    getline(cin, s);
                    int n = s.size();
                    for (int i = 0; i < n; i++)
                    {
                        message_buffer[i] = s[i];
                    }
                    message_buffer[n] = '\0';
                    sendto(client_sd, message_buffer, strlen(message_buffer) + 1, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
                    if ((strncmp(message_buffer, "chat_close", 10)) == 0)
                    {
                        cout << "Connection Terminated\n";
                        break;
                    }
                }
            }
        }
    }
    else
    {
        cout << "\nERROR:Connection Not Established\n";
        close(client_sd);
        abort();
    }
    close(client_sd);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <-s | -c serverIP>" << std::endl;
        return 1;
    }

    if (strcmp(argv[1], "-s") == 0) {
        server();
    } else if (strcmp(argv[1], "-c") == 0 && argc == 3) {
        client(argv[2]);
    } else {
        std::cerr << "Invalid argument. Use <-s | -c serverIP>" << std::endl;
        return 1;
    }

    return 0;
}