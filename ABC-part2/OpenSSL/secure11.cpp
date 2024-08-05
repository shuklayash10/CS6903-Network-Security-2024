#include<iostream>
#include<cstring>
#include<sys/socket.h>
#include<arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>

#define PORT 14000
#define BUF_SIZE 1024

#define COOKIE_SECRET_LENGTH 16
unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
int cookie_initialized=0;

using namespace std;

void error(const char *msg) {
    perror(msg);
    exit(1);
}


int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
	{
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} peer;

	/* Initialize a random secret */
	if (!cookie_initialized)
		{
		if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH))
			{
			printf("error setting random cookie secret\n");
			return 0;
			}
		cookie_initialized = 1;
		}

	/* Read peer information */
	(void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	/* Create buffer with peer's address and port */
	length = 0;
	switch (peer.ss.ss_family) {
		case AF_INET:
			length += sizeof(struct in_addr);
			break;
		case AF_INET6:
			length += sizeof(struct in6_addr);
			break;
		default:
			OPENSSL_assert(0);
			break;
	}
	length += sizeof(in_port_t);
	buffer = (unsigned char*) OPENSSL_malloc(length);

	if (buffer == NULL)
		{
		printf("out of memory\n");
		return 0;
		}

	switch (peer.ss.ss_family) {
		case AF_INET:
			memcpy(buffer,
			       &peer.s4.sin_port,
			       sizeof(in_port_t));
			memcpy(buffer + sizeof(peer.s4.sin_port),
			       &peer.s4.sin_addr,
			       sizeof(struct in_addr));
			break;
		case AF_INET6:
			memcpy(buffer,
			       &peer.s6.sin6_port,
			       sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
			       &peer.s6.sin6_addr,
			       sizeof(struct in6_addr));
			break;
		default:
			OPENSSL_assert(0);
			break;
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
	     (const unsigned char*) buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	memcpy(cookie, result, resultlength);
	*cookie_len = resultlength;

	return 1;
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
	{
	unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	union {
		struct sockaddr_storage ss;
		struct sockaddr_in6 s6;
		struct sockaddr_in s4;
	} peer;

	/* If secret isn't initialized yet, the cookie can't be valid */
	if (!cookie_initialized)
		return 0;

	/* Read peer information */
	(void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	/* Create buffer with peer's address and port */
	length = 0;
	switch (peer.ss.ss_family) {
		case AF_INET:
			length += sizeof(struct in_addr);
			break;
		case AF_INET6:
			length += sizeof(struct in6_addr);
			break;
		default:
			OPENSSL_assert(0);
			break;
	}
	length += sizeof(in_port_t);
	buffer = (unsigned char*) OPENSSL_malloc(length);

	if (buffer == NULL)
		{
		printf("out of memory\n");
		return 0;
		}

	switch (peer.ss.ss_family) {
		case AF_INET:
			memcpy(buffer,
			       &peer.s4.sin_port,
			       sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
			       &peer.s4.sin_addr,
			       sizeof(struct in_addr));
			break;
		case AF_INET6:
			memcpy(buffer,
			       &peer.s6.sin6_port,
			       sizeof(in_port_t));
			memcpy(buffer + sizeof(in_port_t),
			       &peer.s6.sin6_addr,
			       sizeof(struct in6_addr));
			break;
		default:
			OPENSSL_assert(0);
			break;
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
	     (const unsigned char*) buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
		return 1;

	return 0;
	}

SSL_CTX *create_server_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = DTLSv1_server_method();

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
    int chat_ok_reply=0;
    int chat_start_ssl_ack =0;
    int server_fd;
    int client_fd;
    char send_buffer[BUF_SIZE];
    char recieve_buffer[BUF_SIZE];
    struct timeval timeout;
    X509* cert;
    X509* peer_cert;
    SSL *ssl;
    SSL_CTX *ctx;
    // struct sockaddr_in server_addr, client_addr;
    union {
		struct sockaddr_storage ss;
		struct sockaddr_in s4;
		struct sockaddr_in6 s6;
	} server_addr, client_addr;
    socklen_t client_addr_size;
    char buf[BUF_SIZE];

    // Create a UDP socket
    if ((server_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        error("Error opening socket");
        abort();
    }

    // Fill server address structure
    memset((char *)&server_addr, 0, sizeof(server_addr));
    server_addr.s4.sin_family = AF_INET;
    server_addr.s4.sin_addr.s_addr = inet_addr("192.168.0.101");
    server_addr.s4.sin_port = htons(PORT); 

    // Bind the socket to the server address
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        error("Binding failed");
        close(server_fd);
        abort();
    }

    client_addr_size = sizeof(client_addr);

    cout << "Server is waiting for incoming connections...\n";

    memset(recieve_buffer, 0, BUF_SIZE);
    recvfrom(server_fd, recieve_buffer, BUF_SIZE, 0, (struct sockaddr *)&client_addr, &client_addr_size);
    string message(recieve_buffer);
    if(message == "chat_close")
    {
        cout<<"You: Bye!"<<endl; 
        close(server_fd);
        abort();
    }
    if(message == "chat_hello")
    {
        chat_ok_reply=1;
        cout<<"Client: "<<message<<endl;
        string reply = "chat_ok_reply";
        cout<<"You: "<<reply<<endl;
        sendto(server_fd, reply.c_str(), reply.length(), 0, (struct sockaddr *)&client_addr, client_addr_size);
        memset(recieve_buffer, 0, BUF_SIZE);
        recvfrom(server_fd, recieve_buffer, BUF_SIZE, 0, (struct sockaddr *)&client_addr, &client_addr_size);
        message = string(recieve_buffer);
    
        if(message == "chat_START_SSL")
        {
            chat_start_ssl_ack = 1;
            cout<<"Client: "<<message<<endl;
            string reply = "chat_START_SSL_ACK";
            reply += '\0';
            cout<<"You: "<<reply<<endl;
            sendto(server_fd, reply.c_str(), reply.length()+1, 0, (struct sockaddr *)&client_addr, client_addr_size);
            SSL_library_init();
            
            ctx = create_server_context();
            
            SSL_CTX_set_cipher_list(ctx, "ALL:NULL:eNULL:aNULL");
	        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
            
            configure_context(ctx, "/home/yug/Desktop/secure chat/Secure-chat-using-openssl-and-MITM-attacks-main/secure_chat_app/bobcert.pem", "/home/yug/Desktop/secure chat/Secure-chat-using-openssl-and-MITM-attacks-main/secure_chat_app/bob.pem");//put server certificates file names
            SSL_CTX_load_verify_locations(ctx, "/home/yug/Desktop/secure chat/Secure-chat-using-openssl-and-MITM-attacks-main/Root/rootCA.crt", NULL);
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE , NULL);
            // SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT
            SSL_CTX_set_options(ctx, SSL_OP_NO_QUERY_MTU);
            SSL_CTX_set_read_ahead(ctx, 1);
            SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
	        SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);
            ssl = SSL_new(ctx);

            // Create SSL structure
            if (!ssl) {
                ERR_print_errors_fp(stderr);
                close(server_fd);
                SSL_CTX_free(ctx);
                exit(EXIT_FAILURE);
            }

            // Set client address for SSL connection
            BIO *bio = BIO_new_dgram(server_fd, BIO_CLOSE);
            /* Set and activate timeouts */
		    timeout.tv_sec = 5;
		    timeout.tv_usec = 0;
            BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
            // BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &client_addr.ss);
            SSL_set_bio(ssl, bio, bio);
            // SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
            cout<<"before accept"<<endl;
            // Perform DTLS handshake
            if (DTLSv1_listen(ssl, (BIO_ADDR*)&client_addr) <= 0) { //SSL_accept(ssl) <= 0 DTLSv1_listen(ssl, &client_addr) <= 0
                cout<<"hi";
                ERR_print_errors_fp(stderr);
                SSL_shutdown(ssl);
                close(server_fd);
                SSL_CTX_free(ctx);
                exit(EXIT_FAILURE);
            }
            else{
                cout<<"successful"<<endl;
                char client_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(client_addr.s4.sin_addr), client_ip, INET_ADDRSTRLEN);
                unsigned int client_port = ntohs(client_addr.s4.sin_port);
                cout << "Client connected from IP: " << client_ip << ", Port: " << client_port << endl;

                // peer_cert = SSL_get_peer_certificate(ssl);
                // if(peer_cert != nullptr)
                // {
                //     // cout<<" 4here in this\n";
                //     cout<<"hello"<<endl;
                //     X509_NAME_print_ex_fp(stdout, X509_get_subject_name(peer_cert), 0, XN_FLAG_ONELINE);
                // }
                // else
                // {
                //     cout<<"h"<<endl;
                //     ERR_print_errors_fp(stderr);
                //     SSL_free(ssl);
                //     SSL_CTX_free(ctx);
                //     abort();
                // }
                // int result = verify_the_certificate(ssl);
                // if(result == X509_V_OK)
                // {
                //     cout<<"\nClient Certificate Valid\n";
                //     chat_start_ssl_ack = 1;
                // }
                while (true) {
                    char receive_buffer[BUF_SIZE];
                    int bytes_received = SSL_read(ssl, receive_buffer, BUF_SIZE);
                    if (bytes_received <= 0) {
                        ERR_print_errors_fp(stderr);
                        break;
                    }

                    cout << "Client: " << receive_buffer << endl;

                    // Handle application logic here

                    string message;
                    if (string(receive_buffer) == "term") {
                        message = "Connection terminated from Client";
                        cout << message << endl;
                        SSL_write(ssl, message.c_str(), message.length());
                        break;
                    }

                    cout << "You:" << endl;
                    getline(cin, message);

                    SSL_write(ssl, message.c_str(), message.length());
                    if (message == "term") {
                        cout << "Connection terminated by server" << endl;
                        break;
                    }
                }
            }
        }
        else
        {
            cout<<"No chat_START_SSL recieved!!"<<endl;
            char answer;
            cout<<"Want to communicate over unsecure channel(Y/N)?";
            cin>>answer;
            if(answer == 'Y')
            {
                while (true) {
                    char receive_buffer[BUF_SIZE];
                    memset(receive_buffer, 0, BUF_SIZE);

                    // Receive message from client
                    if (recvfrom(server_fd, receive_buffer, BUF_SIZE, 0, (struct sockaddr *)&client_addr, &client_addr_size) < 0) {
                        error("Error on receiving");
                        close(server_fd);
                        exit(EXIT_FAILURE);
                    }

                    cout << "Client: " << receive_buffer << endl;

                    // Check if the received message is "term" to terminate the connection
                    if (strcmp(receive_buffer, "chat_close") == 0) {
                        cout << "\nConnection terminated from Client\n" << endl;
                        break;
                    }

                    // Prompt the user to enter a message for the client
                    string message;
                    cout << "\nEnter message for Client on socket: " << endl;
                    getline(cin, message);

                    // Copy the message to the send buffer and send it to the client
                    strncpy(send_buffer, message.c_str(), BUF_SIZE);
                    if (sendto(server_fd, send_buffer, strlen(send_buffer) + 1, 0, (struct sockaddr *)&client_addr, client_addr_size) < 0) {
                        error("Error on sending");
                        close(server_fd);
                        exit(EXIT_FAILURE);
                    }

                    // Check if the sent message is "term" to terminate the connection
                    if (strcmp(send_buffer, "chat_close") == 0) {
                        cout << "\nConnection terminated by server\n" << endl;
                        break;
                    }
                }

            }
            else if(answer =='N'){
                
                cout<<"\nBye\n"<<endl;
                SSL_free(ssl);    
                SSL_CTX_free(ctx);
                close(server_fd);
                abort();

            }
            else{
                cout<<"Inappropriate Answer"<<endl;
                cout<<"\nBye\n"<<endl;
                SSL_free(ssl);    
                SSL_CTX_free(ctx);
                close(server_fd);
                abort();
            }
        }
    }
    else
    {
        cout<<"No chat_hello recieved!!"<<endl;
        cout<<"\nConnection Not Established\n"<<endl;
        SSL_free(ssl);    
        SSL_CTX_free(ctx);
        close(server_fd);
        abort();
    }
    cout<<"exit";
    close(server_fd);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <-s | -c serverIP>" << std::endl;
        return 1;
    }

    if (strcmp(argv[1], "-s") == 0) {
        server();
    } else if (strcmp(argv[1], "-c") == 0 && argc == 3) {
        // client(argv[2]);
    } else {
        std::cerr << "Invalid argument. Use <-s | -c serverIP>" << std::endl;
        return 1;
    }

    return 0;
}