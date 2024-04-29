#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <regex>
#include <string>
#include <fstream> // file operations
#include <openssl/sha.h> // for Base64 encoding
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

using namespace std;

#define MAXDATASIZE 510 // max bytes can get at once

// Function to parse the client.conf file
pair<string, string> parseConfig(const string& filename) {
    ifstream configFile(filename);
    if (!configFile.is_open()) {
        cout << "Error: Unable to open config file." << endl;
        exit(1);
    }
    string line;
    string serverIP, serverPort;
    while (getline(configFile, line)) {
        size_t pos = line.find('=');
        if (pos != string::npos) {
            string key = line.substr(0, pos);
            string value = line.substr(pos + 1);
            if (key == "SERVER_IP") {
                serverIP = value;
            } else if (key == "SERVER_PORT") {
                serverPort = value;
            }
        }
    }
    return {serverIP, serverPort};
}

// Function to encode a string to Base64
string base64_encode(const string& in) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_write(bio, in.c_str(), static_cast<int>(in.length()));
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return result;
}

int main(int argc, char *argv[]) {
    struct addrinfo hints, *servinfo, *p;
    int sockfd, numbytes, rv;
    char buf[MAXDATASIZE];
    string message;

    if (argc != 2) {
        cout << "format: " << argv[0] << " <client.conf>" << endl;
        return 1;
    }

    // Parse the client.conf file
    pair<string, string> serverConfig = parseConfig(argv[1]);

    string SERVER_IP = serverConfig.first;
    string SERVER_PORT = serverConfig.second;
    const char *PORT = SERVER_PORT.c_str();

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(SERVER_IP.c_str(), PORT, &hints, &servinfo)) != 0) {
        cout << "getaddrinfo: " << gai_strerror(rv) << endl;
        return 1;
    }

    // loop through all the results and connect to the first we can
    for (p = servinfo; p != nullptr; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,p->ai_protocol)) == -1) {
            perror("client: socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("client: connect");
            continue;
        }
        break;
    }

    if (p == nullptr) {
        cout << "client: failed to connect" << endl;
        return 2;
    }

    freeaddrinfo(servinfo); // all done with this structure

    while (true) {
        getline(cin, message);
        
        if (message.substr(0, 4) == "PASS") { // Check for PASS command
            string password = message.substr(5);
            string encoded_password = base64_encode(password); // Encode password in Base64
            string pass_command = "PASS " + encoded_password; // Format/send PASS command
            send(sockfd, pass_command.c_str(), pass_command.length(), 0);
        } else {
            send(sockfd, message.c_str(), message.length(), 0);
        }

        // Receive response from the server (if any)
        if ((numbytes = recv(sockfd, buf, MAXDATASIZE - 1, 0)) == -1) {
            perror("recv");
            exit(1);
        }

        if (numbytes == 0) {
            cout << "Connection closed by server" << endl;
            break;
        }

        buf[numbytes] = '\0';
        cout << buf;
    }

    close(sockfd);
    return 0;
}