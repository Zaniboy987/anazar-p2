// PASS, NICK, SERVER, SQUIT
// PASS <password> <version> <flags> [<options>] / last 3 useless
// SERVER <servername> <hopcount> <token> <info> // last 3 useless
// NICK <nickname> <hopcount> <username> <host> <servertoken> <umode> <realname> // nickname and realname important
// SQUIT <server> <comment> // comment is useless
// NJOIN <channel> [ "@@" / "@" ] [ "+" ] <nickname> *( "," [ "@@" / "@" ] [ "+" ] <nickname> ) // channel is like proj1
// SECTION 5.3 and PART 3 and 4
// run multiple server.conf files

#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <regex>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>
#include <thread>
#include <semaphore.h>
#include <mutex>
#include <ctime>
#include <algorithm>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
using namespace std;

#define MAXDATASIZE 510 // max bytes can get at once
#define BACKLOG 10      // pending queue connections limit
mutex clientsMutex;

class Server {
public:
    int sockfd;
    string servername, nickname, realname;
    vector<string> connect_IP;
    vector<int> connect_sock;

    Server(string servername) : servername(servername) {}
};

class Client {
public:
    int index, sockfd, onChannel;
    bool registered, nick, user, passEntered;
    string nickname, username, realname;

    Client(int index, int sockfd) : index(index), sockfd(sockfd), registered(false), nick(false), user(false), onChannel(0) {}
};

class Channel {
    public:
        string channelName, topic;
        vector<string> users;

        Channel(string channelName, string topic) : channelName(channelName), topic(topic) {}
};

vector<Client> clients; // for multi-users
vector<Channel> channels; // vector of channels
vector<Server> servers; // for multi-servers
sem_t sem; // control # active connections

// Function prototypes
void handle_client(int sockfd);
int send_message(int sockfd, const string& message);
string get_current_time();

// regex functions
regex pass_regex("^PASS\\s+(\\S+)$"); // for clients
regex nick_regex("^NICK\\s+(\\S+)\\s+:([\\S]+)$");
regex user_regex("^USER\\s+(\\S+)\\s+(.+)$");
regex quit_regex("^QUIT\\s+:(.*)$");
regex join_regex("^JOIN\\s+((([&#+!][^,]+)|0)(\\s*,\\s*(([&#+!][^,]+)|0))*)$"); // good for serv too
regex part_regex("^PART\\s+((([&#+!][^,]+)|0)(\\s*,\\s*(([&#+!][^,]+)|0))*)(\\s+:(.*))?$");
regex topic_regex("^TOPIC\\s+((([&#+!][^,]+)|0))(\\s+:(.*))?$"); 
regex names_regex("^NAMES(\\s+([&#+!][^,]+(?:,\\s*([&#+!][^,]+))*)?)?$");
regex privmsg_regex("^PRIVMSG\\s+(\\S+)\\s+:(.*)$");
regex time_regex("^TIME\\s*$");
regex passS_regex("^PASS\\s+(\\S+)\\s+(\\d+)\\s+(\\S+)\\s+(\\S+)$"); // for servers
regex server_regex("^SERVER\\s+((?:\\d{1,3}\\.){3}\\d{1,3})\\s+(\\d+)\\s+(\\d+)\\s+(.*)$");
regex nickS_regex("^NICK\\s+([a-zA-Z0-9]+)\\s+(\\d+)\\s+([a-zA-Z0-9]+)\\s+([a-zA-Z0-9.]+)\\s+(\\d+)\\s+([+-]?[a-zA-Z]+)\\s+:(.*)$"); // ADD ON
regex NJOIN_regex("^NJOIN\\s+([^\\s]+)\\s+([^\\s]+)\\s+([^\\s]+)\\s*$");
regex Squit_regex("^SQUIT\\s+([^\\s]+)\\s+:(.*)$");

string nickname_of_server;
string server_password;

void sigchld_handler(int s) {
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;
    errno = saved_errno;
}

// get sockaddr, IPv4 or IPv6:
void* get_in_addr(struct sockaddr* sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int send_message(int sockfd, const string& message) {
    return send(sockfd, message.c_str(), message.length(), 0);
}

struct ServerConfig {
    string NICK;
    string PORT;
    string PASS;
    vector<pair<string, string>> SOCK_ADDR;
};

ServerConfig parseServerConfig(const string& configFileName) {
    ServerConfig config;
    ifstream configFile(configFileName);
    if (!configFile.is_open()) {
        cout << "Error: Unable to open config file." << endl;
        exit(1);
    }
    string line;
    while (getline(configFile, line)) {
        istringstream iss(line);
        string key, value;
        getline(iss, key, '=');
        getline(iss, value);
        if (key == "NICK") {
            config.NICK = value;
            nickname_of_server = value;
        } else if (key == "PORT") {
            config.PORT = value;
        } else if (key == "PASS") {
            config.PASS = value;
            server_password = value;
        } else if (key == "SOCK_ADDR") {
            size_t pos = value.find(':');
            if (pos != string::npos) {
                string ip = value.substr(0, pos);
                string socket_num = value.substr(pos + 1);
                config.SOCK_ADDR.push_back(make_pair(ip, socket_num));
            }
        }
    }
    return config;
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

void handle_client(int sockfd) {
    sem_wait(&sem); // Wait until a slot is available
    char buf[MAXDATASIZE];
    string nickname, username, realname, repass; 
    bool user = false, nick = false, registered = false, first = true, passEntered = false;
    Client client(clients.size(), sockfd);
    int clientIndex = client.index;

    // Limit the maximum number of processes to 8
    if (clients.size() >= 8) {
        cout << "Max number of clients reached. Closing connection." << endl;
        close(sockfd);
        sem_post(&sem); // Release the slot
        return;
    }

    while (true) {
        int bytes_received = recv(sockfd, buf, MAXDATASIZE - 1, 0);
        if (bytes_received == -1) {
            perror(":recv");
            close(sockfd);
            sem_post(&sem); // Release the slot
            exit(1);
        } else if (bytes_received == 0) {
            continue;
        } else {
            buf[bytes_received] = '\0';
            string message(buf);
            smatch match;
            bool commandRecognized = false;

            if (regex_match(message, match, pass_regex)) { // PASS command
                lock_guard<mutex> lock(clientsMutex);
                commandRecognized = true;
                if (!passEntered) {
                    string password = match.str(1);

                    // Decode the received password from Base64
                    BIO *bio, *b64;
                    b64 = BIO_new(BIO_f_base64());
                    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
                    bio = BIO_new_mem_buf(password.c_str(), -1);
                    bio = BIO_push(b64, bio);

                    char decode_buffer[MAXDATASIZE];
                    int decoded_length = BIO_read(bio, decode_buffer, password.length());
                    decode_buffer[decoded_length] = '\0';
                    string decoded_password(decode_buffer);

                    if (decoded_password == server_password) {
                        commandRecognized = true;
                        // Respond to the client
                        string response = ":" + nickname_of_server + " :Password correct for user " + client.nickname + "\r\n";
                        cout << response;
                        send_message(client.sockfd, response);
                        passEntered = true, client.passEntered = true;                            
                    } else {
                        string response = ":" + nickname_of_server + " 464 :Password incorrect\r\n";
                        cout << response;
                        send_message(client.sockfd, response);
                    }
                } else {
                    string err_response = ":" + nickname_of_server + " 462 " + nickname + " :Unauthorized command (already registered)\r\n";
                    cout << err_response;
                    send_message(client.sockfd, err_response);
                }
            } // end of PASS command

            if (regex_match(message, match, nick_regex)) { // NICK COMMAND
                lock_guard<mutex> lock(clientsMutex);
                commandRecognized = true;
                nickname = match.str(1);
                string nickPass, temp_pass, fromusr_pass;
                size_t colon_pos = message.find(':');
                if (colon_pos != string::npos) {
                    temp_pass = message.substr(colon_pos + 1); // get password after ':'
                } else {
                    string err_response = ":" + nickname_of_server + " 432 " + nickname + " :Erroneous nickname\r\n";
                    cout << err_response;
                    send_message(client.sockfd, err_response);
                    continue;
                }

                for (const auto& c : clients) {
                    if (c.nickname == nickname) {
                        string err_response = ":" + nickname_of_server + " 431 " + nickname + " :Nickname is already in use\r\n";
                        cout << err_response;
                        send_message(client.sockfd, err_response);
                        continue;
                    }
                }

                nickPass = base64_encode(temp_pass);
                bool nickname_found = false, password_matched = false;
                
                // Read from .usr_pass file
                ifstream passwordFile(".usr_pass");
                if (passwordFile.is_open()) {
                    string line;
                    while (getline(passwordFile, line)) {
                        istringstream iss(line);
                        string stored_nickname, stored_pass;
                        getline(iss, stored_nickname, ':');
                        getline(iss, stored_pass);
                        if (stored_nickname == nickname) { // If nickname matches
                            nickname_found = true;
                            fromusr_pass = stored_pass;
                        } }
                    passwordFile.close();
                }

                // Decode the received password from Base64
                BIO *bio, *b64;
                b64 = BIO_new(BIO_f_base64());
                BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
                bio = BIO_new_mem_buf(fromusr_pass.c_str(), -1);
                bio = BIO_push(b64, bio);

                char decode_buffer[MAXDATASIZE];
                int decoded_length = BIO_read(bio, decode_buffer, fromusr_pass.length());
                decode_buffer[decoded_length] = '\0';
                string decoded_password(decode_buffer);

                if (decoded_password == temp_pass) {
                    password_matched = true;
                }
                
                if (nickname_found && !password_matched) { // Nickname found but password mismatch
                    string err_response = ":" + nickname_of_server + " 464 " + nickname + " :Password incorrect\r\n";
                    cout << err_response;
                    send_message(client.sockfd, err_response);
                    continue;
                }

                if (clients.empty() || !client.nick) { // for beginning when nickname 1st being set
                    client.nick = true;
                    client.nickname = nickname;
                    string response = ":" + nickname_of_server + " :Nickname set to " + nickname + "\r\n";
                    ofstream passwordFile(".usr_pass", ios_base::app);
                    if (passwordFile.is_open()) {
                        passwordFile << client.nickname << ":" << nickPass << endl; // Save nickname and password
                        passwordFile.close();
                    }
                    send_message(client.sockfd, response);
                    cout << response;
                } else {
                    client.nickname = nickname;
                    string response = ":" + nickname_of_server + " :Nickname changed to " + nickname + "\r\n";
                    ofstream passwordFile(".usr_pass", ios_base::app);
                    if (passwordFile.is_open()) {
                        passwordFile << client.nickname << ":" << nickPass << endl; // Save nickname and password
                        passwordFile.close();
                    }
                    cout << response;
                    send_message(client.sockfd, response);
                }     
                nick = true;
                client.nick = nick;
            } // end of NICK command
            
            if (regex_match(message, match, user_regex)) { // USER COMMAND
                lock_guard<mutex> lock(clientsMutex);
                commandRecognized = true;
                username = match.str(1);
                realname = match.str(2);

                for (const auto& c : clients) {
                    if (c.username == username) {
                        string err_response = ":" + nickname_of_server + " 462 " + username + " :Username is already in use\r\n";
                        cout << err_response;
                        send_message(client.sockfd, err_response);
                    }
                }

                if (!client.user) { // for beginning when user being set
                    client.user = true;
                    client.username = username;
                    client.realname = realname;
                    string response; 
                    string response1="";
                    if (realname.substr(0, 5) == "0 * :") {
                        response = ":" + nickname_of_server + " :Username set to " + username + " and real name set to " + realname.substr(5) + "\r\n";
                    } else {
                        response = ":" + nickname_of_server + " :Username set to " + username + " and real name set to " + realname + "\r\n";
                    }
                    
                    if (client.user) {
                        client.registered = true;
                    }

                    send_message(client.sockfd, response1);
                    cout << "USER " << username << " " << realname << "\r\n" << response1;
                } else {
                    lock_guard<mutex> lock(clientsMutex);
                    string response;
                    if (realname.substr(0, 5) == "0 * :") {
                        response = ":" + nickname_of_server + " :Username set to " + username + " and real name set to " + realname.substr(5) + "\r\n";
                    } else {
                        response = ":" + nickname_of_server + " :Username set to " + username + " and real name set to " + realname + "\r\n";
                    }
                    cout << response;
                    send_message(client.sockfd, response);
                }

                user = true;
                client.user = user;
            } // end of USER command
            
            if (user && nick && passEntered) { // REGISTER AFTER NICK AND USER
                registered = true;
                client.registered = true;
            } 
            
            if (registered && first) { // PRINT REGISTRATION MESSAGE
                string response = ":" + nickname_of_server + " 001 :Welcome to Calculus IRC " + nickname + "!" + username + "@" + nickname_of_server + "\r\n";
                send_message(client.sockfd, response);
                first = false;
                clients.push_back(client);
            } 
            
            if (regex_match(message, match, quit_regex)) { // QUIT COMMAND
                lock_guard<mutex> lock(clientsMutex);
                commandRecognized = true;

                if (client.registered) {
                    // Send quit message
                    string quit_message = "Client disconnected";
                    string quit_response = ":" + nickname_of_server + " " + client.nickname + " QUIT :" + quit_message + "\r\n";
                    send_message(client.sockfd, quit_response);
                    cout << quit_response;

                    // Close the socket and remove the client from the vector
                    close(client.sockfd);
                    clients.erase(clients.begin() + client.index);

                    // Update indexes of remaining clients
                    for (size_t i = client.index; i < clients.size(); i++) {
                        clients[i].index = i;
                    }
                } else {
                    string response = ":" + nickname_of_server + " 451 :You have not registered\r\n";
                    send_message(client.sockfd, response);
                    cout << response;
                }
                break;
            } // end of QUIT command

            if (regex_match(message, match, Squit_regex)) { // SQUIT COMMAND
                lock_guard<mutex> lock(clientsMutex);
                commandRecognized = true;

                string server = match[1];
                string comment = match[2];

                if (server != servers.at(0).servername){
                    string err_response = ":" + nickname_of_server + " 402 " + server + ":No such server\r\n";
                    send_message(client.sockfd, err_response);
                    cout << err_response;
                    continue;
                }

                // Send quit message
                string quit_response = ":" + nickname_of_server + " " + servers.at(0).servername + " QUIT :" + comment + "\r\n";
                send_message(client.sockfd, quit_response);
                cout << quit_response;

                close(client.sockfd);
                clients.clear();
                exit(1);
            } // end of SQUIT command
            
            if (regex_match(message, match, join_regex)) { // JOIN COMMAND
                lock_guard<mutex> lock(clientsMutex);
                commandRecognized = true;

                if (!client.registered) { // Check if the client is registered
                    string err_response = ":" + nickname_of_server + " 451 :You have not registered\r\n";
                    send_message(client.sockfd, err_response);
                    cout << err_response;
                    continue;
                }

                string val = match.str(1);

                if (val == "0") { // remove client from every channel
                    for (int b = 0; b < channels.size(); b++) {
                        for (int c = 0; c < channels.at(b).users.size(); c++) {
                            if (channels.at(b).users.at(c) == client.nickname) {
                                if (channels.at(b).users.size() == 1 || c == channels.at(b).users.size() - 1) {
                                    channels.at(b).users.pop_back();
                                } else {
                                    string temp = channels.at(b).users.at(channels.at(b).users.size() - 1);
                                    channels.at(b).users.at(c) = temp;
                                    channels.at(b).users.pop_back();
                                }
                                clients.at(b).onChannel = 0; 
                            } 
                        } 
                    }
                    string err_response = ":" + nickname_of_server + " " + client.nickname + ":Left all channels\r\n";
                    send_message(client.sockfd, err_response);
                    cout << err_response;
                    continue;
                } // Leave all currently joined channels.

                if (val != "0") {
                    stringstream ss(val);
                    string channelName, response = "";
                    while (getline(ss, channelName, ',')) {
                        bool isOnChannel = false, channelExists = false, firstTime = false;
                        string currTopic;
                        int i;

                        // Check if channelName is valid (starts with '#', '&', '+', or '!')
                        if (channelName.empty() || (channelName[0] != '#' && channelName[0] != '&' && channelName[0] != '+' && channelName[0] != '!')) {
                            string err_response = ":" + nickname_of_server + " 403 " + client.nickname + " " + channelName + " :No such channel\r\n";
                            send_message(client.sockfd, err_response);
                            cout << err_response;
                            continue;
                        }

                        for (i = 0; i < channels.size(); i++) { // check if client is on channel already
                            if (channels.at(i).channelName == channelName) {
                                for (int j = 0; j < channels.at(i).users.size(); j++) {
                                    if (channels.at(i).users.at(j) == client.nickname) {
                                        isOnChannel = true;
                                    } } }
                        }

                        if (isOnChannel && channels.size() > 0) { // Check if client already joined the channel
                            string err_response = ":" + nickname_of_server + " 443 " + client.nickname + " " + channelName + " :is already on channel\r\n";
                            send_message(client.sockfd, err_response);
                            cout << err_response;
                            continue;
                        }

                        string join_response = ":" + client.nickname + "!~" + client.username + "@" + nickname_of_server + " JOIN :" + channelName + "\n";
                        response += join_response;

                        for (i = 0; i < channels.size(); i++){ // add client to existing channel
                            if(channels.at(i).channelName == channelName) {
                                channels.at(i).users.push_back(client.nickname);
                                currTopic = channels.at(i).topic;
                                channelExists = true;

                                response += ":" + nickname_of_server + " 353 " + client.nickname + " = " + channels.at(i).channelName + " :";
                                for (const auto& user : channels.at(i).users) {
                                    response += user + " ";
                                }
                                response += "\n";
                                cout << response;
                            }
                        }

                        if( (channels.size() > 0) && (!channelExists)) { // adding user to newly created channel when at least 1
                            Channel newChannel(channelName, "");
                            channels.push_back(newChannel);
                            channels.at(channels.size() - 1).users.push_back(client.nickname);
                            currTopic = channels.at(channels.size()-1).topic;
                            client.onChannel++;
                            response += ":" + nickname_of_server + " 353 " + client.nickname + " = " + channels.at(channels.size() - 1).channelName + " :" + channels.at(channels.size() - 1).users.at(0) + "\n";
                        }

                        if(channels.size() == 0) { // adding channel when none are there
                            Channel newChannel(channelName, "");
                            channels.push_back(newChannel);
                            channels.at(0).users.push_back(client.nickname);
                            currTopic = "";
                            firstTime = true, client.onChannel = 1;     
                        }

                        if (currTopic == "") { // Send channel topic to client
                            string topic_response = ":" + nickname_of_server + " 331 " + channelName + " :No topic is set\n";
                            response += topic_response;
                        } else {
                            string topic_response = ":" + nickname_of_server + " 332 " + channelName + " :" + currTopic + "\n";
                            response += topic_response;
                        }

                        if (firstTime) {
                            response += ":" + nickname_of_server + " 353 " + client.nickname + " = " + channels.at(channels.size() - 1).channelName + " :" + channels.at(channels.size() - 1).users.at(0) + "\n";
                        }
                    }
                    cout << response;
                    send_message(client.sockfd, response);                    
                }
            }  // end of JOIN command

            if (regex_match(message, match, NJOIN_regex)) { // NJOIN COMMAND: NJOIN <channel> <nickname> <nickname>
                lock_guard<mutex> lock(clientsMutex);
                commandRecognized = true;

                if (!client.registered) { // Check if the client is registered
                    string err_response = ":" + nickname_of_server + " 451 :You have not registered\r\n";
                    send_message(client.sockfd, err_response);
                    cout << err_response;
                    continue;
                }

                if (match.size() != 4) { // check for 3 parameters
                    string err_response = ":" + nickname_of_server + " 461 " + client.nickname + " NJOIN :Not enough parameters\r\n";
                    send_message(client.sockfd, err_response);
                    cout << err_response;
                    continue;
                }

                string channelName = match[1];
                string nickname1 = match[2];
                string nickname2 = match[3];

                if (client.registered) { // Check if the client is already registered
                    string err_response = ":" + nickname_of_server + " 462 " + client.nickname + " :Unauthorized command (already registered)\r\n";
                    send_message(client.sockfd, err_response);
                    cout << err_response;
                    continue;
                }

                bool channelExists = false;

                for (const auto& channel : channels) { // Check if the channel exists
                    if (channel.channelName == channelName) {
                        channelExists = true;
                    }
                }

                if (!channelExists) { // If the channel doesn't exist, merge it with the servers clients
                    Channel newChannel(channelName, "");
                    channels.push_back(newChannel);
                }

                string njoin_message = ":" + nickname_of_server + " NJOIN " + channelName + " :";
                for (const auto& channel : channels) {
                    if (channel.channelName == channelName) {
                        for (const auto& user : channel.users) {
                            njoin_message += user + " ";
                        }
                        break;
                    }
                }
                njoin_message += "; NJOIN message from " + client.nickname + "\r\n";
                send_message(client.sockfd, njoin_message);
                cout << njoin_message;

            } // end of NJOIN 

            if (regex_match(message, match, part_regex)) { // PART COMMAND
                lock_guard<mutex> lock(clientsMutex);
                commandRecognized = true;

                if (!client.registered) { // Check if the client is registered
                    string err_response = ":" + nickname_of_server + " 451 :You have not registered\r\n";
                    send_message(client.sockfd, err_response);
                    cout << err_response;
                    continue;
                }

                string val = match.str(1);
                string part_message = match.str(6);
                string response="";
                bool isOnChannel = false;

                if (val.find(',') == std::string::npos) { // PART #a
                    for (int i = 0; i < channels.size(); i++) {
                        int j;
                        for (j = 0; j < channels.at(i).users.size(); j++) {
                            if (channels.at(i).users.at(j) == client.nickname) {
                                isOnChannel = true;
                                break;
                            } 
                        }

                        if (channels.at(i).channelName == val && isOnChannel) {
                            if (channels.at(i).users.size() == 1 || j == channels.at(i).users.size() - 1) {
                                channels.at(i).users.pop_back();
                            } else {
                                string temp = channels.at(i).users.at(channels.at(i).users.size() - 1);
                                channels.at(i).users.at(j) = temp;
                                channels.at(i).users.pop_back();
                            }
                        }
                        isOnChannel = false;
                    }
                    // Send PART message to the channel
                    response += ":" + client.nickname + "!~" + client.username + "@" + nickname_of_server + " PART " + val;
                    if (!part_message.empty()) {
                        response += " :" + message;
                    }
                    response += "\r\n";
                } else {
                    // Split channels string by comma
                    stringstream ss(val);
                    string channelName, response;
                    while (getline(ss, channelName, ',')) {
                        int i, j;
                        isOnChannel = false;
                        // Check if channelName is valid (starts with '#', '&', '+', or '!')
                        if (channelName.empty() || (channelName[0] != '#' && channelName[0] != '&' && channelName[0] != '+' && channelName[0] != '!')) {
                            string err_response = ":" + nickname_of_server + " 403 " + client.nickname + " " + channelName + " :No such channel\r\n";
                            send_message(client.sockfd, err_response);
                            cout << err_response;
                            continue;
                        }

                        for (int b = 0; b < channels.size(); b++) { // Check client on channel
                            if (channels.at(i).channelName == channelName) {
                                for (int c = 0; c < channels.at(i).users.size(); c++) {
                                    if (channels.at(i).users.at(j) == client.nickname) {
                                        isOnChannel = true, i=b, j=c;
                                    } } }
                        }

                        if (!isOnChannel) { // Check if client is on the channel
                            string err_response = ":" + nickname_of_server + " 442 " + client.nickname + " " + channelName + " :You're not on that channel\r\n";
                            send_message(client.sockfd, err_response);
                            cout << err_response;
                            continue;
                        }

                        if (channels.at(i).users.size() == 1 || j == channels.at(i).users.size() - 1) {
                            channels.at(i).users.pop_back();
                        } else {
                            string temp = channels.at(i).users.at(channels.at(i).users.size() - 1);
                            channels.at(i).users.at(j) = temp;
                            channels.at(i).users.pop_back();
                        }
                        client.onChannel--;                        

                        // Send PART message to the channel
                        response += ":" + client.nickname + "!~" + client.username + "@" + nickname_of_server + " PART " + channelName;
                        if (!part_message.empty()) {
                            response += " :" + message;
                        }
                        response += "\r\n";
                    }
                }
                send_message(client.sockfd, response);
                cout << response;
            } // end of PART command

            if (regex_match(message, match, topic_regex)) { // TOPIC COMMAND
                lock_guard<mutex> lock(clientsMutex);
                commandRecognized = true;

                // Check if the client is registered
                if (!client.registered) {
                    string err_response = ":" + nickname_of_server + " 451 :You have not registered\r\n";
                    send_message(client.sockfd, err_response);
                    cout << err_response;
                    continue;
                }

                string value = match.str(1);
                string newTopic;
                string channelName;
                bool first = false, sec = false, third = false;

                // Check if the value matches the format "#<channel> :<topic>"
                if (value.size() >= 2 && (value[0] == '#' || value[0] == '$' || value[0] == '+' || value[0] == '!')) {
                    first = true;
                    // Extract channel name
                    size_t pos = value.find(' ');
                    if (value[pos + 1] == ':') {
                        sec = true;
                        channelName = value.substr(0, pos);

                        // Check if newTopic is not empty
                        if (value[pos + 2] != '\0') {
                            third = true;
                            newTopic = value.substr(pos + 2);
                            for (int i = 0; i < channels.size(); i++) {
                                auto& c = channels.at(i);
                                if (c.topic == "") {
                                    c.topic = newTopic;
                                    string topic_response = ":" + nickname_of_server + " 332 " + client.nickname + " " + channelName + " :" + newTopic + "\r\n";
                                    send_message(client.sockfd, topic_response);
                                    cout << topic_response;
                                    break;
                                } } } }
                }

                // Check if the client not on the channel
                if (channels.size() == 0) {
                    string err_response = ":" + nickname_of_server + " 442 " + client.nickname + " " + channelName + " :You're not on that channel\r\n";
                    send_message(client.sockfd, err_response);
                    cout << err_response;
                    continue;
                }

                if (!first) {
                    string response = ":" + nickname_of_server + " 461 " + client.nickname + " TOPIC :Not enough parameters\r\n";
                    cout << response;
                    continue;
                }

                bool channelIsThere = false, clientOnChannel = false;
                int channelIndex = 0;

                // Find the channel
                for (int i = 0; i < channels.size(); i++) {
                    if (channels.at(i).channelName == channelName) {
                        channelIsThere = true;
                        channelIndex = i;
                    }
                }

                if (!channelIsThere) {
                    string err_response = ":" + nickname_of_server + " 403 " + client.nickname + " " + channelName + " :No such channel\r\n";
                    send_message(client.sockfd, err_response);
                    cout << err_response;
                    continue;
                }

                for (int i = 0; i < channels.at(channelIndex).users.size(); i++) {
                    if (channels.at(channelIndex).users.at(i) == nickname) {
                        clientOnChannel = true;
                    }
                }

                if (!clientOnChannel) {
                    string err_response = ":" + nickname_of_server + " 442 " + client.nickname + " " + channelName + " :You're not on that channel\r\n";
                    send_message(client.sockfd, err_response);
                    cout << err_response;
                    continue;
                }

                if (first && sec && !third) { // If no topic provided, return the current topic
                    channels.at(channelIndex).topic.clear();
                    string topic_response = ":" + nickname_of_server + client.nickname + " " + channelName + " :Topic reset\r\n";
                    send_message(client.sockfd, topic_response);
                    cout << topic_response;
                } else if (sec && !(third)) { // If empty string, remove the topic
                    string topic_response = ":" + nickname_of_server + " 331 " + client.nickname + " " + channelName + " :" + channels.at(channelIndex).topic + "\r\n";
                    send_message(client.sockfd, topic_response);
                    cout << topic_response;
                } else { // Change the topic
                    channels.at(channelIndex).topic = newTopic;
                    string topic_response = ":" + client.nickname + "!~" + client.username + "@" + nickname_of_server + " TOPIC " + channelName + " :" + newTopic + "\r\n";
                    send_message(client.sockfd, topic_response);
                    cout << topic_response;
                }
            } // end of TOPIC command 

            if (regex_match(message, match, names_regex)) { // NAMES COMMAND
                lock_guard<mutex> lock(clientsMutex);
                commandRecognized = true;

                if (!client.registered) { // Check if the client is registered
                    string err_response = ":" + nickname_of_server + " 451 :You have not registered\r\n";
                    send_message(client.sockfd, err_response);
                    cout << err_response;
                    continue;
                }

                string channelList = match.str(1);
                string response="";
                response += ":" + client.nickname + "!~" + client.username + "@" + nickname_of_server + " NAMES " + channelList + "\r\n";

                if (channelList.empty()) { // No channels specified (e.g. NAMES)
                    for (int i = 0; i < channels.size(); i++){
                        response += ":" + nickname_of_server + " 353 " + client.nickname + " = " + channels.at(i).channelName + " :";
                        for (const auto& user : channels.at(i).users) {
                            response += user + " ";
                        }
                        response += "\r\n";
                    }

                    response += ":" + nickname_of_server + " 353 " + client.nickname + " * :"; // users not on any visible channel
                    for (int i = 0; i < clients.size(); i++) {
                        if (clients.at(i).nickname == client.nickname && client.onChannel == 0) {
                            response += clients.at(i).nickname + " ";
                        }
                    }
                    response += "\r\n";
                    send_message(client.sockfd, response);
                    cout << response;
                    continue;
                } 

                if (channels.size() == 0) { // if no channels added yet
                    response += ":" + nickname_of_server + " 353 " + client.nickname + " * :"; // users not on any visible channel
                    for (int i = 0; i < clients.size(); i++) {
                        if (clients.at(i).onChannel == 0) {
                            response += clients.at(i).nickname + " ";
                        }
                    }
                    response += "\r\n";
                    send_message(client.sockfd, response);
                    cout << response;
                    continue;
                }

                channelList = match.str(1).substr(1);
                if (channelList.find(',') == std::string::npos) { // NAMES #a
                    for (int i = 0; i < channels.size(); i++) {
                        if (channels.at(i).channelName == channelList) {
                            response += ":" + nickname_of_server + " 353 " + client.nickname + " = " + channels.at(i).channelName + "\r\n";
                        }
                    }
                } else { // channel(s) specified in NAMES (e.g. NAMES #a,#b)
                    stringstream ss(channelList);
                    string channelName;
                    while (getline(ss, channelName, ',')) {
                        for (int i = 0; i < channels.size(); i++){ // add client to existing channel
                            if(channels.at(i).channelName == channelName) {
                                response += ":" + nickname_of_server + " 353 " + client.nickname + " = " + channels.at(i).channelName + " :";
                                for (const auto& user : channels.at(i).users) {
                                    response += user + " ";
                                }
                                response += "\r\n";
                            } } }
                }
                response += ":" + nickname_of_server + " 353 " + client.nickname + " * :"; // users not on any visible channel
                for (int i = 0; i < clients.size(); i++) {
                    if (clients.at(i).nickname == client.nickname && client.onChannel == 0) {
                        response += clients.at(i).nickname + " ";
                    }
                }
                response += "\r\n";
                send_message(client.sockfd, response);
                cout << response;
            } // end of NAMES command

            if (regex_match(message, match, time_regex)) { // TIME command
                lock_guard<mutex> lock(clientsMutex);
                commandRecognized = true;

                if (client.registered) {
                    string current_time = get_current_time();
                    string response = ":" + client.nickname + "!~" + client.username + "@" + nickname_of_server + " 391 " + current_time + "\r";
                    cout << response;
                    send_message(client.sockfd, response);
                } else {
                    string response = ":" + nickname_of_server + " 451 :You have not registered\r\n";
                    send_message(client.sockfd, response);
                    cout << response;
                }
            } // end of Time command

            if (regex_match(message, match, privmsg_regex)) { // PRIVMSG COMMAND
                lock_guard<mutex> lock(clientsMutex);
                commandRecognized = true;

                if (!registered) {
                    string response = ":" + nickname_of_server + " 451 " + client.nickname + " :You have not registered\r\n";
                    send_message(client.sockfd, response);
                    cout << response;
                    continue;
                }

                string target = match.str(1);
                string msg = match.str(2);
                int targetIndex;

                bool is_channel = false; 
                for (const auto& c : channels) { // Check if the target is a user or a channel
                    if (c.channelName == target) {
                        is_channel = true;
                        break;
                    }
                }

                if (!is_channel) { // Check if the target user exists
                    bool target_exists = false;
                    for (const auto& c : clients) {
                        if (c.nickname == target) {
                            target_exists = true;
                            targetIndex = c.index;
                            break;
                        }
                    }
                    if (!target_exists) { // error response if target doesn't exist
                        string err_response = ":" + nickname_of_server + " 401 " + client.nickname + " " + target + " :No such nick/channel\r\n";
                        send_message(client.sockfd, err_response);
                        cout << err_response;
                        continue;
                    }
                }

                if (!is_channel) {
                    string privmsg_response = ":" + client.nickname + "!~" + client.username + "@" + nickname_of_server + " PRIVMSG " + target + " :" + msg + "\r\n";
                    send_message(clients.at(targetIndex).sockfd, privmsg_response);
                    cout << privmsg_response;
                }

                // If it's a channel, broadcast the message to all users in the channel
                if (is_channel) {
                    for (auto& channel : channels) {
                        if (channel.channelName == target) {
                            for (const auto& user : channel.users) {
                                for (const auto& c : clients) {
                                    if (c.nickname == user) {
                                        string privmsg_broadcast = ":" + client.nickname + "!~" + client.username + "@" + nickname_of_server + " PRIVMSG " + target + " :" + msg + "\r\n";
                                        send_message(c.sockfd, privmsg_broadcast);
                                        cout << privmsg_broadcast;
                                        break;
                                    } } } } } }
            } // end of PRIVMSG command
            
            if (!commandRecognized) { // if no command recognized
                string error_msg = ":" + nickname_of_server + " 451 " + message + " :Unknown command\r\n";
                send_message(client.sockfd, error_msg);
                cout << error_msg; 
            }
        }
    }
    sem_post(&sem); // Release the slot
}

string get_current_time() {
    time_t now = time(0);
    return ctime(&now);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cout << "Format: " << argv[0] << " <server.config>" << endl;
        return 1;
    }
    sem_init(&sem, 0, 8); // Initialize semaphore with value 8
    string configFileName = argv[1];
    ServerConfig serverConfig = parseServerConfig(configFileName);
    ServerConfig nickname_server = parseServerConfig(configFileName);
    int counter = 0;

    // Connect to servers specified in server.conf file
    while (counter <= 3) {
        auto addrIt = serverConfig.SOCK_ADDR.begin();
        while (addrIt != serverConfig.SOCK_ADDR.end()) {
            cout << "Trying to connect to " << addrIt->first << ":" << addrIt->second << endl;
            int serverSockfd;
            struct addrinfo hints, *servinfo, *p;
            int rv;

            memset(&hints, 0, sizeof hints);
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;

            if ((rv = getaddrinfo(addrIt->first.c_str(), addrIt->second.c_str(), &hints, &servinfo)) != 0) {
                cout << "getaddrinfo: " << gai_strerror(rv) << endl;
                addrIt++;
                continue;
            }

            for (p = servinfo; p != NULL; p = p->ai_next) {
                if ((serverSockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
                    perror("client: socket");
                    continue;
                }

                if (connect(serverSockfd, p->ai_addr, p->ai_addrlen) == -1) {
                    close(serverSockfd);
                    perror("Server: connect");
                    continue;
                }
                break;
            }

            if (p == NULL) {
                cout << "Server: failed to connect" << endl;
                addrIt++;
                freeaddrinfo(servinfo);
                continue;
            }

            cout << "Connected to server successfully!" << endl;

            freeaddrinfo(servinfo);
            break;
        }

        if (addrIt != serverConfig.SOCK_ADDR.end()) {
            break;
        }
        // Sleep for a while before retrying
        std::this_thread::sleep_for(std::chrono::seconds(1));
        counter++;
    }

    int sockfd, new_fd, rv;
    int yes = 1;
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr;
    struct sigaction sa;
    socklen_t sin_size;
    char s[INET6_ADDRSTRLEN];
    char port[6]; // for storing port number (maximum 5 digits + null terminator)

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rv = getaddrinfo(NULL, nickname_server.PORT.c_str(), &hints, &servinfo)) != 0) {
        cout << "getaddrinfo: " << gai_strerror(rv) << endl;
        return 1;
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror(":server socket");
            continue;
        }
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            perror(":setsockopt");
            exit(1);
        }
        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror(":server bind");
            continue;
        }
        break;
    }

    freeaddrinfo(servinfo);

    if (p == NULL) {
        fprintf(stderr, ":failed to bind server\n");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1) {
        perror(":listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror(":sigaction");
        exit(1);
    }
    printf(":waiting for server registration...\n");

    // server authentication
    bool isRegistered = false, passEntered = false, serverNamed = false, serverNicked = false;
    string servername, nickname, realname; 
    while (!isRegistered) {
        printf(">> ");
        string message;
        smatch match;
        getline(cin, message);

        if (regex_match(message, match, passS_regex)) { // PASS command for server
            if (!passEntered) {
                string password = match.str(1);
                if (password == server_password) {     
                    cout << ":" << nickname_of_server << " :Password is correct\n";
                    passEntered = true;                            
                } else {
                    cout << ":" << nickname_of_server << " :Password is incorrect\n";
                }
            } else if (!passEntered) {
                cout << ":Unauthorized command (already registered)" << endl;
            }
        } // end of PASS

        if (regex_match(message, match, server_regex)) { // SERVER command for server
            if (!serverNamed) {
                stringstream ss(match.str(1));
                string serv;
                getline(ss, serv, ' '); // Get string before first space
                cout << serv << " SERVER " << nickname_of_server << " " << match.str(2) << " " << match.str(3) << " " << match.str(4) << endl;
                servername = serv;
                serverNamed = true;
            } else if (serverNamed) {
                cout << ":Unauthorized command (already registered)" << endl;
            }
        } // end of SERVER

        if (regex_match(message, match, nickS_regex)) { // NICK command for server
            if (!serverNicked) {
                cout << match[1] << " NICK " << nickname_of_server << " :" << match.str(7) << endl;
                nickname = match[1], realname = match.str(7);
                serverNicked = true;
            } else if (serverNicked) {
                cout << ":Unauthorized command (already registered)" << endl;
            }
        } // end of SERVER

        if (passEntered && serverNamed && serverNicked) {
            isRegistered = true;
            Server currServer(servername);
            servers.push_back(currServer);
            servers.at(0).nickname = nickname;
            servers.at(0).realname = realname;
        }
    }

    printf(":waiting for connections...\n");
    while (1) {
        sin_size = sizeof their_addr;
        new_fd = accept(sockfd, (struct sockaddr*)&their_addr, &sin_size);
        if (new_fd == -1) {
            perror("accept");
            continue;
        }
        inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr*)&their_addr), s, sizeof s);

        // Get port number
        if (their_addr.ss_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&their_addr;
            snprintf(port, sizeof port, "%d", ntohs(sin->sin_port));
        } else {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&their_addr;
            snprintf(port, sizeof port, "%d", ntohs(sin6->sin6_port));
        }

        printf(":got connection from %s:%s\n", s, port); // Print IP address and port
        thread(handle_client, new_fd).detach(); // detach thread. allow to run independently
    }
    sem_destroy(&sem);
    return 0;
}