Name: Azan Nazaar
Email: anazar1@binghamton.edu

Note: 
- All commands are capitalized (i.e. NICK, USER, TIME, etc.)
- '>>' is used for the terminal and not to be entered 
- Under client.conf, make sure that SERVER_IP=y.y.y.y is set to the
value outputted by running "hostname -I", before running (same concept for server config files)

In order to compile the program enter:
>> make

For creating respective servers, the formt to follow when entering is:
>> ./server <server.conf file for respective server>

Since the server registration was really buggy, placed "printf(":waiting for server registration...\n");"
as an indicator for the current server to register itself with the following 3 commands beneath:

PASS:
- For entering the password to register the server, the <password> should match
the string given in the respective server.conf file. The format is:
Pass <password> <version> <flags> [<options>]

A real-time example where <password> = password, would be:  
PASS password 0210010000 IRC|aBgH$ Z


SERVER:
- For registering a server name where <servername> should be the IP address such as
by using the command "hostname -I" where the format should look like:
SERVER <servername> <hopcount> <token> <info>

A real-time example for this would be
SERVER 128.226.114.206 5 34 :Experimental server


NICK:
- For registering the nickname and realname of the server where the sample format is:
NICK  <nickname> <hopcount> <username> <host> <servertoken> <umode> <realname>

A real-time example for this would be 
NICK syrk 5 kalt millennium.stealth.net 34 +i :Christophe Kalt




// client is to be used after modifications are made and when ""
For example
>> ./client <client.conf>


Then once inside, new clients are prompeted to enter a nickname, then
register with both a username and real_name. The following commands are
shown below with their respective uses, 


PASS:
- For entering the password to register the client, the format would be:
Pass <password>

A real-time example would be:  
PASS password 


NICK:
- For making OR changing the nickname and is one of the requirements
before a client can be fully registered. The format for this would be:
NICK <nickname> :<password>

A real-time example would be:  
NICK Wiz :wizpassword


USER:
- For making a user with username and real_name and is the 2nd requirement
before a client can be registered. The format for this would be:
USER <username> 0 * :<realname>

A real-time example would be:  
USER guest 0 * :Ronnie Reagan


// Commands once the user has been registered
QUIT:
- For quitting where message can be anything like "left for the bathroom":
QUIT :<message>

A real-time example would be:  
QUIT :left


SQUIT:
- For quitting the server and associated clients where the message can be anything like "left for the bathroom":
SQUIT <server> :<message>

A real-time example would be:  
SQUIT 128.226.114.206 :leaving


JOIN:
- For creating/joining channels with the current user and has the following
formats:
JOIN <channel name starting with either #, & or !>
JOIN <channel 1>,<channel 2>,...
JOIN 0

A real-time example would be: 
Join #r,#t,!u


NJOIN:
- For merging clients from different servers into one where the format looks like: 
NJOIN <channel> <nickname> <nickname>

A real-time example would be: 
NJOIN #a jelly peanut


PART:
- For leaving specific channel(s). Has the following format:
PART <channel name>
PART <channel1>,<channel2>...

A real-time example would be: 
PART #twilight_zone


TOPIC:
- For setting, clearing or viewing the topic of a channel respectively. Has the 
following format:
TOPIC <channel name> :<topic to set>
TOPIC <channel name> :
TOPIC <channel name>

A real-time example would be: 
TOPIC #test


NAMES:
- For listing out all the names or names of users in channel(s). The format
is the following:  
NAMES <channel>
NAMES <channel1>,<channel2>...
NAMES

A real-time example would be:
NAMES #twilight_zone,#42


PRIVMSG: 
- For sending private messages to userss where format is as follows:
PRIVMSG <recipient> :<message>

Real-time examples would be:
PRIVMSG Angel :yes I'm receiving it !
PRIVMSG #a :Hello there rest of a!


TIME:
- For printing out the time of the message. The only acceptable command is:
TIME


EXTRA NOTES
- Registering the server in the beginngin with other ones is extremely buggy and has not been tested
- For QUIT & PRIVMSG, continue entering other commands as sometimes the message will be printed 
in the next output, but should return to normal after a few commands