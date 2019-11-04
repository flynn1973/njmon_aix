/*
    njmonNG_collector.c -- receives data from njmon clients and saves as files or real-time injection into databases like ELK,Splunk,influxdb.
    injector programms can be of any kind,language. This is an alternative to the use of ssh. 
    Developer: Nigel Griffiths.
    (C) Copyright 2018 Nigel Griffiths

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
    
    See Makefile for compilation. 
 */

#define VERSION 31
#define PROTOCOL_VERSION "12NG"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include<pthread.h>
// slog library
#include "../slog/slog.h"

#define BUFSIZE 64 * 1024  /* larger = more efficient */
#define ERROR      42
#define LOG        44

#define SECRET_LENGTH 256
#define MAX_CONNECTIONS 1000

#define DEBUG if(debug)


char local_secret[SECRET_LENGTH] = {"Oxdeadbeef"};
char injector_command[4096] = {"/usr/local/bin/injector.py"};

// initialize the mutex
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

int debug = 0;
int socketfd;
int save_json;
int port;
int injector ;


int en[94] = {
 8, 85, 70, 53, 93, 72, 61,  1, 41, 36,
49, 92, 44, 42, 25, 58, 81, 15, 57, 10,
54, 60, 12, 45, 43, 91, 22, 86, 65,  9,
27, 18, 37, 39,  2, 68, 46, 71,  6, 79,
76, 84, 59, 75, 82,  4, 48, 55, 64,  3,
 7, 56, 40, 73, 77, 69, 88, 13, 35, 11,
66, 26, 52, 78, 28, 89, 51,  0, 30, 50,
34,  5, 32, 21, 14, 38, 19, 29, 24, 33,
47, 31, 80, 16, 83, 90, 67, 23, 20, 17,
74, 62, 87, 63 };


int de[94] = {
67,  7, 34, 49, 45, 71, 38, 50,  0, 29,
19, 59, 22, 57, 74, 17, 83, 89, 31, 76,
88, 73, 26, 87, 78, 14, 61, 30, 64, 77,
68, 81, 72, 79, 70, 58,  9, 32, 75, 33,
52,  8, 13, 24, 12, 23, 36, 80, 46, 10,
69, 66, 62,  3, 20, 47, 51, 18, 15, 42,
21,  6, 91, 93, 48, 28, 60, 86, 35, 55,
 2, 37,  5, 53, 90, 43, 40, 54, 63, 39,
82, 16, 44, 84, 41,  1, 27, 92, 56, 65,
85, 25, 11,  4 };

void mixup(char *s)
{
    int i;
    for (i = 0; s[i]; i++) {
	if(s[i] <= ' ') continue;
	if(s[i] >  '~') continue;
	s[i] = en[s[i]-33]+33;
    }
}

void unmix(char *s)
{
    int i;
    for (i = 0; s[i]; i++) {
	if(s[i] <= ' ') continue;
	if(s[i] >  '~') continue;
	s[i] = de[s[i]-33]+33;
    }
}



/* worker thread 
 * The new thread receives the pointer to the args struct and is responsible for freeing the allocated memory.
 * Using the convention of casting _args to args 
 */

void * socketThread(void *arg)
{ 
	int fd = *((int *)arg);
	int j;
        FILE * json_file_fd = (FILE *)0; 
	int bytes;
       	int ret;
	static char printbuffer[BUFSIZE+1]; 

	char preamble[256];
	char name[256];
	char hostname[256];
	char utc[256];
	char remote_secret[SECRET_LENGTH];
	char version[256];
	char postamble[256];
	FILE * pop = (FILE *)0;


	//printf("fd is %d - injector_command is %s - save_json is %d - port is %d - injector is %d\n",fd, injector_command, save_json, port, injector );
        
	
        uint32_t preamble_datalen;
        uint32_t preamble_netlen;

	int preamble_headerlength = 0;
        
	while(preamble_headerlength < 4){
        ret = recv(fd, &preamble_netlen+preamble_headerlength, 4-preamble_headerlength, 0);
              if (ret == -1) { break; };
              preamble_headerlength += ret;
        }
        DEBUG slog_debug(0,"START Transmission");
        DEBUG slog_debug(0,"%d bytes of preamble header received",ret);

	preamble_datalen = ntohl(preamble_netlen);

	DEBUG slog_debug(0,"client anounced %d bytes preamble messagelength",preamble_datalen);
	char * preamble_data = malloc(preamble_datalen+1);
        int preamble_total = 0; // return number actually sent here
        int preamble_bytesleft = preamble_datalen; // how many we have left to send

	while(preamble_total < preamble_datalen) {
	ret = recv(fd,preamble_total+preamble_data, preamble_bytesleft, MSG_WAITALL); 	/* receive preamble */
	     if (ret == -1) { break; };
	     preamble_total += ret;
             preamble_bytesleft -= ret;
        }

	DEBUG slog_debug(0,"%d bytes of preamble data were actually received from client",ret);
        	
	
	preamble_data[ret]=0;		/* terminate the buffer */
	unmix(preamble_data);
       
	for(j=0;j<ret-1;j++) {	/* check for illegal parent directory use .. */
		if(preamble_data[j] == '.' && preamble_data[j+1] == '.') {
			slog_error(0,"Parent directory (..) path names not supported character-position");
			exit(3);
		}
		if(preamble_data[j] == '\\') {
			slog_error(0,"Parent directory (\\) path names not supported character-position");
			exit(3);
		}
	}


	ret = sscanf(preamble_data, "%s %s %s %s %s %s %s", preamble, name, hostname, utc, remote_secret, version, postamble);
	slog_info(0,"New Request name=%s, hostname=%s, utc=%s, protocol-version=%s",name, hostname, utc, version);
	if( ret != 7) {
		slog_error(0,"Badly formed request returned %s, %s",preamble_data,ret);
		exit(3);
	}

	if(!isalnum(hostname[0]) ) /* alphabetic or number */ {
		slog_error(0,"Badly formed hostname start char %s, %s",hostname,hostname[0]);
	        exit(3);
	}
	for(j=0;j<strlen(hostname);j++) {
	    if(!isalnum(hostname[j]))
		/* hostname[j] = '_';  replace non-digit or letter with underscore */
            if(hostname[j] == '.')
		hostname[j] = 0;  /* replace fullstop with END of name */
	}
	for(j=0;j<strlen(utc);j++) {
	    if(utc[j] == '-' || utc[j] == ':' || utc[j] == 'T' )
		continue;
	    if(!isdigit(utc[j]))
		utc[j] = '_';  /* replace non-digit with underscore */
	}

	/* no checks for preamble and postamble as they are random */
	if( strncmp(utc,      "201", 3) ) {  /* works until 2020 year */
		slog_error(0,"Missing year in request %s",preamble_data);
	        exit(3);
	}
	if( strncmp(remote_secret,   local_secret, sizeof(local_secret)) ) {
		slog_error(0,"Missing remote_secret in request %s",preamble_data);
	        exit(3);
	}
	if( strncmp(version, PROTOCOL_VERSION, 4) ) {
		slog_error(0,"Missing or wrong version in request, maybe not NG? %s",preamble_data);
	        exit(3);
	}
	
          
                uint32_t nm_datalen;
                uint32_t nm_netlen;

                int nm_headerlength = 0;

		while(nm_headerlength < 4){
                    ret = recv(fd, &nm_netlen+nm_headerlength, 4-nm_headerlength, 0);
                    if (ret == -1) { break; };
                    nm_headerlength += ret;
               }   
               
	       DEBUG slog_debug(0,"%d bytes of njmon header received from client %s",ret,hostname);	

               nm_datalen = ntohl(nm_netlen);

	       DEBUG slog_debug(0,"client %s anounced %d bytes njmon messagelength",hostname, nm_datalen);
	        
	       char * nm_data = malloc(nm_datalen+1);
               int nm_total = 0; // return number actually sent here
               int nm_bytesleft = nm_datalen; // how many we have left to send

	       while(nm_total < nm_datalen) {
               ret = recv(fd, nm_total+nm_data, nm_bytesleft, MSG_WAITALL);       /* receive actual njmon data */
                   if (ret == -1) { break; };
                   nm_total += ret;
                   nm_bytesleft -= ret;
               }  
               
	      DEBUG slog_debug(0, "%d bytes of njmon data were actually received from client %s", ret, hostname); 

              nm_data[ret]=0;           /* terminate the buffer */



      	      if(save_json) {
			DEBUG slog_debug(0,"save_json reached");
			
			sprintf(printbuffer,"%s-%s.json", hostname, utc);
			if(( json_file_fd = fopen(printbuffer,"w")) == NULL) {
                        slog_error(0, "Failed to open file for writing, %s, %d",printbuffer,errno);
			exit(1);
                        }
			slog_info(0,"opened %s",printbuffer);

			if((bytes = fwrite(nm_data,1,strlen(nm_data),json_file_fd)) != strlen(nm_data)) {
				slog_error(0,"Failed to write JSON file %s,%s,%d",hostname,bytes,errno);
				exit(1);
			}
			//fflush(json_file_fd);
			fclose(json_file_fd);
		}

		   if(injector) {
                        DEBUG slog_debug(0, "injector reached");
                        DEBUG slog_debug(0,"Starting injector helper %s",injector_command);
                        errno = 0;
                        if ( (pop = popen(injector_command, "w") ) == NULL ) {
                        slog_error(0,"popen injector FAILED continue without injection %d",errno);
                        pop = 0;
                        }
			if (pop) {
				DEBUG slog_debug(0, "print to injector reached");
				if( (bytes = fwrite(nm_data,1,strlen(nm_data),pop)) != strlen(nm_data)) {
					slog_error(0,"Failed to write to injector %s,%s,%d",hostname,bytes,errno);
					pop = (FILE *)0; /* stop writing */
					exit(1);
				}
			}
			fflush(pop);
			pclose(pop);

                    }
       
        free(preamble_data); 
        free(nm_data);	
	DEBUG slog_debug(0, "closing socket");
	shutdown(fd,SHUT_WR);
	close(fd);
	DEBUG slog_debug(0, "exit thread");
	DEBUG slog_debug(0,"END Transmission");
	pthread_exit(NULL);
	          
}        



void hint(char *command)
{
	(void)printf(
	"hint: %s -p port -d directory [ -i ] [ -X secret ] [ -c injector_command ] -n -D\n"
	"or\n"
	"hint: %s -a collector.conf\n"
	"njmon Collector version=%d protocol=%s\n\n"
	"Do not mix the -a option with the command line options\n"
	"\tnjmonNG_collector daemon saves njmon output files\n"
	"\tExample: njmonNG_collector -p 8181 -d /home/nigel\n"
	"\tExample: njmonNG_collector -p 8181 -d /home/sally -i -X abcd1234\n"
	"\tExample: njmonNG_collector -p 8181 -d /home/janet -i -X beetlejuice -c /home/janet/injector_for_DB42.py -n\n\n"
	"\tDefault is just saving the file to the supplied directory based on hostname+date+time.json\n\n"
	"\tWith the -i option is also pipes the data to an injector to a stats database\n"
	"\t    You need to place a suitable injector for your stats database at %s (default).\n"
	"\t    Override the full pathname of the injector with the -c option. Normally a Python program.\n\n"
	"\tYou can set the shared secret (password or phrase) with the -X secret option.\n"
	"\t    Or set this to the NJMON_SECRET shell variable.\n\n"
	"\tIf using an injector then you can switch off saving to a JSON file with:\n"
	"\t    -n\n\n"
	"\tUse nohup if you want to run the program in the background\n\n"
	"\tUse -D flag for verbose logging\n\n"
	"\tcollector.conf contents should be like this:\n\n"
	"\t\tport=8181\n"
	"\t\tdirectory=/home/nag/njmondata\n"
	"\t\tsecret=abc123\n"
	"\t\tinject=1\n"
	"\t\tinjector=/usr/local/bin/njmon_for_linux_to_InfluxDB_injector_30.py\n"
	"\t\tjson=1\n"
	"Note: for inject and json options: 1=on and 0=off\n\n"
	"\tNo warranty given or implied\n"
	"\tNigel Griffiths nigelargriffiths@hotmail.com\n", 
		command, command, VERSION, PROTOCOL_VERSION, injector_command);
	exit(0);
}


int main(int argc, char **argv)
{
	
	char buffer[4096];
	int ch;
	int listenfd; 
	int line = 0;
	char *s;
	char *directory = 0;
	char *filename = 0;
	FILE * fp  = (FILE *)0;

        struct sockaddr_in serverAddr;
        struct sockaddr_storage serverStorage;
        socklen_t addr_size;

	// init slog config
	slog_init("njmon_collector", "slog.cfg", 1, 1);

	SlogConfig slgCfg;
        slog_config_get(&slgCfg);
        slgCfg.nToFile = 1;
	slgCfg.nFileStamp = 0;
	slgCfg.nPretty = 1;
	slgCfg.nLogLevel = 1;
	slgCfg.nFileLevel =3;	
        slog_config_set(&slgCfg);


        s = getenv("NJMON_SECRET");
        if(s != 0) { strncpy(local_secret, s, SECRET_LENGTH); }

        while (-1 != (ch = getopt(argc, argv, "h?Dp:d:c:X:ina:"))) {
                switch (ch) {
                case 'h':
                case '?':
                        hint(argv[0]);
                        break;
		case 'D':
                        debug=1;
                        break;
                case 'p':
                        port = atoi(optarg);
                        break;
                case 'd':
                        directory = optarg;
                        break;
                case 'c':
                        strncpy(injector_command, optarg, 4095);;
			if (access(injector_command, X_OK) == -1) {
			    slog_error(0,"ERROR: injector command %s is not executable %s",injector_command);	
			    exit(1);
			}
                        break;
                case 'n':
                        save_json  = 0;
			break;
                case 'i':
                        injector = 1;
			break;
                case 'X':
                        strncpy(local_secret,  optarg, SECRET_LENGTH -1);
                        break;
                case 'a':
                        filename=optarg;
			if( (fp = fopen(filename,"r")) == NULL ) {
                                slog_error(0,"Failed to fopen %s", filename);
				exit(99);
			}

			while(fgets(buffer,4096 -1,fp) != NULL ) {
				line++;
				buffer[strlen(buffer)-1] = 0;
				/* printf("line=->%s<-\n",buffer); */
				if(strncmp("port=",buffer,strlen("port=")) == 0) {
					if( sscanf(&buffer[5],"%d",&port) != 1)
						printf("duff port number line=%d line=%s\n",line,buffer);
				}
				if(strncmp("directory=",buffer,strlen("directory=")) == 0) {
					directory = malloc(strlen(buffer));
					strcpy(directory,&buffer[strlen("directory=")]);
				}
				if(strncmp("secret=",buffer,strlen("secret=")) == 0) {
					if( sscanf(&buffer[7],"%s",local_secret) != 1)
						printf("duff local_secret\n");
				}
				if(strncmp("inject=",buffer,strlen("inject=")) == 0) {
					if( sscanf(&buffer[7],"%d",&injector) != 1)
						printf("duff inject\n");
				}
				if(strncmp("injector=",buffer,strlen("injector=")) == 0) {
					if( sscanf(&buffer[9],"%s",injector_command) != 1)
						printf("duff injector_command\n");
				}
				if(strncmp("json=",buffer,strlen("json=")) == 0) {
					if( sscanf(&buffer[5],"%d",&save_json) != 1)
						printf("duff json\n");
				}
			}
			
			if (fp) {fclose(fp); fp = NULL;}
			
			/*printf("Config: port=%d, directory=%s, secret=%s, inject=%d, injector=%s, json=%d\n",
				port, directory, local_secret, injector, injector_command, save_json); */
                        break;
                default:
			slog_error(0,"Unexpected command parameter \"%c\" = 0x%x - bailing out",(char)ch, ch);
			exit(3);
                        break;
        	}
        }
	if(port == -1) {
		slog_error(0,"mandatory -p port option missing");
		exit(3);
	}
	if(port < 0 || port >60000) {
		slog_error(0,"Invalid port number %d(try 1->60000)",port);
		exit(3);
	}
	if(directory == (char *)0) {
		slog_error(0,"Mandatory -d directory option missing");
		exit(3);
	}

	if( !strncmp(directory,"/"   ,2 ) || !strncmp(directory,"/etc", 5 ) ||
	    !strncmp(directory,"/bin",5 ) || !strncmp(directory,"/lib", 5 ) ||
	    !strncmp(directory,"/tmp",5 ) || !strncmp(directory,"/usr", 5 ) ||
	    !strncmp(directory,"/dev",5 ) || !strncmp(directory,"/sbin",6) ){
		slog_error(0,"Bad top directory %s, see njmon_collector -?",directory);
		exit(3);
	}
	if(!save_json && !injector) {
		slog_error(0,"Bad combination = don't save JSON and no injector = nothing to do!")
		exit(3);	
	}
#ifdef CHROOT
	if(chroot(directory) == -1)  /* best security but can't run python */
#else
	if(chdir(directory) == -1)   /* lets hope the user account is secure */
#endif
		{

		slog_error(0,"can't change to directory %s",directory);
		exit(3);
		slog_error(0,"Invalid port number %d(try 1->60000)",port);
		exit(3);
	}
	if(directory == (char *)0) {
		slog_error(0,"Mandatory -d directory option missing");
		exit(3);
	}

	if( !strncmp(directory,"/"   ,2 ) || !strncmp(directory,"/etc", 5 ) ||
	    !strncmp(directory,"/bin",5 ) || !strncmp(directory,"/lib", 5 ) ||
	    !strncmp(directory,"/tmp",5 ) || !strncmp(directory,"/usr", 5 ) ||
	    !strncmp(directory,"/dev",5 ) || !strncmp(directory,"/sbin",6) ){
		 slog_error(0,"Bad top directory %s, see njmon_collector -?",directory);
		 exit(3);
	}
	if(!save_json && !injector) {
		slog_error(0,"Bad combination = don't save JSON and no injector = nothing to do!");
		exit(3);
	}
#ifdef CHROOT
	if(chroot(directory) == -1)  /* best security but can't run python */
#else
	if(chdir(directory) == -1)  /* lets hope the user account is secure */
#endif
	{
		slog_error(0,"can't change to directory %s",directory);
		exit(3);
	}
	free(directory);


	  //Create the socket.

          if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) { 
	     slog_error(0, "System call socket create FAILED %d",errno);
	     exit(3);
	  }
         // Configure settings of the server address struct
         // Address family = Internet

         serverAddr.sin_family = AF_INET;

         //Set port number, using htons function to use proper byte order

        serverAddr.sin_port = htons(port);

        //Set IP address to any 

        serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

       //Set all bits of the padding field to 0

        memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);
        
	// allow reuse of local resources
	int reuse = 1;
        if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0) {
		slog_error(0,"setting SO_REUSEADDR FAILED %d",errno);
	        exit(3);
	}
        #ifdef SO_REUSEPORT
        if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0) {
		slog_error(0,"setting SO_REUSEPORT FAILED %d",errno);
	        exit(3);
	}
        #endif
        
	// Bind the address struct to the socket
	if(bind(listenfd, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) <0) {
		slog_error(0,"System call socket bind FAILED %d",errno);
	        exit(3); 
	}
	//Listen on the socket, with 250 max pending/unaccepted connection requests queued 
	if( listen(listenfd,250)==0 ) {
		slog_info(0,"READY, waiting for connections");
	}
	else {
		slog_error(0,"System call socket listen  FAILED %d",errno);
		exit(3);
	}

	
	
	pthread_t tid[MAX_CONNECTIONS];
        int i = 0;

	
	while(1) {
 
                        //Accept call creates a new socket for the incoming connection
                         addr_size = sizeof serverStorage;
			 
			 // allocate socketfd on the heap to avoid nasty race conditions
			 int *socketfd = (int*)malloc(sizeof(int));

                         *socketfd = accept(listenfd, (struct sockaddr *) &serverStorage, &addr_size);

			 // close socket when connection limit is reached, this is líttle bit dirty but should suffice for now
			 // would be nice to send message to client, maybe will implement this later
			 if( i >= MAX_CONNECTIONS)
			 {
				 slog_error(0,"Connection Limit reached! %d",socketfd);
				 close((int) *socketfd);
				 i--;
			 }


                        //create a thread for each client request and assign the client request to it for processing 
                        //the main thread can now serve the next request
			int err_create = pthread_create(&tid[i], NULL, socketThread, socketfd);
                        if(err_create) {
				slog_error(0,"Failed to create thread %d",err_create);
			        exit(3);
			}

			int err_join = pthread_join(tid[i],NULL);
			if(err_join) {
				slog_error(0,"Failed to join thread %d",err_join);
				exit(3);
			}
			free((void*)socketfd);

	}
return 0;

}
