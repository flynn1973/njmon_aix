/*
    njmon.c -- collects AIX performance data and generates JSON format data.
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
 */

/* Data in the perfstat library not collected and why
	tape total = already collect individual tapes & not expecting many tapes
	bio dev = tried this but "No bio device found." 
	thread = too many threads and low value
	WPAR various stats - wait for user demand as its adds to many stats
   To do
	processor pool
	diskpath = SAN multi-path MPIO
*/

/* 
Compiling xlc or gcc are fine
   cc njmon_aix_vXX.c -o njmon_aix -lperfstat -O3 -D<options below>

Explanation of ifdef and ifndef
#ifdef AIX53 historic only - prints out the path_count and paths but only in AIX 53
#ifdef SSP only - -u and -U includes Shared Storage Pool stats in VIOS 2.2=AIX6 TL9 but inclear about VIOS 3.1=AIX7.2 TL3
#ifdef VIOS - -v vhost (virtual adapter) and virtual disk target
#ifndef AIX6 - AIX has a two missing stats compared to AIX7 Also needed fir VIOS 2.2

for AIX 6 
	-D AIX6
for VIOS 2.2
	-D AIX6 -D VIOS -D SSP
for AIX 7
	none required
for VIOS 3.1
	-D VIOS -D SSP
*/
/* Makefile - - - - - - - - - - - - - - - - - */
#ifdef MAKEFILE
CFLAGS=-g -O3 
LDFLAGS=-lperfstat

FILE=njmon_aix_v20.c

OUT72=njmon_aix72_v20
OUT722=njmon_aix722_v20
OUT71=njmon_aix71_v20
OUT61=njmon_aix61_v20
OUTvios2=njmon_vios2_v20
OUTvios3=njmon_vios3_v20

aix72:
	cc $(CFLAGS) -o $(OUT72) $(FILE) $(LDFLAGS) 

aix722:
	cc $(CFLAGS) -o $(OUT722) $(FILE) $(LDFLAGS) 

aix71:
	gcc $(CFLAGS) -o $(OUT71) $(FILE) $(LDFLAGS)

aix61:
	gcc $(CFLAGS) -o $(OUT61) $(FILE) $(LDFLAGS) -D AIX6

vios2:
	gcc $(CFLAGS) -o $(OUTvios2) $(FILE) $(LDFLAGS) -D AIX6 -D VIOS -D SSP

vios3:
	gcc $(CFLAGS) -o $(OUTvios3) $(FILE) $(LDFLAGS) -D VIOS -D SSP

clean:
	rm -f njmon_aix72_v11 njmon_aix71_v11 njmon_aix61_v11 njmon_vios2_v11 njmon_vios3_v11

#endif
/* - - - - - - - - - - - - - - - - - */

/* Only used in comms to the njmon_collector */
#define COLLECTOR_VERSION  "12"  

/*njmon version */
#define VERSION  "31@17/07/2019"

char	version[] = VERSION;
static char	*SccsId = "njmon for AIX " VERSION;
char	*command;

/* Work around an AIX bug in oslevel -s */
int rpmstuck = 0;

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <libperfstat.h>

#include <ctype.h>
#include <signal.h>
#include <pwd.h>
#include <time.h>
#include <string.h>
#include <strings.h>
#include <mntent.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/vminfo.h>
#include <sys/time.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/vfs.h>
/* for flesystems */
#include <fcntl.h>
#include <fstab.h>
#include <sys/statfs.h>

#include <sys/systemcfg.h>

#define FUNCTION_START if(debug)fprintf(stderr,"%s called line %d\n",__func__, __LINE__);
#define DEBUG if(debug)

void   interrupt(int signum)
{
        switch(signum) {
        case SIGUSR1:
        case SIGUSR2:
                fflush(NULL);
                exit(0);
                break;
	}
}

int sockfd = 1;   /*default is stdout, only changed if we are using a remote socket */
int debug = 0;
int danger = 0;

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */
#ifndef NOREMOTE
/* below incldes are for socket handling */
#include <netinet/in.h>
#include <arpa/inet.h>

void pexit(char * msg) { perror(msg); exit(1); }

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

int create_socket(char *ip_address, long port, char *hostname, char *utc, char *secretstr)
{
int i;
//char buffer[8196];
char * buffer = calloc(8196, sizeof(*buffer));
static struct sockaddr_in serv_addr;
int rc;

	DEBUG printf("socket: trying to connect to %s:%d\n",ip_address,port);
	if((sockfd = socket(AF_INET, SOCK_STREAM,0)) <0) 
		pexit("njmon:socket() call failed");

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(ip_address);
	serv_addr.sin_port = htons(port);

        /* allow reuse of local resources */ 
        int reuse = 1;
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
        perror("setsockopt(SO_REUSEADDR) failed");
        #ifdef SO_REUSEPORT
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse)) < 0)
        perror("setsockopt(SO_REUSEPORT) failed");
        #endif


	/* Connect tot he socket offered by the web server */
	if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) <0) 
		//pexit("njmon: connect() call failed");
                perror("create_socket: connect() call failed");

	/* Now the sockfd can be used to communicate to the server the GET request */
	sprintf(buffer,"preamble-here njmon %s %s %s %s postamble-here", 
			hostname, utc, secretstr, COLLECTOR_VERSION);
	DEBUG printf("hello string=\"%s\"\n",buffer);
	mixup(buffer);
	//if(write(sockfd, buffer, strlen(buffer)) <0 )
        //pexit("njmon: write() to socket failed");

        rc = write(sockfd, buffer, strlen(buffer));
                if (rc < 0 && errno == EPIPE)
                {
                    perror("create_socket: EPIPE detected, write to socket failed, server down?");
                    close(sockfd);
                }
                    return rc;
}
#endif /* NOREMOTE */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */


/*   p functions to generate JSON output 
*    psection(name) and psectionend() 
*     	add "name": { 
*
*     	    } 
* 
*    psub(name) and psubend() 
*       similar to psection/psectionend but one level deeper
*
*    pstring(name,"abc"), 
*    plong(name, 1234) and 
*    pdouble(name, 1234.546) 
*    phex(name, hedadecimal number) 
*    praw(name) for other stuff in a raw format
*     	add "name": data,
*           
*    the JSON is appended to the buffer "output" so
*        we can remove the trailing "," before we close the entry with a "}"
*        we can write the whole record in a single write (push()) to help down stream tools
*/

int njmon_stats = 0;
int njmon_sections = 0;
int njmon_subsections = 0;
int njmon_string = 0;
int njmon_long = 0;
int njmon_double = 0;
int njmon_hex = 0;

#define ONE_LEVEL 1
#define MULTI_LEVEL 9
int mode = MULTI_LEVEL;
int oldmode = 0;
int samples = 0;

char *output;
long output_size = 0;
long output_char = 0;
char *nullstring = "";
long level = 0;

double nominal_mhz = 1;
double current_mhz = 2;

void remove_ending_comma_if_any()
{
        if(output[output_char -2] == ',') {
            output[output_char -2] = '\n';
            output_char--;
        }
}

void buffer_check()
{
long size;
	if( output_char > (long)(output_size * 0.95) ) { /* within 5% of the end */
		size = output_size + (1024 * 1024); /* add another MB */
		output = realloc((void *)output, size);
		output_size = size;
	}
}

void praw(char *string)
{
	output_char += sprintf(&output[output_char], "%s",string);
}

void pstart()
{
	DEBUG praw("START");
	praw("{\n");
}

void pfinish()
{
	DEBUG praw("FINISH");
        remove_ending_comma_if_any();
	praw("}\n");
}

void psample()
{
	DEBUG praw("SAMPLE");
	praw("  {\n"); /* start of sample */
}

void psampleend(int ending)
{
	DEBUG praw("SAMPLEEND");
	if(mode == MULTI_LEVEL) {
                remove_ending_comma_if_any();
	}
        if(ending)
                praw("  }\n");  /* end of sample */
        else
                praw("  },\n"); /* end of sample more to come */

}

char *saved_section;
char *saved_resource;
long saved_level = 1;

void indent()
{
int i;
	DEBUG praw("INDENT");

	if(mode == ONE_LEVEL) saved_level = 2;

	for(i=0; i < saved_level; i++)
		praw("     ");
}

void psection(char *section)
{
	buffer_check();
	njmon_sections++;
	saved_section = section;
	if(mode == MULTI_LEVEL){
		indent();
		output_char += sprintf(&output[output_char], "\"%s\": {\n", section);
	} 
	saved_level++;
}

void psectionend() /* final means last data strutcure so no comma is needed */
{
	buffer_check();
	saved_section  = NULL;
	saved_resource = NULL;
	saved_level--;
	if(mode == MULTI_LEVEL){
                remove_ending_comma_if_any();
		indent();
		praw("},\n");
	}
}

void psub(char *resource)
{
	njmon_subsections++;
	saved_resource = resource;
	if(mode == MULTI_LEVEL){
		indent();
		output_char += sprintf(&output[output_char], "\"%s\": {\n", resource);
	} 
	saved_level++;
}

void psubend() /* final means last data strutcure so no comma is needed */
{
	saved_resource = NULL;
	saved_level--;
	if(mode == MULTI_LEVEL) {
                remove_ending_comma_if_any();
		indent();
		praw("},\n");
	}
}

void phex(char *name, long long value)
{
	njmon_hex++;
	indent();
	if(mode == ONE_LEVEL) {
		output_char += sprintf(&output[output_char], "\"%s%s%s_%s\": \"0x%08llx\",\n", 
				saved_section, 
				saved_resource==NULL?"":"_",
				saved_resource==NULL?"":saved_resource, 
				name, value);
	}
	else {
		output_char += sprintf(&output[output_char], "\"%s\": \"0x%08llx\",\n", name, value);
	}
	DEBUG printf("phex(%s,%lld) count=%ld\n",name,value,output_char);
}

void plong(char *name, long long value)
{
	njmon_long++;
	indent();
	if(mode == ONE_LEVEL) {
		output_char += sprintf(&output[output_char], "\"%s%s%s_%s\": %lld,\n", 
				saved_section, 
				saved_resource==NULL?"":"_",
				saved_resource==NULL?"":saved_resource, 
				name, value);
	}
	else {
		output_char += sprintf(&output[output_char], "\"%s\": %lld,\n", name, value);
	}
	DEBUG printf("plong(%s,%lld) count=%ld\n",name,value,output_char);
}

void pdouble(char *name, double value)
{
	njmon_double++;
	indent();
	if(mode == ONE_LEVEL) {
		output_char += sprintf(&output[output_char], "\"%s%s%s_%s\": %.3f,\n", 
				saved_section, 
				saved_resource==NULL?"":"_",
				saved_resource==NULL?"":saved_resource, 
				name, value);
	}
	else {
		output_char += sprintf(&output[output_char], "\"%s\": %.3f,\n", name, value);
	}
	DEBUG printf("pdouble(%s,%.1f) count=%ld\n",name,value,output_char);
}

void pstring(char *name, char *value)
{
	buffer_check();
	njmon_string++;
	indent();
	if(mode == ONE_LEVEL) {
		output_char += sprintf(&output[output_char], "\"%s%s%s_%s\": \"%s\",\n", 
				saved_section, 
				saved_resource==NULL?"":"_",
				saved_resource==NULL?"":saved_resource, 
				name, value);
	}
	else {
		output_char += sprintf(&output[output_char], "\"%s\": \"%s\",\n", name, value);
	}
	DEBUG printf("pstring(%s,%s) count=%ld\n",name,value,output_char);
}

void pstats()
{
	psection("njmon_stats");
	plong("section",    njmon_sections);
	plong("subsections",njmon_subsections);
	plong("string",     njmon_string);
	plong("long",       njmon_long);
	plong("double",     njmon_double);
	plong("hex",        njmon_hex);
	psectionend("njmon_stats");
}

int push()
{
int rc;
	buffer_check();
	DEBUG {
		printf("DEBUG size=%ld\n",output_char);
		printf("%s",output);
	}
	//if( write(sockfd,output,output_char) < 0) {
	//	/* if stdout failed there is not must we can do so stop */
	//	perror("njmon write to stdout failed, stopping now.");
	//	exit(99);
	//}
    
       rc = write(sockfd,output,output_char);

          if (rc < 0 && errno == EPIPE)
                {
                    perror("push: EPIPE detected, push to socket failed, server down?");
                    close(sockfd);
                }
 
        

	fflush(NULL);  /* force I/O output now */
	DEBUG printf("Flushed output buffer, size=%ld\n",output_char);
	output[0] = 0;
	output_char = 0;
        return rc;
}

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - */

/* for loadavg SBITS */
#include <sys/proc.h>
void remove_nl(char *string)
{
	int	len;

	len = strlen(string);
	if (string[len - 1] == '\n') /* Remove NL */
		string[len - 1] = 0;
}


#define RETURN 1
#define EXIT 2
#define DUMP 3

void assert(const unsigned char *file, 
	const unsigned char *function,
	const unsigned int line, 
	const unsigned char *expression,
	char *reason, 
	int next,
	int flag,
	long long value,
	void *ptr)
{
	int	*c;

	fprintf(stderr, "ERROR: njmon version %s\n", version);
	fprintf(stderr, "ERROR: Assert Failure in file=\"%s\" in function=\"%s\" at line=%d\n", file, function, line);
	fprintf(stderr, "ERROR: Reason=%s\n", reason);
	if(flag)
		fprintf(stderr, "ERROR: Pointer=0x%x\n", (char *)ptr);
	else
		fprintf(stderr, "ERROR: Value=%lld\n", value);
	fprintf(stderr, "ERROR: Expression=[[%s]]\n", expression);
	if (errno != 0) {
		fprintf(stderr, "ERROR: errno=%d\n", errno);
		perror("ERROR: errno means ");
	}
	switch (next) {
	case RETURN:
		fprintf(stderr, "ERROR: Switching off these stats and continuing\n");
		return;
	case EXIT: 
		fprintf(stderr, "ERROR: Exiting njmon\n");
		exit(666);
	case DUMP:
		fprintf(stderr, "ERROR: Forcing an njmon core dump\n");
		c = NULL;
		*c = 42;
		/* should never get here */
	}
	/* should never get here */
}


#define ASSERT(expression, reason, next, value)         { \
        if(debug) \
                printf("ASSERT CHECK: %s %s %d %s %s %d %ld\n",  __FILE__, __func__, __LINE__, "expression", reason, next, (long long)value); \
        if( !(expression) ) \
        assert( __FILE__, __func__, __LINE__, "expression", reason, next, 0, (long long)value, NULL); }

#define ASSERT_PTR(expression, reason, next, ptr)         { \
        if(debug) \
                printf("ASSERT CHECK: %s %s %d %s %s %d %ld\n",  __FILE__, __func__, __LINE__, "expression", reason, next, (void *)ptr); \
        if( !(expression) ) \
        assert( __FILE__, __func__, __LINE__, "expression", reason, next, 1, 0, ptr); }





/* get and save data */

void aix_server()
{
	static int first_time = 1;
	static int	aix_version = 0;      /* which AIX version */
	static int	aix_tl = 0;
	static int	aix_sp = 0;
	static int	aix_year = 0;
	static int	aix_week = 0;

	static char	serial_no[9];
	static char	lpar_num_name[31];
	static char	machine_type[31];
	static char	uname_node[31];
	char	oslevel_command[256];

	FILE * pop;
	char	string[4096];
	int	i;

	FUNCTION_START;
	if (first_time) {
		first_time = 0;

		if(rpmstuck)
			strcpy(oslevel_command,"oslevel >2>/dev/null");
		else
			strcpy(oslevel_command,"oslevel -s >2>/dev/null");

		if ( (pop = popen("oslevel -s 2>/dev/null", "r") ) != NULL ) {
			if ( fgets(string, 256, pop) != NULL) {
				if(rpmstuck) {
					/* 7.2.0.0 */
					sscanf(string, "%d.%d", &aix_version, &aix_tl);
				} else {
					/* 7200-01-01-1642 */
					sscanf(string, "%d-%d-%d-%2d%2d", &aix_version, &aix_tl, &aix_sp, &aix_year, &aix_week);
				}
			}
			pclose(pop);
		} else {
			ASSERT_PTR(pop == NULL, "oslevel -s", RETURN, pop);
		}

		/* serial number */
		if ( (pop = popen("uname -u 2>/dev/null", "r") ) != NULL ) {
			if ( fgets(string, 256, pop) != NULL) {
				strncpy(serial_no, &string[6], 8);
			}
			pclose(pop);
			remove_nl(serial_no);
		} else {
			strcpy(serial_no, "none");
			ASSERT_PTR(pop == NULL, "uname -u(serial no)", RETURN, pop);
		}

		/* LPAR Number Name like "17 myLPAR" */
		if ( (pop = popen("uname -L 2>/dev/null", "r") ) != NULL ) {
			if ( fgets(string, 256, pop) != NULL) {
				strncpy(lpar_num_name, &string[0], 30);
			}
			pclose(pop);
			if ( lpar_num_name[0] == '-' && lpar_num_name[1] == '1')
				strcpy(lpar_num_name, "notset");

			if ( lpar_num_name[0] == '1' && lpar_num_name[1] == ' ' && 
			    lpar_num_name[2] == 'N' && lpar_num_name[3] == 'U' && 
			    lpar_num_name[4] == 'L' && lpar_num_name[5] == 'L'  )
				strcpy(lpar_num_name, "NULL");

			for (i = 0; i < 4; i++) {       /* change to comma seperated */
				if (lpar_num_name[i] == ' ') {
					lpar_num_name[i] = ',';
					break;
				}
			}
			remove_nl(lpar_num_name);
		} else {
			strcpy(lpar_num_name, "none");
			ASSERT_PTR(pop == NULL, "uname -L(lpar no & name)", RETURN, pop);
		}

		/* Machine type */
		if ( (pop = popen("uname -M 2>/dev/null", "r") ) != NULL ) {
			if ( fgets(string, 256, pop) != NULL) {
				strncpy(machine_type, &string[0], 30);
			}
			pclose(pop);
			remove_nl(machine_type);
		} else {
			strcpy(machine_type, "unknown");
			ASSERT_PTR(pop == NULL, "uname -M(machine-type)", RETURN, pop);
		}

		/* Node */
		if ( (pop = popen("uname -n 2>/dev/null", "r") ) != NULL ) {
			if ( fgets(string, 256, pop) != NULL) {
				strncpy(uname_node, &string[0], 30);
			}
			pclose(pop);
			remove_nl(uname_node);
		} else {
			strcpy(uname_node, "unknown");
			ASSERT_PTR(pop == NULL, "uname -n (node)", RETURN, pop);
		}
	}

	psection("server");
	pdouble("aix_version",(double)aix_version / 1000.0);
	plong("aix_technology_level",	aix_tl);
	plong("aix_service_pack",	aix_sp);
	plong("aix_build_year",		2000 + aix_year);
	plong("aix_build_week",		aix_week);
	pstring("serial_no",		serial_no);
	pstring("lpar_number_name",	lpar_num_name);
	pstring("machine_type",		machine_type);
	pstring("uname_node",		uname_node);
	psectionend();
}


int	error( char *buf)
{
	fprintf(stderr, "ERROR: %s\n", buf);
	exit(1);
}

time_t timer;           /* used to work out the time details*/
struct tm *tim;         /* used to work out the local hour/min/second */

void get_time()
{

        timer = time(0);
}

void get_localtime()
{
        tim = localtime(&timer);
        tim->tm_year += 1900;    /* read localtime() manual page!! */
        tim->tm_mon += 1;        /* because it is 0 to 11 */
}

/* UTC is best to use as its time zone indepentant */
void get_utc()
{
        tim = gmtime(&timer);
        tim->tm_year += 1900;  /* read gmtime() manual page!! */
        tim->tm_mon += 1;      /* because it is 0 to 11 */
}

void    date_time(long seconds, long loop, long maxloops)
{
        //char   buffer[256];
          char * buffer = calloc(256, sizeof(*buffer));

        /* This is ISO 8601 datatime string format - ughly but get over it! :-) */
        get_time();
        get_localtime();
        psection("timestamp");
        sprintf(buffer,"%04d-%02d-%02dT%02d:%02d:%02d",
            tim->tm_year,
            tim->tm_mon,
            tim->tm_mday,
            tim->tm_hour,
            tim->tm_min,
            tim->tm_sec);
        pstring("datetime",buffer);
        get_utc();
        sprintf(buffer,"%04d-%02d-%02dT%02d:%02d:%02d",
            tim->tm_year,
            tim->tm_mon,
            tim->tm_mday,
            tim->tm_hour,
            tim->tm_min,
            tim->tm_sec);
        pstring("UTC",buffer);
        plong("snapshot_seconds",seconds);
        plong("snapshot_maxloops",maxloops);
        plong("snapshot_loop",loop);
        psectionend();
}

/* - - - - - gpfs - - - - */
#ifndef NOGPFS
int gpfs_na = 0; /* Not available, switches off any futher GPFS stats collection attempts */
char ip[1024]; /* IP address */
char nn[1024]; /* Node name (I think) */

/* this is the io_s stats data structure */
/* _io_s_ _n_ 192.168.50.20 _nn_ ems1-hs _rc_ 0 _t_ 1548346611 _tu_ 65624 _br_ 0 _bw_ 0 _oc_ 1 _cc_ 1 _rdc_ 0 _wc_ 0 _dir_ 1 _iu_ 0 */
struct gpfs_io {
        long rc;
        long t;
        long tu;
        long br;
        long bw;
        long oc;
        long cc;
        long rdc;
        long wc;
        long dir;
        long iu;
} gpfs_io_prev, gpfs_io_curr;

/* this is the fs_io_s stats data structure */
/*_fs_io_s_ _n_ 192.168.50.20 _nn_ ems1-hs _rc_ 0 _t_ 1548519197 _tu_ 560916 _cl_ SBANK_ESS.gpfs.net _fs_ cesroot _d_ 4 _br_ 224331 _bw_ 225922 _o
c_ 63 _cc_ 58 _rdc_ 35 _wc_ 34 _dir_ 2 _iu_ 14 */

#define MAX_FS 64

struct gpfs_fs { /* this is the fs_io_s stats data structure */
        long rc;
        long t;
        long tu;
        char cl[512];
        char fs[512];
        long d;
        long br;
        long bw;
        long oc;
        long cc;
        long rdc;
        long wc;
        long dir;
        long iu;
} gpfs_fs_prev[MAX_FS], gpfs_fs_curr[MAX_FS];

int outfd[2];
int infd[2];
int pid = -999;

int gpfs_grab()
{
int i = 0;
int index = 0;
int records = 0;
int ret;
int count;
char b[1024];
//char buffer[2048];
char * buffer = calloc(8196, sizeof(*buffer));

        if(gpfs_na)
                return -1;
        /* first the total I/O stats */
        count = write(outfd[1], "io_s\n", strlen("io_s\n"));
        if(count != strlen("io_s\n")) {
                gpfs_na = 1;
                return 0;
        }
        count = read(infd[0], buffer, sizeof(buffer)-1);
        if (count >= 0) {
                buffer[count] = 0;
                /*                                       1      2      3      4      5      6      7      8      9      10     11 */
                ret = sscanf(buffer, "%s %s %s %s %s %s %ld %s %ld %s %ld %s %ld %s %ld %s %ld %s %ld %s %ld %s %ld %s %ld %s %ld",
                        b, b, &ip[0],
                        b, &nn[0],
                        b, &gpfs_io_curr.rc,
                        b, &gpfs_io_curr.t,
                        b, &gpfs_io_curr.tu,
                        b, &gpfs_io_curr.br,
                        b, &gpfs_io_curr.bw,
                        b, &gpfs_io_curr.oc,
                        b, &gpfs_io_curr.cc,
                        b, &gpfs_io_curr.rdc,
                        b, &gpfs_io_curr.wc,
                        b, &gpfs_io_curr.dir,
                        b, &gpfs_io_curr.iu);
        } else {
                gpfs_na = 1;
        }

        /* second the 1 or more filesystem  I/O stats */
        index = 0;
        count = write(outfd[1], "fs_io_s\n", strlen("fs_io_s\n"));
        if(count != strlen("fs_io_s\n")) {
                gpfs_na = 1;
                return 0;
        }
        count = read(infd[0], buffer, sizeof(buffer)-1);
        buffer[count] = 0; /*ensure a zero string ending */
#ifdef TEST
{
        /* fake a second filesystem */
        int len;
        len = strlen(buffer);
        strncpy(&buffer[len],buffer,len);
        count = strlen(buffer);
}
#endif
        if (count >= 0) {
                for(i=0; i < count;i++) {
                        if(buffer[i] == '\n' ) records++;
                }
                if(records >64)
                        records = 64;
                for(i=0; i < records; i++) {
/*_fs_io_s_ _n_ 192.168.50.20 _nn_ ems1-hs _rc_ 0 _t_ 1548519197 _tu_ 560916 _cl_ SBANK_ESS.gpfs.net _fs_ cesroot _d_ 4 _br_ 224331 _bw_ 225922 _o
c_ 63 _cc_ 58 _rdc_ 35 _wc_ 34 _dir_ 2 _iu_ 14 */
                /*                                       1      2      3      4      5      6      7      8      9      10     11 */
                ret = sscanf(&buffer[index], "%s %s %s %s %s %s %ld %s %ld %s %ld %s %s %s %s %s %ld %s %ld %s %ld %s %ld %s %ld %s %ld %s %ld %s %ld %s %ld",
                        b, b, &ip[0],
                        b, &nn[0],
                        b, &gpfs_fs_curr[i].rc,
                        b, &gpfs_fs_curr[i].t,
                        b, &gpfs_fs_curr[i].tu,
                        b, &gpfs_fs_curr[i].cl[0],
                        b, &gpfs_fs_curr[i].fs[0],
                        b, &gpfs_fs_curr[i].d,
                        b, &gpfs_fs_curr[i].br,
                        b, &gpfs_fs_curr[i].bw,
                        b, &gpfs_fs_curr[i].oc,
                        b, &gpfs_fs_curr[i].cc,
                        b, &gpfs_fs_curr[i].rdc,
                        b, &gpfs_fs_curr[i].wc,
                        b, &gpfs_fs_curr[i].dir,
                        b, &gpfs_fs_curr[i].iu);
                        for( ; index < count; index++) {
                                if( buffer[index] == '\n') {    /* find newline = terminating the current record */
                                        index++;                /* move to after the newline */
                                        break;
                                }
                        }
                        if(index == count)
                                break;
                }
        } else {
                gpfs_na = 1;
        }
        return records;
}

void gpfs_init()
{
    int filesystems = 0;
    struct stat sb; /* to check if mmpmon is executable and gpfs is installed */

    FUNCTION_START;
    /* call shell script to start mmpmon binary */
    char *argv[]={ "/usr/lpp/mmfs/bin/mmksh", "-c", "/usr/lpp/mmfs/bin/mmpmon -s -p", 0}; /* */

    /* Alternative: direct start of mmpmon */
    /* char *argv[]={ "/usr/lpp/mmfs/bin/tspmon", "1000", "1", "1", "0", "0", "60", "0", "/var/mmfs/mmpmon/mmpmonSocket", 0}; */

    if( getuid() != 0 )
        gpfs_na = 1; /* not available = mmpmon required root user */

    if(stat(argv[0], &sb) != 0)
        gpfs_na = 1; /* mmksh not available = no file */

    if(!(sb.st_mode & S_IXUSR))
        gpfs_na = 1; /* not available = not executable */

    if(gpfs_na) {
        DEBUG printf("gpfs not present or not possible\n");
        return;
    }

    if( pipe(outfd) != 0) { /* Where the parent is going to write outfd[1] to   child input outfd[0] */
            gpfs_na = 1;
            return;
    }
    if( pipe(infd) != 0) {  /* From where parent is going to read  infd[0] from child output infd[1] */
            gpfs_na = 1;
            return;
    }

    if( (pid = fork()) == 0) { /* for the mmpmon child */
        /* child process */
        close(0);
        dup2(outfd[0], 0);

        close(1);
        dup2(infd[1], 1);

        /* Not required for the child */
                close(outfd[0]);
                close(outfd[1]);
                close(infd[0]);
                close(infd[1]);

        execv(argv[0], argv);
        /* never returns */
    } else {
        /* parent process */
        close(outfd[0]); /* These are being used by the child */
        close(infd[1]);
        filesystems  = gpfs_grab();
        /* copy to the previous records for next time */
        memcpy((void *)&gpfs_io_prev, (void *)&gpfs_io_curr, sizeof(struct gpfs_io));
        memcpy((void *)&gpfs_fs_prev[0], (void *)&gpfs_fs_curr[0], sizeof(struct gpfs_fs) * filesystems);
    }
}

void gpfs_data(double elapsed)
{
        //char buffer[10000];
        char * buffer = calloc(10000, sizeof(*buffer));
        int records;
        int i;
        int ret;

    	FUNCTION_START;
        if(gpfs_na)
                return;

        records = gpfs_grab(&gpfs_io_curr, &gpfs_fs_curr);

#define DELTA_GPFS(xxx)  ((double)(gpfs_io_curr.xxx - gpfs_io_prev.xxx)/elapsed)

        psection("gpfs_io_total");
        pstring("node",ip);
        pstring("name",nn);
        plong("rc",             gpfs_io_curr.rc); /* status */
        plong("time",           gpfs_io_curr.t); /* epoc seconds */
        plong("tu",             DELTA_GPFS(tu));
        plong("readbytes",      DELTA_GPFS(br));
        plong("writebytes",     DELTA_GPFS(bw));
        plong("open",           DELTA_GPFS(oc));
        plong("close",          DELTA_GPFS(cc));
        plong("reads",          DELTA_GPFS(rdc));
        plong("writes",         DELTA_GPFS(wc));
        plong("directorylookup",DELTA_GPFS(dir));
        plong("inodeupdate",    DELTA_GPFS(iu));
        psectionend();

        memcpy((void *)&gpfs_io_prev, (void *)&gpfs_io_curr, sizeof(struct gpfs_io));

#define DELTA_GPFSFS(xxx)  ((double)(gpfs_fs_curr[i].xxx - gpfs_fs_prev[i].xxx)/elapsed)

        psection("gpfs_filesystems");
        for(i=0; i < records; i++) {
            psub(gpfs_fs_curr[i].fs);
                pstring("node",ip);
                pstring("name",nn);
                plong("rc",             gpfs_fs_curr[i].rc); /* status */
                plong("time",           gpfs_fs_curr[i].t); /* epoc seconds */
                plong("tu",             DELTA_GPFSFS(tu));
                pstring("cl",           gpfs_fs_curr[i].cl);
                /*pstring("fs",         gpfs_fs_curr[i].fs); */
                plong("disks",          gpfs_fs_curr[i].d);
                plong("readbytes",      DELTA_GPFSFS(br));
                plong("writebytes",     DELTA_GPFSFS(bw));
                plong("open",           DELTA_GPFSFS(oc));
                plong("close",          DELTA_GPFSFS(cc));
                plong("reads",          DELTA_GPFSFS(rdc));
                plong("writes",         DELTA_GPFSFS(wc));
                plong("directorylookup",DELTA_GPFSFS(dir));
                plong("inodeupdate",    DELTA_GPFSFS(iu));
            psubend();
        }
        psectionend();

        memcpy((void *)&gpfs_fs_prev[0], (void *)&gpfs_fs_curr[0], sizeof(struct gpfs_fs) * records);
}
#endif /* NOGPFS */
/* - - - End of GPFS - - - - */


void	ps_part_config()
{
	int	rc;
	static perfstat_partition_config_t config;

    	FUNCTION_START;
	rc = perfstat_partition_config(NULL, &config, sizeof(perfstat_partition_config_t), 1);
	ASSERT(rc > 0, "perfstat_partition_config()", RETURN, rc);

	nominal_mhz = config.processorMHz;
	psection("config");
	pstring("partitionname",config.partitionname);
	pstring("nodename", config.nodename);
	/* phex("partition_type_flags", (long long)(config.conf)); */

	pstring("processorFamily", config.processorFamily);
	pstring("processorModel",  config.processorModel);
	pstring("machineID",       config.machineID);
	pdouble("processorMHz",    config.processorMHz);
	/* plong("pcpu_min",     config.numProcessors.min); this reports zero every time */
	plong("pcpu_max",     config.numProcessors.max);
	/* plong("pcpu_desired", config.numProcessors.desired); this reports zero every time */
	plong("pcpu_online",  config.numProcessors.online);

	pstring("OSname",    config.OSName);
	pstring("OSversion", config.OSVersion);
	pstring("OSbuild",   config.OSBuild);

	plong("lcpus", config.lcpus);
	plong("smtthreads",config.smtthreads);
	plong("drives", config.drives);
	plong("nw_adapter", config.nw_adapters);

	plong("cpucap_min",     config.cpucap.min);
	plong("cpucap_max",     config.cpucap.max);
	plong("cpucap_desired", config.cpucap.desired);
	plong("cpucap_online",  config.cpucap.online);
	plong("cpucap_weightage", config.cpucap_weightage);

	pdouble("entitled_proc_capacity", config.entitled_proc_capacity / 100.0);

	plong("vcpus_min",     config.vcpus.min);
	plong("vcpus_max",     config.vcpus.max);
	plong("vcpus_desired", config.vcpus.desired);
	plong("vcpus_online",  config.vcpus.online);

	plong("processor_poolid", config.processor_poolid);
	plong("activecpusinpool", config.activecpusinpool);
	plong("cpupool_weightage", config.cpupool_weightage);
	plong("sharedpcpu", config.sharedpcpu);
	plong("maxpoolcap", config.maxpoolcap);
	plong("entpoolcap", config.entpoolcap);

	plong("mem_min",     config.mem.min);
	plong("mem_max",     config.mem.max);
	plong("mem_desired", config.mem.desired);
	plong("mem_online",  config.mem.online);
	plong("mem_weightage",config. mem_weightage);

	plong("ams_totiomement", config.totiomement);
	plong("ams_mempoolid",   config.mempoolid);
	plong("ams_hyperpgsize", config.hyperpgsize);
	plong("expanded_mem_min",     config.mem.min);
	plong("expanded_mem_max",     config.mem.max);
	plong("expanded_mem_desired", config.mem.desired);
	plong("expanded_mem_online",  config.mem.online);
	plong("ame_targetmemexpfactor", config.targetmemexpfactor);
	plong("ame_targetmemexpsize",   config.targetmemexpsize);
	phex("subprocessor_mode", config.subprocessor_mode);
	psectionend();
}

/* partition total */
perfstat_partition_total_t part;
unsigned long long	hardware_ticks;

void	ps_part_total()
{
	static unsigned long long	timebase_saved;
	int	rc;
	char	part_name[IDENTIFIER_LENGTH];

    	FUNCTION_START;
	part_name[0] = 0;
	rc = perfstat_partition_total(NULL, &part, sizeof(perfstat_partition_total_t), 1);
	ASSERT(rc > 0, "perfstat_partition_total()", RETURN, rc);

	hardware_ticks = part.timebase_last - timebase_saved;
	timebase_saved = part.timebase_last;
}


void ps_one_disk_adapter(perfstat_diskadapter_t dstat, perfstat_diskadapter_t fstat, double elapsed)
{
    	FUNCTION_START;
	psub(dstat.name);
	pstring("description", dstat.description);
	switch (dstat.adapter_type) {
		SCSI:  pstring("adapter_type", "SCSI, SAS, other"); break;
		VHOST: pstring("adapter_type", "Virtual SCSI/SAS Adapter"); break;
		FC:    pstring("adapter_type", "Fiber Channel"); break;
		default: pstring("adapter_type", "unknown"); break;
	}
	plong("devices", dstat.number);
	plong("size_mb", dstat.size);
	plong("free_mb", dstat.free);
	plong("capable_rate_kbps", dstat.xrate);
	plong("bsize", dstat.dk_bsize);

	pdouble("transfers",  ((double)(dstat.xfers     - fstat.xfers)) / elapsed);  
	pdouble("rtransfers", ((double)(dstat.dk_rxfers - fstat.dk_rxfers)) / elapsed);  
	pdouble("wtransfers", ((double)((dstat.xfers    - dstat.dk_rxfers) - (fstat.xfers - fstat.dk_rxfers) )) / elapsed);  
	pdouble("read_kb",    ((double)(dstat.rblks     - fstat.rblks)) / elapsed / 2); /* stat is 512 byt blocks */
	pdouble("write_kb",   ((double)(dstat.wblks     - fstat.wblks)) / elapsed / 2); /* stat is 512 byt blocks */
	pdouble("read_time",  ((double)(dstat.dk_rserv  - fstat.dk_rserv)) / elapsed ); /* read  service time */
	pdouble("write_time", ((double)(dstat.dk_wserv  - fstat.dk_wserv)) / elapsed ); /* write service time */
	pdouble("time", ((double)(dstat.time  - fstat.time )) / elapsed); /* check */
	psubend();
}

/* adpaters */
int	adapters;
perfstat_diskadapter_t *diskadapt;
perfstat_diskadapter_t *disksaved;

void ps_disk_adapter_init()
{
	int	rc;
	char	adaptname[IDENTIFIER_LENGTH];

    	FUNCTION_START;
	/* find out the number of adapters */
	adaptname[0] = 0;
	adapters = perfstat_diskadapter(NULL, NULL, sizeof(perfstat_diskadapter_t), 0);
	ASSERT(adapters > 0, "perfstat_diskadapter(init)", RETURN, adapters);
	if(adapters < 0) {
		adapters = 0;
		return;
	}

	/* printf("%d adapter(s) found\n",adapters); */
	/* just assume these work OK, so no error checking */
	diskadapt = malloc(sizeof(perfstat_diskadapter_t) * adapters);
	ASSERT_PTR(diskadapt != NULL, "malloc", EXIT, diskadapt);

	disksaved  = malloc(sizeof(perfstat_diskadapter_t) * adapters);
	ASSERT_PTR(disksaved != NULL, "malloc", EXIT, disksaved);
	adaptname[0] = 0;
	rc = perfstat_diskadapter((perfstat_id_t * )adaptname, disksaved, sizeof(perfstat_diskadapter_t), adapters);
	ASSERT(rc > 0, "perfstat_diskadapter()", RETURN, rc);
        if(adapters < 0) {
                adapters = 0;
                return;
        }
}

void ps_disk_adapter_stats(double elapsed)
{
	int	i;
	int	rc;
	char	adaptname[IDENTIFIER_LENGTH];

    	FUNCTION_START;
	if(adapters == 0)
		return;
	adaptname[0] = 0;
	rc = perfstat_diskadapter((perfstat_id_t * )adaptname, diskadapt, sizeof(perfstat_diskadapter_t), adapters);
	ASSERT(rc > 0, "perfstat_diskadapter()", RETURN, rc);
	if(adapters < 0) {
                adapters = 0;
                return;
        }


	psection("disk_adapters");
	for (i = 0; i < rc; i++) {
		ps_one_disk_adapter(diskadapt[i], disksaved[i], elapsed);
	}
	psectionend();
	memcpy(disksaved, diskadapt, sizeof(perfstat_diskadapter_t) * adapters);
}

#ifdef VIOS
/* VIOS virtual adpaters */
int	vios_vhosts;
perfstat_diskadapter_t *vhostcurr;
perfstat_diskadapter_t *vhostsave;

void ps_vios_vhost_init()
{
	int	rc;
	char	vadaptname[IDENTIFIER_LENGTH];

    	FUNCTION_START;
	/* find out the number of virtual adapters */
	vadaptname[0] = 0;
	vios_vhosts = perfstat_virtualdiskadapter(NULL, NULL, sizeof(perfstat_diskadapter_t), 0);
	DEBUG printf("perfstat_virtualdiskadapter: %d virtual adapter(s) found\n",vios_vhosts); 
	ASSERT(vios_vhosts >= 0, "perfstat_virtualdiskadapter(init)", RETURN, vios_vhosts);
	if(vios_vhosts <= 0) {
		vios_vhosts = 0;
		return;
	}

	/* just assume these work OK, so no error checking */
	vhostcurr = malloc(sizeof(perfstat_diskadapter_t) * vios_vhosts);
	ASSERT_PTR(vhostcurr != NULL, "malloc", EXIT, vhostcurr);

	vhostsave = malloc(sizeof(perfstat_diskadapter_t) * vios_vhosts);
	ASSERT_PTR(vhostsave  != NULL, "malloc", EXIT, vhostsave);
	vadaptname[0] = 0;
	rc = perfstat_virtualdiskadapter((perfstat_id_t * )vadaptname, vhostsave, sizeof(perfstat_diskadapter_t), vios_vhosts);
	ASSERT(rc >= 0, "perfstat_virtualdiskadapter()", RETURN, rc);
        if(vios_vhosts <= 0) {
                vios_vhosts = 0;
                return;
        }
}

void ps_vios_vhost_stats(double elapsed)
{
	int	i;
	int	rc;
	char	vadaptname[IDENTIFIER_LENGTH];

    	FUNCTION_START;
	if(vios_vhosts == 0)
		return;
	vadaptname[0] = 0;
	rc = perfstat_virtualdiskadapter((perfstat_id_t * )vadaptname, vhostcurr, sizeof(perfstat_diskadapter_t), vios_vhosts);
	ASSERT(rc > 0, "perfstat_virtualdiskadapter()", RETURN, rc);
        if(vios_vhosts <= 0) {
                vios_vhosts = 0;
                return;
        }

	psection("vios_vhost");
	for (i = 0; i < rc; i++) {
		ps_one_disk_adapter(vhostcurr[i], vhostsave[i], elapsed);
	}
	psectionend();
	memcpy(vhostsave, vhostcurr, sizeof(perfstat_diskadapter_t) * vios_vhosts);
}
#endif /* VIOS */

/* Fibre Channel adpaters */

void ps_one_fc_adapter(perfstat_fcstat_t curr, perfstat_fcstat_t save, double e)
{
    	FUNCTION_START;
		if(curr.adapter_type == 0)
			psub(curr.name);	/* physical name like fcs5 */
		else
			psub(curr.vfc_name);    /* virtual name like vfchost6 */

		switch (curr.state) {
		FC_UP:   pstring("state", "UP"); break;
		FC_DOWN: pstring("state", "DOWN"); break;
		default: pstring("state", "unknown"); break;
		}

		pdouble("InputRequests",  ((double)(curr.InputRequests  - save.InputRequests))/e);
		pdouble("OutputRequests", ((double)(curr.OutputRequests - save.OutputRequests))/e);
		pdouble("InputBytes",     ((double)(curr.InputBytes     - save.InputBytes))/e);
		pdouble("OutputBytes",    ((double)(curr.OutputBytes    - save.OutputBytes))/e);
	
		plong("EffMaxTransfer",   curr.EffMaxTransfer);

		plong("NoDMAResourceCnt", curr.NoDMAResourceCnt);
		plong("NoCmdResourceCnt", curr.NoCmdResourceCnt);

		if(curr.AttentionType == 0)
		    pstring("AttentionType",    "Link down");
		else
		    pstring("AttentionType",    "Link up");

		plong("SecondsSinceLastReset", curr.SecondsSinceLastReset);

		pdouble("TxFrames",    ((double)(curr.TxFrames - save.TxFrames))/e);
		pdouble("TxWords",     ((double)(curr.TxWords  - save.TxWords))/e);
		pdouble("RxFrames",    ((double)(curr.RxFrames - save.RxFrames))/e);
		pdouble("RxWords",     ((double)(curr.RxWords  - save.RxWords))/e);

		/* skipped loads of error rates here */

		plong("PortSpeed",  curr.PortSpeed);
		plong("PortSupportedSpeed", curr.PortSupportedSpeed);
		plong("PortFcId",   curr.PortFcId);
		pstring("PortType", curr.PortType);
		phex("PortWWN",     curr.PortWWN);
		if(curr.adapter_type == 0)
		    pstring("adapter_type",    "Fibre Channel");
		if (curr.adapter_type == 1) {
		    pstring("adapter_type",   "Virtual Fibre Channel");
		    pstring("physical_name", curr.name);
		    pstring("client_part_name", curr.client_part_name);
		}
		psubend();
}

int	fc_adapters;
perfstat_fcstat_t *fc_stat;
perfstat_fcstat_t *fc_save;

void ps_fc_stat_init()
{
	int	rc;
	char	fc_adaptname[IDENTIFIER_LENGTH];

    	FUNCTION_START;
	/* find out the number of adapters */
	fc_adaptname[0] = 0;
	fc_adapters = perfstat_fcstat(NULL, NULL, sizeof(perfstat_fcstat_t), 0);
	ASSERT(fc_adapters >= 0, "perfstat_fcstat(init)", EXIT, fc_adapters);
	if(fc_adapters == 0) {
		DEBUG fprintf(stderr,"No Fibre Channel Adapters\n");
		return;
	}

	/* printf("%d fc adapter(s) found\n",fc_adapters); */
	/* just assume these work OK, so no error checking */
	fc_stat = malloc(sizeof(perfstat_fcstat_t) * fc_adapters);
	ASSERT_PTR(fc_stat != NULL, "malloc", EXIT, fc_stat);

	fc_save = malloc(sizeof(perfstat_fcstat_t) * fc_adapters);
	ASSERT_PTR(fc_save  != NULL, "malloc", EXIT, fc_save);
	fc_adaptname[0] = 0;
	rc = perfstat_fcstat((perfstat_id_t * )fc_adaptname, fc_save, sizeof(perfstat_fcstat_t), fc_adapters);
	ASSERT(rc > 0, "perfstat_fcstat(save)", EXIT, rc);
}

void ps_fc_stats(double elapsed)
{
	int	i;
	int	rc;
	char	fc_adaptname[IDENTIFIER_LENGTH];

    	FUNCTION_START;
	if(fc_adapters == 0) return;

	fc_adaptname[0] = 0;
	rc = perfstat_fcstat((perfstat_id_t * )fc_adaptname, fc_stat, sizeof(perfstat_fcstat_t), fc_adapters);
	ASSERT(rc > 0, "perfstat_fcstat()", EXIT, rc);

	psection("fc_adapters");
	for (i = 0; i < rc; i++) {
		ps_one_fc_adapter(fc_stat[i], fc_save[i], elapsed);
	}
	psectionend();
	memcpy(fc_save, fc_stat, sizeof(perfstat_fcstat_t) * fc_adapters);
}

/* VIOS virtual FC adapters */
int	vios_vfc_adapters;
perfstat_fcstat_t *vfc_curr;
perfstat_fcstat_t *vfc_save;

void ps_vios_vfc_init()
{
	int	rc;
	char	vfc_name[IDENTIFIER_LENGTH];

    	FUNCTION_START;
	/* find out the number of virtual FC adapters */
	vfc_name[0] = 0;
	vios_vfc_adapters = perfstat_virtual_fcadapter(NULL, NULL, sizeof(perfstat_fcstat_t), 0);
	DEBUG printf("perfstat_virtual_fcadapter: %d virtual FC adapter(s) found\n",vios_vfc_adapters); 
	ASSERT(vios_vfc_adapters >= 0, "perfstat_virtual_fcadapter(init)", EXIT, vios_vfc_adapters);

	if(vios_vfc_adapters <= 0) {
		vios_vfc_adapters = 0;
		return;
	}

	/* just assume these work OK, so no error checking */
	vfc_curr = malloc(sizeof(perfstat_fcstat_t) * vios_vfc_adapters);
	ASSERT_PTR(vfc_curr != NULL, "malloc", EXIT, vfc_curr);

	vfc_save = malloc(sizeof(perfstat_fcstat_t) * vios_vfc_adapters);
	ASSERT_PTR(vfc_curr  != NULL, "malloc", EXIT, vfc_save);
	vfc_name[0] = 0;
	rc = perfstat_virtual_fcadapter((perfstat_id_t * )vfc_name, vfc_save, sizeof(perfstat_fcstat_t), vios_vfc_adapters);
	ASSERT(rc >= 0, "perfstat_virtual_fcadapter(first save)", EXIT, rc);
}

void ps_vios_vfc_stats(double elapsed)
{
	int	i;
	int	rc;
	char	vfc_name[IDENTIFIER_LENGTH];

    	FUNCTION_START;
	if(vios_vfc_adapters == 0)
		return;
	vfc_name[0] = 0;
	rc = perfstat_virtual_fcadapter((perfstat_id_t * )vfc_name, vfc_curr, sizeof(perfstat_fcstat_t), vios_vfc_adapters);
	ASSERT(rc > 0, "perfstat_virtual_fcadapter()", EXIT, rc);

	psection("vios_virtual_fcadapter");
	for (i = 0; i < rc; i++) {
		ps_one_fc_adapter(vfc_curr[i], vfc_save[i], elapsed);
	}
	psectionend();
	memcpy(vfc_save, vfc_curr, sizeof(perfstat_fcstat_t) * vios_vfc_adapters);
}



/* perfstat_bridgeadapters */
int     net_bridges = 0;
perfstat_netadapter_t *netbridge_statp;
perfstat_netadapter_t *netbridge_statq;

char first_SEA[256];
char first_SEA_found = 0;

/* return the network adapter type string */
char    *netadapter_type(netadap_type_t type)
{
        switch (type) {
        case NET_PHY:  return "Physical";
        case NET_SEA:  return "SEA";
        case NET_VIR:  return "Virtual";
        case NET_HEA:  return "HEA";
        case NET_EC:   return "EtherChannel";

#ifndef NET_VLAN /* strangely missing in AIX 7.1 */
#define NET_VLAN 5
#endif /* NET_VLAN */

        case NET_VLAN: return "VLAN";
        default:
                return "type-unknown";
        }
}

void ps_one_net_adapter(perfstat_netadapter_t curr, perfstat_netadapter_t prev, double elapsed)
{
#define adapt_delta(xxx)  #xxx, ((double)(curr.xxx - prev.xxx) / elapsed)
#define adapt_num(xxx)    #xxx, ((double)(curr.xxx))

    	FUNCTION_START;
	psub(curr.name);
	pstring("adapter_type",netadapter_type(curr.adapter_type));
	pdouble(adapt_delta(tx_packets));
	pdouble(adapt_delta(tx_bytes));
	pdouble(adapt_delta(tx_interrupts));
	pdouble(adapt_delta(tx_errors));
	pdouble(adapt_delta(tx_packets_dropped));
	pdouble(adapt_delta(tx_queue_size));
	pdouble(adapt_num(tx_queue_len));      /* absolute number */
	pdouble(adapt_num(tx_queue_overflow)); /* absolute number */
	pdouble(adapt_delta(tx_broadcast_packets));
	pdouble(adapt_delta(tx_multicast_packets));
	pdouble(adapt_delta(tx_carrier_sense));
	pdouble(adapt_delta(tx_DMA_underrun));
	pdouble(adapt_delta(tx_lost_CTS_errors));
	pdouble(adapt_delta(tx_max_collision_errors));
	pdouble(adapt_delta(tx_late_collision_errors));
	pdouble(adapt_delta(tx_deferred));
	pdouble(adapt_delta(tx_timeout_errors));
	pdouble(adapt_num(tx_single_collision_count));  /* absolute number */
	pdouble(adapt_num(tx_multiple_collision_count)); /* absolute number */

	pdouble(adapt_delta(rx_packets));
	pdouble(adapt_delta(rx_bytes));
	pdouble(adapt_delta(rx_interrupts));
	pdouble(adapt_delta(rx_errors));
	pdouble(adapt_num(rx_packets_dropped)); /* absolute number */
	pdouble(adapt_num(rx_bad_packets));     /* absolute number */
	pdouble(adapt_delta(rx_multicast_packets));
	pdouble(adapt_delta(rx_broadcast_packets));
	pdouble(adapt_delta(rx_CRC_errors));
	pdouble(adapt_delta(rx_DMA_overrun));
	pdouble(adapt_delta(rx_alignment_errors));
	pdouble(adapt_delta(rx_noresource_errors));
	pdouble(adapt_delta(rx_collision_errors));
	pdouble(adapt_num(rx_packet_tooshort_errors)); /* absolute  number */
	pdouble(adapt_num(rx_packet_toolong_errors));  /* absolute  number */
	pdouble(adapt_delta(rx_packets_discardedbyadapter));
	psubend();
}

void    ps_net_bridge_init()
{
        int     rc;
        perfstat_id_t   netbridge_name;

    	FUNCTION_START;
	if(first_SEA_found == 0) /* no SEA = no data */
		return;

        /* check how many perfstat structures are available */
	strcpy(netbridge_name.name, first_SEA);
        net_bridges =  perfstat_bridgedadapters(&netbridge_name, NULL, sizeof(perfstat_netadapter_t), 0);
        ASSERT(net_bridges >= 0, "perfstat_netadapter(init)", EXIT, net_bridges);
        DEBUG printf("net bridgeadapters=%d\n",net_bridges);
	if(net_bridges == 0) {
		first_SEA_found = 0; /* block further attempts */
		return;
	}
        /* allocate enough memory for all the structures */
        netbridge_statp = malloc(net_bridges * sizeof(perfstat_netadapter_t));
        ASSERT_PTR(netbridge_statp != NULL, "malloc(neta_statp)", EXIT, netbridge_statp);

        netbridge_statq = malloc(net_bridges * sizeof(perfstat_netadapter_t));
        ASSERT_PTR(netbridge_statq != NULL, "malloc(neta_statq)", EXIT, netbridge_statq);

        /* ask to get all the structures available in one call */
        netbridge_name.name[0] = 0;
	strcpy(netbridge_name.name, first_SEA);
        rc = perfstat_bridgedadapters(&netbridge_name, netbridge_statq, sizeof(perfstat_netadapter_t), net_bridges);
        ASSERT(rc > 0, "perfstat_bridgedadapters(1st data)", EXIT, rc);
        ASSERT(rc == net_bridges, "perfstat_bridgedadapters(confused API)", EXIT, net_bridges);
}


void ps_net_bridge_stats(double elapsed)
{
	int	i;
	int	rc;
        perfstat_id_t   netbridge_name;

    	FUNCTION_START;
        if(first_SEA_found == 0) /* no SEA = no data */
                return;
        strcpy(netbridge_name.name, first_SEA);
        rc = perfstat_bridgedadapters(&netbridge_name, netbridge_statp, sizeof(perfstat_netadapter_t), net_bridges);
        ASSERT(rc > 0, "perfstat_bridgedadapters(1st data)", EXIT, rc);

	psection("network_bridged");
	for (i = 0; i < rc; i++) {
		ps_one_net_adapter(netbridge_statp[i], netbridge_statq[i], elapsed);
	}
	psectionend();
	memcpy(netbridge_statq, netbridge_statp, sizeof(perfstat_netadapter_t) * net_bridges);
}


/* perfstat_netadapters */
int	neta_total;
perfstat_netadapter_t *neta_statp;
perfstat_netadapter_t *neta_statq;

void	ps_net_adapter_init()
{
	int	i;
	int	rc;
	perfstat_id_t	neta_name;

    	FUNCTION_START;
	/* check how many perfstat structures are available */
	neta_name.name[0] = 0;
	neta_total =  perfstat_netadapter(NULL, NULL, sizeof(perfstat_netadapter_t), 0);
	ASSERT(neta_total > 0, "perfstat_netadapter(init)", EXIT, neta_total);
	DEBUG fprintf(stderr, "netadapters=%d\n",neta_total);
	/* allocate enough memory for all the structures */
	neta_statp = malloc(neta_total * sizeof(perfstat_netadapter_t));
	ASSERT_PTR(neta_statp != NULL, "malloc(neta_statp)", EXIT, neta_statp);
	neta_statq = malloc(neta_total * sizeof(perfstat_netadapter_t));
	ASSERT_PTR(neta_statq != NULL, "malloc(neta_statq)", EXIT, neta_statq);

	/* ask to get all the structures available in one call */
	neta_name.name[0] = 0;
	rc = perfstat_netadapter(&neta_name, neta_statq, sizeof(perfstat_netadapter_t), neta_total);
	ASSERT(rc > 0, "perfstat_netadapter(1st data)", EXIT, rc);

	/* Search for the first SEA - is this might be a VIOS */
	for (i = 0; i < rc; i++) {
		if(neta_statq[i].adapter_type == NET_SEA){
			strncpy(first_SEA,neta_statq[i].name,255);
			first_SEA_found = 1;
			DEBUG printf("Saving SEA %s %s.\n",neta_statq[i].name,first_SEA);
			break;
		}
	}
}


void	ps_net_adapter_stats(double elapsed)
{
	int	rc;
	int	i;
	perfstat_id_t neta_name;

    	FUNCTION_START;
	neta_name.name[0] = 0;
	rc = perfstat_netadapter(&neta_name, neta_statp, sizeof(perfstat_netadapter_t), neta_total);
	ASSERT(rc > 0, "perfstat_netadapter(data)", EXIT, rc);

#define neta_delta(xxx)  #xxx, ((double)(neta_statp[i].xxx - neta_statq[i].xxx) / elapsed)
#define neta_num(xxx)    #xxx, ((double)(neta_statp[i].xxx))

	psection("network_adapters");
	for (i = 0; i < rc; i++) {
		ps_one_net_adapter(neta_statp[i], neta_statq[i], elapsed);
	}
	psectionend();

	memcpy(neta_statq, neta_statp, sizeof(perfstat_netadapter_t) * neta_total);
}


/* perfstat_netinterface */
int	net_total;
perfstat_netinterface_t *net_statp;
perfstat_netinterface_t *net_statq;

void	ps_net_interface_init()
{
	int	rc;
	char	net_name[IDENTIFIER_LENGTH];

    	FUNCTION_START;
	/* check how many perfstat structures are available */
	net_name[0] = 0;
	net_total =  perfstat_netinterface(NULL, NULL, sizeof(perfstat_netinterface_t), 0);
	ASSERT(net_total > 0, "perfstat_netinterface(init)", EXIT, net_total);

	/* allocate enough memory for all the structures */
	net_statp = malloc(net_total * sizeof(perfstat_netinterface_t));
	ASSERT_PTR(net_statp != NULL, "malloc(net_statp)", EXIT, net_statp);

	net_statq = malloc(net_total * sizeof(perfstat_netinterface_t));
	ASSERT_PTR(net_statq != NULL, "malloc(net_statq)", EXIT, net_statq);

	/* ask to get all the structures available in one call */
	net_name[0] = 0;
	rc = perfstat_netinterface((perfstat_id_t * )net_name, net_statq, sizeof(perfstat_netinterface_t), net_total);
	ASSERT(rc > 0, "perfstat_netinterface(data)", EXIT, rc);
}


void	ps_net_interface_stats(double elapsed)
{
	int	rc;
	int	i;
	char	net_name[IDENTIFIER_LENGTH];

    	FUNCTION_START;
	net_name[0] = 0;
	rc = perfstat_netinterface((perfstat_id_t * )net_name, net_statp, 
	    sizeof(perfstat_netinterface_t), net_total);
	ASSERT(rc > 0, "perfstat_netinterface(data)", EXIT, rc);

#define net_delta(xxx)  #xxx, ((double)(net_statp[i].xxx - net_statq[i].xxx) / elapsed)

	psection("network_interfaces");

	for (i = 0; i < rc; i++) {
		psub(net_statp[i].name);
		pstring("description", net_statp[i].description);
		plong("mtu", net_statp[i].mtu);
		pdouble(net_delta(ipackets));
		pdouble(net_delta(ibytes));
		pdouble(net_delta(ierrors));
		pdouble(net_delta(opackets));
		pdouble(net_delta(obytes));
		pdouble(net_delta(oerrors));
		pdouble(net_delta(collisions));
		pdouble(net_delta(xmitdrops));
		pdouble(net_delta(if_iqdrops));
		pdouble(net_delta(if_arpdrops));
		pdouble("bitrate_mbit", (double)(net_statp[i].bitrate) / 1024.0 / 1024.0);
		psubend();
	}
	psectionend();
	memcpy(net_statq, net_statp, sizeof(perfstat_netinterface_t) * net_total);
}


/* perfstat_netinterface_total */
perfstat_netinterface_total_t nettot_a;
perfstat_netinterface_total_t nettot_b;

void	ps_net_total_init()
{
	int	rc;
	char	net_name[IDENTIFIER_LENGTH];

    	FUNCTION_START;
	rc = perfstat_netinterface_total(NULL, &nettot_a, sizeof(perfstat_netinterface_total_t), 1);
	ASSERT(rc > 0, "perfstat_netinterface_total(init)", EXIT, rc);
}

#define nettot_delta(xxx)  #xxx, ((double)(nettot_b.xxx - nettot_a.xxx) / elapsed)

void	ps_net_total_stats(double elapsed)
{
	int	rc;

    	FUNCTION_START;
	rc = perfstat_netinterface_total(NULL, &nettot_b, sizeof(perfstat_netinterface_total_t), 1);
	ASSERT(rc > 0, "perfstat_netinterface_total(data)", EXIT, rc);

	psection("network_total");
	plong("networks",nettot_b.number);
	pdouble(nettot_delta(ipackets));
	pdouble(nettot_delta(ibytes));
	pdouble(nettot_delta(ierrors));
	pdouble(nettot_delta(opackets));
	pdouble(nettot_delta(obytes));
	pdouble(nettot_delta(oerrors));
	pdouble(nettot_delta(collisions));
	pdouble(nettot_delta(xmitdrops));
	psectionend();
	memcpy(&nettot_a, &nettot_b, sizeof(perfstat_netinterface_total_t));
}

/* perfstat_cpu */
int	cpu_total; /* used in CPU and Disk stat collection */
perfstat_cpu_t *cpu_statp;
perfstat_cpu_t *cpu_statq;

void	ps_cpu_init()
{
	int	rc;
	char	cpu_name[IDENTIFIER_LENGTH];

    	FUNCTION_START;
	/* check how many perfstat structures are available */
	cpu_name[0] = 0;
	cpu_total = perfstat_cpu(NULL, NULL, sizeof(perfstat_cpu_t), 0);
	/* DEBUG printf("rc=%d errno=%d perfstat_cpu(NULL)\n",cpu_total, errno); */
	if (cpu_total <= 0) 
		printf("rc=%d errno=%d perfstat_cpu(NULL)\n", cpu_total, errno);
	ASSERT(cpu_total > 0, "perfstat_cpu(init)", EXIT, cpu_total);

	/* allocate enough memory for all the structures */
	cpu_statp = malloc(cpu_total * sizeof(perfstat_cpu_t));
	ASSERT_PTR(cpu_statp != NULL, "malloc(cpu_statp)", EXIT, cpu_statp);

	cpu_statq = malloc(cpu_total * sizeof(perfstat_cpu_t));
	ASSERT_PTR(cpu_statq != NULL, "malloc(cpu_statq)", EXIT, cpu_statq);

	/* ask to get all the structures available in one call */
	cpu_name[0] = 0;
	rc = perfstat_cpu((perfstat_id_t * )cpu_name, cpu_statq, sizeof(perfstat_cpu_t), cpu_total);
	ASSERT(rc > 0, "perfstat_cpu(data)", EXIT, rc);
}

void	ps_cpu_stats(double elapsed)
{
	int	rc;
	int	i;
	long	total;
	char	cpu_name[IDENTIFIER_LENGTH];
	char cpuname[256];

    	FUNCTION_START;
	cpu_name[0] = 0;
	rc = perfstat_cpu((perfstat_id_t * )cpu_name, (perfstat_cpu_t * )cpu_statp, sizeof(perfstat_cpu_t), cpu_total);
	ASSERT(rc > 0, "perfstat_cpu()", EXIT, rc);
#ifdef OLDNAMES
	psection("logical_cpu");
#else
	psection("cpu_logical");
#endif
	for (i = 0; i < rc; i++) {
/*
		sprintf(cpuname,"lcpu%03d",i);
printf("i=%d name=%s\n",i,cpu_statp[i].name);
printf("user=%ld user=%ld diff=%ld\n",(long)cpu_statp[i].user,(long)cpu_statq[i].user,(long)(cpu_statp[i].user  - cpu_statq[i].user));
printf("sys =%ld sys =%ld diff=%ld\n",(long)cpu_statp[i].sys ,(long)cpu_statq[i].sys ,(long)(cpu_statp[i].sys   - cpu_statq[i].sys ));
printf("wait=%ld wait=%ld diff=%ld\n",(long)cpu_statp[i].wait,(long)cpu_statq[i].wait,(long)(cpu_statp[i].wait  - cpu_statq[i].wait));
printf("idle=%ld idle=%ld diff=%ld\n",(long)cpu_statp[i].idle,(long)cpu_statq[i].idle,(long)(cpu_statp[i].idle  - cpu_statq[i].idle));
*/
		psub(cpu_statp[i].name);
		/* These are raw number of clock ticks spent so convert into percentages */
		total = (long)(cpu_statp[i].user  - cpu_statq[i].user) +
			(long)(cpu_statp[i].sys   - cpu_statq[i].sys ) + 
			(long)(cpu_statp[i].wait  - cpu_statq[i].wait) +
			(long)(cpu_statp[i].idle  - cpu_statq[i].idle);
		if(total <= 0.0) {
			plong("user", 0);
			plong("sys",  0);
			plong("wait", 0);
			plong("idle", 0);
		} else {
			plong("user", (long)(((double)cpu_statp[i].user  - (double)cpu_statq[i].user)*100.0/(double)total));
			plong("sys",  (long)(((double)cpu_statp[i].sys   - (double)cpu_statq[i].sys )*100.0/(double)total));
			plong("wait", (long)(((double)cpu_statp[i].wait  - (double)cpu_statq[i].wait)*100.0/(double)total));
			plong("idle", (long)(((double)cpu_statp[i].idle  - (double)cpu_statq[i].idle)*100.0/(double)total));
		}
		psubend();
	}
	psectionend();
#ifdef OLDNAMES
	psection("physical_cpu");
#else
	psection("cpu_physical");
#endif
	for (i = 0; i < rc; i++) {
/*
                sprintf(cpuname,"pcpu%03d",i);
*/
                psub(cpu_statp[i].name);
		plong("user", (long)((cpu_statp[i].puser - cpu_statq[i].puser) * 100.0 / (double)hardware_ticks));
		plong("sys",  (long)((cpu_statp[i].psys  - cpu_statq[i].psys ) * 100.0 / (double)hardware_ticks));
		plong("wait", (long)((cpu_statp[i].pwait - cpu_statq[i].pwait) * 100.0 / (double)hardware_ticks));
		plong("idle", (long)((cpu_statp[i].pidle - cpu_statq[i].pidle) * 100.0 / (double)hardware_ticks));
		psubend();
	}
	psectionend();
	psection("cpu_syscalls");
	for (i = 0; i < rc; i++) {
/*
                sprintf(cpuname,"cpu%03d",i);
*/
                psub(cpu_statp[i].name);
		pdouble("syscall",    (double)(cpu_statp[i].syscall  - cpu_statq[i].syscall)/elapsed);
		pdouble("sysread",    (double)(cpu_statp[i].sysread  - cpu_statq[i].sysread)/elapsed);
		pdouble("syswrite",   (double)(cpu_statp[i].syswrite - cpu_statq[i].syswrite)/elapsed);
		pdouble("sysfork",    (double)(cpu_statp[i].sysfork  - cpu_statq[i].sysfork)/elapsed);
		pdouble("sysexec",    (double)(cpu_statp[i].sysexec  - cpu_statq[i].sysexec)/elapsed);
		pdouble("sysreadch",  (double)(cpu_statp[i].readch   - cpu_statq[i].readch)/elapsed);
		pdouble("syswritech", (double)(cpu_statp[i].writech  - cpu_statq[i].writech)/elapsed);
		psubend();
	}
	psectionend();
	memcpy(cpu_statq, cpu_statp, sizeof(perfstat_cpu_t) * cpu_total);
}

/* PROCESSES */
perfstat_process_t *process_p; /* previous snapsot */
perfstat_process_t *process_c; /* current snapshot */
perfstat_process_t *process_t; /* temporary */
perfstat_process_t *process_u; /* results of the util function */
perfstat_rawdata_t  proc_rawdata;
long proc_items;
long proc_last_time;
long proc_this_time;

double cpu_threshold = 0.001 ; /* processes using less than this are excluded in the output */

void	ps_process_init()
{
	int	rc;
	perfstat_id_t processname= {""};

    	FUNCTION_START;
	rc = perfstat_process(NULL, NULL, sizeof(perfstat_process_t), 0);
	ASSERT(rc > 0, "perfstat_process(NULL)", EXIT, rc);
	DEBUG printf("%d = perfstat_process(1) - %d\n",rc,errno);

	/* setup the pointers */
	proc_items = rc * 2;  /* add a few incase processes are being created quickly */
	process_p = malloc( (proc_items) * sizeof(perfstat_process_t));
	process_c = malloc( (proc_items) * sizeof(perfstat_process_t));
	process_u = malloc( (proc_items) * sizeof(perfstat_process_t));

	/* get initial set of data  at the current point to be previous at the first stats capture */
	rc = perfstat_process(&processname, process_c, sizeof(perfstat_process_t), proc_items);
	ASSERT(rc > 0, "perfstat_process(data2)", EXIT, rc);
	DEBUG printf("%d = perfstat_process(2) - %d\n",rc,errno);
	proc_this_time = rc;
}


void	ps_process_util()
{
	int	rc;
	int	i;
	perfstat_id_t processname= {""};
	char procname[64];

	/* Async I/O */
	int is_aio = 0;
	long aioprocs = 0;
	long aiorunning = 0;
	double aiocpu = 0.0;

    	FUNCTION_START;
	/* rotate the data structures */
	process_t = process_p;
	process_p = process_c;
	process_c = process_t;

	proc_last_time = proc_this_time;

	rc = perfstat_process(&processname, process_c, sizeof(perfstat_process_t), proc_items);
	ASSERT(rc > 0, "perfstat_process(data3)", EXIT, rc);
	DEBUG printf("%d = perfstat_process(3) - %d\n",rc,errno);

	proc_this_time = rc;
	/* Set up compare data for utilisation */
        proc_rawdata.type = UTIL_PROCESS;
        proc_rawdata.curstat = process_c;
        proc_rawdata.prevstat = process_p;
        proc_rawdata.sizeof_data = sizeof(perfstat_process_t);
        proc_rawdata.cur_elems = proc_this_time;
        proc_rawdata.prev_elems = proc_last_time;

        rc = perfstat_process_util(&proc_rawdata, process_u, sizeof(perfstat_process_t), proc_items);
	ASSERT(rc > 0, "perfstat_process_util(data)", EXIT, rc);
	DEBUG printf("%d = perfstat_process_util(4) - %d\n",rc,errno);

	if(rc < 1) return;

	psection("processes");
	/*
	plong("sizeof",  sizeof(perfstat_process_t));
	plong("items",   proc_items);
	plong("returned",rc);
	plong("error",   errno);
	*/
	is_aio = 0;
	for(i = 0; i < rc; i++) {

	    /* Async I/O - often used by Oracle */
	    /* TESSTING if(!strncmp(process_u[i].proc_name, "ncpu", 4)) {*/
	    if(!strncmp(process_u[i].proc_name, "aioserver", 9)) { 
		is_aio = 1;
		aioprocs++;
		aiocpu += process_u[i].ucpu_time + process_u[i].scpu_time;
	    } else {
		is_aio = 0;
	    }

	    if(cpu_threshold < 0.0 || (process_u[i].ucpu_time + process_u[i].ucpu_time) > cpu_threshold) {
		if(is_aio)	/* Async I/O */
			aiorunning++;
		sprintf(procname, "process_%lld", (long long)process_u[i].pid);
		psub(procname);
		plong("pid",		process_u[i].pid);
		pstring("name",		process_u[i].proc_name);
		plong("priority",	process_u[i].proc_priority);
		plong("num_threads",    process_u[i].num_threads);
		plong("uid",		process_u[i].proc_uid);
		plong("wparid",		process_u[i].proc_classid);
		plong("size",		process_u[i].proc_size);
		plong("real_mem_data",	process_u[i].proc_real_mem_data);
		plong("real_mem_text",	process_u[i].proc_real_mem_text);
		plong("virt_mem_data",	process_u[i].proc_virt_mem_data);
		plong("virt_mem_text",	process_u[i].proc_virt_mem_text);
		plong("shared_lib_data",process_u[i].shared_lib_data_size);
		plong("heap_size",	process_u[i].heap_size);
		plong("real_inuse",	process_u[i].real_inuse);
		plong("virt_inuse",	process_u[i].virt_inuse);
		plong("pinned", 	process_u[i].pinned);
		plong("pgsp_inuse",	process_u[i].pgsp_inuse);
		plong("filepages",	process_u[i].filepages);
		plong("real_inuse_map",	process_u[i].real_inuse_map);
		plong("virt_inuse_map",	process_u[i].virt_inuse_map);
		plong("pinned_inuse_map", process_u[i].pinned_inuse_map);
		pdouble("ucpu_time",	process_u[i].ucpu_time);
		pdouble("scpu_time",	process_u[i].scpu_time);
		/* plong("last_timebase",	process_u[i].last_timebase); */
		plong("inBytes",	process_u[i].inBytes);
		plong("outBytes",	process_u[i].outBytes);
		plong("inOps",		process_u[i].inOps);
		plong("outOps",		process_u[i].outOps);
		psubend();
	    }
	}
	psectionend();
	if(aioprocs) {
		psection("aioserver");
		plong("aioprocs", aioprocs);
		plong("aiorunning", aiorunning);
		pdouble("aiocpu", aiocpu);
		psectionend();
	}
}


/* CPU TOTAL */
/* macro to calculate the difference between previous and current values */
#define DELTA(member) (cpu_tot_p->member - cpu_tot_q->member)
#define DELTAD(member) (double)((double)cpu_tot_p->member - (double)cpu_tot_q->member)

/* the two copies of the cpu data */
perfstat_cpu_total_t cpu_tot[2];

perfstat_cpu_total_t *cpu_tot_q; /* current snapshot */
perfstat_cpu_total_t *cpu_tot_p; /* previous snapsot */
perfstat_cpu_total_t *cpu_tot_t; /* temporary */
perfstat_cpu_util_t cpu_util;
perfstat_rawdata_t rawdata;


void	ps_cpu_total_init()
{
	int	rc;

    	FUNCTION_START;
	/* setup the pointers */
	cpu_tot_q = &cpu_tot[0];
	cpu_tot_p = &cpu_tot[1];
	/* get initial set of data */
	rc = perfstat_cpu_total(NULL, cpu_tot_q, sizeof(perfstat_cpu_total_t), 1);
	ASSERT(rc > 0, "perfstat_cpu_total(init)", EXIT, rc);

	/* Set up compare data for utilisation */
        rawdata.type = UTIL_CPU_TOTAL;
        rawdata.curstat = cpu_tot_p;
        rawdata.prevstat = cpu_tot_q;
        rawdata.sizeof_data = sizeof(perfstat_cpu_total_t);
        rawdata.cur_elems = 1;
        rawdata.prev_elems = 1;

        rc = perfstat_cpu_util(&rawdata, &cpu_util, sizeof(perfstat_cpu_util_t), 1);
	ASSERT(rc > 0, "perfstat_cpu_util(init)", EXIT, rc);
}


void	ps_cpu_total_stats(double elapsed)
{
	int	rc;
	double	total;
	double	ptotal;
	union {
		int	a;
		unsigned int	b;
	} un;

    	FUNCTION_START;
	rc = perfstat_cpu_total(NULL, cpu_tot_p, sizeof(perfstat_cpu_total_t), 1);
	ASSERT(rc > 0, "perfstat_cpu_total(data)", EXIT, rc);

	/* Set up compare data for utilisation */
        rawdata.type = UTIL_CPU_TOTAL;
        rawdata.curstat = cpu_tot_p;
        rawdata.prevstat = cpu_tot_q;
        rawdata.sizeof_data = sizeof(perfstat_cpu_total_t);
        rawdata.cur_elems = 1;
        rawdata.prev_elems = 1;

        rc = perfstat_cpu_util(&rawdata, &cpu_util, sizeof(perfstat_cpu_util_t), 1);
	ASSERT(rc > 0, "perfstat_cpu_util(data)", EXIT, rc);

	current_mhz = nominal_mhz * cpu_util.freq_pct / 100.0;

	psection("cpu_util");
	pdouble("user_pct", 	   cpu_util.user_pct);
	pdouble("kern_pct", 	   cpu_util.kern_pct);
	pdouble("idle_pct", 	   cpu_util.idle_pct);
	pdouble("wait_pct", 	   cpu_util.wait_pct);

	pdouble("physical_busy",cpu_util.physical_busy);
	pdouble("physical_consumed",cpu_util.physical_consumed);

	pdouble("idle_donated_pct",cpu_util.idle_donated_pct);
	pdouble("busy_donated_pct",cpu_util.busy_donated_pct);

	pdouble("idle_stolen_pct",cpu_util.idle_stolen_pct);
	pdouble("busy_stolen_pct",cpu_util.busy_stolen_pct);

	pdouble("entitlement", 	   cpu_util.entitlement);
	pdouble("entitlement_pct",  cpu_util.entitlement_pct);
	pdouble("freq_pct", 	   cpu_util.freq_pct);
	pdouble("nominal_mhz", 	   nominal_mhz);
	pdouble("current_mhz", 	   current_mhz);
	psectionend();


	psection("cpu_details");
	plong("cpus_active", 	cpu_tot_p->ncpus);
	plong("cpus_configured",cpu_tot_p->ncpus_cfg);
	pdouble("mhz", 		(double) (cpu_tot_p->processorHZ / 1000000));
	pstring("cpus_description", cpu_tot_p->description);
	psectionend();

	psection("kernel");
	pdouble("pswitch", 		DELTA(pswitch) / elapsed);
	pdouble("syscall", 		DELTA(syscall) / elapsed);
	pdouble("sysread", 		DELTA(sysread) / elapsed);
	pdouble("syswrite", 		DELTA(syswrite) / elapsed);
	pdouble("sysfork", 		DELTA(sysfork) / elapsed);
	pdouble("sysexec", 		DELTA(sysexec) / elapsed);

	pdouble("readch", 		DELTA(readch) / elapsed);
	pdouble("writech", 		DELTA(writech) / elapsed);

	pdouble("devintrs", 		DELTA(devintrs) / elapsed);
	pdouble("softintrs", 		DELTA(softintrs) / elapsed);

	pdouble("load_avg_1_min", 	(double)cpu_tot_p->loadavg[0] / (double)(1 << SBITS));
	pdouble("load_avg_5_min", 	(double)cpu_tot_p->loadavg[1] / (double)(1 << SBITS));
	pdouble("load_avg_15_min", 	(double)cpu_tot_p->loadavg[2] / (double)(1 << SBITS));

	un.a = cpu_tot_p->lbolt; 		/* ticks since last reboot */
	pdouble("uptime_days", 		(float)un.b / HZ / 60.0 / 60.0 / 24.0);

	plong("runque", 		DELTA(runque)); /* fixed */
	plong("swpque", 		DELTA(swpque)); /* fixed */
	if (DELTA(runque) == 0 || DELTA(runocc) == 0)
		pdouble("run_queue", 0.0);
	else
		pdouble("run_queue", 	((double)(DELTA(runque)))/((double)(DELTA(runocc)))); /* fixed */
	if (DELTA(swpque) == 0 || DELTA(swpocc) == 0)
		pdouble("swp_queue", 0.0);
	else
		pdouble("swp_queue", 	((double)(DELTA(swpque)))/((double)(DELTA(swpocc)))); /* fixed */

	pdouble("bread", 		DELTA(bread) / elapsed);
	pdouble("bwrite", 		DELTA(bwrite) / elapsed);
	pdouble("lread", 		DELTA(lread) / elapsed);
	pdouble("lwrite", 		DELTA(lwrite) / elapsed);
	pdouble("phread", 		DELTA(phread) / elapsed);
	pdouble("phwrite", 		DELTA(phwrite) / elapsed);

	plong("runocc_count", 		DELTA(runocc));
	plong("swpocc_count", 		DELTA(swpocc));
	plong("runocc_avg", 		DELTA(runocc) / elapsed);
	plong("swpocc_avg", 		DELTA(swpocc) / elapsed);

	pdouble("iget", 		DELTA(iget) / elapsed);
	pdouble("namei", 		DELTA(namei) / elapsed);
	pdouble("dirblk", 		DELTA(dirblk) / elapsed);
	
	pdouble("msg", 			DELTA(msg) / elapsed);
	pdouble("sema", 		DELTA(sema) / elapsed);
	pdouble("rcvint", 		DELTA(rcvint) / elapsed);
	pdouble("xmtint", 		DELTA(xmtint) / elapsed);
	pdouble("mdmint", 		DELTA(mdmint) / elapsed);
	pdouble("tty_rawinch", 		DELTA(tty_rawinch) / elapsed);
	pdouble("tty_caninch", 		DELTA(tty_caninch) / elapsed);
	pdouble("tty_rawoutch", 	DELTA(tty_rawoutch) / elapsed);

	pdouble("ksched", 		DELTA(ksched) / elapsed);
	pdouble("koverf", 		DELTA(koverf) / elapsed);
	pdouble("kexit", 		DELTA(kexit) / elapsed);

	pdouble("rbread",             	DELTA(rbread) / elapsed);
	pdouble("rcread",             	DELTA(rcread) / elapsed);
	pdouble("rbwrt",              	DELTA(rbwrt) / elapsed);
	pdouble("rcwrt",              	DELTA(rcwrt) / elapsed);

	pdouble("traps",              	DELTA(traps) / elapsed);

	plong("ncpus_high", 		cpu_tot_p->ncpus_high); /* new */
	pdouble("decrintrs", 		DELTA(decrintrs) / elapsed); /* new */
	pdouble("mpcrintrs", 		DELTA(mpcrintrs) / elapsed); /* new */
	pdouble("mpcsintrs", 		DELTA(mpcsintrs) / elapsed); /* new */
	pdouble("phantintrs", 		DELTA(phantintrs) / elapsed); /* new */

	pdouble("idle_donated_purr",    (double)DELTA(idle_donated_purr) );
	pdouble("idle_donated_spurr",   (double)DELTA(idle_donated_spurr) );
	pdouble("busy_donated_purr",    (double)DELTA(busy_donated_purr) );
	pdouble("busy_donated_spurr",   (double)DELTA(busy_donated_spurr) );
	pdouble("idle_stolen_purr",     (double)DELTA(idle_stolen_purr) );
	pdouble("idle_stolen_spurr",    (double)DELTA(idle_stolen_spurr) );
	pdouble("busy_stolen_purr",     (double)DELTA(busy_stolen_purr) );
	pdouble("busy_stolen_spurr",    (double)DELTA(busy_stolen_spurr) );

	plong("iowait",   		cpu_tot_p->iowait );
	plong("physio",   		cpu_tot_p->physio );
	plong("twait",   		cpu_tot_p->twait );

	pdouble("hpi",    		(double)DELTA(hpi) / elapsed );
	pdouble("hpit",   		(double)DELTA(hpit) / elapsed );

	plong("spurrflag", 		cpu_tot_p->spurrflag);
	plong("tb_last",    		cpu_tot_p->tb_last);
	pdouble("purr_coalescing",    	(double)DELTA(purr_coalescing) / elapsed );
	pdouble("spurr_coalescing",   	(double)DELTA(spurr_coalescing) / elapsed );
	psectionend();

	total  = DELTA(user) + DELTA(sys) + DELTA(idle) + DELTA(wait);
	ptotal  = DELTA(puser) + DELTA(psys) + DELTA(pidle) + DELTA(pwait);

#ifdef OLDNAMES
	psection("total_logical_cpu");
#else
	psection("cpu_logical_total");
#endif
	pdouble("user", 100.0 * (double) DELTA(user) /  total);
	pdouble("sys",  100.0 * (double) DELTA(sys)  / total);
	pdouble("wait", 100.0 * (double) DELTA(wait) / total);
	pdouble("idle", 100.0 * (double) DELTA(idle) / total);
	psectionend();

#ifdef OLDNAMES
	psection("total_physical_cpu");
#else
	psection("cpu_physical_total");
#endif
	pdouble("user", 100.0 * (double) DELTA(puser) / ptotal);
	pdouble("sys",  100.0 * (double) DELTA(psys)  / ptotal);
	pdouble("wait", 100.0 * (double) DELTA(pwait) / ptotal);
	pdouble("idle", 100.0 * (double) DELTA(pidle) / ptotal);
	psectionend();

	ptotal  = DELTA(puser_spurr) + DELTA(psys_spurr) + DELTA(pidle_spurr) + DELTA(pwait_spurr);

#ifdef OLDNAMES
	psection("total_physical_cpu_spurr");
#else
	psection("cpu_physical_total_spurr");
#endif
	pdouble("puser", 100.0 * (double) DELTA(puser_spurr) / ptotal);
	pdouble("psys",  100.0 * (double) DELTA(psys_spurr)  / ptotal);
	pdouble("pidle", 100.0 * (double) DELTA(pidle_spurr) / ptotal);
	pdouble("pwait", 100.0 * (double) DELTA(pwait_spurr) / ptotal);
	psectionend();

	/* Swap the pointer around ready for next time */
	cpu_tot_t = cpu_tot_p;
	cpu_tot_p = cpu_tot_q;
	cpu_tot_q = cpu_tot_t;
}
char junk1[1024];
struct vminfo vmi_prev;
char junk2[1024];
struct vminfo vmi_now;
char junk3[1024];

void	ps_vminfo_init()
{
	int	rc;

    	FUNCTION_START;
	rc = vmgetinfo(&vmi_prev, VMINFO, sizeof(struct vminfo ));
	ASSERT(rc == 0, "vmgetinfo(init)", EXIT, rc);
}

void	ps_vminfo(double elapsed)
{
	int	rc;

#define vminfo_double(xxx)         pdouble( # xxx, ((double)(vmi_now.xxx - vmi_prev.xxx)) / (double)elapsed);
#define vminfo_long(xxx)         plong  ( # xxx, (long long)(vmi_now.xxx));

    	FUNCTION_START;
	ASSERT(elapsed != 0.0, "vmgetinfo(data) elapsed", DUMP, (long long)elapsed);
	rc = vmgetinfo(&vmi_now, VMINFO, sizeof(struct vminfo ));
	ASSERT(rc == 0, "vmgetinfo(data)", EXIT, rc);

	psection("vminfo");
	vminfo_double(pgexct);	/* see /usr/include/sys/vminfo.h these are incrementing counters */
	vminfo_double(pgrclm);
	vminfo_double(lockexct);
	vminfo_double(backtrks);
	vminfo_double(pageins);
	vminfo_double(pageouts);
	vminfo_double(pgspgins);
	vminfo_double(pgspgouts);
	vminfo_double(numsios);
	vminfo_double(numiodone);
	vminfo_double(zerofills);
	vminfo_double(exfills);
	vminfo_double(scans);
	vminfo_double(cycles);
	vminfo_double(pgsteals);
	/* other vallues available but what do they mean  to non AIX Kernal programmers */

	vminfo_long(numfrb);		/* see /usr/include/sys/vminfo.h these are values */
	vminfo_long(numclient);
	vminfo_long(numcompress);
	vminfo_long(numperm);
	vminfo_long(maxperm);
	vminfo_long(memsizepgs);
	vminfo_long(numvpages);
	vminfo_long(minperm);
	vminfo_long(minfree);
	vminfo_long(maxfree);
	vminfo_long(maxclient);
	vminfo_long(npswarn);
	vminfo_long(npskill);
	vminfo_long(minpgahead);
	vminfo_long(maxpgahead);
	vminfo_long(ame_memsizepgs);
	vminfo_long(ame_numfrb);
	vminfo_long(ame_factor_tgt);
	vminfo_long(ame_factor_actual);
	vminfo_long(ame_deficit_size);

	/* another 100 stats in here but only a kernel programmer would understand them */
	psectionend();
	memcpy(&vmi_prev, &vmi_now, sizeof(struct vminfo) );
}


perfstat_tape_t *tape_prev;
perfstat_tape_t *tape_now;
int tapes;

void	ps_tape_init()
{
	int	rc;
	perfstat_id_t first;

    	FUNCTION_START;
	DEBUG fprintf(stderr,"ps_tape_init()\n");
	tapes = perfstat_tape(NULL, NULL, sizeof(perfstat_tape_t), 0);
	DEBUG fprintf(stderr,"ps_tape_init number of tapes=%d\n",tapes);

	/* return code is number of structures returned */
	ASSERT(tapes >= 0, "perfstat_tape(init)", EXIT, tapes);
	if (tapes == 0 ) {
		return;
	}
	tape_prev = malloc(sizeof(perfstat_tape_t) * tapes);
	ASSERT_PTR(tape_prev != NULL, "malloc(tape_prev)", EXIT, tape_prev);
	tape_now  = malloc(sizeof(perfstat_tape_t) * tapes);
	ASSERT_PTR(tape_now != NULL, "malloc(tape_now)", EXIT, tape_now);
	strcpy(first.name, FIRST_TAPE);
	rc = perfstat_tape(&first, tape_prev, sizeof(perfstat_tape_t), tapes);
}

void	ps_tape(double elapsed)
{
	int	rc;
	int	i;
	perfstat_id_t first;

#define tape_long(xxx) 		plong(   # xxx, tape_now[i].xxx);
#define tape_double(xxx)	pdouble( # xxx, ((double)(tape_now[i].xxx - tape_prev[i].xxx)) / (double)elapsed);

    	FUNCTION_START;
	if(tapes == 0) {	/* dont output anything if no tape drives found */
		return;
	}
	DEBUG fprintf(stderr,"ps_tape() tapes=%d\n",tapes);
	strcpy(first.name, FIRST_TAPE);
	rc = perfstat_tape(&first, tape_now, sizeof(perfstat_tape_t), tapes);
	/* return code is number of structures returned */
	ASSERT(rc > 0, "perfstat_tapes(data)", EXIT, tapes);
	psection("tapes");
	for(i=0; i < rc; i++) {
		psub(tape_now[i].name);
		pstring("description", tape_now[i].description);

		tape_long( size);
		tape_long( free);
		tape_long( bsize);

		pstring("adapter", tape_now[i].adapter);
		tape_long(paths_count);

		tape_double(xfers);
		tape_double(rxfers);
		tape_double(wblks);
		tape_double(rblks);
		tape_double(time);

		tape_double(rserv);
		tape_double(rtimeout);
		tape_double(rfailed);
		tape_long(min_rserv);
		tape_long(max_rserv);
		tape_double(wserv);
		tape_double(wtimeout);
		tape_double(wfailed);
		tape_long(min_wserv);
		tape_long(max_wserv);

		psubend();
	}
	psectionend();
	// memcpy(&tape_prev, &tape_now, sizeof(perfstat_tape_t) * tapes );
         /* ctremel: avoid segfaults with tape devices caused by pointer overlaps */ 
           memcpy(tape_prev, tape_now, sizeof(perfstat_tape_t) * tapes );
}


perfstat_memory_page_t mem_page_prev[4];
perfstat_memory_page_t mem_page_now[4];
int mem_pages;

void	ps_memory_page_init()
{
	int	rc;
	perfstat_psize_t pagesize;

    	FUNCTION_START;
	mem_pages = perfstat_memory_page(NULL, NULL, sizeof(perfstat_memory_page_t), 0);

	/* return code is number of structures returned */
	ASSERT(mem_pages > 0, "perfstat_memory_page(init)", RETURN, mem_pages);
	if(mem_pages <= 0) {	/* found njmon compiled for 7.1 TL4 sp2 fails on AIX 7.1 TL4 sp4 */
		mem_pages = 0;
	}
	pagesize.psize = FIRST_PSIZE;
	rc = perfstat_memory_page(&pagesize, &mem_page_prev[0], sizeof(perfstat_memory_page_t), mem_pages);
}

void	ps_memory_page(double elapsed)
{
	int	rc;
	int	i;
	perfstat_psize_t pagesize;

#define mp_long(xxx) 		plong(   # xxx, mem_page_now[i].xxx);
#define mp_double(xxx)		pdouble( # xxx, ((double)(mem_page_now[i].xxx - mem_page_prev[i].xxx)) / (double)elapsed);

    	FUNCTION_START;
	if(mem_pages == 0) { 	/* found njmon compiled for 7.1 TL4 sp2 fails on AIX 7.1 TL4 sp4 */
		return;
	}
	pagesize.psize = FIRST_PSIZE;
	rc = perfstat_memory_page(&pagesize, &mem_page_now[0], sizeof(perfstat_memory_page_t), mem_pages);
	/* return code is number of structures returned */
	ASSERT(rc > 0, "perfstat_memory_page(data)", EXIT, rc);
	psection("memory_page");
	for(i=0; i < rc; i++) {
		switch(mem_page_now[i].psize) {
			case PAGE_4K:  psub("4KB"); break;
			case PAGE_64K: psub("64KB"); break;
			case PAGE_16M: psub("16MB"); break;
			case PAGE_16G: psub("16GB"); break;
			default: psub("unknown"); break;
		}
		mp_long( real_total);
		mp_long( real_free);
		mp_long( real_pinned);
		mp_long( real_inuse);
		mp_double( pgexct);
		mp_double( pgins);
		mp_double( pgouts);
		mp_double( pgspins);
		mp_double( pgspouts);
		mp_double( scans);
		mp_double( cycles);
		mp_double( pgsteals);
		mp_long( numperm);
		mp_long( numpgsp);
		mp_long( real_system);
		mp_long( real_user);
		mp_long( real_process);
		mp_long( virt_active);
		mp_long( comprsd_total);
		mp_long( comprsd_wseg_pgs);
		mp_double( cpgins);
		mp_double( cpgouts);

		mp_long( cpool_inuse);
		mp_long( ucpool_size);
		mp_long( comprsd_wseg_size);
		mp_long( real_avail);
		psubend();
	}
	psectionend();
	memcpy(&mem_page_prev, &mem_page_now, sizeof(perfstat_memory_page_t) * mem_pages );
}

perfstat_memory_total_t mem_prev;
perfstat_memory_total_t mem_now;

void	ps_memory_init()
{
	int	rcy;
	int	rc;

    	FUNCTION_START;
	rc = perfstat_memory_total(NULL, &mem_prev, sizeof(perfstat_memory_total_t), 1);
	/* return code is number of structures returned */
	ASSERT(rc > 0, "perfstat_memory_total(init)", EXIT, rc);
}

void	ps_memory(double elapsed)
{
	int	rc;

#define memory_long(xxx) 		plong(   # xxx, mem_now.xxx);
#define memory_double(xxx)		pdouble( # xxx, ((double)(mem_now.xxx - mem_prev.xxx)) / (double)elapsed);

    	FUNCTION_START;
	rc = perfstat_memory_total(NULL, &mem_now, sizeof(perfstat_memory_total_t), 1);
	/* return code is number of structures returned */
	ASSERT(rc > 0, "perfstat_memory_total(data)", EXIT, rc);

	psection("memory");
	memory_long(virt_total);
	memory_long(real_total);
	memory_long(real_free);
	memory_long(real_pinned);
	memory_long(real_inuse);
	memory_double(pgbad);
	memory_double(pgexct);
	memory_double(pgins);
	memory_double(pgouts);
	memory_double(pgspins);
	memory_double(pgspouts);
	memory_double(scans);
	memory_double(cycles);
	memory_double(pgsteals);
	memory_long(numperm);
	memory_long(pgsp_total);
	memory_long(pgsp_free);
	memory_long(pgsp_rsvd);

	memory_long(real_system);
	memory_long(real_user);
	memory_long(real_process);
	memory_long(virt_active);

	memory_long(iome);
	memory_long(iomu);
	memory_long(iohwm);
	memory_long(pmem);

	memory_long(comprsd_total);
	memory_long(comprsd_wseg_pgs);
	memory_long(cpgins);
	memory_long(cpgouts);
	memory_long(true_size);
	memory_long(expanded_memory);
	memory_long(comprsd_wseg_size);
	memory_long(target_cpool_size);
	memory_long(max_cpool_size);
	memory_long(min_ucpool_size);
	memory_long(cpool_size);
	memory_long(ucpool_size);
	memory_long(cpool_inuse);
	memory_long(ucpool_inuse);
	memory_long(real_avail);
	memory_long(bytes_coalesced);
	memory_long(bytes_coalesced_mempool);
	psectionend();
	memcpy(&mem_prev, &mem_now, sizeof(perfstat_memory_total_t) );
}

int pagingspaces = 0;
perfstat_pagingspace_t *paging;

void ps_paging_init()
{
    	FUNCTION_START;
        /* check how many perfstat_pagingspace_t structures are available */
	DEBUG printf("ps_paging_init()\n");
        pagingspaces = perfstat_pagingspace(NULL, NULL, sizeof(perfstat_pagingspace_t), 0);

        ASSERT(pagingspaces > 0, "perfstat_pagingspace(init)", EXIT, pagingspaces);
	DEBUG printf("ps_paging_init() found %d\n",pagingspaces);

	if(pagingspaces > 0)
		paging = malloc( sizeof(perfstat_pagingspace_t) * pagingspaces);
}

void ps_paging()
{
        int     rc;
	int	i;
        char    pagename[IDENTIFIER_LENGTH];

    	FUNCTION_START;
	if(pagingspaces <= 0)
		return;

        pagename[0] = 0;
        rc = perfstat_pagingspace((perfstat_id_t * )pagename, paging, sizeof(perfstat_pagingspace_t), pagingspaces);
        /* return code is number of structures returned */
	DEBUG printf("ps_paging() found %d\n",rc);
        ASSERT(rc > 0, "perfstat_pagingspace(data)", RETURN, rc);
	if(rc <= 0) {  /* this is a work around for unexpected perfstat library behaviour = fails at second attempt */
		pagingspaces = 0;
		return;
	}
	psection("paging_spaces");
	for(i=0;i<rc;i++) {
		psub(paging[i].name);
		if(paging[i].type == LV_PAGING) {
			pstring("type","LV");
			pstring("vgname",paging[i].u.lv_paging.vgname);
		}
		if(paging[i].type == NFS_PAGING) {
			pstring("type","NFS");
			pstring("hosname", paging[i].u.nfs_paging.hostname);
			pstring("filename",paging[i].u.nfs_paging.filename);
		}
		plong("lp_size", paging[i].lp_size);
		plong("mb_size", paging[i].mb_size);
		plong("mb_used", paging[i].mb_used);
		plong("io_pending", paging[i].io_pending);
		plong("active", paging[i].active);
		plong("automatic", paging[i].automatic);
		psubend();

	}
	psectionend();
}

void	filesystems()
{
	int	i;
	int	fd;
	struct fstab *fstab_buffer;
	struct stat stat_buffer;
	struct statfs statfs_buffer;
	float	fs_size;
	float	fs_free;
	float	fs_size_used;
	float	fs_inodes_used;

    	FUNCTION_START;
	psection("filesystems");
	setfsent();
	for (i = 0; (fstab_buffer = getfsent() ) != NULL; i++) {
		if (stat(fstab_buffer->fs_file, &stat_buffer) != -1 ) {
			if (stat_buffer.st_flag & FS_MOUNT) {
				if ( (fd = open(fstab_buffer->fs_file, O_RDONLY)) != -1) {
					if (fstatfs( fd, &statfs_buffer) != -1) {
						if (!strncmp(fstab_buffer->fs_spec, "/proc", 5)) { /* /proc gives invalid/insane values */
							fs_size = 0;
							fs_free = 0;
							fs_size_used = 100.0;
							fs_inodes_used = 100.0;
						} else {
							fs_size = (float)statfs_buffer.f_blocks * 4.0 / 1024.0;
							fs_free = (float)statfs_buffer.f_bfree * 4.0 / 1024.0;
							fs_size_used = ((float)statfs_buffer.f_blocks - (float)statfs_buffer.f_bfree)
							 / (float)statfs_buffer.f_blocks * 100.0;
							fs_inodes_used = ((float)statfs_buffer.f_files - (float)statfs_buffer.f_ffree)
							 / (float)statfs_buffer.f_files * 100.0;
						}
						psub(fstab_buffer->fs_file);
						pstring("mount",  fstab_buffer->fs_file);
						pstring("device", fstab_buffer->fs_spec);
						pdouble("size_mb", fs_size);
						pdouble("free_mb", fs_free);
						pdouble("used_percent", fs_size_used);
						pdouble("inode_percent", fs_inodes_used);
						psubend();
					} else {
						perror("error");
						fprintf(stderr, "fstatfs() of %s failed errno=%d\n", fstab_buffer->fs_file,
						     errno);
					}
					close(fd);
				} else {
					perror("error");
					fprintf(stderr, "open(%s,O_RDONLY) failed errno=%d\n", fstab_buffer->fs_file, errno);
				}
			}
		} else {
			perror("error");
			fprintf(stderr, "stat of %s failed errno=%d\n", fstab_buffer->fs_file, errno);
		}
	}
	endfsent();
	psectionend();
}

/* Logical Volumes */
int	lvs = 1;
perfstat_logicalvolume_t *lv_stat;
perfstat_logicalvolume_t *lv_save;

void ps_lv_init()
{
	int	rc;
	char	lv_name[IDENTIFIER_LENGTH];

    	FUNCTION_START;
        if(lvs == 0) return;

	perfstat_config(PERFSTAT_ENABLE | PERFSTAT_LV, NULL);
	/* find out the number of adapters */
	lv_name[0] = 0;
	lvs = perfstat_logicalvolume(NULL, NULL, sizeof(perfstat_logicalvolume_t), 0);
	ASSERT(lvs > 0, "perfstat_logicalvolume(init)", EXIT, lvs);

	lv_stat = malloc(sizeof(perfstat_logicalvolume_t) * lvs);
	ASSERT_PTR(lv_stat != NULL, "malloc", EXIT, lv_stat);

	lv_save = malloc(sizeof(perfstat_logicalvolume_t) * lvs);
	ASSERT_PTR(lv_save != NULL, "malloc", EXIT, lv_save);
	lv_name[0] = 0;
	rc = perfstat_logicalvolume((perfstat_id_t * )lv_name, lv_save, sizeof(perfstat_logicalvolume_t), lvs);
	if(rc == -1 && errno == 13) { 
		/* errno = 13 means Permission denied */
		/* You have to be root user or equivalent to collect Logical Volume stats 
		   I think this is because there are performance implications of switching on AIX trace */
		lvs = 0;
		return;
	}
	ASSERT(rc > 0, "perfstat_logicalvolume(save)", EXIT, rc);
}


void ps_lv_stats(double elapsed)
{
	int	i;
	int	rc;
	char	lv_name[IDENTIFIER_LENGTH];
	char	string[512];

    	FUNCTION_START;
	if(lvs == 0) return;

	lv_name[0] = 0;
	rc = perfstat_logicalvolume((perfstat_id_t * )lv_name, lv_stat, sizeof(perfstat_logicalvolume_t), lvs);
	ASSERT(rc > 0, "perfstat_fcstat(data)", EXIT, rc);

	psection("logicalvolumes");
	for (i = 0; i < rc; i++) {
		psub(lv_stat[i].name);
		pstring("vgname",  lv_stat[i].vgname);
		plong("open_close",lv_stat[i].open_close);

		switch((long)lv_stat[i].state) {
		case	0: pstring("state", "Undefined=0"); break;
		case	1: pstring("state", "Defined=1"); break;
		case	2: pstring("state", "Stale=2"); break;
		case	4: pstring("state", "MirrorBackup=4"); break;
		case	5: pstring("state", "PassiveRecovery=5"); break;
			
		default: 
			sprintf(string,"unknown=%d",lv_stat[i].state); 
			pstring("state", string); break;
		}

		plong("mirror_policy",           lv_stat[i].mirror_policy);
		plong("mirror_write_consistency",lv_stat[i].mirror_write_consistency);
		plong("write_verify",            lv_stat[i].write_verify);
		plong("ppsize_mb",               lv_stat[i].ppsize);
		plong("logical_partitions",      lv_stat[i].logical_partitions);
		plong("mirrors",                 lv_stat[i].mirrors);
		pdouble("iocnt",   ((double)(lv_stat[i].iocnt    - lv_save[i].iocnt))/elapsed);
		pdouble("kbreads", ((double)(lv_stat[i].kbreads  - lv_save[i].kbreads))/elapsed);
		pdouble("kbwrites",((double)(lv_stat[i].kbwrites - lv_save[i].kbwrites))/elapsed);
		psubend();
	}
	psectionend();
	memcpy(lv_save, lv_stat, sizeof(perfstat_logicalvolume_t) * lvs);
}

/* Volume Groups */
int	vgs = 1;
perfstat_volumegroup_t *vg_stat;
perfstat_volumegroup_t *vg_save;

void ps_vg_init()
{
	int	rc;
	char	vg_name[IDENTIFIER_LENGTH];

    	FUNCTION_START;
        if(vgs == 0) return;

	perfstat_config(PERFSTAT_ENABLE | PERFSTAT_VG, NULL);
	/* find out the number of adapters */
	vg_name[0] = 0;
	vgs = perfstat_volumegroup(NULL, NULL, sizeof(perfstat_volumegroup_t), 0);
	ASSERT(vgs > 0, "perfstat_volumegroup(size)", EXIT, vgs);

	vg_stat = malloc(sizeof(perfstat_volumegroup_t) * vgs);
	ASSERT_PTR(vg_stat != NULL, "malloc", EXIT, vg_stat);

	vg_save = malloc(sizeof(perfstat_volumegroup_t) * vgs);
	ASSERT_PTR(vg_save != NULL, "malloc", EXIT, vg_save);
	vg_name[0] = 0;
	rc = perfstat_volumegroup((perfstat_id_t * )vg_name, vg_save, sizeof(perfstat_volumegroup_t), vgs);
	if(rc == -1 && errno == 13) { 
		/* errno = 13 means Permission denied */
		/* You have to be root user or equivalent to collect Volumg Group stats 
		   I think this is because there are performance implications of switching on AIX trace */
		vgs = 0;
		return;
	}
	ASSERT(rc > 0, "perfstat_volumegroup(save)", EXIT, rc);
}


void ps_vg_stats(double elapsed)
{
	int	i;
	int	rc;
	char	vg_name[IDENTIFIER_LENGTH];

    	FUNCTION_START;
	if(vgs == 0) return;

	vg_name[0] = 0;
	rc = perfstat_volumegroup((perfstat_id_t * )vg_name, vg_stat, sizeof(perfstat_volumegroup_t), vgs);
	ASSERT(rc > 0, "perfstat_volumegroup(data)", EXIT, rc);

	psection("volumegroups");
	for (i = 0; i < rc; i++) {
		psub(vg_stat[i].name);
		plong("total_disks",           vg_stat[i].total_disks);
		plong("active_disks",          vg_stat[i].active_disks);
		plong("total_logical_volumes", vg_stat[i].total_logical_volumes);
		plong("opened_logical_volumes",vg_stat[i].opened_logical_volumes);

		pdouble("iocnt",   ((double)(vg_stat[i].iocnt    - vg_save[i].iocnt))/elapsed);
		pdouble("kbreads", ((double)(vg_stat[i].kbreads  - vg_save[i].kbreads))/elapsed);
		pdouble("kbwrites",((double)(vg_stat[i].kbwrites - vg_save[i].kbwrites))/elapsed);

		plong("variedState",vg_stat[i].variedState);
		psubend();
	}
	psectionend();
	memcpy(vg_save, vg_stat, sizeof(perfstat_volumegroup_t) * vgs);
}

char	hostname[1024];
char	fullhostname[1024];

void get_hostname()
{
	static int set = 0;
	int i;
	int len;

    	FUNCTION_START;
	if(set == 1)
		return;
	set = 1;
	if ( gethostname(hostname, sizeof(hostname)) == 0) {
		strcpy(fullhostname, hostname);
		len = strlen(hostname);
		for(i=0;i < len; i++){
			if(hostname[i] == '.') {
				hostname[i] = 0;
				break;
			}
		}
	} else {
		strcpy(hostname,     "not found");
		strcpy(fullhostname, "not.found");
	}
}

void	identity()
{
	FILE * fp;
	char	buf[1024+1];
	int	i;
	/* user name and id */
	struct passwd *pw;
	uid_t uid;

    	FUNCTION_START;
	get_hostname();
	psection("identity");
	pstring("hostname", hostname);
	pstring("fullhostname", fullhostname);
	pstring("njmon_command", command);
	pstring("njmon_version", version);
	uid = geteuid();
	if (pw = getpwuid (uid)) {
		pstring("username", pw->pw_name);
		plong("userid", uid);
	} else {
		pstring("username", "unknown");
		plong("userid", -1);
	}
	psectionend();
}


void	hint(char *program)
{
    	FUNCTION_START;
	printf("%s: help information. Version:%s\n\n", program,version);
	printf("- Performance stats collector outputing JSON format. Default is stdout\n");
	printf("- Core syntax:     %s -s seconds -c count\n", program);
	printf("- JSON style:      -M  or -S or -O\n");
	printf("- File output:     -m directory -f\n");
	printf("- Check & restart: -k\n");
	printf("- Data options:    -P -L -V -v -u -U -? -d\n");
#ifndef NOREMOTE
        printf("- njmon collector output: -i host -p port -X secret\n");
#endif /* NOREMOTE */
	printf("\n");
	printf("\t-s seconds : seconds between snapshots of data (default 60 seconds)\n");
	printf("\t-c count   : number of snapshots then stop     (default forever)\n\n");
	printf("\t-S         : Older Single level output format   (section names form part of the value names)\n");
	printf("\t-M         : Multiple level output format (section & subsection names (default))\n");
	printf("\t-O         : Older Multiple level output format (like -M but identity before samples)\n\n");
	printf("\t-m directory : Program will cd to the directory before output\n");
	printf("\t-f         : Output to file (not stdout) to two files below\n");
	printf("\t           : Data:   hostname_<year><month><day>_<hour><minutes>.json\n");
	printf("\t           : Errors: hostname_<year><month><day>_<hour><minutes>.err\n\n");
	printf("\t-k         : Read /tmp/njmon.pid for a running njmon PID & if found running then this copy exits\n\n");
	printf("\t-P         : Also collect process stats         (these can be very large)\n");
	printf("\t-t percent : Process CPU cut-off threshold percent.   Default 0.001%\n");
	printf("\t-L         : Don't collect Logical Volume stats (takes extra CPU cycles)\n");
	printf("\t-V         : Don't collect Volume Group   stats (takes extra CPU cycles)\n");
	printf("\t           : -L & -V requires root access. If not root these are silently switched off\n");
#ifdef VIOS
	printf("\t-v         : VIOS data on virtual disks, virtual FC and virtual networks\n");
#else
	printf("\t-v         : Note: VIOS options compiled out of binary\n");
#endif /* VIOS */
#ifdef SSP
	printf("\t-u         : VIOS SSP data like pool, pv and LU\n");
	printf("\t-U         : VIOS SSP data like -u plus VIOS cluster data\n");
	printf("\t           : Warning this can add 2 seconds per VIOS in the SSP cluster\n");
#else
	printf("\t-U -u      : Note: SSP options compiled out of binary\n");
#endif /* SSP */
	printf("\t-?         : Output this help message and stop\n");
	printf("\t-h         : Same as -?\n");
	printf("\t-d         : Switch on debugging\n");
#ifndef NOREMOTE
        printf("Push data to collector: add -h hostname -p port\n");
        printf("\t-i ip      : IP address or hostname of the njmon central collector\n");
        printf("\t-p port    : port number on collector host\n");
        printf("\t-X         : Set the remote collector secret or use shell NJMON_SECRET\n");
#endif /* NOREMOTE */
#ifndef STAY_CONNECT
        printf("\t-x         : print the child PID (useful in scripts to cleanly kill njmon later)\n");
#endif /* STAY_CONNECT */
	printf("\n");
	printf("Examples:\n");
	printf("    1 Every 5 mins all day\n");
	printf("\t/home/nag/njmon -s 300 -c 288 -f -m /home/perf\n");
	printf("    2 Piping to data handler using defaults -s60 forever\n");
	printf("\t/home/nag/njmon | myprog\n");
	printf("    3 Add process stats and LV + VG data for an hout\n");
	printf("\t./njmon -s60 -c 60 -PLV > njmon.json\n");
	printf("    4 Collect daytime VIOS extra including SSP (if compiled in)\n");
	printf("\t./njmon -s60 -c 720 -vuU > njmon_on_vios.json\n");

	printf("    5 Crontab entry - 4 minutes after midnight save local data every 30 secons\n");
	printf("\t4 0 * * * /home/nag/njmon -s 30 -c 2880 -f -m /home/perf\n");

	printf("    6 Crontab - hourly check/restart remote njmon, pipe stats back & insert into local DB\n");
	printf("\t0 * * * * /usr/bin/ssh nigel@server /usr/lbin/njmon -k -s 300 -c 288 | /lbin/injector\n");

	printf("    7 Crontab - for pumping data to the central collector\n");
	printf("\t0 0 * * * /usr/local/bin/njmon -s 300 -c 288 -i myadminhost -p 8181 -X SECRET42 \n");
	printf("\n");
	/*
	# minute hour 0-23 day_of_month 1-31 month 1-12 weekday 0-6 Sunday-Saturday command
	*/

}


/* See /usr/include/sys/iplcb.h to explain the below */
#define XINTFRAC        ((double)(_system_configuration.Xint)/(double)(_system_configuration.Xfrac))

/* hardware ticks per millisecond */
#define HWTICS2MSECS(x)    (((double)x * XINTFRAC)/1000000.0)

#ifndef FIRST_DISK
#define FIRST_DISK ""
#endif

char	*fix(char *s) /* Removes odd punctuation from names */
{
	int	j;
    	FUNCTION_START;
	for (j = 0; j < IDENTIFIER_LENGTH; j++) {
		if(s[j] == 0) break;
		if(s[j] == '\\') s[j] = '?' ;
		if(s[j] == ' ')    continue;
		if (isalpha(s[j])) continue; 
		if (isdigit(s[j])) continue; 
		if (ispunct(s[j])) continue; 
		s[j] = '?' ;
	}
	return s;
}


int	disks;
perfstat_disk_t *diskprev;
perfstat_disk_t *diskcurr;

void	ps_disk_init()
{
	int	rc;
	char	disk_name[IDENTIFIER_LENGTH];

    	FUNCTION_START;
	rc = perfstat_partial_reset(NULL, FLUSH_DISK | RESET_DISK_MINMAX);
	ASSERT(rc == 0, "perfstat_partial_reset()", EXIT, rc);

	/* check how many perfstat_disk_t structures are available */
	disks = perfstat_disk(NULL, NULL, sizeof(perfstat_disk_t), 0);
	ASSERT(disks > 0, "perfstat_disk(init)", EXIT, disks);

	/* allocate enough memory for all the structures */
	diskprev = malloc( sizeof(perfstat_disk_t) * disks);
	ASSERT_PTR(diskprev != NULL, "malloc(diskprev)", EXIT, diskprev);

	diskcurr = malloc( sizeof(perfstat_disk_t) * disks);
	ASSERT_PTR(diskcurr != NULL, "malloc(diskcurr)", EXIT, diskcurr);

	/* ask to get all the structures available in one call */
	/* return code is number of structures returned */
	disk_name[0] = 0;
	rc = perfstat_disk((perfstat_id_t * )disk_name, diskprev, sizeof(perfstat_disk_t), disks);
	ASSERT(rc > 0, "perfstat_disk(init again)", EXIT, rc);
	/* printf("Found %d disks\n",rc); */
}

void ps_one_disk(perfstat_disk_t curr, perfstat_disk_t prev, double elapsed)
{
    	FUNCTION_START;
	psub(fix(curr.name));
	pstring("description", fix(curr.description));
	pstring("vg",          fix(curr.vgname));
	plong("blocksize",  curr.bsize);

#define DISK_DELTA(member) ((double)curr.member - (double)prev.member)

	plong("size_mb", 	curr.size);
	plong("free_mb", 	curr.free);
	pdouble("xrate_read", DISK_DELTA(xrate) / elapsed);
	pdouble("xfers",      DISK_DELTA(xfers) / elapsed);
	pdouble("read_blks",  DISK_DELTA(rblks) / (double)elapsed);
	pdouble("write_blks", DISK_DELTA(wblks) / (double)elapsed);
	pdouble("read_mbps",  (double)DISK_DELTA(rblks) * (double)curr.bsize / 1024.0 / elapsed);
	pdouble("write_mbps", (double)DISK_DELTA(wblks) * (double)curr.bsize / 1024.0 / elapsed);
	pdouble("busy",       (double)DISK_DELTA(time) / (double)elapsed);
	plong("qdepth",      curr.qdepth);

	/* skip cd{n} */
	if( !( curr.name[0] == 'c' && curr.name[1] == 'd' && isdigit(curr.name[2]) ) ) {
#define NONZERO(x) ((x)?(x):1)
		pdouble("rserv_min", curr.min_rserv);
		pdouble("rserv_max", curr.max_rserv);
		pdouble("rserv_avg", (double)(HWTICS2MSECS(DISK_DELTA(rserv)) / NONZERO(DISK_DELTA(__rxfers))));
		plong("rtimeout",  curr.rtimeout);
		plong("rfailed",   curr.rfailed);

		pdouble("wserv_min", curr.min_wserv);
		pdouble("wserv_max", curr.max_wserv);
		pdouble("wserv_avg", (double)(HWTICS2MSECS(DISK_DELTA(wserv)) / NONZERO(DISK_DELTA(__rxfers))));
		plong("wtimeout",  curr.wtimeout);
		plong("wfailed",   curr.rfailed);

		pdouble("wqueue_time_min", curr.wq_min_time);
		pdouble("wqueue_time_max", curr.wq_max_time);
		pdouble("wqueue_time_avg", 
		    (double)(HWTICS2MSECS(DISK_DELTA(wq_time)) / NONZERO(DISK_DELTA(xfers)) / elapsed) );

		pdouble("avgWQsz", (double)(DISK_DELTA(wq_sampled)) / (100.0 * (double)elapsed * (double)cpu_total));
		pdouble("avgSQsz", (double)(DISK_DELTA(q_sampled)) / (100.0 * (double)elapsed * (double)cpu_total));
		plong("SQfull", DISK_DELTA(q_full));
		plong("wq_depth", curr.wq_depth);
	}
	psubend();
}

void	ps_disk_stats(double elapsed)
{
	int	i;
	int	j;
	int	rc;
	char	diskname[IDENTIFIER_LENGTH];

    	FUNCTION_START;
	diskname[0] = 0;
	rc = perfstat_disk((perfstat_id_t * )diskname, diskcurr, sizeof(perfstat_disk_t), disks);
	/* printf("disks=%d, rc=%d\n", disks, rc); */
	ASSERT(rc > 0, "perfstat_disk(data)", EXIT, rc);

	psection("disks");
	for (i = 0; i < disks; i++) {
		ps_one_disk(diskcurr[i], diskprev[i], elapsed);
	}
	psectionend();

#ifdef AIX53
	"AIX53 Details\n");
	for (i = 0; i < rc; i++)
		printf("%10s Paths=%u Adapter=\"%s\"\n",
		    fix(diskcurr[i].name), diskcurr[i].paths_count, fix(diskcurr[i].adapter));
#endif

	memcpy(diskprev, diskcurr, sizeof(perfstat_disk_t) * disks );
}

#ifdef VIOS
int	targets;
perfstat_disk_t *targetprev;
perfstat_disk_t *targetcurr;

void	ps_vios_target_init()
{
	int	rc;
	char	target_name[IDENTIFIER_LENGTH];

    	FUNCTION_START;
	/* check how many perfstat_disk_t structures are available */
	targets = perfstat_virtualdisktarget(NULL, NULL, sizeof(perfstat_disk_t), 0);
	ASSERT(targets >= 0, "perfstat_disk(init)", EXIT, targets);

	if(targets <= 0) {
		vios_vhosts = 0;
		return;
	}
	/* allocate enough memory for all the structures */
	targetprev = malloc( sizeof(perfstat_disk_t) * targets);
	ASSERT_PTR(targetprev != NULL, "malloc(tartgetprev)", EXIT, targetprev);
	targetcurr = malloc( sizeof(perfstat_disk_t) * targets);
	ASSERT_PTR(targetcurr != NULL, "malloc(tartgetcurr)", EXIT, targetcurr);

	/* ask to get all the structures available in one call */
	/* return code is number of structures returned */
	target_name[0] = 0;
	rc = perfstat_virtualdisktarget((perfstat_id_t * )target_name, targetprev, sizeof(perfstat_disk_t), targets);
	ASSERT(rc > 0, "perfstat_virtualdisktarget(init again)", EXIT, rc);
	DEBUG printf("Found %d virtualdisktargets\n",rc); 
}

void ps_vios_target_stats(double elapsed)
{
	int	i;
	int	rc;
	char	targetname[IDENTIFIER_LENGTH];

    	FUNCTION_START;
	if(targets == 0)
		return;
	targetname[0] = 0;
	rc = perfstat_virtualdisktarget((perfstat_id_t * )targetname, targetcurr, sizeof(perfstat_disk_t), targets);
	ASSERT(rc > 0, "perfstat_virtualtargetadapter(init)", EXIT, rc);

	psection("vios_disk_target");
	for (i = 0; i < rc; i++) {
		ps_one_disk(targetcurr[i], targetprev[i], elapsed);
	}
	psectionend();
	memcpy(targetprev, targetcurr, sizeof(perfstat_disk_t) * targets);
}
#endif /* VIOS */

perfstat_disk_total_t disktotal_a;
perfstat_disk_total_t disktotal_b;

void	ps_disk_total_init()
{
	int	rc;
	char	disktot_name[IDENTIFIER_LENGTH];

    	FUNCTION_START;
	/* ask to get all the structures available in one call */
	/* return code is number of structures returned */
	disktot_name[0] = 0;
	rc = perfstat_disk_total(NULL, &disktotal_a, sizeof(perfstat_disk_total_t), 1);
	ASSERT(rc > 0, "perfstat_disk_total(init)", EXIT, rc);

	/* Repeat this  request: 
	   I sespect libperfstat first supplies sum since booting stats
	*/
	rc = perfstat_disk_total(NULL, &disktotal_a, sizeof(perfstat_disk_total_t), 1);
	ASSERT(rc > 0, "perfstat_disk_total(init)", EXIT, rc);
}

#define DISKTOTAL_DELTA(member) (disktotal_b.member - disktotal_a.member)

void	ps_disk_total_stats(double elapsed)
{
	int	rc;
	char	disktot_name[IDENTIFIER_LENGTH];

    	FUNCTION_START;
	disktot_name[0] = 0;
	rc = perfstat_disk_total(NULL, &disktotal_b, sizeof(perfstat_disk_total_t), 1);
	ASSERT(rc > 0, "perfstat_disktotal(data)", EXIT, rc);

	psection("disk_total");
	plong("disks", disktotal_b.number);
	plong("size",  disktotal_b.size);
	plong("free",  disktotal_b.free);
	pdouble("xrate_read", DISKTOTAL_DELTA(xrate) / elapsed);
	pdouble("xfers",      DISKTOTAL_DELTA(xfers) / elapsed);
	pdouble("read_blks",  DISKTOTAL_DELTA(rblks) / (double)elapsed);
	pdouble("write_blks", DISKTOTAL_DELTA(wblks) / (double)elapsed);
	pdouble("time",       DISKTOTAL_DELTA(time) / elapsed);
	pdouble("rserv",      DISKTOTAL_DELTA(rserv) / elapsed);
	pdouble("wserv",      DISKTOTAL_DELTA(wserv) / elapsed);
	pdouble("rtimeout",   DISKTOTAL_DELTA(rtimeout) / elapsed);
	pdouble("wtimeout",   DISKTOTAL_DELTA(wtimeout) / elapsed);
	pdouble("rfailed",    DISKTOTAL_DELTA(rfailed) / elapsed);
	pdouble("wfailed",    DISKTOTAL_DELTA(wfailed) / elapsed);
	pdouble("wq_time",    DISKTOTAL_DELTA(wq_time) / elapsed);
	plong("wq_depth", disktotal_b.wq_depth);
	psectionend();
	memcpy(&disktotal_a, &disktotal_b, sizeof(perfstat_disk_total_t));
}


int netbuffs = 0;
perfstat_netbuffer_t *netbuffs_stat;

void ps_netbuffs_init()
{
    FUNCTION_START;
    if(danger) return;
    netbuffs =  perfstat_netbuffer(NULL, NULL, sizeof(perfstat_netbuffer_t), 0);
    ASSERT(netbuffs > 0, "perfstat_netbuffer(init)", RETURN, netbuffs);
    if (netbuffs <= 0) { /* check for error */
	  netbuffs = 0;
	  return;
    }
	
    /* allocate enough memory for all the structures */
    netbuffs_stat = calloc(netbuffs, sizeof(perfstat_netbuffer_t));
    ASSERT_PTR(netbuffs_stat != NULL, "perfstat_netbuffer(init)", RETURN, netbuffs_stat);
    if(netbuffs_stat==NULL){
	netbuffs = 0;
	return;
    }
    
} 

void ps_netbuffs()
{
    static perfstat_id_t first;
    int ret, i;
    char name[256];

    FUNCTION_START;
    if(danger) return;
    if (netbuffs == 0) { /* then init failed so skip */
        return;
    }

    /* set name to first interface */
    strcpy(first.name, FIRST_NETBUFFER);
   
    /* ask to get all the structures available in one call */
    /* return code is number of structures returned */
    ret = perfstat_netbuffer(&first, netbuffs_stat, sizeof(perfstat_netbuffer_t), netbuffs);
    
    ASSERT(ret > 0, "perfstat_netbuffer(init)", RETURN, ret);
    /* check for error */
    if (ret <= 0) {
	  netbuffs = 0;
	  exit(-1);
    }
    psection("netbuffers");
    for(i=0;i<ret;i++){
	sprintf(name, "size%s", netbuffs_stat[i].name);
    	psub(name);
        plong("inuse",netbuffs_stat[i].inuse);
        plong("calls",netbuffs_stat[i].calls);
        plong("delayed",netbuffs_stat[i].delayed);
        plong("free",netbuffs_stat[i].free);
        plong("failed",netbuffs_stat[i].failed);
        plong("highwatermark",netbuffs_stat[i].highwatermark);
        plong("freed",netbuffs_stat[i].freed);
	psubend();
    }
    psectionend("netbuffers");
}

/* LPAR */
#include <sys/dr.h>

lpar_info_format1_t f1;
lpar_info_format2_t f2;
lpar_info_format2_t f2_prev;

void dr_lpar_init()
{
	int	rc;

    	FUNCTION_START;
	rc = lpar_get_info(LPAR_INFO_FORMAT2, &f2_prev, sizeof(f2_prev));
	ASSERT(rc == 0, "lpar_get_info(f2_prev)", EXIT, rc);
}

void dr_lpar_stats()
{
	int	i;
	int	rc;
	int	tot;

	 unsigned long long dispatch_wheel_time;

	/* Not clear how this compares with uptime values or how to use there stats 
         * lpar_load_t load;
         * rc=getlparload(&load,sizeof(lpar_load_t));
         * printf("\nlpar_load returned=%d loadavg=%d utilavg=%d shift=%d\n",rc,load.loadavg,load.utilavg,(int)load.loadavgshift);
	 */

    	FUNCTION_START;
	rc = lpar_get_info(LPAR_INFO_FORMAT1, &f1, sizeof(f1));
	ASSERT(rc == 0, "lpar_get_info(f1)", EXIT, rc);

	psection("lpar_format1");

#define printf1(xxx)        plong(   # xxx, (long long)f1.xxx);
#define printf1percent(xxx)     pdouble( # xxx, (double)f1.xxx/ 100.0);
#define printf1_string(xxx) pstring( # xxx, (char *)f1.xxx);

	printf1_string(lpar_name);
	printf1(min_memory);
	printf1(max_memory);
	printf1(memory_region);
	printf1(dispatch_wheel_time);

	dispatch_wheel_time = f1.dispatch_wheel_time;

	printf1(lpar_number);
	printf1(lpar_flags);
	printf1(max_pcpus_in_sys);
	printf1(min_vcpus);
	printf1(max_vcpus);
	printf1(min_lcpus);
	printf1(max_lcpus);
	printf1percent(minimum_capacity);
	printf1percent(maximum_capacity);
	printf1percent(capacity_increment);
	printf1(smt_threads);
#ifndef AIX6
	printf1(num_lpars);
#endif
	printf1percent(desired_capacity);
	printf1(desired_vcpus);
	printf1(desired_memory);
	printf1(desired_variable_capwt);
#ifndef AIX6
	printf1(servpar_id);
#endif
	printf1(true_max_memory);
	printf1(true_min_memory);
	printf1(ame_max_memory);
	printf1(ame_min_memory);
	printf1(spcm_status);
	printf1(spcm_max);

	psectionend();

	rc = lpar_get_info(LPAR_INFO_FORMAT2, &f2, sizeof(f2));
	ASSERT(rc == 0, "lpar_get_info(f2)", EXIT, rc);

	psection("lpar_format2");

#define printf2(xxx)        plong( # xxx, (long long)f2.xxx);
#define printf2percent(xxx) pdouble( # xxx, (double)f2.xxx / 100.0);
#define printf2_hex(xxx)    phex( # xxx, (long long)f2.xxx);
#define printf2_rate(xxx)   plong( # xxx, ( (double)(f2.xxx - f2_prev.xxx) ) / (double)f1.dispatch_wheel_time  );

	printf2(online_memory);
	printf2_rate(tot_dispatch_time);
	/* 
	 * printf("tot_dispatch_time=%lld prev=%lld delta=%lld dispatch_wheel_time=%lld cpu=%.1f\n",
	 * 	f2.tot_dispatch_time, f2_prev.tot_dispatch_time, f2.tot_dispatch_time - f2_prev.tot_dispatch_time, f1.dispatch_wheel_time,
	 * (double)(f2.tot_dispatch_time - f2_prev.tot_dispatch_time)/(double)f1.dispatch_wheel_time);
	 */ 

	printf2_rate(pool_idle_time);
	printf2(dispatch_latency);
	printf2_hex(lpar_flags); /* actually a hexadecimal flag */
	printf2(pcpus_in_sys);
	printf2(online_vcpus);
	printf2(online_lcpus);
	printf2(pcpus_in_pool);
	printf2(unalloc_capacity);
	printf2percent(entitled_capacity);
	printf2(variable_weight);
	printf2(unalloc_weight);
	printf2(min_req_vcpu_capacity);
	printf2(group_id);
	printf2(pool_id);
	printf2(shcpus_in_sys);
	printf2percent(max_pool_capacity);
	printf2percent(entitled_pool_capacity);
	printf2_rate(pool_max_time);
	printf2_rate(pool_busy_time);
	printf2_rate(pool_scaled_busy_time);
	printf2_rate(shcpu_tot_time);
	printf2_rate(shcpu_busy_time);
	printf2_rate(shcpu_scaled_busy_time);
	printf2(ent_mem_capacity);
	printf2(phys_mem);
	printf2(vrm_pool_physmem);
	printf2(hyp_pagesize);
	printf2(vrm_pool_id);
	printf2(vrm_group_id);
	printf2(var_mem_weight);
	printf2(unalloc_var_mem_weight);
	printf2(unalloc_ent_mem_capacity);
	printf2(true_online_memory);
	printf2(ame_online_memory);
	printf2(ame_type);
	printf2(ame_factor);
	printf2(em_part_major_code);
	printf2(em_part_minor_code);
	printf2(bytes_coalesced);
	printf2(bytes_coalesced_mempool);
	printf2(purr_coalescing);
	printf2(spurr_coalescing);
	psectionend(); /* Final section */

	memcpy(&f2_prev, &f2, sizeof(f2));
}

#ifdef SSP
perfstat_ssp_t *ssp_global;
perfstat_ssp_t *ssp_disk;
perfstat_ssp_t *ssp_lu;
perfstat_ssp_t *ssp_node;

int global_count;
int disk_count;
int lu_count;
int node_count;

int	ssp_mode = 0;       /* collect basic SSP data pool, disk, LU */
int	ssp_node_mode = 0;  /* collect SSP cluster data, can take 2 seconds per VIOS */

void ps_ssp_init()
{
    	FUNCTION_START;
        /* Enable the VIOS SSP cluster statistics */
        if( perfstat_config(PERFSTAT_ENABLE|PERFSTAT_CLUSTER_STATS, NULL) < 0) {
                fprintf(stderr, "perfstat_config SSP is not available. Only run this on a VIOS 2.2.6+ with a Shared Storeage Pool errno=%d\n",errno);
		ssp_mode = 0;
		ssp_node_mode = 0;
		return;
	}

        /* Determine the numbers of stats available */
        if( (global_count = perfstat_ssp(NULL, NULL, sizeof(perfstat_ssp_t),0,SSPGLOBAL) ) < 0) {
                fprintf(stderr,"perfstat_ssp(global init) errno=%d\n", errno);
		ssp_mode = 0;
		ssp_node_mode = 0;
		return;
	}
        if( (disk_count   = perfstat_ssp(NULL, NULL, sizeof(perfstat_ssp_t),0,SSPDISK) ) < 0) {
                fprintf(stderr, "perfstat_ssp(disk init)errno=%d", errno);
		ssp_mode = 0;
		ssp_node_mode = 0;
		return;
	}
        if( (lu_count     = perfstat_ssp(NULL, NULL, sizeof(perfstat_ssp_t),0,SSPVTD) ) < 0) {
                fprintf(stderr, "perfstat_ssp(lu init) errno=%d\n", errno);
		ssp_mode = 0;
		ssp_node_mode = 0;
		return;
	}

        /* Prepare memory buffers */
        ssp_global = (perfstat_ssp_t *) malloc(sizeof(perfstat_ssp_t) * global_count);
        ssp_disk   = (perfstat_ssp_t *) malloc(sizeof(perfstat_ssp_t) * disk_count);
        ssp_lu     = (perfstat_ssp_t *) malloc(sizeof(perfstat_ssp_t) * lu_count);
        if(ssp_global == (perfstat_ssp_t *)NULL || ssp_disk == (perfstat_ssp_t *)NULL || ssp_lu == (perfstat_ssp_t *)NULL ) {
                fprintf(stderr, "malloc failure requesting space to store perfstat data errno=%d\n", errno);
		ssp_mode = 0;
		ssp_node_mode = 0;
	}
}

void ps_ssp()
{
	int i;
	int rc;
	char string[1024];

    	FUNCTION_START;
        if( (rc = perfstat_ssp(NULL, ssp_global, sizeof(perfstat_ssp_t),global_count,SSPGLOBAL) ) <0) {
                fprintf(stderr, "perfstat_ssp(SSPGLOBAL) errno=%d\n", errno);
		ssp_mode = 0;
		ssp_node_mode = 0;
		return;
	}

        psection("ssp_global");
        pstring("ClusterName",  ssp_global->cluster_name);
        pstring("PoolName",     ssp_global->spool_name);
        plong("TotalSpace_MB",     ssp_global->u.global.total_space);
        plong("TotalUsedSpace_MB", ssp_global->u.global.total_used_space);
	psectionend();

        if( (rc = perfstat_ssp(NULL, ssp_disk, sizeof(perfstat_ssp_t),disk_count,SSPDISK) ) < 0) {
                fprintf(stderr, "perfstat_ssp(SSPDISK) errno=%d\n", errno);
		ssp_mode = 0;
		ssp_node_mode = 0;
		return;
	}

	psection("ssp_pv");
        for(i=0; i<rc; i++) {
	    psub(ssp_disk[i].u.disk.diskname);
            plong("capacity_MB",    ssp_disk[i].u.disk.capacity);
            plong("free_MB",        ssp_disk[i].u.disk.free);
            pstring("tiername",     ssp_disk[i].u.disk.tiername);
            pstring("failure_group",ssp_disk[i].u.disk.fgname);
	    psubend();
        }
	psectionend();

        if( (rc = perfstat_ssp(NULL, ssp_lu, sizeof(perfstat_ssp_t),lu_count,SSPVTD) ) < 0) {
                fprintf(stderr,"perfstat_ssp(SSPLU) errno=%d\n",errno);
		ssp_mode = 0;
		ssp_node_mode = 0;
		return;
	}

	psection("ssp_lu");
        for(i=0; i<rc; i++){
	    psub(ssp_lu[i].u.vtd.lu_name);
            pstring("type",         ssp_lu[i].u.vtd.lu_type);
            plong("size_MB",        ssp_lu[i].u.vtd.lu_size);
            plong("free_MB",        ssp_lu[i].u.vtd.lu_free);
            plong("usage_MB",       ssp_lu[i].u.vtd.lu_usage);
            plong("client)LPAR_id", ssp_lu[i].u.vtd.client_id);
            pstring("MTM",          ssp_lu[i].u.vtd.mtm);
            pstring("VTDname",      ssp_lu[i].u.vtd.vtd_name);
            pstring("DRCname",      ssp_lu[i].u.vtd.drcname);
            pstring("udid",         ssp_lu[i].u.vtd.lu_udid);
	    psubend();
        }
	psectionend();

}

void ps_ssp_node_init()
{
    	FUNCTION_START;
	if( (node_count     = perfstat_ssp(NULL, NULL, sizeof(perfstat_ssp_t),0,SSPNODE) ) <= 0) {
	    fprintf(stderr,"perfstat_ssp(node init)failed retuend %d errno %d\n", node_count, errno);
	    ssp_node_mode = 0;
	    return;
	}

	if( (ssp_node   = (perfstat_ssp_t *) malloc(sizeof(perfstat_ssp_t) * node_count)) == (perfstat_ssp_t *)NULL ) {
	    fprintf(stderr,"perfstat_ssp(malloc) failed retuend %d errno %d\n", node_count, errno);
	    ssp_node_mode = 0;
	}
}

void ps_ssp_node()
{
	int i;
	int rc;

        if( (rc = perfstat_ssp(NULL, ssp_node, sizeof(perfstat_ssp_t),node_count,SSPNODE) ) < 0) {
		fprintf(stderr, "perfstat_ssp(SSPNODE) failed returned %d errono=%d\n",rc,errno);
		ssp_node_mode = 0;
		return;
	}

	psection("ssp_node");
        for(i=0; i<rc; i++){
            psub(ssp_node[i].u.node.hostname);
            pstring("ipaddress",  ssp_node[i].u.node.ip);
            pstring("MTMS",       ssp_node[i].u.node.mtms);
            plong("lparid",       ssp_node[i].u.node.lparid);
            pstring("ioslevel",   ssp_node[i].u.node.ioslevel);
            pstring("status",     (ssp_node[i].u.node.status==1?"OK":"-"));
            pstring("poolstatus", (ssp_node[i].u.node.poolstatus==1?"OK":"-"));
	    psubend();
        }
	psectionend();
}
#endif /* SSP */

/* check_pid_file() and make_pid_file()
   If you start njmon and it finds there is a copy running already then it will quitely stop.
   You can hourly start njmon via crontab and not end up with dozens of copies runnings.
   It also means if the server reboots then njmon start in the next hour.
    Side-effect: it creates a file called /tmp/njmon.pid
*/
char pid_filename[] = "/tmp/njmon.pid";

void make_pid_file()
{
int fd;
int ret;
//char buffer[32];
char * buffer = calloc(32, sizeof(*buffer));

    	FUNCTION_START;
    if((fd = creat(pid_filename, O_CREAT | O_WRONLY)) < 0) {
        printf("can't open new file for writing fd=%d\n",fd);
        perror("open");
        return; /* no file */
    }
    printf("write file descriptor=%d\n",fd);
    sprintf(buffer, "%ld \n", getpid() );
    printf("write \"%s\"\n", buffer);
    if((ret = write(fd, buffer, strlen(buffer))) <=0)
        printf("write failed ret=%d\n",ret);
    close(fd);
}

void check_pid_file()
{
//char buffer[32];
char * buffer = calloc(32, sizeof(*buffer));
int fd;
pid_t pid;
int ret;

    if((fd = open(pid_filename, O_RDONLY )) < 0) {
        printf("no file or can't open it\n");
        make_pid_file();
        return; /* no file */
    }
    printf("file descriptor=%d\n",fd);
    printf("file exists and readable and opened\n");
    if(read(fd, buffer, 31) > 0) { /* has some data */
            printf("file has some content\n");
            buffer[31]=0;
            if( sscanf(buffer, "%ld", &pid) == 1) {
                printf("read a pid from the file OK = %ld\n",pid);
                ret = kill(pid, 0);
                printf("kill %ld, 0) = returned =%d\n",pid, ret);
                if(ret == 0) {
                        printf("we have a njmon running - exit\n");
                        exit(13);
                }
            }
    }
    /* if we got here there is a file but the content is duff or the process is not running */
    close(fd);
    remove(pid_filename);
    make_pid_file();
}


/* MAIN */
int	main(int argc, char **argv)
{

	char	secret[256] = { 'O',  'x', 'd', 'e', 'a', 'd', 'b', 'e', 'e', 'f', 0 };
	int	commlen;
	int 	i;
	int 	processes = 0;
	long	loop;
	long	maxloops = -1;
	long	seconds = 60;
	long	port = -1;
	long	wport = -1;
	int	vios_mode = 0;
	int	directory_set = 0;
	char	directory[4096+1];
	int	file_output = 0;
	char	filename[64];
	//char	buffer[8192];
        char * buffer = calloc(8196, sizeof(*buffer));
	char	host[1024 +1] = { 0	};
	char   *s;
	int	hostmode = 0;
	int	ch;
	double	elapsed;
	double	previous_time;
	double	current_time;

        double  sleep_start;
        double  sleep_end;
        double  sleep_time;
        double  execute_start;
        double  execute_end;
        double  execute_time;
        double  accumalated_delay = 0.0;
        long    tmp_long;
        long    sleep_seconds;

	struct  timeval tv;
	FILE   *fp;
	int	print_child_pid = 0;
	int	child_pid = 0;
        int     rc; 
        
	debug = atoi(getenv("NJMON_DEBUG"));
    	FUNCTION_START;
	njmon_stats = atoi(getenv("NJMON_STATS"));
	s = getenv("NJMON_SECRET");
	if(s != 0) 
		strncpy(secret, s, 128);

        signal(SIGUSR1, interrupt);
        signal(SIGUSR2, interrupt);
        /* ignore SIGPIPE, yield EPIPE instead */
        sigaction(SIGPIPE, &(struct sigaction){SIG_IGN}, NULL);

	while (-1 != (ch = getopt(argc, argv, "c:s:?hdDfm:SMOPrkLVvuUi:p:xX:t:"))) {
		switch (ch) {
		case 's': 
			seconds = atoi(optarg);
			if (seconds < 1)
				seconds = 1;
			break;
		case 'c': 
			maxloops = atoi(optarg); 
			break;
		case '?': 
		case 'h': 
			hint(argv[0]); 
			exit(0);
		case 'd': 
			debug=1;
			break;
		case 'D': 
			danger=1;
			break;
		case 'f': 
			file_output = 1;
			break;
		case 'm':
			directory_set = 1;
			strncpy(directory, optarg, 4096);
			directory[4096] = 0;
			break;
		case 'S': 
			mode = ONE_LEVEL;
			break;
		case 'M': 
			mode = MULTI_LEVEL;
			break;
		case 'O': 
			mode = MULTI_LEVEL;
			oldmode = 1;
			break;
		case 'P': 
			processes = 1;
			break;
		case 'r': 
			rpmstuck = 1;
			break;
		case 'k': 
			check_pid_file();
			break;
		case 'L': 
			lvs =0;
			break;
		case 'V': 
			vgs = 0;
			break;
		case 'v': 
			vios_mode = 1;
			break;
#ifdef SSP
		case 'u': 
			ssp_mode = 1;
			break;
		case 'U': 
			ssp_mode = 1;
			ssp_node_mode = 1;
			break;
#endif /* SSP */
#ifndef NOREMOTE
		case 'i':
			strncpy(host, optarg, 1024);
			host[1024] = 0;
			hostmode = 1;
			break;
		case 'p': 
			port = atoi(optarg); 
			break;
		case 'X': 
			strncpy(secret,optarg,128); 
			break;
#endif /* NOREMOTE */
		case 'x': 
			print_child_pid = 1;
			break;
		case 't': 
			cpu_threshold = atof(optarg);
			break;
		default:
			printf("Unexpected command parameter \"%c\" = 0x%x\n - bailing out\n", (char)ch, ch);
			exit(12);
			break;
		}
	}
#ifndef NOREMOTE
	if(hostmode == 1 && port == 0) {
		printf("%s -i %s set but not the -p port option\n", argv[0], host);
		exit(52);
	}
	if(hostmode == 0 && port > 0) {
		printf("%s -p %d but not the -i ip-address option\n", argv[0], port);
		exit(53);
	}
	if(hostmode == 1 && port != 0) { /* We are attempting sending the data remotely */
		if(isalpha(host[0])) {
			struct hostent *he;

			he = gethostbyname(host);
			if( he == NULL) {
				printf("hostname=%s to IP address convertion failed, bailing out\n",hostname);
				exit(98);
			}
			/*
			    printf("name=%s\n",he->h_name);
			    printf("type=%d = ",he->h_addrtype);
			    switch(he->h_addrtype) {
				case AF_INET: printf("IPv4\n"); break;
				case AF_INET6: printf("(IPv6\n"); break;
				default: printf("unknown\n");
			    }
			    printf("length=%d\n",he->h_length);
			*/

			/* this could return multiple IP addresses but we assume its the first one */
		        if ( he->h_addr_list[0] != NULL) {
				strcpy( host, inet_ntoa( *(struct in_addr*)(he->h_addr_list[0])));
		        } else {
				printf("hostname=%s to IP address convertion failed, bailing out\n",host);
				exit(98);
			}
		}
		get_hostname();
		get_time();
		get_utc();
		sprintf(buffer,"%04d-%02d-%02dT%02d:%02d:%02d",
		    tim->tm_year,
		    tim->tm_mon,
		    tim->tm_mday,
		    tim->tm_hour,
		    tim->tm_min,
		    tim->tm_sec);
		rc = create_socket(host, port, hostname, buffer, secret);
                if (rc < 0) {
                    printf("create_socket: rc of initial connect is %d,giving up.\n",rc);
                    exit(99);
                }
	}
#endif /* NOREMOTE */
	if(directory_set) {
		if (chdir(directory) == -1) {
			perror("Change Directory failed");
			printf("Directory attempted was: %s\n", directory);
			exit(11);
		}
	}
	if(file_output) {
		get_hostname();
		get_time();
		get_localtime();
                sprintf( filename, "%s_%02d%02d%02d_%02d%02d.json",
                                 hostname,
                                 tim->tm_year,
                                 tim->tm_mon,
                                 tim->tm_mday,
                                 tim->tm_hour,
                                 tim->tm_min);
                if ((fp = freopen(filename, "w", stdout)) == 0 ) {
                        perror("opening file for stdout");
                        fprintf(stderr,"ERROR nmon filename=%s\n", filename);
                        exit(13);
                }
                sprintf( filename, "%s_%02d%02d%02d_%02d%02d.err",
                                 hostname,
                                 tim->tm_year,
                                 tim->tm_mon,
                                 tim->tm_mday,
                                 tim->tm_hour,
                                 tim->tm_min);
                if ((fp = freopen(filename, "w", stderr)) == 0 ) {
                        perror("opening file for stderr");
                        fprintf(stderr,"ERROR nmon filename=%s\n", filename);
                        exit(14);
                }
	}
	fflush(NULL);
#ifdef ASSERT_TEST
ASSERT(2 == 1, "assert test", DUMP, (long long)debug); 
#endif
	/* disconnect from terminal */
	DEBUG printf("forking debug=%d\n", debug);
	if (debug == 0) { /* if not debuging mode */
		if ((child_pid = fork()) != 0) {
			DEBUG printf("forking parent child_pid=%d\n", child_pid);
			if (print_child_pid)
				printf("%d\n", child_pid);
			exit(0); /* parent returns OK */
		}
        }
	DEBUG printf("child running\n");
        if (!debug ) {
		/*
                close(0);
                close(1);
                close(2);
		*/
                setpgrp(); /* become process group leader */
                signal(SIGHUP, SIG_IGN); /* ignore hangups */
        }
	output_size = 1024 * 1024;
	output = malloc(output_size);
	commlen = 1;  /* for the terminating zero */
	for (i = 0; i < argc; i++){
		commlen = commlen + strlen(argv[i]) +1; /* +1 for spaces */
	}
	command = malloc(commlen);
	command[0] = 0;
	for (i = 0; i < argc; i++) {
		strcat(command, argv[i]);
		if( i != (argc -1) )
		strcat(command, " ");
	}

	/* seed incrementing counters */
	ps_cpu_init();
	ps_cpu_total_init();
	ps_memory_init();
	ps_memory_page_init();
	ps_paging_init();
	ps_vminfo_init();
	ps_net_interface_init();
    	ps_net_adapter_init();
	ps_net_total_init();
	if(vios_mode)
		ps_net_bridge_init();
    	ps_netbuffs_init();
	ps_disk_init();
	ps_disk_total_init();
	ps_disk_adapter_init();
#ifdef VIOS
	if(vios_mode) {
		ps_vios_vhost_init();
		ps_vios_target_init();
		ps_vios_vfc_init();
	}
#endif /* VIOS */
#ifdef SSP
	if(ssp_mode) {
		ps_ssp_init();
		ps_ssp_node_init();
	}
#endif /* SSP */
	ps_fc_stat_init();
	ps_lv_init();
	ps_vg_init();
	ps_tape_init();
	dr_lpar_init();
#ifndef NOGPFS
	gpfs_init();
#endif /* NOGPFS */

	if(processes) ps_process_init();

	gettimeofday(&tv, 0);
	previous_time = (double)tv.tv_sec + (double)tv.tv_usec * 1.0e-6;

	/* sleep so the first snapshot has some real-ish data */
	if(seconds <= 60)
	    sleep_seconds = seconds;
	else
	    sleep_seconds = 60; /* if a long time between snapshot do a quick one now so we have one in the bank */
	sleep(sleep_seconds); 

	gettimeofday(&tv, 0);
	current_time = (double)tv.tv_sec + (double)tv.tv_usec * 1.0e-6;
	elapsed = current_time - previous_time;
	
	/* pre-amble */
	if(mode == MULTI_LEVEL) {
		pstart();
		if(oldmode) identity();
		if(samples) praw("  \"samples\": [\n");
	}
	if(mode == ONE_LEVEL) {
		praw("[\n");
	}

	for (loop = 0; maxloops == -1 || loop < maxloops; loop++) {

                if(accumalated_delay < 1.0) {
                        sleep_seconds = seconds;
                } else {
                        /* double to long coercion removes the fraction of a second */
                        tmp_long = (long)(accumalated_delay);
                        sleep_seconds = seconds - tmp_long;
                        accumalated_delay = accumalated_delay - (double)tmp_long;
                        /* add some sanity checks so we don't try to handle negative seconds */
                        if(accumalated_delay < 0.0) {
                                accumalated_delay = 0.0;
                        }
                        if(sleep_seconds < 1 ) {
                                /* minimum sleep(1) */
                                sleep_seconds = 1;
                        }
                }

                if(loop == 0) {  /* don't calulate this on the first loop */
                        accumalated_delay = 0.0;
		} else {
			DEBUG printf("calling sleep(%d) . . .\n",seconds);
			gettimeofday(&tv, 0);
			sleep_start = (double)tv.tv_sec + ((double)tv.tv_usec * 1.0e-6);
			sleep(sleep_seconds);
			gettimeofday(&tv, 0);
			sleep_end = (double)tv.tv_sec + ((double)tv.tv_usec * 1.0e-6);
			sleep_time = sleep_end - sleep_start;
                        accumalated_delay += sleep_time - (double)sleep_seconds + (double)execute_time;
                }
		gettimeofday(&tv, 0);
                execute_start = (double)tv.tv_sec + ((double)tv.tv_usec * 1.0e-6);

		psample();
#ifdef TIMERS
        /* for testing
                if(loop == 10) accumalated_delay += 1.5;
                if(loop == 20) accumalated_delay += 2.5;
                if(loop == 30) accumalated_delay += 3.5;
        */
                psection("njmontime");
                 plong("njmon_seconds", seconds);
                 pdouble("njmon_sleep_time", sleep_time);
                 pdouble("njmon_execute_time", execute_time);
                 pdouble("njmon_accumalated", accumalated_delay);
                 plong("njmon_sleep_seconds", sleep_seconds);
                psectionend();
#endif /* timers */

		/* calculate elapsed time to include sleep and data collection time */
		if(loop != 0)
			previous_time = current_time;
		gettimeofday(&tv, 0);
		current_time = (double)tv.tv_sec + ((double)tv.tv_usec * 1.0e-6);
		ASSERT(current_time != previous_time, "Elapsed Calculation", DUMP, (long long)elapsed); 
		elapsed = current_time - previous_time;
		DEBUG pdouble("elapsed",elapsed);

		DEBUG praw("SAMPLE");
		if(mode == ONE_LEVEL || oldmode == 0) {
			identity();
		}
		date_time(seconds, loop, maxloops);
		ps_part_config();
		aix_server();
		ps_part_total(); /* get hw ticks */
		ps_cpu_stats(elapsed);
		ps_cpu_total_stats(elapsed);
		ps_memory(elapsed);
		ps_memory_page(elapsed);
		ps_paging();
		ASSERT(elapsed != 0.0, "main(looping) elapsed", DUMP, (long long)elapsed);
		ps_vminfo(elapsed);
		ps_net_interface_stats(elapsed);
		ps_net_adapter_stats(elapsed);
		ps_net_total_stats(elapsed);
		if(vios_mode) 
			ps_net_bridge_stats(elapsed);
		ps_netbuffs();
		ps_disk_stats(elapsed);
		ps_disk_total_stats(elapsed);
		ps_disk_adapter_stats(elapsed);
#ifdef VIOS
		if(vios_mode) {
			ps_vios_vhost_stats(elapsed);
			if(vios_mode) ps_vios_target_stats(elapsed);
			ps_vios_vfc_stats(elapsed);
		}
#endif /* VIOS */
#ifdef SSP
		if(ssp_mode) {
			ps_ssp();
			ps_ssp_node();
		}
#endif /* SSP */
		ps_fc_stats(elapsed);
		filesystems();
		ps_lv_stats(elapsed);
		ps_vg_stats(elapsed);
		ps_tape(elapsed);
		dr_lpar_stats();
#ifndef NOGPFS
		gpfs_data(elapsed);
#endif /* NOGPFS */

		if(processes) ps_process_util();

		DEBUG praw("Sample");
		psampleend(loop == (maxloops -1));
		rc = push();
                if (rc < 0) {
                printf("push1: rc is %d,trying reconnect.\n",rc);
                create_socket(host, port, hostname, buffer, secret);
                }
		/* debugging = uncomment to crash here!
		ASSERT(loop == 42, "CRASHer", DUMP, loop); 
		*/

                gettimeofday(&tv, 0);
                execute_end = (double)tv.tv_sec + ((double)tv.tv_usec * 1.0e-6);
		execute_time = execute_end - execute_start;
	}
	/* finish-of */
	if(mode == ONE_LEVEL) {
                remove_ending_comma_if_any();
		praw("]\n");
		if(njmon_stats)pstats();
	}
	if( mode == MULTI_LEVEL) {
                remove_ending_comma_if_any();
		if(samples) praw(" ]\n");
		if(njmon_stats)pstats();
		pfinish("");
	}
	rc = push();
        if (rc < 0) {
        printf("push2: rc is %d,trying reconnect.\n",rc);
        create_socket(host, port, hostname, buffer, secret);
        }
	return 0;
}
/* - - - The End - - - */
