#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <errno.h>
#include <memory.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <fcntl.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netdb.h>

#include <linux/if_tun.h>
#include <getopt.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>   	/* SSLeay stuff */
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include "utility.h"


// toggle controling whether to show debug information
#define DEBUG 0
#define USER_DB "users.db"

#define do_error(x) { do_error(x); exit(1); }
#define ERROR(x, args ...) { fprintf(stderr,"ERROR:" x, ## args); exit(1); }

// define length of hmac
#define HMAC_LEN 16
// buffer size of one packet
#define BUFF_SIZE 51200
#define KEY_IV_SIZE 16

#define HASHLEN 32
#define SALTLEN 5

#define CHK_NULL(x) if ((x)==NULL) { printf("NULL!!\n"); exit(1); }
#define CHK_ERR(err,s) if ((err)==-1) { do_error(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

/* Make these what you want for cert & key files */
static char SER_CERTF[] = "server.crt";
static char SER_KEYF[] = "server.key";
static char CLI_CERTF[] = "client.crt";
static char CLI_KEYF[] = "client.key";
static char CACERT[] = "ca.crt";
// certificate for server / client side
static char SER_CERT_PASS[] = "ashwani";
static char CLI_CERT_PASS[] = "ashwani";
// common names
static char SER_CERT_CN[] = "SERVER";
static char CLI_CERT_CN[] = "CLIENT";
static char CLI_CERT_CN2[] = "CLIENT2";

unsigned char KEY[KEY_IV_SIZE], IV[KEY_IV_SIZE];

// generate random key
void genKey(unsigned char* key) {
    int i;
    srand(time(NULL));
    for (i=0; i<KEY_IV_SIZE; i++)
   	 key[i] = 65 + (rand()%26);
}

// generate random iv
void genIV(unsigned char* iv) {
    int i;
    srand(time(NULL));
    for (i=0; i<KEY_IV_SIZE; i++)
   	 iv[i] = 48 + (rand()%10);
}

void showKeyOrIV(unsigned char* chrs) {
    int i;
    for (i=0; i<KEY_IV_SIZE; i++)
   	 printf("%c", chrs[i]);
}

// get hash value of one message
void getHash(char * msg, int len, char * digt) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    size_t md_len, i;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    char hashname[] = "md5";    // I am just gonna use md5 here
    OpenSSL_add_all_digests();
    md = EVP_get_digestbyname(hashname);
    if(!md) {
   	 printf("Unknown message digest %s\n", hashname);
   	 exit(1);
    }
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, msg, len);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_destroy(mdctx);
    // md_len == HMAC_LEN == 16 at this stage
    memcpy(digt, md_value, HMAC_LEN);
}

// verify the hmac, truncate the buff (by decrease the len) when verification is done
// NOTE: return 0 when matches
int checkHMAC(char * payload, int * l) {
    char digt1[HMAC_LEN], digt2[HMAC_LEN], buff[BUFF_SIZE];    // digt1 is for the HMAC from buff, digt2 is calculated HMAC
    int i, len = *l;
    // I will change the len here
    len -= HMAC_LEN;
    if (len <=0) return 1;
    memcpy(digt1, payload + len, HMAC_LEN);
    memcpy(buff, payload, len);
    getHash(buff, len, digt2);
    if (DEBUG) {
   	 printf("checking HMAC: ");
   	 for(i = 0; i < HMAC_LEN; i++) printf("%02x", digt1[i]);
   	 printf(" / ");
   	 for(i = 0; i < HMAC_LEN; i++) printf("%02x", digt2[i]);
   	 printf("\n");
    }
    *l = len;
    return strncmp(digt1, digt2, HMAC_LEN);
}

// append HMAC to the end of buff
void appendHMAC(char * payload, int * l) {
    char digt[HMAC_LEN], buff[BUFF_SIZE];
    int i, len = *l;
    memcpy(buff, payload, len);
    getHash(buff, len, digt);
    for (i=0;i<HMAC_LEN;i++)
   	 *(payload + len + i) = digt[i];
    len += HMAC_LEN;
    if (DEBUG) {
   	 printf("\nappend HMAC: ");
   	 for(i = len-HMAC_LEN; i < len; i++) printf("%02x", *(payload+i));
   	 printf("\n");
    }
    *l = len;
}

// decrypt / encrypt packet
int do_crypt(unsigned char *key, unsigned char * iv, char * packet, int *l, int do_encrypt) {
    unsigned char outbuf[BUFF_SIZE + EVP_MAX_BLOCK_LENGTH];
    int inlen = *l, outlen, tmplen, i;
    unsigned char input[BUFF_SIZE];
    // convert text
    memcpy(input, packet, inlen);
    if (DEBUG) {
   	 printf("\n(before crypted) payload: ");
   	 for(i = 0; i < inlen; i++) printf("%02x", *(input+i));
   	 printf("\n");
    }

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, key, iv, do_encrypt);

    if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, input, inlen)) {
   	 /* Error */
   	 EVP_CIPHER_CTX_cleanup(&ctx);
   	 return 0;
    }
    if(!EVP_CipherFinal_ex(&ctx, outbuf + outlen, &tmplen)) {
   	 /* Error */
   	 EVP_CIPHER_CTX_cleanup(&ctx);
   	 return 0;
    }
    outlen += tmplen;
    if (DEBUG) {
   	 printf("\n(crypted) payload: ");
   	 for(i = 0; i < outlen; i++) printf("%02x", *(outbuf+i));
   	 printf("\n");
    }
    memcpy(packet, outbuf, outlen);    // update packet
    *l = outlen;
    EVP_CIPHER_CTX_cleanup(&ctx);
    return 1;    // return as successful
}

// display usage information
void usage() {
    fprintf(stderr, "Usage: MiniVPN [-s port|-c targetip:port]\n");
    exit(0);
}

// set up key exchange context
void keyXchange_setupCTX(char* certf, char* keyf, SSL_METHOD* meth, SSL_CTX** ctx, char* pass) {
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
    (*ctx) = SSL_CTX_new(meth);
    /*
    if (!(*ctx)) {
   	 printf("CTX is null!");
   	 ERR_print_errors_fp(stderr);
   	 exit(2);
    }
    */
    SSL_CTX_set_default_passwd_cb_userdata((*ctx), pass);
    SSL_CTX_set_verify((*ctx), SSL_VERIFY_PEER, NULL);
    SSL_CTX_load_verify_locations((*ctx), CACERT, NULL);
    if (SSL_CTX_use_certificate_file((*ctx), certf, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file((*ctx), keyf, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if (!SSL_CTX_check_private_key((*ctx))) {
        do_error("Mismatch between the private key and the certificate. Hence, aborting.\n");
    }
}

// check peer's certificate
void keyXchange_chk_peer_cert(SSL* ssl, char* cert_cn_name) {
    X509* rcvd_cert;
    char common_name[256];
    char* str;
    //fprintf (stdout, "SSL connection using %s\n", SSL_get_cipher (ssl)); fflush(stdout);
    if (SSL_get_verify_result(ssl)!=X509_V_OK)  do_error("Verification for certificate failed.\n");

    rcvd_cert = SSL_get_peer_certificate (ssl);
    
    if (rcvd_cert == NULL) {
        do_error("Certificate missing from the client!!\n");
    }
    else{
        X509_NAME_get_text_by_NID(X509_get_subject_name(rcvd_cert),  NID_commonName, common_name, 256);
        char * commonName2 = CLI_CERT_CN2;
        if((strcasecmp(common_name, cert_cn_name) == 0 )|| (strcasecmp(common_name, commonName2) == 0) ) {
            fprintf(stdout, "The common names for the certs are matched.\n"); fflush(stdout);
        } 
        else {
            fprintf(stdout, "Common name: %s received from connection does not match with existing.\n", common_name);
            do_error("Common name doesn't match host name\n");
        }
        X509_free (rcvd_cert);
    } 
}

// send key to remote
void keyXchange_sendKey(SSL* ssl, unsigned char* key) {
    int i;
    char buf[4096];
    buf[0] = 'k';    // mark as key
    for (i=0; i<KEY_IV_SIZE; i++)
   	 buf[i+1] = key[i];
    i = SSL_write(ssl, buf, KEY_IV_SIZE+1);
    CHK_SSL(i);
    // read echo
    i = SSL_read(ssl, buf, sizeof(buf) - 1);
    CHK_SSL(i);
    buf[i] = '\0';
    if (buf[0]=='l') {
   	 printf("Key confirmed by remote peer: ");
   	 showKeyOrIV(key);
   	 printf("\n");
    }
    else
   	 do_error("Key exchange fail!\n");
}

// send iv to remote
void keyXchange_sendIV(SSL* ssl, unsigned char* iv) {
    int i;
    char buf[4096];
    buf[0] = 'i';    // mark as iv
    for (i=0; i<KEY_IV_SIZE; i++)
   	 buf[i+1] = iv[i];
    i = SSL_write(ssl, buf, KEY_IV_SIZE+1);
    CHK_SSL(i);
    // read echo
    i = SSL_read(ssl, buf, sizeof(buf) - 1);
    CHK_SSL(i);
    buf[i] = '\0';
    if (buf[0]=='j') {
   	 printf("IV confirmed by remote peer: ");
   	 showKeyOrIV(iv);
   	 printf("\n");
    }
    else
   	 do_error("IV exchange fail!\n");
}

int keyXchange_receiveKey(SSL* ssl, char* buf, size_t len, unsigned char* key) {
    int i;
    if (len!=KEY_IV_SIZE+1 || buf[0]!='k') return 0;
    for (i=1; i<len; i++)
   	 key[i-1] = buf[i];
    i = SSL_write(ssl, "l", 1);
    CHK_SSL(i);
    printf("KEY received: ");
    showKeyOrIV(key);
    printf("\n");
    return 1;
}

int keyXchange_receiveIV(SSL* ssl, char* buf, size_t len, unsigned char* iv) {
    int i;
    if (len!=KEY_IV_SIZE+1 || buf[0]!='i') return 0;
    for (i=1; i<len; i++)
   	 iv[i-1] = buf[i];
    i = SSL_write(ssl, "j", 1);
    CHK_SSL(i);
    printf("IV received: ");
    showKeyOrIV(iv);
    printf("\n");
    return 1;
}

int get_sha_256(char *input, unsigned char *output)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    if(!SHA256_Update(&ctx, input, strlen(input))) return 0;
    if(!SHA256_Final(hash, &ctx)) return 0;
    
    printf("SHA256,strlen(hash):%d\n",strlen(hash));
    strncpy(output,hash,HASHLEN);
    printf("SHA256,strlen(output):%d\n",strlen(output));
    
    
    int i = 0;
    for(i = 0;i < HASHLEN ; i++) {
        printf("%02x",output[i]);
    }
    printf("\n");
    return 1;
    
}



     

// key exchange part for server
void setup_session(int *sd, int listen_port, char* commonName, unsigned char* key, unsigned char* iv, int pipefd, int pid) {
    
    SSL_CTX* ctx;
    SSL* ssl_connect;
    
    int is_user_verified = 0;

    keyXchange_setupCTX(SER_CERTF, SER_KEYF, SSLv23_server_method(), &ctx, SER_CERT_PASS);

    ssl_connect = SSL_new(ctx);
    SSL_set_fd(ssl_connect, *sd);
    SSL_accept(ssl_connect);	 

    char input_user_name[15]; 
    char input_user_password[15];

    char db_user[15];
    char db_salt[SALTLEN];
    char db_password[HASHLEN];

    int listen_sd, i;
    struct sockaddr_in sa_serv, sa_cli;
    size_t client_len;

    FILE *fp;
    fp = fopen(USER_DB, "r");
    if (fp == NULL) do_error("Error while opening user db");

    SSL_write (ssl_connect, "Please provide login name:", strlen("Please provide login name"));
    int name_length;
    name_length = SSL_read (ssl_connect, input_user_name, sizeof(input_user_name)-1);
    input_user_name[name_length] = '\0';
    
    while(fscanf(fp, "%s %s %s", db_user, db_salt, db_password) != EOF) {
        if (strcmp(input_user_name, db_user) == 0) {
            fprintf(stdout, "Login successful!!\n"); fflush(stdout);
            is_user_verified = 1;
            break;
        }
    }
    fclose(fp);
    if (is_user_verified == 0) {
        close(*sd);
        SSL_free(ssl_connect);
        do_error("Aborting as user is not present in DB.\n");
    }
    SSL_write(ssl_connect, "Please provide password:", strlen("Please provide password:"));
    int password_length;
    password_length = SSL_read (ssl_connect, input_user_password, sizeof(input_user_password)-1);
    input_user_password[password_length] = '\0';

    char salt_and_password[30];
    unsigned char pass_hash[HASHLEN];

    strcpy(salt_and_password, db_salt); strcat(salt_and_password, input_user_password);
    get_sha_256(salt_and_password, pass_hash);

    fp = fopen("users_temporary_password_hash", "w+");
    int iterator = 0;
    while(iterator < HASHLEN){
        fprintf(fp, "%02x", pass_hash[iterator]);
        iterator++;
    }
    fprintf(fp, "\n");
    fclose(fp);
    
    char pass_buffer[250];
    char buffer[4096];
    fp = fopen("users_temporary_password_hash", "r");
    fscanf(fp, "%s", pass_buffer);
    fclose(fp);

    int passwords_match = 0;
    for(i=0; i<HASHLEN; i++) {
        if (pass_buffer[i] != db_password[i]) passwords_match = 1;
    }

    if (passwords_match == 1) {
        SSL_write(ssl_connect, "You entered wrong password.", strlen("You entered wrong password."));
        close(*sd);
        SSL_free(ssl_connect);
        do_error("The entered passwords do not match.\n");
    }

    SSL_write(ssl_connect, "Authentication is Successful.", strlen("Authentication is Successful.")); fprintf(stdout, "The user is successfully authenticated.\n"); fflush(stdout);
    keyXchange_chk_peer_cert(ssl_connect, commonName);

    int private_key = 0, init_vector = 0;
    int key_length;
    int exchange_key, exchange_iv;
    while (1){
   	    private_key = 0;
   	    init_vector = 0;
        while (!private_key || !init_vector) {
            key_length = SSL_read(ssl_connect, buffer, sizeof(buffer)-1);
            buffer[key_length] = '\0';
            exchange_key = keyXchange_receiveKey(ssl_connect, buffer, key_length, KEY);
            exchange_iv = keyXchange_receiveIV(ssl_connect, buffer, key_length, IV);
            if(private_key || exchange_key) private_key = 1;
            if(init_vector || exchange_iv) init_vector = 1;
        }
        for (i=0; i<KEY_IV_SIZE; i++) {
            if (i == 0) buffer[i] = 'k';
            buffer[i+1] = KEY[i];
            buffer[i+KEY_IV_SIZE+1] = IV[i];
        }
   	    buffer[KEY_IV_SIZE*2+1] = '\0';
     
        private_key = 0;
   	    init_vector = 0;

        for (i=0; i<KEY_IV_SIZE; i++) {
            if((int)KEY[i]) private_key = 1;
            if((int)IV[i]) init_vector = 1;
        }
        if (!private_key && !init_vector) {
            fprintf(stdout, "Client disconnected, hence aborting this child process to free resources.\n");
            kill(pid, SIGTERM);
            wait();
            break;
        }
   	    write(pipefd, buffer, KEY_IV_SIZE*2+2);
         //break;
    }

    close(*sd);
    SSL_free(ssl_connect);
    SSL_CTX_free(ctx);
}


 

//void create_tunnel()

void start_session(int MODE, int listen_port, char *ip, int remote_port, int pipefd) {
    struct sockaddr_in sin, sout;
    struct ifreq ifr;
    socklen_t soutlen;
    int fd, s, l, i, keyXchange_count = 0;
    fd_set fdset;
    char buf[BUFF_SIZE], digt[HMAC_LEN];
    char passed_message[BUFF_SIZE+15];
    char *recv_client_ip;

    // open tunnel
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) do_error("open");

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN;    // always use tun here
    strncpy(ifr.ifr_name, "tun%d", IFNAMSIZ);
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) do_error("ioctl");
    printf("There is tun interface allocated interface, the name is: %s.\n", ifr.ifr_name);


    s = socket(PF_INET, SOCK_DGRAM, 0);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(listen_port);

    int opt = 1;
    if( setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int)) < 0 ) {
        do_error("[-] Error! Cannot reuse address");
        //retn = -1;
    }

    if (bind(s,(struct sockaddr *)&sin, sizeof(sin)) < 0) do_error("bind");
    soutlen = sizeof(sout);
    if (MODE == 2) { // for client
   	 sout.sin_family = AF_INET;
   	 sout.sin_port = htons(remote_port);
   	 inet_aton(ip, &sout.sin_addr);
    }

    // the real VPN part
    while (1) {
        l = read(pipefd, buf, sizeof(buf));
        //printf("******* l = %d, and buf = %s", l, buf);
        if (l > 0) {    // if we get some command from parent process
            if (l == 1 && buf[0]=='q') {
                do_error("Aborting as per received command..");
                // _exit(0);
            }
            else if (buf[0]=='k') {
                //fprintf(stdout, "######Inside the buf = k block.########"); fflush(stdout);
                for (i=0; i<KEY_IV_SIZE; i++) {
                    KEY[i] = buf[i+1];
                    IV[i] = buf[i+KEY_IV_SIZE+1];
                }
                keyXchange_count++;
            }
            printf("Printing the Key: ");
            showKeyOrIV(KEY);
            printf("Printing the Init Vector: ");
            showKeyOrIV(IV);
            printf("\n");
        }
        if (!keyXchange_count) {
            sleep(1);
            continue;
        }

        FD_ZERO(&fdset);
        FD_SET(fd, &fdset);
        FD_SET(s, &fdset);
        if (select(fd+s+1, &fdset,NULL,NULL,NULL) < 0) do_error("select");
        if (FD_ISSET(fd, &fdset)){
                fprintf(stdout, "\n Sending the packet..."); fflush(stdout);
                l = read(fd, buf, BUFF_SIZE);
                if (l < 0) do_error("read");

                memset(passed_message, 0, sizeof(passed_message));
                memcpy(passed_message, buf, 15);
                if (strcmp(passed_message, recv_client_ip) != 0){
                    write(fd, buf, l);
                }

                else{
                    if(do_crypt(KEY, IV, buf, &l, 1)) {
                        fprintf(stdout, "\n Printing the Encrypted Data...: \n"); fflush(stdout);
                        for(i = 0; i < l; i++) {
                            fprintf(stdout, "%02x", *(buf+i)); fflush(stdout);
                        }
                        fprintf(stdout, "\n"); fflush(stdout);

                        appendHMAC(buf, &l);
                        fprintf(stdout, "\n Printing the Data...: \n"); fflush(stdout);
                        for(i = 0; i < l; i++) {
                            fprintf(stdout, "%02x", *(buf+i)); fflush(stdout);
                        }
                        fprintf(stdout, "\n"); fflush(stdout);
                        if (sendto(s, buf, l, 0, (struct sockaddr *)&sout, soutlen) < 0) do_error("sendto");
                    }
                    else {
                        fprintf(stdout, "Packet is dropped as unable to encrypt the packet..\n");
                    }
                }
        }
        else{
                fprintf(stdout, "\n Receiving the packet..."); fflush(stdout);
                l = recvfrom(s, buf, BUFF_SIZE, 0, (struct sockaddr *)&sout, &soutlen);
                recv_client_ip = inet_ntoa(sout.sin_addr);
                fprintf(stdout, "\n Printing the Encrypted Data...: \n"); fflush(stdout);
                for(i = 0; i < l; i++) {
                    fprintf(stdout, "%02x", *(buf+i)); fflush(stdout);
                }
                fprintf(stdout, "\n"); fflush(stdout);
                if (checkHMAC(buf, &l)){
                    fprintf(stdout, "The HMACs didn't match, hence dropping the packets..\n"); fflush(stdout);
                }
                else {
                    if(do_crypt(KEY, IV, buf, &l, 0)){
                        fprintf(stdout, "\n Printing the Decrypted Data...: \n"); fflush(stdout);
                        for(i = 0; i < l; i++) {
                            fprintf(stdout, "%02x", *(buf+i)); fflush(stdout);
                        }
                        fprintf(stdout, "\n"); fflush(stdout);
                        memset(passed_message, 0, sizeof(passed_message));
                        fprintf(stdout, "*****Client IP: %s", recv_client_ip);
                        memcpy(passed_message, recv_client_ip, 15);
                        memcpy(passed_message+15, buf, l);
                        if(write(fd, passed_message, l+15) < 0) do_error("write");
                    }
                    else {
                        fprintf(stdout, "Packet is dropped as unable to decrypt the packet..\n");
                    }
                }
            }
    }
}


int main(int argc, char *argv[]) {

    // Define the variables to be used in this program.
    char *server_ip; // server IP is stored as a string
    int server_port = strtol(argv[1], NULL, 10); // server port is stored as an integer
    int remote_port;
    struct sockaddr_in servaddr, cliaddr;
	size_t clientlen = sizeof(cliaddr);
    
    pid_t pid1, pid2;

    int parent_sockfd;
    // Creating the socket file descriptor for TCP using SOCK_STREAM.
	if ((parent_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
		do_error("Socket creation failed for the server.\n");
    }

    /* This eliminates the "ERROR on binding: Address already in use" 
	 * error when the server re-run immediately after it is killed.
	 */
    //int setsock; // flag value for setsockopt.
	//setsock = 1;
	//setsockopt(parent_sockfd, SOL_SOCKET, SO_REUSEADDR, 
	//			(const void *)&setsock , sizeof(int));

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(server_port);

      // Bind the socket with the servaddr address.
	if (bind(parent_sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0){
		do_error("Failed to bind the server to the socket file descriptor.\n");
    }

    // make this socket ready to accept connection requests using listen()	
	if (listen(parent_sockfd, 5) < 0){ // allow 5 connection requests to queue up  
		do_error("Error while listening to connection requests.\n");
    }

    int child_sockfd;
    while(1){
        fprintf(stdout, "Inside this.........\n"); fflush(stdout);
        // accept() to wait for a connection request, it returns a new file descriptor.
		child_sockfd = accept(parent_sockfd, (struct sockaddr *) &cliaddr, &clientlen);
		if (child_sockfd < 0){
			do_error("Error while accepting the connection request from client.\n");
        }

        fprintf(stdout, "Accepted a connection request from the client from IP: %s, PORT: %i\n", inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port));
        if (child_sockfd > 0){
            pid1 = fork();
            if (pid1 == 0) break;
        }
    }
        
    int pipe_fd[2];
    pipe(pipe_fd);
    fcntl(pipe_fd[0], F_SETFL, O_NONBLOCK);
    if ((pid2 = fork()) > 0){
        close(pipe_fd[0]);
        setup_session(&child_sockfd, server_port, CLI_CERT_CN, KEY, IV, pipe_fd[1], pid2);
    }
    else{
        close(pipe_fd[1]);
        start_session(1, server_port, server_ip, remote_port, pipe_fd[0]);
        fprintf(stdout, "Served one client, exiting.\n"); fflush(stdout);
    }
}     
