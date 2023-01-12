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
    if (!(*ctx)) {
   	 printf("CTX is null!");
   	 ERR_print_errors_fp(stderr);
   	 exit(2);
    }
    SSL_CTX_set_default_passwd_cb_userdata((*ctx), pass);
    SSL_CTX_set_verify((*ctx), SSL_VERIFY_PEER, NULL);
    SSL_CTX_load_verify_locations((*ctx), CACERT, NULL);
    if (SSL_CTX_use_certificate_file((*ctx), certf, SSL_FILETYPE_PEM) <= 0) {
   	 ERR_print_errors_fp(stderr);
   	 exit(3);
    }
    if (SSL_CTX_use_PrivateKey_file((*ctx), keyf, SSL_FILETYPE_PEM) <= 0) {
   	 ERR_print_errors_fp(stderr);
   	 exit(4);
    }
    if (!SSL_CTX_check_private_key((*ctx))) {
   	 fprintf(stderr,"Private key does not match the certificate public key\n");
   	 exit(5);
    }
}

// check peer's certificate
void keyXchange_chk_peer_cert(SSL* ssl, char* commonName) {
    X509* peer_cert;
    char* str;
    char peer_CN[256];
    printf ("SSL connection using %s\n", SSL_get_cipher (ssl));
    /* Get client's certificate (note: beware of dynamic allocation) - opt */
    if (SSL_get_verify_result(ssl)!=X509_V_OK)
   	 do_error("Certificate doesn't verify.\n");
    peer_cert = SSL_get_peer_certificate (ssl);
    if (peer_cert != NULL) {
   	 // check common name here
   	 X509_NAME_get_text_by_NID(X509_get_subject_name(peer_cert),  NID_commonName, peer_CN, 256);
     char * commonName2 = CLI_CERT_CN2;
   	 if((strcasecmp(peer_CN, commonName) == 0 )|| (strcasecmp(peer_CN, commonName2) == 0) ) {
        printf("Common Names Matched.!!");
    } 
   	 else {
   		 printf("peer common name: %s, local request!!\n", peer_CN);
   		 do_error("Common name doesn't match host name\n");
   	 
   	 }

   	 X509_free (peer_cert);
    } else
   	 do_error("Peer does not have certificate.\n");
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

int sha256(char *input, unsigned char *output)
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

int setup_session(char* ip, int remote_port, char* commonName, unsigned char* key, unsigned char* iv, int pipefd, int pid) {
    
    SSL_CTX* ctx;
    SSL* ssl_connect;

    keyXchange_setupCTX(CLI_CERTF, CLI_KEYF, SSLv23_client_method(), &ctx, CLI_CERT_PASS);

    int sock_fd, i;
    struct sockaddr_in servaddr;
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(ip);
    servaddr.sin_port = htons(remote_port);

    connect(sock_fd, (struct sockaddr*)&servaddr, sizeof(servaddr));
    ssl_connect = SSL_new(ctx);   
    SSL_set_fd (ssl_connect, sock_fd);
    SSL_connect(ssl_connect);   
   
    keyXchange_chk_peer_cert(ssl_connect, commonName);

    char input_user_name[15];
    char input_user_password[15];

    char buffer[4096];

    int message_length;
    message_length = SSL_read (ssl_connect, buffer, sizeof(buffer)-1);
    buffer[message_length] = '\0';
    fprintf(stdout, "%s\n", buffer); fflush(stdout);
    
    gets(input_user_name);
    message_length = SSL_write(ssl_connect, input_user_name, strlen(input_user_name));
    
    message_length = SSL_read(ssl_connect, buffer, sizeof(buffer)-1);
    fprintf(stdout, "%s\n", buffer); fflush(stdout);
    
    gets(input_user_password);
    message_length = SSL_write(ssl_connect, input_user_password, strlen(input_user_password));
    
    message_length = SSL_read(ssl_connect, buffer, sizeof(buffer)-1);
    buffer[message_length] = '\0';
    fprintf(stdout, "%s\n", buffer); fflush(stdout);

    while (1) {
   	    fprintf(stdout, "Enter the number as required: \n"); fflush(stdout);
        fprintf(stdout, "1 to continue, 0 to abort, and 2 to change init vector and key:\n"); fflush(stdout);
    
        memset(buffer, 0, 4096);
   	    scanf("%s", buffer);

        if (strlen(buffer) == 1) {
            if (buffer[0]=='0') {
                kill(pid, SIGTERM); wait();
                break;
            }
            else if (buffer[0]=='2') {
                fprintf(stdout, "Enter the key or Generate new key by entering 1.\n"); fflush(stdout);
                memset(buffer, 0, 4096);
                scanf("%s", buffer);
                if (buffer[0]=='1') {
                    genKey(KEY);
                }
                else {
                    for (i=0; i<strlen(buffer) && i<KEY_IV_SIZE; i++)
                        KEY[i] = buffer[i];
                    if (i<KEY_IV_SIZE) genKey((unsigned char*)buffer);
                    for (; i<KEY_IV_SIZE; i++)
                        KEY[i] = buffer[i];
                }
                printf("Enter the Init Vector or Generate new Init Vector by entering 1.\n");
                memset(buffer, 0, 4096);
                scanf("%s", buffer);
                if (buffer[0]=='1') {
                    genIV(IV);
                }
                else {
                    for (i=0; i<strlen(buffer) && i<KEY_IV_SIZE; i++)
                        IV[i] = buffer[i];
                    if (i<KEY_IV_SIZE) genIV((unsigned char*)buffer);
                    for (; i<KEY_IV_SIZE; i++)
                        IV[i] = buffer[i];
                }
            }
        }
        else if (strlen(buffer) > 0 && buffer[0]!='1') {
            continue;
        }

        keyXchange_sendKey(ssl_connect, key);
        keyXchange_sendIV(ssl_connect, iv);

        for (i=0; i<KEY_IV_SIZE; i++) {
            if (i == 0) buffer[i] = 'k';
            buffer[i+1] = KEY[i];
            buffer[i+KEY_IV_SIZE+1] = IV[i];
        }
        buffer[KEY_IV_SIZE*2+1] = '\0';
        write(pipefd, buffer, KEY_IV_SIZE*2+2);
    }
    
    for (i=0; i<KEY_IV_SIZE; i++) {
        KEY[i] = 0; IV[i] = 0;
    }

    keyXchange_sendKey(ssl_connect, key);
    keyXchange_sendIV(ssl_connect, iv);

    SSL_shutdown(ssl_connect);
    close(sock_fd);
    SSL_free(ssl_connect);
    SSL_CTX_free(ctx);
}


void start_session(int MODE, int listen_port, char *ip, int remote_port, int pipefd) {
    struct sockaddr_in sin, sout;
    struct ifreq ifr;
    socklen_t soutlen;
    int fd, s, l, i, keyXchange_count = 0;
    fd_set fdset;
    char buf[BUFF_SIZE], digt[HMAC_LEN];

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
        else{
                fprintf(stdout, "\n Receiving the packet..."); fflush(stdout);
                l = recvfrom(s, buf, BUFF_SIZE, 0, (struct sockaddr *)&sout, &soutlen);
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

                        if(write(fd, buf, l) < 0) do_error("write");
                    }
                    else {
                        fprintf(stdout, "Packet is dropped as unable to decrypt the packet..\n");
                    }
                }
            }
    }
}



int main(int argc, char *argv[]) {
    char *server_ip = argv[1]; // server IP is stored as a string
    int server_port = strtol(argv[2], NULL, 10); // server port is stored as an integer
    int listen_port;
    listen_port = 0;

    int pipe_fd[2];
    pipe(pipe_fd);
    fcntl(pipe_fd[0], F_SETFL, O_NONBLOCK);
    pid_t pid;
    pid = fork();
    if(pid > 0){
        close(pipe_fd[0]);
        genKey(KEY);
        genIV(IV);
        setup_session(server_ip, server_port, SER_CERT_CN, KEY, IV, pipe_fd[1], pid);
    }
    else if (pid == 0){
        close(pipe_fd[1]);
        start_session(2, listen_port, server_ip, server_port, pipe_fd[0]);
    }
}
