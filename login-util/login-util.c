//
// Created by chorm on 2020-08-27.
//

#include <login-variables.h>
#include <login-util.h>
#include <stdio.h>

#include <inttypes.h>
#include <stdint.h>

#include <unistd.h>
#include <fcntl.h>

#include <errno.h>

#include <termios.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <string.h>

#include <openssl/rand.h>

__attribute__((constructor)) static void init_login(void){
    OPENSSL_init();
    RAND_poll();
}


int get_user_directory(uid_t uid){
    char buf[128];
    snprintf(buf,128,"%" PRIxMAX,(intmax_t)uid);
    int users_root = open(LCLOGIN_USERS_ROOT,O_RDONLY|O_DIRECTORY);
    if(users_root<0)
        return -1;
    int fd = openat(users_root,buf,O_RDONLY|O_DIRECTORY);
    int errn = errno;
    close(users_root);
    if(fd<0){
        errno = errn;
        return -1;
    }
    return fd;
}
int get_user_name_directory(const char* uname){
    int users_root = open(LCLOGIN_USERS_ROOT,O_RDONLY|O_DIRECTORY);
    if(users_root<0)
        return -1;
    int fd = openat(users_root,uname,O_RDONLY|O_DIRECTORY);
    int errn = errno;
    close(users_root);
    if(fd<0){
        errno = errn;
        return -1;
    }
    return fd;
}
int get_group_directory(gid_t gid){
    char buf[128];
    snprintf(buf,128,"%" PRIxMAX,(intmax_t)gid);
    int groups_root = open(LCLOGIN_GROUPS_ROOT,O_RDONLY|O_DIRECTORY);
    if(groups_root<0)
        return -1;
    int fd = openat(groups_root,buf,O_RDONLY|O_DIRECTORY);
    int errn = errno;
    close(groups_root);
    if(fd<0){
        errno = errn;
        return -1;
    }
    return fd;
}
int get_group_name_directory(const char* gname){
    int groups_root = open(LCLOGIN_GROUPS_ROOT,O_RDONLY|O_DIRECTORY);
    if(groups_root<0)
        return -1;
    int fd = openat(groups_root,gname,O_RDONLY|O_DIRECTORY);
    int errn = errno;
    close(groups_root);
    if(fd<0){
        errno = errn;
        return -1;
    }
    return fd;
}

static ssize_t digest(const char* c,uint16_t dgst,unsigned char SALT[32],unsigned char buf[],size_t size){
    const EVP_MD* md;
    switch(dgst&LCLOGIN_HASH_IDENT_MASK){
#ifdef LCLOGIN_HASH_SUPPORTED_sha224
        case LCLOGIN_HASH_sha224:
            md = EVP_sha224();
        break;
#endif
#ifdef LCLOGIN_HASH_SUPPORTED_sha256
        case LCLOGIN_HASH_sha256:
            md = EVP_sha256();
        break;
#endif
#ifdef LCLOGIN_HASH_SUPPORTED_sha384
        case LCLOGIN_HASH_sha384:
            md = EVP_sha384();
        break;
#endif
#ifdef LCLOGIN_HASH_SUPPORTED_sha512
        case LCLOGIN_HASH_sha512:
            md = EVP_sha512();
        break;
#endif
#ifdef LCLOGIN_HASH_SUPPORTED_sha3_224
        case LCLOGIN_HASH_sha3_224:
            md = EVP_sha3_224();
        break;
#endif
#ifdef LCLOGIN_HASH_SUPPORTED_sha3_256
        case LCLOGIN_HASH_sha3_256:
            md = EVP_sha3_256();
        break;
#endif
#ifdef LCLOGIN_HASH_SUPPORTED_sha3_384
        case LCLOGIN_HASH_sha3_384:
            md = EVP_sha3_384();
        break;
#endif
#ifdef LCLOGIN_HASH_SUPPORTED_sha3_512
        case LCLOGIN_HASH_sha3_512:
            md = EVP_sha512();
        break;
#endif
        default:
            errno=EINVAL;
            return -1;
    }
    EVP_MD_CTX* ctx = EVP_MD_CTX_create();
    EVP_DigestInit(ctx,md);
    unsigned char TMP[EVP_MAX_MD_SIZE];
    unsigned size_out;
    EVP_DigestUpdate(ctx,c,strlen(c));
    EVP_DigestUpdate(ctx,SALT,32);
    EVP_DigestFinal(ctx,TMP,&size_out);
    if(size<size_out){
        errno = ERANGE;
        return -1;
    }
    memcpy(buf,TMP,size_out);
    return size_out;
}

static ssize_t read_passwd(int fd,char* pass){
    ssize_t s;
    char* end = pass+2047;
    if(isatty(fd)){
        struct termios prev;
        struct termios inf;
        tcgetattr(fd,&prev);
        tcgetattr(fd,&inf);
        inf.c_lflag &= ~(ECHO|ECHOE);
        tcsetattr(fd,TCSANOW,&inf);
        for(char* cursor = pass;cursor!=end;){
            if((s=read(fd,cursor,1))>0)
                cursor++;
            else if(s==0)
                break;
            else if(errno==EINTR)
                continue;
            else
                return -1;
        }

        memset(pass,0,2048);
        tcsetattr(fd,TCSANOW,&prev);
    }else{
        for(char* cursor = pass;cursor!=end;){
            if((s=read(fd,cursor,1))>0)
                cursor++;
            else if(s==0)
                break;
            else if(errno==EINTR)
                continue;
            else
                return -1;
        }
    }
    return 0;
}

ssize_t get_passwd(int fd,unsigned char buf[],size_t size){
    if(size<34)
        return -1;
    char* pass = (char*)OPENSSL_malloc(2048);
    memset(pass,0,2048);
    if(read_passwd(fd,pass)<0){
        int errn = errno;
        OPENSSL_free(pass);
        errno = errn;
        return -1;
    }
    buf[0] = LCLOGIN_DEFAULT_PASSWD_HASH&0xff;
    buf[1] = (LCLOGIN_DEFAULT_PASSWD_HASH&0xff00)>>8;
    RAND_bytes(buf+2,32);
    ssize_t ret = digest(pass,LCLOGIN_DEFAULT_PASSWD_HASH,buf+2,buf+34,size-34);
    OPENSSL_free(pass);
    return ret;
}

int check_passwd(int fd,const char* user){
    int dir_fd = get_user_name_directory(user);
    if(dir_fd<0)
        return -1;
    int passwd = openat(dir_fd,"passwd",O_RDONLY);
    if(passwd<0){
        int errn = errno;
        close(dir_fd);
        if(errn==EACCES)
            return 1;
        else
            return -1;
    }
    close(dir_fd);
    unsigned char hash[2] = {0};
    if(read(passwd,hash,2)<0) {
        int errn = errno;
        close(passwd);
        errno =errn;
        return -1;
    }
    if(hash[0]==0xFF&&hash[1]==0xFF)
        return 0;
    unsigned char salt[32];
    if(read(passwd,salt,32)<0){
        int errn = errno;
        close(passwd);
        errno =errn;
        return -1;
    }

    unsigned char rhash[EVP_MAX_MD_SIZE]={0};
    unsigned char ahash[EVP_MAX_MD_SIZE]={0};
    if(read(passwd,rhash,EVP_MAX_MD_SIZE)<0) {
        int errn = errno;
        close(passwd);
        errno = errn;
        return -1;
    }
    close(passwd);

    char* pass = (char*)OPENSSL_malloc(2048);
    memset(pass,0,2048);
    if(read_passwd(fd,pass)<0){
        int errn = errno;
        OPENSSL_free(pass);
        errno = errn;
        return -1;
    }
    ssize_t s = digest(pass,((uint16_t)hash[0])|(((uint16_t)hash[1])<<8),salt,ahash,EVP_MAX_MD_SIZE);
    int errn = errno;
    OPENSSL_free(pass);
    errn = errno;
    if(s<0)
        return -1;
    else if(memcmp(rhash,ahash,EVP_MAX_MD_SIZE)!=0)
        return 1;
    else
        return 0;

}


