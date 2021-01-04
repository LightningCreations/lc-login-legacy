//
// Created by chorm on 2020-08-27.
//

#include <unistd.h>
#include <error.h>
#include <utmp.h>
#include <string.h>
int main(int argc,char** argv){
    const char* HELP =
            "Usage: %s [-p] [-h host] [uname] [ENV=VAR...]\n"
            "\tor: %s [-p] [-h host] -f uname\n"
            ""
    if(geteuid()!=0)
        error(1,0,"Cannot operate login, except as root\n");

    char uname[1024] = {0};
    char host[1024] = {0};
    _Bool has_uname = 0;
    _Bool preauth = 0;
    _Bool preserve_env = 0;
    int opt;
    while((opt=getopt(argc,argv,"ph:r:f:"))!=-1)
        switch(opt){
        case 'p':
            preserve_env = 1;
        break;
        case 'f':
            preauth = 1;
            has_uname = 1;
            strncpy(uname,optarg,1024);
        break;
        case 'h':
            strncpy(host,optarg,1024);
            break;
        case 'r':
            error(1,0,"rlogin is not supported by lc-login due to deprecation");
        default:
            error(1,0,HELP,argv[0],argv[0]);
        }


}