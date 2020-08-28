//
// Created by chorm on 2020-08-27.
//

#include <unistd.h>
#include <error.h>

int main(void){
    if(geteuid()!=0)
        error(1,0,"Cannot operate login, except as root\n");

}