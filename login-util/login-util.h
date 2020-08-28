//
// Created by chorm on 2020-08-27.
//

#ifndef LC_LOGIN_LOGIN_PROMPT_H
#define LC_LOGIN_LOGIN_PROMPT_H

#include <sys/types.h>


/// Opens a file descriptor to the users information directory
/// \return A file descriptor with accesses, or a negative value if an error occured. 
int open_users_dir(void);

///
/// Reads a passwd from the terminal, without echoing.
/// \param name The user to check
/// \return 0 if the check succeed, 1 if it failed, and a negative value if an error occured (which sets errno)
int check_passwd(int fd,const char* name);

/// Reads a password from the terminal without echoing, an return its hash in buf.
/// \param fd The file descriptor to read from
/// \param buf The buffer to return the hash in, including the algorithm name
/// \param size The size of the buf. This should be larger than the default algorithm's size + 32 bytes + a 2 byte header
///
ssize_t get_passwd(int fd,unsigned char buf[],size_t size);

/// Opens the information directory for the user specified by uid
/// \param uid
int get_user_directory(uid_t uid);
int get_user_name_directory(const char* uname);
int get_group_directory(gid_t gid);
int get_group_name_directory(const char* gname);

#endif //LC_LOGIN_LOGIN_PROMPT_H
