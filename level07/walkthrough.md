# Level06 Walkthrough
## Initial Analysis
### 1. Examine the Binary
```bash
level06@OverRide:~$ ls -la
total 17
dr-xr-x---+ 1 level06 level06   80 Sep 13  2016 .
dr-x--x--x  1 root    root     260 Oct  2  2016 ..
-rw-r--r--  1 level06 level06  220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root       7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level06 level06 3533 Sep 10  2016 .bashrc
-rwsr-s---+ 1 level07 users   6860 Sep 10  2016 level06
-rw-r--r--+ 1 level06 level06   41 Oct 19  2016 .pass
-rw-r--r--  1 level06 level06  675 Sep 10  2016 .profile
```
**Key observations:**

setuid and setgid binary (s flags in permissions)

Owned by level07 user

When executed, runs with level07 privileges

## 2. Test Basic Execution
```bash
level06@OverRide:~$ ./level06
***********************************
*		level06		  *
***********************************
-> Enter Login: test
***********************************
***** NEW ACCOUNT DETECTED ********
***********************************
-> Enter Serial: 12345
```
**Observations:**

Program asks for login and serial

No success message with wrong credentials

Must find valid login/serial pair

## Reverse Engineering
### 3. Function Analysis
```bash
(gdb) info functions
All defined functions:
0x08048510  printf@plt
0x08048520  strcspn@plt
0x08048530  fflush@plt
0x08048540  getchar@plt
0x08048550  fgets@plt
0x08048560  signal@plt
0x08048570  alarm@plt
0x08048580  __stack_chk_fail@plt
0x08048590  puts@plt
0x080485a0  system@plt          ← Target!
0x080485e0  __isoc99_scanf@plt
0x080485f0  ptrace@plt           ← Anti-debugging!
0x08048748  auth
0x08048879  main
```
### 4. Disassembling main
```bash
(gdb) disas main
assembly
0x08048879 <+0>:     push   %ebp
0x0804887a <+1>:     mov    %esp,%ebp
0x0804887c <+3>:     and    $0xfffffff0,%esp
0x0804887f <+6>:     sub    $0x50,%esp

# Print banner
0x080488a5 <+44>:    call   0x8048590 <puts@plt>   # "***********************************"
0x080488b1 <+56>:    call   0x8048590 <puts@plt>   # "*            level06              *"
0x080488bd <+68>:    call   0x8048590 <puts@plt>   # "***********************************"

# Get login with fgets (32 bytes max)
0x080488cf <+86>:    mov    0x804a060,%eax        # stdin
0x080488d4 <+91>:    mov    %eax,0x8(%esp)
0x080488d8 <+95>:    movl   $0x20,0x4(%esp)       # 32 bytes
0x080488e0 <+103>:   lea    0x2c(%esp),%eax       # buffer at esp+0x2c
0x080488e7 <+110>:   call   0x8048550 <fgets@plt>

# Print more banner
0x080488f3 <+122>:   call   0x8048590 <puts@plt>   # "***********************************"
0x080488ff <+134>:   call   0x8048590 <puts@plt>   # "***** NEW ACCOUNT DETECTED ********"
0x0804890b <+146>:   call   0x8048590 <puts@plt>   # "***********************************"

# Get serial with scanf
0x0804891d <+164>:   mov    $0x8048a60,%eax       # "%d" format
0x08048922 <+169>:   lea    0x28(%esp),%edx       # buffer for serial
0x08048926 <+173>:   mov    %edx,0x4(%esp)
0x0804892a <+177>:   mov    %eax,(%esp)
0x0804892d <+180>:   call   0x80485e0 <__isoc99_scanf@plt>

# Call auth(login, serial)
0x08048932 <+185>:   mov    0x28(%esp),%eax       # serial input
0x08048936 <+189>:   mov    %eax,0x4(%esp)
0x0804893a <+193>:   lea    0x2c(%esp),%eax       # login buffer
0x0804893e <+197>:   mov    %eax,(%esp)
0x08048941 <+200>:   call   0x8048748 <auth>

# If auth returns 0, spawn shell
0x08048946 <+205>:   test   %eax,%eax
0x08048948 <+207>:   jne    0x8048969 <main+240>
0x0804894a <+209>:   movl   $0x8048b52,(%esp)     # "Authenticated!"
0x08048951 <+216>:   call   0x8048590 <puts@plt>
0x08048956 <+221>:   movl   $0x8048b61,(%esp)     # "/bin/sh"
0x0804895d <+228>:   call   0x80485a0 <system@plt> # SPAWN SHELL! 🎯
```
### 5. Disassembling auth - The Anti-Debugging
```bash
(gdb) disas auth
assembly
0x08048748 <+0>:     push   %ebp
0x08048749 <+1>:     mov    %esp,%ebp
0x0804874b <+3>:     sub    $0x28,%esp

# Remove newline from login
0x0804874e <+6>:     movl   $0x8048a63,0x4(%esp)  # "\n"
0x08048756 <+14>:    mov    0x8(%ebp),%eax        # login
0x08048759 <+17>:    mov    %eax,(%esp)
0x0804875c <+20>:    call   0x8048520 <strcspn@plt>
0x08048761 <+25>:    add    0x8(%ebp),%eax
0x08048764 <+28>:    movb   $0x0,(%eax)           # replace newline with null

# Check login length
0x08048767 <+31>:    movl   $0x20,0x4(%esp)       # max 32
0x0804876f <+39>:    mov    0x8(%ebp),%eax
0x08048772 <+42>:    mov    %eax,(%esp)
0x08048775 <+45>:    call   0x80485d0 <strnlen@plt>
0x0804877a <+50>:    mov    %eax,-0xc(%ebp)       # len

# If len <= 5, authentication fails
0x08048786 <+62>:    cmpl   $0x5,-0xc(%ebp)
0x0804878a <+66>:    jg     0x8048796 <auth+78>
0x0804878c <+68>:    mov    $0x1,%eax
0x08048791 <+73>:    jmp    0x8048877 <auth+303>

# ANTI-DEBUGGING: ptrace check
0x08048796 <+78>:    movl   $0x0,0xc(%esp)
0x0804879e <+86>:    movl   $0x1,0x8(%esp)
0x080487a6 <+94>:    movl   $0x0,0x4(%esp)
0x080487ae <+102>:   movl   $0x0,(%esp)
0x080487b5 <+109>:   call   0x80485f0 <ptrace@plt>
0x080487ba <+114>:   cmp    $0xffffffff,%eax
0x080487bd <+117>:   jne    0x80487ed <auth+165>

# If ptrace fails (being debugged), print error and exit
0x080487bf <+119>:   movl   $0x8048a68,(%esp)     # "No ptrace for you"
0x080487c6 <+126>:   call   0x8048590 <puts@plt>
0x080487cb <+131>:   movl   $0x8048a8c,(%esp)     # "Sorry, no shell for you"
0x080487d2 <+138>:   call   0x8048590 <puts@plt>
0x080487d7 <+143>:   movl   $0x8048ab0,(%esp)     # "Don't try to hack us!"
0x080487de <+150>:   call   0x8048590 <puts@plt>
0x080487e3 <+155>:   mov    $0x1,%eax
0x080487e8 <+160>:   jmp    0x8048877 <auth+303>
```
### 6. The Serial Generation Algorithm
After ptrace check, the algorithm computes the expected serial:

assembly
0x080487ed <+165>:   mov    0x8(%ebp),%eax        # login
0x080487f0 <+168>:   add    $0x3,%eax             # login[3] (4th character)
0x080487f3 <+171>:   movzbl (%eax),%eax
0x080487f6 <+174>:   movsbl %al,%eax
0x080487f9 <+177>:   xor    $0x1337,%eax
0x080487fe <+182>:   add    $0x5eeded,%eax
0x08048803 <+187>:   mov    %eax,-0x10(%ebp)      # initial value

# Loop over each character of login
0x0804880d <+197>:   jmp    0x804885b <auth+275>

0x0804880f <+199>:   mov    -0x14(%ebp),%eax
0x08048812 <+202>:   add    0x8(%ebp),%eax
0x08048815 <+205>:   movzbl (%eax),%eax
0x08048818 <+208>:   cmp    $0x1f,%al             # if char <= 31
0x0804881a <+210>:   jg     0x8048823 <auth+219>
0x0804881c <+212>:   mov    $0x1,%eax             # invalid char
0x08048821 <+217>:   jmp    0x8048877 <auth+303>

# Complex hashing: new = old + (char ^ old * something)
0x08048823 <+219>:   mov    -0x14(%ebp),%eax
0x08048826 <+222>:   add    0x8(%ebp),%eax
0x08048829 <+225>:   movzbl (%eax),%eax
0x0804882c <+228>:   movsbl %al,%eax
0x0804882f <+231>:   mov    %eax,%ecx
0x08048831 <+233>:   xor    -0x10(%ebp),%ecx
0x08048834 <+236>:   mov    $0x88233b2b,%edx
0x08048839 <+241>:   mov    %ecx,%eax
0x0804883b <+243>:   mul    %edx
0x0804883d <+245>:   mov    %ecx,%eax
0x0804883f <+247>:   sub    %edx,%eax
0x08048841 <+249>:   shr    %eax
0x08048843 <+251>:   add    %edx,%eax
0x08048845 <+253>:   shr    $0xa,%eax
0x08048848 <+256>:   imul   $0x539,%eax,%eax
0x0804884e <+262>:   mov    %ecx,%edx
0x08048850 <+264>:   sub    %eax,%edx
0x08048852 <+266>:   mov    %edx,%eax
0x08048854 <+268>:   add    %eax,-0x10(%ebp)
0x08048857 <+271>:   addl   $0x1,-0x14(%ebp)

# Loop for all characters
0x0804885b <+275>:   mov    -0x14(%ebp),%eax
0x0804885e <+278>:   cmp    -0xc(%ebp),%eax
0x08048861 <+281>:   jl     0x804880f <auth+199>

# Compare calculated serial with user input
0x08048863 <+283>:   mov    0xc(%ebp),%eax        # user input
0x08048866 <+286>:   cmp    -0x10(%ebp),%eax      # vs calculated
0x08048869 <+289>:   je     0x8048872 <auth+298>
0x0804886b <+291>:   mov    $0x1,%eax
0x08048870 <+296>:   jmp    0x8048877 <auth+303>

0x08048872 <+298>:   mov    $0x0,%eax             # SUCCESS!
Bypassing the Anti-Debugging
7. Using GDB to Bypass ptrace
Since the program uses ptrace() to detect debugging, we need to bypass it:

bash
(gdb) catch syscall ptrace
Catchpoint 1 (syscall 'ptrace' [26])

(gdb) commands 1
Type commands for breakpoint(s) 1, one per line.
End with a line saying just "end".
>set $eax=0
>continue
>end
This makes ptrace() always return 0 (success), bypassing the anti-debugging check.

8. Finding the Serial for "coucou"
Set a breakpoint at the comparison:

bash
(gdb) b *auth+286
Breakpoint 2 at 0x8048866

(gdb) run
Starting program: /home/users/level06/level06
***********************************
*		level06		  *
***********************************
-> Enter Login: coucou
***********************************
***** NEW ACCOUNT DETECTED ********
***********************************
-> Enter Serial: 1234

Catchpoint 1 (call to syscall ptrace), 0xf7fdb440 in __kernel_vsyscall ()
Catchpoint 1 (returned from syscall ptrace), 0xf7fdb440 in __kernel_vsyscall ()

Breakpoint 2, 0x08048866 in auth ()

(gdb) p $eax
$1 = 1234                   # Our input serial

(gdb) x/x $ebp-0x10
0xffffd5b8:     0x005f1ae1  # Calculated serial
The calculated serial is 0x005f1ae1 = 6232801 in decimal.

Exploitation
9. The Correct Credentials
For login "coucou", the valid serial is 6232801.

bash
level06@OverRide:~$ ./level06
***********************************
*		level06		  *
***********************************
-> Enter Login: coucou
***********************************
***** NEW ACCOUNT DETECTED ********
***********************************
-> Enter Serial: 6232801
Authenticated!
$ whoami
level07
$ cat /home/users/level07/.pass
GbcPDRgsFK77LNnnuh7QyFYA2942Gp1yKEfcYt7s
$ exit
10. Switch to level07
bash
level06@OverRide:~$ su level07
Password: GbcPDRgsFK77LNnnuh7QyFYA2942Gp1yKEfcYt7s
level07@OverRide:~$
Vulnerability Summary
Root Cause:
Complex authentication: The program uses a custom hashing algorithm

No vulnerability per se - we need to reverse the algorithm or extract the serial at runtime

Exploitation Technique:
Bypass ptrace: Used GDB's catch syscall to force ptrace to return 0

Extract serial: Set breakpoint at comparison to read the calculated value

Enter credentials: Used the extracted serial to authenticate

Shell obtained: system("/bin/sh") executed with level07 privileges

Key Learning Points:
Anti-debugging techniques can be bypassed with GDB

Custom hashing algorithms can be reversed or extracted at runtime

Breakpoints can be used to read intermediate values

ptrace is a common anti-debugging mechanism

Final Commands
bash
# Run the program normally
./level06

# Enter login
coucou

# Enter serial (from GDB extraction)
6232801
Password for level07: GbcPDRgsFK77LNnnuh7QyFYA2942Gp1yKEfcYt7s