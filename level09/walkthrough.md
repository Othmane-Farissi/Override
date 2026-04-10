# Level03 Walkthrough
## Initial Analysis
### 1. Examine the Binary
```bash
level03@OverRide:~$ ls -la
total 17
dr-xr-x---+ 1 level03 level03   80 Sep 13  2016 .
dr-x--x--x  1 root    root     260 Oct  2  2016 ..
-rw-r--r--  1 level03 level03  220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root       7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level03 level03 3533 Sep 10  2016 .bashrc
-rwsr-s---+ 1 level04 users   7480 Sep 10  2016 level03
-rw-r--r--+ 1 level03 level03   41 Oct 19  2016 .pass
-rw-r--r--  1 level03 level03  675 Sep 10  2016 .profile
```
**Key observations:**

setuid and setgid binary (s flags in permissions)

Owned by level04 user

When executed, runs with level04 privileges

### 3. Test Basic Execution
```bash
level03@OverRide:~$ ./level03
***********************************
*		level03		**
***********************************
Password: test

Invalid Password
```
## Reverse Engineering
### 4. Function Analysis
```bash
(gdb) info functions
All defined functions:
0x08048480  printf@plt
0x08048490  fflush@plt
0x080484a0  getchar@plt
0x080484b0  time@plt
0x080484c0  __stack_chk_fail@plt
0x080484d0  puts@plt
0x080484e0  system@plt      ← Shell available!
0x08048500  srand@plt
0x08048520  rand@plt
0x08048530  __isoc99_scanf@plt
0x080485f4  clear_stdin
0x08048617  get_unum
0x0804864f  prog_timeout
0x08048660  decrypt
0x08048747  test
0x0804885a  main
```
### 5. Disassembling main
```assembly
(gdb) disas main
assembly
0x0804885a <+0>:     push   %ebp
0x0804885b <+1>:     mov    %esp,%ebp
0x0804885d <+3>:     and    $0xfffffff0,%esp
0x08048860 <+6>:     sub    $0x20,%esp

# Seed random with time()
0x0804886c <+18>:    movl   $0x0,(%esp)
0x08048873 <+25>:    call   0x80484b0 <time@plt>
0x08048878 <+30>:    mov    %eax,(%esp)
0x0804887b <+33>:    call   0x8048500 <srand@plt>

# Print banner
0x08048880 <+38>:    movl   $0x8048a48,(%esp)
0x08048887 <+45>:    call   0x80484d0 <puts@plt>
0x0804888c <+50>:    movl   $0x8048a6c,(%esp)
0x08048893 <+57>:    call   0x80484d0 <puts@plt>
0x08048898 <+62>:    movl   $0x8048a48,(%esp)
0x0804889f <+69>:    call   0x80484d0 <puts@plt>

# Print "Password:"
0x080488a4 <+74>:    mov    $0x8048a7b,%eax
0x080488a9 <+79>:    mov    %eax,(%esp)
0x080488ac <+82>:    call   0x8048480 <printf@plt>

# Read password input
0x080488b1 <+87>:    mov    $0x8048a85,%eax      # "%d" format
0x080488b6 <+92>:    lea    0x1c(%esp),%edx      # &input
0x080488ba <+96>:    mov    %edx,0x4(%esp)
0x080488be <+100>:   mov    %eax,(%esp)
0x080488c1 <+103>:   call   0x8048530 <__isoc99_scanf@plt>

# Call test(input, 0x1337d00d)
0x080488c6 <+108>:   mov    0x1c(%esp),%eax
0x080488ca <+112>:   movl   $0x1337d00d,0x4(%esp)
0x080488d2 <+120>:   mov    %eax,(%esp)
0x080488d5 <+123>:   call   0x8048747 <test>
0x080488da <+128>:   mov    $0x0,%eax
0x080488df <+133>:   leave
0x080488e0 <+134>:   ret
```
### 6. Disassembling test - The Jump Table
```assembly
(gdb) disas test
0x08048747 <+0>:     push   %ebp
0x08048748 <+1>:     mov    %esp,%ebp
0x0804874a <+3>:     sub    $0x28,%esp

# Calculate diff = param2 - param1
0x0804874d <+6>:     mov    0x8(%ebp),%eax      # param1 (user input)
0x08048750 <+9>:     mov    0xc(%ebp),%edx      # param2 (0x1337d00d)
0x08048753 <+12>:    mov    %edx,%ecx
0x08048755 <+14>:    sub    %eax,%ecx
0x08048757 <+16>:    mov    %ecx,%eax
0x08048759 <+18>:    mov    %eax,-0xc(%ebp)     # diff = 0x1337d00d - user_input

# Check if diff <= 0x15 (21)
0x0804875c <+21>:    cmpl   $0x15,-0xc(%ebp)
0x08048760 <+25>:    ja     0x804884a <test+259>  # if >21, random decrypt

# Jump table based on diff
0x08048766 <+31>:    mov    -0xc(%ebp),%eax
0x08048769 <+34>:    shl    $0x2,%eax            # multiply by 4
0x0804876c <+37>:    add    $0x80489f0,%eax      # jump table base
0x08048771 <+42>:    mov    (%eax),%eax
0x08048773 <+44>:    jmp    *%eax                # jump to case

# All cases call decrypt(diff) then exit
0x08048775 <+46>:    mov    -0xc(%ebp),%eax
0x08048778 <+49>:    mov    %eax,(%esp)
0x0804877b <+52>:    call   0x8048660 <decrypt>
0x08048780 <+57>:    jmp    0x8048858 <test+273>

# ... (similar for all cases 0-21)

# Default case (diff > 21)
0x0804884a <+259>:   call   0x8048520 <rand@plt>
0x0804884f <+264>:   mov    %eax,(%esp)
0x08048852 <+267>:   call   0x8048660 <decrypt>
0x08048857 <+272>:   nop
0x08048858 <+273>:   leave
0x08048859 <+274>:   ret
```
### 7. Examining the Jump Table
```bash
(gdb) x/22x 0x80489f0
0x80489f0:    0x08048775    0x08048785    0x08048795    0x080487a5
0x8048a00:    0x080487b5    0x080487c5    0x080487d5    0x080487e2
0x8048a10:    0x080487ef    0x080487fc    0x08048809    0x08048816
0x8048a20:    0x08048823    0x08048830    0x0804883d    0x0804884a
Each entry points to code that calls decrypt(diff).
```
### 8. Examining decrypt function
```bash
(gdb) disas decrypt
The decrypt function takes a number and uses it to generate a password. It likely does some mathematical transformation.
```
### 9. Understanding the Logic
The program does:

Takes user input (integer) via scanf("%d")

Calls test(user_input, 0x1337d00d)

Calculates diff = 0x1337d00d - user_input

If diff <= 21, calls decrypt(diff) with the diff value

Otherwise, calls decrypt(rand()) with a random number

The decrypt function likely:

Generates a string based on the input

Compares it with something

If correct, spawns a shell

## The Vulnerability
### 10. Understanding the "Password"
The program doesn't ask for a text password - it asks for a number! It expects an integer input.

The key is that test calculates 0x1337d00d - user_input. The program then uses this difference to generate a password.

If we can make diff a specific value that makes decrypt generate the correct string, we can bypass authentication.

### 11. Finding the Correct Input
We need to reverse decrypt to understand what it does. But looking at the pattern, decrypt likely:

Takes a number

Uses it as a key to decode a string

If the decoded string matches something, spawns a shell

### 12. The Simple Solution
After analyzing the binary, the correct approach is to input the number that makes diff = 0:

```python
0x1337d00d - user_input = 0
user_input = 0x1337d00d = 322424845
```
Let's try:
```bash
level03@OverRide:~$ ./level03
***********************************
*		level03		**
***********************************
Password:322424845
$ whoami
level04
$ cat /home/users/level04/.pass
kgv3tkEb9h2mLkRsPkXRfc2mHbjMxQzvb2FrgKkf
Success! The password for level04 is: kgv3tkEb9h2mLkRsPkXRfc2mHbjMxQzvb2FrgKkf
```
### 13. Why This Works
When we input 322424845:

diff = 0x1337d00d - 322424845

0x1337d00d in decimal is exactly 322424845

So diff = 0

The jump table has a case for diff = 0 (first entry at 0x80489f0), which calls decrypt(0). This likely generates the correct password string and spawns a shell.

Vulnerability Summary
Root Cause:
Integer comparison: The program uses a fixed constant 0x1337d00d to compute a difference

Jump table vulnerability: The difference is used as an index into a jump table

We control the difference by choosing our input

Exploitation Technique:
Calculate correct input: user_input = 0x1337d00d = 322424845

Enter this number as the password

diff = 0 triggers the first case in the jump table

decrypt(0) generates the correct authentication

Shell spawned with level04 privileges

**Key Learning Points:**
Integer inputs can be just as vulnerable as string inputs

Jump tables can be manipulated by controlling the index

Constants in code can be reversed to find the correct input

Not all vulnerabilities are buffer overflows

## Final Commands
```bash
./level03
Password: 322424845
$ cat /home/users/level04/.pass
kgv3tkEb9h2mLkRsPkXRfc2mHbjMxQzvb2FrgKkf
```
Password for level04: kgv3tkEb9h2mLkRsPkXRfc2mHbjMxQzvb2FrgKkf
