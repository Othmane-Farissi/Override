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

### 2. Test Basic Execution
```bash
level03@OverRide:~$ ./level03
***********************************
*		level03		**
***********************************
Password: test

Invalid Password
```
## Reverse Engineering
### 3. Function Analysis
```bash
level03@OverRide:~$ gdb level03
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
4. Disassembling main
```bash
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

# Read integer input
0x080488b1 <+87>:    mov    $0x8048a85,%eax      # "%d"
0x080488b6 <+92>:    lea    0x1c(%esp),%edx
0x080488ba <+96>:    mov    %edx,0x4(%esp)
0x080488be <+100>:   mov    %eax,(%esp)
0x080488c1 <+103>:   call   0x8048530 <__isoc99_scanf@plt>

# Call test(user_input, 0x1337d00d)
0x080488c6 <+108>:   mov    0x1c(%esp),%eax
0x080488ca <+112>:   movl   $0x1337d00d,0x4(%esp)
0x080488d2 <+120>:   mov    %eax,(%esp)
0x080488d5 <+123>:   call   0x8048747 <test>
0x080488da <+128>:   mov    $0x0,%eax
0x080488df <+133>:   leave
0x080488e0 <+134>:   ret
```
### 5. Disassembling test
```bash
(gdb) disas test
assembly
0x08048747 <+0>:     push   %ebp
0x08048748 <+1>:     mov    %esp,%ebp
0x0804874a <+3>:     sub    $0x28,%esp

# Calculate diff = 0x1337d00d - user_input
0x0804874d <+6>:     mov    0x8(%ebp),%eax
0x08048750 <+9>:     mov    0xc(%ebp),%edx
0x08048753 <+12>:    mov    %edx,%ecx
0x08048755 <+14>:    sub    %eax,%ecx
0x08048757 <+16>:    mov    %ecx,%eax
0x08048759 <+18>:    mov    %eax,-0xc(%ebp)

# Check if diff <= 21
0x0804875c <+21>:    cmpl   $0x15,-0xc(%ebp)
0x08048760 <+25>:    ja     0x804884a <test+259>   # if >21, use random

# Jump table for diff 0-21
0x08048766 <+31>:    mov    -0xc(%ebp),%eax
0x08048769 <+34>:    shl    $0x2,%eax            # multiply by 4
0x0804876c <+37>:    add    $0x80489f0,%eax      # jump table base
0x08048771 <+42>:    mov    (%eax),%eax
0x08048773 <+44>:    jmp    *%eax                # jump to case

# All cases call decrypt(diff)
0x08048775 <+46>:    mov    -0xc(%ebp),%eax
0x08048778 <+49>:    mov    %eax,(%esp)
0x0804877b <+52>:    call   0x8048660 <decrypt>
0x08048780 <+57>:    jmp    0x8048858 <test+273>

# ... (similar for diff=1 to 21)

# Default case (diff > 21)
0x0804884a <+259>:   call   0x8048520 <rand@plt>
0x0804884f <+264>:   mov    %eax,(%esp)
0x08048852 <+267>:   call   0x8048660 <decrypt>
0x08048857 <+272>:   nop
0x08048858 <+273>:   leave
0x08048859 <+274>:   ret
```
### 6. Disassembling decrypt - The Core Logic
```bash
(gdb) disas decrypt
assembly
0x08048660 <+0>:     push   %ebp
0x08048661 <+1>:     mov    %esp,%ebp
0x08048663 <+3>:     push   %edi
0x08048664 <+4>:     push   %esi
0x08048665 <+5>:     sub    $0x40,%esp

# Stack canary
0x08048668 <+8>:     mov    %gs:0x14,%eax
0x0804866e <+14>:    mov    %eax,-0xc(%ebp)
0x08048671 <+17>:    xor    %eax,%eax

# Encrypted string (16 bytes)
0x08048673 <+19>:    movl   $0x757c7d51,-0x1d(%ebp)
0x0804867a <+26>:    movl   $0x67667360,-0x19(%ebp)
0x08048681 <+33>:    movl   $0x7b66737e,-0x15(%ebp)
0x08048688 <+40>:    movl   $0x33617c7d,-0x11(%ebp)
0x0804868f <+47>:    movb   $0x0,-0xd(%ebp)

# XOR decryption loop
0x080486c7 <+103>:   lea    -0x1d(%ebp),%eax
0x080486ca <+106>:   add    -0x28(%ebp),%eax
0x080486cd <+109>:   movzbl (%eax),%eax
0x080486d0 <+112>:   mov    %eax,%edx
0x080486d2 <+114>:   mov    0x8(%ebp),%eax      # diff argument
0x080486d5 <+117>:   xor    %edx,%eax           # XOR with diff
0x080486d7 <+119>:   mov    %eax,%edx
0x080486d9 <+121>:   lea    -0x1d(%ebp),%eax
0x080486dc <+124>:   add    -0x28(%ebp),%eax
0x080486df <+127>:   mov    %dl,(%eax)          # store decrypted byte

# Compare with "Congratulations!"
0x080486ed <+141>:   lea    -0x1d(%ebp),%eax
0x080486f0 <+144>:   mov    %eax,%edx
0x080486f2 <+146>:   mov    $0x80489c3,%eax
0x080486f7 <+151>:   mov    $0x11,%ecx          # 17 bytes
0x080486fc <+156>:   repz cmpsb                 # compare strings

# If match, spawn shell
0x08048713 <+179>:   jne    0x8048723 <decrypt+195>
0x08048715 <+181>:   movl   $0x80489d4,(%esp)   # "/bin/sh"
0x0804871c <+188>:   call   0x80484e0 <system@plt>  # SHELL! 🎯

# If not match, print "Invalid Password"
0x08048723 <+195>:   movl   $0x80489dc,(%esp)
0x0804872a <+202>:   call   0x80484d0 <puts@plt>
```
### 7. Examining the Strings
```bash
(gdb) x/s 0x80489c3
0x80489c3:      "Congratulations!"

(gdb) x/s 0x80489d4
0x80489d4:      "/bin/sh"

(gdb) x/s 0x80489dc
0x80489dc:      "Invalid Password"
```
## The Encryption Analysis
### 8. Extracting the Encrypted Bytes
The encrypted string is stored as 4 DWORDs in little-endian format:

```assembly
0x757c7d51 = [0x51, 0x7d, 0x7c, 0x75]
0x67667360 = [0x60, 0x73, 0x66, 0x67]
0x7b66737e = [0x7e, 0x73, 0x66, 0x7b]
0x33617c7d = [0x7d, 0x7c, 0x61, 0x33]
So the full encrypted bytes (16 bytes) are:
```
```text
0x51, 0x7d, 0x7c, 0x75, 0x60, 0x73, 0x66, 0x67,
0x7e, 0x73, 0x66, 0x7b, 0x7d, 0x7c, 0x61, 0x33
```
### 9. The Decryption Process
Each byte is XORed with the diff value:

```text
decrypted_byte = encrypted_byte XOR diff
After XOR, the result must equal the string "Congratulations!".
```
### 10. Finding the Correct Diff
Let's calculate diff using the first byte:

Encrypted first byte: 0x51

Target first byte: 'C' = 0x43

diff = 0x51 XOR 0x43 = 0x12 (18 decimal)

Verify with second byte:

Encrypted: 0x7d

Target: 'o' = 0x6f

0x7d XOR 0x6f = 0x12 (18)

All bytes will yield the same XOR result because it's consistent. Therefore:

```text
diff = 18
```
### 11. Calculating the User Input
From the test function:

```text
diff = 0x1337d00d - user_input
Therefore:

user_input = 0x1337d00d - diff
user_input = 322424845 - 18
user_input = 322424827
```
## Exploitation
### 12. The Solution
```bash
level03@OverRide:~$ ./level03
***********************************
*		level03		**
***********************************
Password:322424827
$ whoami
level04
$ cat /home/users/level04/.pass
kgv3tkEb9h2mLkRsPkXRc2mZ02gnQ4Y5x6Hm7e7b
$ exit
13. Switch to level04
bash
level03@OverRide:~$ su level04
Password: kgv3tkEb9h2mLkRsPkXRc2mZ02gnQ4Y5x6Hm7e7b
level04@OverRide:~$
```
## Vulnerability Summary
**Root Cause:**
Custom encryption: The program encrypts the string "Congratulations!" with XOR

Fixed constant: Uses 0x1337d00d to calculate the XOR key

User-controlled input: We can choose the value that makes the decryption produce the correct string

Exploitation Technique:
Extract encrypted string from the binary

Identify target string "Congratulations!"

Calculate XOR key: diff = encrypted[0] XOR target[0] = 18

Reverse the test function: user_input = 0x1337d00d - diff = 322424827

Enter the number to trigger successful decryption

Shell obtained with level04 privileges

**Key Learning Points:**
XOR encryption is reversible if you know either the plaintext or the key

Jump tables can be used for efficient switch statements

Static analysis of encrypted strings can reveal the correct input

Not all vulnerabilities require buffer overflows - logic flaws work too

## Security Mitigations (present):
Protection	Purpose	Status
Stack canary	Detect overflow	✓ Enabled
NX	Non-executable stack	✗ Disabled
ASLR	Randomize addresses	✗ Disabled
**Final Commands**
```bash
./level03
Password: 322424827
Password for level04: kgv3tkEb9h2mLkRsPkXRc2mZ02gnQ4Y5x6Hm7e7b
```
