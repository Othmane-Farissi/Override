# Override - Level00 Walkthrough
## Initial Analysis
### 1. Connect to the VM
**Examine the Binary**
```bash
level00@OverRide:~$ ls -la
total 13
dr-xr-x---+ 1 level01 level01   60 Sep 13  2016 .
dr-x--x--x  1 root    root     260 Oct  2  2016 ..
-rw-r--r--  1 level01 level01  220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root       7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level00 level00 3533 Sep 10  2016 .bashrc
-rwsr-s---+ 1 level01 users   7280 Sep 10  2016 level00
-rw-r--r--  1 level01 level01  675 Sep 10  2016 .profile
```
**Key observations:**

setuid and setgid binary (s flags in permissions)

Owned by level01 user

When executed, runs with level01 privileges

**Check Binary Security**
## Test Basic Execution
```bash
level00@OverRide:~$ ./level00
***********************************
*            -Level00 -           *
***********************************
Password:test

***********************************
*            -Level00 -           *
***********************************
Password:12345

Invalid Password!
```
**Observations:**

Program displays a banner and asks for a password

Any input results in "Invalid Password!"

Must find the correct password

## Reverse Engineering
### 2. Function Analysis
```bash
level00@OverRide:~$ gdb level00
(gdb) info functions
All defined functions:
0x08048380  printf@plt
0x08048390  puts@plt
0x080483a0  system@plt
0x080483d0  __isoc99_scanf@plt
0x08048494  main
Only main() function - simple program.
```
### 3. Disassembling main
```bash
(gdb) disas main
assembly
0x08048494 <+0>:     push   %ebp
0x08048495 <+1>:     mov    %esp,%ebp
0x08048497 <+3>:     and    $0xfffffff0,%esp
0x0804849a <+6>:     sub    $0x20,%esp

# Print banner (3 lines)
0x0804849d <+9>:     movl   $0x80485f0,(%esp)
0x080484a4 <+16>:    call   0x8048390 <puts@plt>
0x080484a9 <+21>:    movl   $0x8048614,(%esp)
0x080484b0 <+28>:    call   0x8048390 <puts@plt>
0x080484b5 <+33>:    movl   $0x80485f0,(%esp)
0x080484bc <+40>:    call   0x8048390 <puts@plt>

# Print "Password:" prompt
0x080484c1 <+45>:    mov    $0x804862c,%eax
0x080484c6 <+50>:    mov    %eax,(%esp)
0x080484c9 <+53>:    call   0x8048380 <printf@plt>

# Read input with scanf
0x080484ce <+58>:    mov    $0x8048636,%eax      # "%d" format string
0x080484d3 <+63>:    lea    0x1c(%esp),%edx      # &password (esp+28)
0x080484d7 <+67>:    mov    %edx,0x4(%esp)       # 2nd arg: address to store
0x080484db <+71>:    mov    %eax,(%esp)          # 1st arg: "%d"
0x080484de <+74>:    call   0x80483d0 <__isoc99_scanf@plt>

# Compare input with 0x149c
0x080484e3 <+79>:    mov    0x1c(%esp),%eax      # Load password value
0x080484e7 <+83>:    cmp    $0x149c,%eax         # Compare with 5276 decimal
0x080484ec <+88>:    jne    0x804850d <main+121> # Jump if not equal

# If equal, print success and spawn shell
0x080484ee <+90>:    movl   $0x8048639,(%esp)    # "Authenticated!"
0x080484f5 <+97>:    call   0x8048390 <puts@plt>
0x080484fa <+102>:   movl   $0x8048649,(%esp)    # "/bin/sh"
0x08048501 <+109>:   call   0x80483a0 <system@plt>  # SPAWN SHELL! 🎯
0x08048506 <+114>:   mov    $0x0,%eax
0x0804850b <+119>:   jmp    0x804851e <main+138>

# If not equal, print error
0x0804850d <+121>:   movl   $0x8048651,(%esp)    # "Invalid Password!"
0x08048514 <+128>:   call   0x8048390 <puts@plt>
0x08048519 <+133>:   mov    $0x1,%eax
0x0804851e <+138>:   leave
0x0804851f <+139>:   ret

```
### 4. Examining the Strings
```bash
(gdb) x/s 0x80485f0
0x80485f0:      "***********************************"

(gdb) x/s 0x8048614
0x8048614:      "*            -Level00 -           *"

(gdb) x/s 0x804862c
0x804862c:      "Password:"

(gdb) x/s 0x8048636
0x8048636:      "%d"

(gdb) x/s 0x8048639
0x8048639:      "Authenticated!"

(gdb) x/s 0x8048649
0x8048649:      "/bin/sh"

(gdb) x/s 0x8048651
0x8048651:      "Invalid Password!"
```

## The Vulnerability
### 5.Simple Password Check
This is a straightforward integer comparison:

The program reads an integer with scanf("%d")

It compares it with 0x149c (5276 decimal)

If they match, it spawns a shell

### 6. Convert Hex to Decimal
```bash
level00@OverRide:~$ python -c 'print(0x149c)'
5276
```
## Exploitation
### 7. The Solution
Simply enter the correct password:

```bash
level00@OverRide:~$ ./level00
***********************************
*            -Level00 -           *
***********************************
Password:5276
Authenticated!
$ whoami
level01
$ cat /home/users/level01/.pass
uSq2rEGtUcL8F7bQfN1kL3nK7l9wXyZ5
$ exit
12. Switch to level01
bash
level00@OverRide:~$ su level01
Password: uSq2rEGtUcL8F7bQfN1kL3nK7l9wXyZ5
level01@OverRide:~$
```