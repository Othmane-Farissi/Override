#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void decrypt(int key);
int test(int input, int constant);

int main(void) {
    int user_input;
    
    srand(time(NULL));
    
    puts("***********************************");
    puts("*\t\tlevel03\t\t**");
    puts("***********************************");
    printf("Password:");
    
    scanf("%d", &user_input);
    test(user_input, 0x1337d00d);
    
    return 0;
}

int test(int user_input, int constant) {
    int diff = constant - user_input;
    
    if (diff <= 21) {
        // Jump table - calls decrypt(diff)
        decrypt(diff);
    } else {
        // Random fallback
        decrypt(rand());
    }
    return 0;
}

void decrypt(int key) {
    // Encrypted string (16 bytes + null)
    unsigned char encrypted[] = {
        0x51, 0x7d, 0x7c, 0x75,  // "Q}|u"
        0x60, 0x73, 0x66, 0x67,  // "`sfg"
        0x7e, 0x73, 0x66, 0x7b,  // "~sf{"
        0x7d, 0x7c, 0x61, 0x33,  // "}|a3"
        0x00                      // null terminator
    };
    
    unsigned char *decrypted = encrypted;
    int len = strlen((char *)encrypted);
    
    // XOR decryption
    for (int i = 0; i < len; i++) {
        decrypted[i] = encrypted[i] ^ key;
    }
    
    // Check if decrypted string matches "Congratulations!"
    if (strcmp((char *)decrypted, "Congratulations!") == 0) {
        system("/bin/sh");
    } else {
        puts("Invalid Password");
    }
}