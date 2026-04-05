int main() {
    int password;
    
    puts("***********************************");
    puts("*            -Level00 -           *");
    puts("***********************************");
    printf("Password:");
    scanf("%d", &password);
    
    if (password == 0x149c) {  // 5276 in decimal
        puts("Authenticated!");
        system("/bin/sh");
        return 0;
    } else {
        puts("Invalid Password!");
        return 1;
    }
}