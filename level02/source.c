int main() {
    char file_password[41];   // at rbp-0xa0
    char username[100];       // at rbp-0x70
    char user_password[100];  // at rbp-0x110
    FILE *file;
    int bytes_read;
    
    // Read password from file
    file = fopen("/home/users/level03/.pass", "r");
    if (!file) error();
    
    bytes_read = fread(file_password, 1, 41, file);
    if (bytes_read != 41) error();
    
    fclose(file);
    
    // Display banner
    puts("===== [ Secure Access System v1.0 ] =====");
    puts("/***************************************\\");
    puts("| You must login to access this system. |");
    puts("\\***************************************/");
    
    // Get username
    printf("--[ Username: ");
    fgets(username, 100, stdin);
    username[strcspn(username, "\n")] = 0;
    
    // Get password
    printf("--[ Password: ");
    fgets(user_password, 100, stdin);
    user_password[strcspn(user_password, "\n")] = 0;
    
    puts("*****************************************");
    
    // Compare passwords
    if (strncmp(file_password, user_password, 41) == 0) {
        printf("Greetings, %s!\n", username);
        system("/bin/sh");  // Shell!
    } else {
        printf("%s does not have access!\n", username);
        exit(1);
    }
}