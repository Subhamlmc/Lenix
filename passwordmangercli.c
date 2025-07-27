// this is for lazy peoples to store password locally with ZipCrypto Encryption !!
#include <stdlib.h>
#include <stdio.h>

int main() {
    const char *filename = "password.txt";
    const char *zipname = "password.zip";

void storePasswords() {
    char platform[100];
    char password[100];
    int save;

    printf("How many creds do you want to save? ");
    scanf("%d", &save);
    getchar(); 

    FILE *file = fopen("manager.txt", "a");
    if (!file) {
        perror("Error opening file");
        return;
    }

    for (int i = 0; i < save; i++) {
        printf("Enter the name of Platform (e.g., Facebook, YouTube, Gmail): ");
        fgets(platform, sizeof(platform), stdin);
        platform[strcspn(platform, "\n")] = 0;

        printf("Enter the password of the media: ");
        fgets(password, sizeof(password), stdin);
        password[strcspn(password, "\n")] = 0;

        fprintf(file, "%s:%s\n", platform, password);
    }

    fclose(file);
    printf("Passwords saved to manager.txt\n");

    // Step 2: Encrypt using zip -e
    printf("Encrypting manager.txt to manager.zip...\n");
    int zipResult = system("zip -e manager.zip manager.txt");  // prompts for password
    if (zipResult != 0) {
        fprintf(stderr, "Error: Failed to encrypt manager.txt\n");
        return;
    }

    // Step 3: Remove original file
    int rmResult = system("rm manager.txt");
    if (rmResult != 0) {
        fprintf(stderr, "Warning: manager.txt not deleted\n");
    } else {
        printf("Original file manager.txt deleted.\n");
    }
}
