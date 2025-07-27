// this is for lazy peoples to store password locally with ZipCrypto Encryption !!
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_LEN 200

void storePasswords();
void dumpPasswords();
void readPasswords();

int main() {
    int ask;

    printf("Welcome to Password Manager!!\n");
    printf("What do you want to do?\n");
    printf("Cases:\n");
    printf("1) Store Password.\n");
    printf("2) Dump all stored passwords.\n");
    printf("3) Read all stored passwords.\n");
    printf("4) Exit.\n");
    printf("Enter the Case number (e.g., 1): ");

    scanf("%d", &ask);
    getchar();  // consume newline

    switch (ask) {
        case 1:
            storePasswords();
            break;
        case 2:
            dumpPasswords();
            break;
        case 3:
            readPasswords();
            break;
        case 4:
            printf("Exiting...\n");
            exit(0);
        default:
            printf("Invalid option!\n");
    }

    return 0;
}

void storePasswords() {
    char platform[100];
    char password[100];
    int save;

    printf("How many creds do you want to save? ");
    scanf("%d", &save);
    getchar();  // consume newline

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

    // Encrypt the file
    printf("Encrypting manager.txt with zip -e (you'll be prompted for a password)...\n");
    int zipResult = system("zip -e manager.zip manager.txt");
    if (zipResult != 0) {
        fprintf(stderr, "Error: Failed to zip manager.txt\n");
        return;
    }

    // Delete original file
    int rmResult = system("rm manager.txt");
    if (rmResult != 0) {
        fprintf(stderr, "Warning: Failed to delete manager.txt\n");
    } else {
        printf("Original file deleted for security.\n");
    }
}

void dumpPasswords() {
    // Unzip first (requires password)
    printf("Unzipping manager.zip to manager.txt (you'll be prompted for a password)...\n");
    if (system("unzip -o manager.zip") != 0) {
        fprintf(stderr, "Error: Failed to unzip manager.zip\n");
        return;
    }

    FILE *file = fopen("manager.txt", "r");
    if (!file) {
        perror("Error opening manager.txt");
        return;
    }

    printf("\nDumping all stored passwords (raw file contents):\n\n");

    char ch;
    while ((ch = fgetc(file)) != EOF) {
        putchar(ch);
    }

    fclose(file);
    system("rm manager.txt");
}

void readPasswords() {
    // Unzip first (requires password)
    printf("Unzipping manager.zip to manager.txt (you'll be prompted for a password)...\n");
    if (system("unzip -o manager.zip") != 0) {
        fprintf(stderr, "Error: Failed to unzip manager.zip\n");
        return;
    }

    FILE *file = fopen("manager.txt", "r");
    if (!file) {
        perror("Error opening manager.txt");
        return;
    }

    char line[MAX_LEN];
    printf("\nStored Passwords:\n\n");
    while (fgets(line, sizeof(line), file)) {
        char *colon = strchr(line, ':');
        if (colon != NULL) {
            *colon = '\0';
            char *platform = line;
            char *password = colon + 1;
            password[strcspn(password, "\n")] = 0;

            printf("Platform: %-15s | Password: %s\n", platform, password);
        }
    }

    fclose(file);

    system("rm manager.txt");
}

