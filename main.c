#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sodium.h>

#ifdef _WIN32
    #include <conio.h>
    #include <windows.h>
#else
    #include <termios.h>
    #include <unistd.h>
#endif

#define MAX_LEN 256
#define MIN_MASTER_PASS_LEN 11
#define SALT_LEN crypto_pwhash_SALTBYTES
#define HASH_LEN crypto_pwhash_STRBYTES
#define KEY_LEN crypto_secretbox_KEYBYTES
#define NONCE_LEN crypto_secretbox_NONCEBYTES
#define MAC_LEN crypto_secretbox_MACBYTES

// Cross-platform getch implementation
#ifndef _WIN32
int getch() {
    struct termios oldt, newt;
    int ch;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    ch = getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return ch;
}
#endif

// Cross-platform clipboard copy function
void copy_to_clipboard(const char *text) {
    #ifdef _WIN32
        // Windows clipboard
        if (OpenClipboard(NULL)) {
            EmptyClipboard();
            HGLOBAL hClipboardData = GlobalAlloc(GMEM_DDESHARE, strlen(text) + 1);
            if (hClipboardData) {
                char *pchData = (char*)GlobalLock(hClipboardData);
                strcpy(pchData, text);
                GlobalUnlock(hClipboardData);
                SetClipboardData(CF_TEXT, hClipboardData);
            }
            CloseClipboard();
        }
    #elif __APPLE__
        // macOS clipboard
        char command[MAX_LEN * 2];
        snprintf(command, sizeof(command), "echo '%s' | pbcopy", text);
        system(command);
    #else
        // Linux clipboard (requires xclip)
        char command[MAX_LEN * 2];
        snprintf(command, sizeof(command), "echo '%s' | xclip -selection clipboard", text);
        system(command);
    #endif
}

// Secure memory clearing
void secure_wipe(void *ptr, size_t len) {
    sodium_memzero(ptr, len);
}

// Hide typed input with '*'
void get_hidden_password(char *password, size_t max_len) {
    int i = 0;
    char ch;
    while ((ch = getch()) != '\r' && ch != '\n' && i < max_len - 1) {
        if (ch == '\b' || ch == 127) { // Handle backspace
            if (i > 0) {
                printf("\b \b");
                i--;
            }
        } else if (ch >= 32 && ch <= 126) { // Printable characters
            password[i++] = ch;
            printf("*");
        }
    }
    password[i] = '\0';
    printf("\n");
}

// Convert binary data to hex string
void bin2hex(char *hex, const unsigned char *bin, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + (i * 2), "%02x", bin[i]);
    }
    hex[len * 2] = '\0';
}

// Convert hex string to binary data
void hex2bin(unsigned char *bin, const char *hex, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + (i * 2), "%2hhx", &bin[i]);
    }
}

// Derive encryption key from master password
int derive_key(unsigned char *key, const char *password, const unsigned char *salt) {
    if (crypto_pwhash(key, KEY_LEN, password, strlen(password), salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        return -1; // Out of memory
    }
    return 0;
}

// Hash master password for storage
int hash_master_password(char *hash_str, const char *password) {
    if (crypto_pwhash_str(hash_str, password, strlen(password),
                          crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        return -1; // Out of memory
    }
    return 0;
}

// Verify master password
int verify_master_password(const char *hash_str, const char *password) {
    return crypto_pwhash_str_verify(hash_str, password, strlen(password));
}

// Encrypt password data
int encrypt_password(unsigned char *ciphertext, const char *plaintext, const unsigned char *key) {
    unsigned char nonce[NONCE_LEN];
    randombytes_buf(nonce, sizeof(nonce));
    
    // Copy nonce to beginning of ciphertext
    memcpy(ciphertext, nonce, NONCE_LEN);
    
    // Encrypt after the nonce
    if (crypto_secretbox_easy(ciphertext + NONCE_LEN, (unsigned char*)plaintext, 
                              strlen(plaintext), nonce, key) != 0) {
        return -1;
    }
    
    return 0;
}

// Decrypt password data
int decrypt_password(char *plaintext, const unsigned char *ciphertext, size_t ciphertext_len, const unsigned char *key) {
    if (ciphertext_len < NONCE_LEN + MAC_LEN) {
        return -1; // Invalid ciphertext
    }
    
    unsigned char nonce[NONCE_LEN];
    memcpy(nonce, ciphertext, NONCE_LEN);
    
    if (crypto_secretbox_open_easy((unsigned char*)plaintext, ciphertext + NONCE_LEN, 
                                   ciphertext_len - NONCE_LEN, nonce, key) != 0) {
        return -1; // Decryption failed
    }
    
    return 0;
}

// Check if master password meets minimum requirements
int validate_master_password(const char *password) {
    int len = strlen(password);
    int has_upper = 0, has_special = 0;
    
    if (len < MIN_MASTER_PASS_LEN) {
        return 0;
    }
    
    for (int i = 0; i < len; i++) {
        if (isupper(password[i])) {
            has_upper = 1;
        }
        if (!isalnum(password[i])) {
            has_special = 1;
        }
    }
    
    return has_upper && has_special;
}

// Password strength checker
int check_password_strength(const char *password) {
    int len = strlen(password);
    int has_lower = 0, has_upper = 0, has_digit = 0, has_special = 0;
    
    if (len < 8) return 0; // Very weak
    
    for (int i = 0; i < len; i++) {
        if (islower(password[i])) has_lower = 1;
        if (isupper(password[i])) has_upper = 1;
        if (isdigit(password[i])) has_digit = 1;
        if (!isalnum(password[i])) has_special = 1;
    }
    
    int score = has_lower + has_upper + has_digit + has_special;
    
    if (len >= 12 && score >= 3) return 3; // Strong
    if (len >= 10 && score >= 2) return 2; // Medium
    if (len >= 8 && score >= 1) return 1;  // Weak
    return 0; // Very weak
}

void display_password_strength(int strength) {
    switch (strength) {
        case 0:
            printf("[!] Password Strength: Very Weak - Consider using a stronger password\n");
            break;
        case 1:
            printf("[*] Password Strength: Weak - Consider adding more character types\n");
            break;
        case 2:
            printf("[+] Password Strength: Medium - Good password\n");
            break;
        case 3:
            printf("[++] Password Strength: Strong - Excellent password\n");
            break;
    }
}

// Save user salt to file
void save_user_salt(const char *username, const unsigned char *salt) {
    FILE *file = fopen("user_salts.txt", "a");
    if (file) {
        char hex_salt[SALT_LEN * 2 + 1];
        bin2hex(hex_salt, salt, SALT_LEN);
        fprintf(file, "%s %s\n", username, hex_salt);
        fclose(file);
    }
}

// Load user salt from file
int load_user_salt(const char *username, unsigned char *salt) {
    FILE *file = fopen("user_salts.txt", "r");
    if (!file) return -1;
    
    char stored_user[MAX_LEN], hex_salt[SALT_LEN * 2 + 1];
    while (fscanf(file, "%s %s", stored_user, hex_salt) == 2) {
        if (strcmp(stored_user, username) == 0) {
            hex2bin(salt, hex_salt, SALT_LEN);
            fclose(file);
            return 0;
        }
    }
    fclose(file);
    return -1;
}

void register_user() {
    FILE *file = fopen("user_data.txt", "a+");
    if (!file) {
        printf("Error opening user file.\n");
        return;
    }

    char username[MAX_LEN], password[MAX_LEN];
    char existing_user[MAX_LEN], existing_hash[HASH_LEN];
    int exists = 0;

    printf("Enter a username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = '\0'; // Remove newline

    // Check if username already exists
    rewind(file);
    while (fscanf(file, "%s %s", existing_user, existing_hash) == 2) {
        if (strcmp(existing_user, username) == 0) {
            exists = 1;
            break;
        }
    }

    if (exists) {
        printf("[-] Username already exists. Please choose another.\n");
        fclose(file);
        return;
    }

    // Display security warning
    printf("\n*** SECURITY WARNING ***\n");
    printf("===============================================\n");
    printf("If you forget your master password, your entire password\n");
    printf("database will be permanently locked and inaccessible.\n");
    printf("There is NO way to recover or reset your master password.\n");
    printf("Please store your master password in a secure location.\n");
    printf("===============================================\n\n");

    printf("Master password requirements:\n");
    printf("* Minimum %d characters\n", MIN_MASTER_PASS_LEN);
    printf("* At least 1 uppercase letter\n");
    printf("* At least 1 special character\n\n");

    while (1) {
        printf("Enter a master password: ");
        get_hidden_password(password, sizeof(password));

        if (validate_master_password(password)) {
            break;
        } else {
            printf("[-] Master password does not meet requirements. Please try again.\n");
        }
    }

    // Generate and save salt for this user
    unsigned char salt[SALT_LEN];
    randombytes_buf(salt, sizeof(salt));
    save_user_salt(username, salt);

    // Hash the master password for storage
    char hash_str[HASH_LEN];
    if (hash_master_password(hash_str, password) != 0) {
        printf("[-] Error hashing password. Registration failed.\n");
        secure_wipe(password, sizeof(password));
        fclose(file);
        return;
    }

    // Store username and hashed password
    fprintf(file, "%s %s\n", username, hash_str);
    fclose(file);

    // Clear sensitive data
    secure_wipe(password, sizeof(password));
    secure_wipe(hash_str, sizeof(hash_str));
    secure_wipe(salt, sizeof(salt));

    printf("[+] Registration complete!\n");
}

int login_user(char *logged_user, unsigned char *master_key) {
    FILE *file = fopen("user_data.txt", "r");
    if (!file) {
        printf("[-] No users registered.\n");
        return 0;
    }

    char stored_user[MAX_LEN], stored_hash[HASH_LEN];
    char username[MAX_LEN], password[MAX_LEN];

    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = '\0'; // Remove newline

    printf("Enter master password: ");
    get_hidden_password(password, sizeof(password));

    // Find user and verify password
    int found = 0;
    while (fscanf(file, "%s %s", stored_user, stored_hash) == 2) {
        if (strcmp(username, stored_user) == 0) {
            if (verify_master_password(stored_hash, password) == 0) {
                found = 1;
                strcpy(logged_user, username);
                
                // Load the user's salt
                unsigned char salt[SALT_LEN];
                if (load_user_salt(username, salt) != 0) {
                    printf("[-] Error loading user salt.\n");
                    found = 0;
                    break;
                }
                
                // Derive encryption key from master password using stored salt
                if (derive_key(master_key, password, salt) != 0) {
                    printf("[-] Error deriving encryption key.\n");
                    found = 0;
                }
                
                secure_wipe(salt, sizeof(salt));
                break;
            }
        }
    }

    fclose(file);
    secure_wipe(password, sizeof(password));

    if (found) {
        printf("[+] Login successful.\n");
        return 1;
    } else {
        printf("[-] Invalid credentials.\n");
        return 0;
    }
}

void delete_user(const char *logged_user) {
    char confirm[MAX_LEN];
    printf("Are you sure you want to delete your account? Type 'YES' to confirm: ");
    fgets(confirm, sizeof(confirm), stdin);
    confirm[strcspn(confirm, "\n")] = '\0'; // Remove newline

    if (strcmp(confirm, "YES") != 0) {
        printf("[-] Account deletion cancelled.\n");
        return;
    }

    // Delete user from user_data.txt
    FILE *file = fopen("user_data.txt", "r");
    FILE *temp = fopen("temp_user.txt", "w");
    if (!file || !temp) {
        printf("Error opening user files.\n");
        return;
    }

    char user[MAX_LEN], hash[HASH_LEN];
    while (fscanf(file, "%s %s", user, hash) == 2) {
        if (strcmp(user, logged_user) != 0) {
            fprintf(temp, "%s %s\n", user, hash);
        }
    }
    fclose(file);
    fclose(temp);
    remove("user_data.txt");
    rename("temp_user.txt", "user_data.txt");

    // Delete user salt from user_salts.txt
    file = fopen("user_salts.txt", "r");
    if (file) {
        temp = fopen("temp_salts.txt", "w");
        if (temp) {
            char stored_user[MAX_LEN], hex_salt[SALT_LEN * 2 + 1];
            while (fscanf(file, "%s %s", stored_user, hex_salt) == 2) {
                if (strcmp(stored_user, logged_user) != 0) {
                    fprintf(temp, "%s %s\n", stored_user, hex_salt);
                }
            }
            fclose(temp);
            remove("user_salts.txt");
            rename("temp_salts.txt", "user_salts.txt");
        }
        fclose(file);
    }

    // Delete all this user's saved passwords
    file = fopen("passwords.txt", "r");
    if (file) {
        temp = fopen("temp_pass.txt", "w");
        if (temp) {
            char line[MAX_LEN * 4];
            while (fgets(line, sizeof(line), file)) {
                if (strncmp(line, logged_user, strlen(logged_user)) != 0 || 
                    line[strlen(logged_user)] != ' ') {
                    fputs(line, temp);
                }
            }
            fclose(temp);
            remove("passwords.txt");
            rename("temp_pass.txt", "passwords.txt");
        }
        fclose(file);
    }

    printf("[+] Account and all data deleted successfully.\n");
}

void save_password(const char *logged_user, const unsigned char *master_key) {
    char website[MAX_LEN], site_username[MAX_LEN], password[MAX_LEN];
    
    printf("Enter website: ");
    fgets(website, sizeof(website), stdin);
    website[strcspn(website, "\n")] = '\0'; // Remove newline

    // Check if website already exists
    FILE *check_file = fopen("passwords.txt", "r");
    if (check_file) {
        char line[MAX_LEN * 4];
        while (fgets(line, sizeof(line), check_file)) {
            char stored_user[MAX_LEN], stored_website[MAX_LEN];
            if (sscanf(line, "%s %s", stored_user, stored_website) == 2) {
                if (strcmp(stored_user, logged_user) == 0 && strcmp(stored_website, website) == 0) {
                    printf("[-] This website already exists in your saved passwords.\n");
                    fclose(check_file);
                    return;
                }
            }
        }
        fclose(check_file);
    }

    printf("Enter username (optional, or '-' if none): ");
    fgets(site_username, sizeof(site_username), stdin);
    site_username[strcspn(site_username, "\n")] = '\0'; // Remove newline

    printf("Enter password: ");
    get_hidden_password(password, sizeof(password));

    // Check password strength
    int strength = check_password_strength(password);
    display_password_strength(strength);

    // Encrypt the password
    unsigned char ciphertext[MAX_LEN + NONCE_LEN + MAC_LEN];
    if (encrypt_password(ciphertext, password, master_key) != 0) {
        printf("[-] Error encrypting password.\n");
        secure_wipe(password, sizeof(password));
        return;
    }

    // Convert to hex for storage
    char hex_ciphertext[sizeof(ciphertext) * 2 + 1];
    bin2hex(hex_ciphertext, ciphertext, strlen(password) + NONCE_LEN + MAC_LEN);

    // Save to file
    FILE *file = fopen("passwords.txt", "a");
    if (!file) {
        printf("Error opening password file.\n");
        secure_wipe(password, sizeof(password));
        return;
    }

    fprintf(file, "%s %s %s %s\n", logged_user, website, site_username, hex_ciphertext);
    fclose(file);

    // Clear sensitive data
    secure_wipe(password, sizeof(password));
    secure_wipe(ciphertext, sizeof(ciphertext));

    printf("[+] Password saved securely.\n");
}

void view_websites(const char *logged_user) {
    FILE *file = fopen("passwords.txt", "r");
    if (!file) {
        printf("[-] No saved passwords.\n");
        return;
    }

    char line[MAX_LEN * 4];
    printf("Saved websites:\n");
    int found = 0;
    
    while (fgets(line, sizeof(line), file)) {
        char user[MAX_LEN], website[MAX_LEN], username[MAX_LEN];
        if (sscanf(line, "%s %s %s", user, website, username) >= 3) {
            if (strcmp(user, logged_user) == 0) {
                printf("- %s (user: %s)\n", website, strcmp(username, "-") == 0 ? "N/A" : username);
                found = 1;
            }
        }
    }

    if (!found) {
        printf("[-] No saved passwords found.\n");
    }

    fclose(file);
}

void get_password(const char *logged_user, const unsigned char *master_key) {
    FILE *file = fopen("passwords.txt", "r");
    if (!file) {
        printf("[-] No saved passwords.\n");
        return;
    }

    char target[MAX_LEN];
    printf("Enter website to retrieve password: ");
    fgets(target, sizeof(target), stdin);
    target[strcspn(target, "\n")] = '\0'; // Remove newline

    char line[MAX_LEN * 4];
    int found = 0;

    while (fgets(line, sizeof(line), file)) {
        char user[MAX_LEN], website[MAX_LEN], username[MAX_LEN], hex_ciphertext[MAX_LEN * 2];
        if (sscanf(line, "%s %s %s %s", user, website, username, hex_ciphertext) == 4) {
            if (strcmp(user, logged_user) == 0 && strcmp(website, target) == 0) {
                // Convert hex to binary
                size_t ciphertext_len = strlen(hex_ciphertext) / 2;
                unsigned char ciphertext[MAX_LEN + NONCE_LEN + MAC_LEN];
                hex2bin(ciphertext, hex_ciphertext, ciphertext_len);
                
                // Decrypt password
                char plaintext[MAX_LEN];
                if (decrypt_password(plaintext, ciphertext, ciphertext_len, master_key) == 0) {
                    printf("[+] Username: %s\n", strcmp(username, "-") == 0 ? "N/A" : username);
                    printf("[+] Password for %s: %s\n", website, plaintext);
                    
                    // Copy password to clipboard
                    copy_to_clipboard(plaintext);
                    printf("[*] Password copied to clipboard!\n");
                    
                    // Clear sensitive data
                    secure_wipe(plaintext, sizeof(plaintext));
                    found = 1;
                } else {
                    printf("[-] Error decrypting password. Data may be corrupted.\n");
                }
                break;
            }
        }
    }

    if (!found) {
        printf("[-] Website not found.\n");
    }

    fclose(file);
}

void update_password(const char *logged_user, const unsigned char *master_key) {
    char target[MAX_LEN], new_pass[MAX_LEN];
    printf("Enter website to update: ");
    fgets(target, sizeof(target), stdin);
    target[strcspn(target, "\n")] = '\0'; // Remove newline

    FILE *file = fopen("passwords.txt", "r");
    FILE *temp = fopen("temp.txt", "w");

    if (!file || !temp) {
        printf("Error opening file.\n");
        return;
    }

    char line[MAX_LEN * 4];
    int found = 0;

    while (fgets(line, sizeof(line), file)) {
        char user[MAX_LEN], website[MAX_LEN], username[MAX_LEN], hex_ciphertext[MAX_LEN * 2];
        if (sscanf(line, "%s %s %s %s", user, website, username, hex_ciphertext) == 4) {
            if (strcmp(user, logged_user) == 0 && strcmp(website, target) == 0) {
                printf("Enter new password: ");
                get_hidden_password(new_pass, sizeof(new_pass));
                
                // Check password strength
                int strength = check_password_strength(new_pass);
                display_password_strength(strength);
                
                // Encrypt new password
                unsigned char ciphertext[MAX_LEN + NONCE_LEN + MAC_LEN];
                if (encrypt_password(ciphertext, new_pass, master_key) == 0) {
                    char new_hex_ciphertext[sizeof(ciphertext) * 2 + 1];
                    bin2hex(new_hex_ciphertext, ciphertext, strlen(new_pass) + NONCE_LEN + MAC_LEN);
                    fprintf(temp, "%s %s %s %s\n", user, website, username, new_hex_ciphertext);
                    found = 1;
                } else {
                    printf("[-] Error encrypting new password.\n");
                    fputs(line, temp);
                }
                
                secure_wipe(new_pass, sizeof(new_pass));
                secure_wipe(ciphertext, sizeof(ciphertext));
            } else {
                fputs(line, temp);
            }
        } else {
            fputs(line, temp);
        }
    }

    fclose(file);
    fclose(temp);
    remove("passwords.txt");
    rename("temp.txt", "passwords.txt");

    if (found)
        printf("[+] Password updated securely.\n");
    else
        printf("[-] Website not found.\n");
}

void delete_website(const char *logged_user) {
    char target[MAX_LEN];
    printf("Enter website to delete: ");
    fgets(target, sizeof(target), stdin);
    target[strcspn(target, "\n")] = '\0'; // Remove newline

    FILE *file = fopen("passwords.txt", "r");
    FILE *temp = fopen("temp.txt", "w");

    if (!file || !temp) {
        printf("Error opening file.\n");
        return;
    }

    char line[MAX_LEN * 4];
    int found = 0;

    while (fgets(line, sizeof(line), file)) {
        char user[MAX_LEN], website[MAX_LEN];
        if (sscanf(line, "%s %s", user, website) >= 2) {
            if (strcmp(user, logged_user) == 0 && strcmp(website, target) == 0) {
                found = 1;
                continue;
            }
        }
        fputs(line, temp);
    }

    fclose(file);
    fclose(temp);
    remove("passwords.txt");
    rename("temp.txt", "passwords.txt");

    if (found)
        printf("[+] Website deleted.\n");
    else
        printf("[-] Website not found.\n");
}

int main() {
    // Initialize libsodium
    if (sodium_init() < 0) {
        printf("[-] Failed to initialize libsodium.\n");
        return 1;
    }

    int choice;
    char logged_user[MAX_LEN];
    unsigned char master_key[KEY_LEN];

    while (1) {
        printf("\n*** Welcome to VaultCLI ***\n");
        printf("1. Register\n2. Login\n3. Exit\nEnter choice: ");
        scanf("%d", &choice);
        getchar(); // Consume newline

        if (choice == 1) {
            register_user();
        } else if (choice == 2) {
            if (login_user(logged_user, master_key)) {
                int opt;
                while (1) {
                    printf("\n1. Save Password\n2. View Saved Websites\n3. Get Password\n4. Update Password\n5. Delete Website\n6. Delete Account\n7. Logout\nChoose: ");
                    scanf("%d", &opt);
                    getchar(); // Consume newline

                    if (opt == 1)
                        save_password(logged_user, master_key);
                    else if (opt == 2)
                        view_websites(logged_user);
                    else if (opt == 3)
                        get_password(logged_user, master_key);
                    else if (opt == 4)
                        update_password(logged_user, master_key);
                    else if (opt == 5)
                        delete_website(logged_user);
                    else if (opt == 6) {
                        delete_user(logged_user);
                        secure_wipe(master_key, sizeof(master_key));
                        break;
                    }
                    else if (opt == 7) {
                        secure_wipe(master_key, sizeof(master_key));
                        break;
                    }
                    else
                        printf("Invalid option.\n");
                }
            }
        } else if (choice == 3) {
            printf("Exiting program. Goodbye!\n");
            break;
        } else {
            printf("Invalid choice.\n");
        }
    }

    return 0;
}