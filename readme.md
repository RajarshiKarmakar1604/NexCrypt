# NexCrypt 🔐
### ⚠️ WARNING: Not Production Ready ⚠️

> **NexCrypt is under active development and is NOT ready for public or production use.**  
> Security has not been audited, and bugs may be present.  
> **Use entirely at your own risk.**


A secure, cross-platform command-line password manager built with C and libsodium cryptography.

## ✨ Planned Features

- 👥 **Multi-user support** - Multiple users can have separate encrypted password vaults
- 🔒 **Strong encryption** - Uses libsodium's authenticated encryption (XSalsa20 + Poly1305)
- 🔑 **Secure key derivation** - Argon2 password hashing with unique salts per user
- 🌐 **Cross-platform** - Works on Windows, macOS, and Linux
- 📊 **Password strength analysis** - Evaluates and displays password security levels
- 📋 **Clipboard integration** - Automatically copies retrieved passwords to clipboard
- 🛡️ **Secure memory handling** - Sensitive data is securely wiped from memory
- 👁️‍🗨️ **Hidden password input** - Passwords are masked during entry with asterisks

## 🔐 Security Features

- 🚫 **No password recovery** - If you forget your master password, your data is permanently inaccessible
- 🧂 **Per-user salt generation** - Each user has a unique cryptographic salt
- ✅ **Authenticated encryption** - Data integrity is verified during decryption
- 🎲 **Secure random number generation** - Uses cryptographically secure randomness
- 🧹 **Memory protection** - Sensitive data is cleared from memory after use

## 📋 Requirements

### Dependencies
- **libsodium** - Cryptographic library 🔐
- **Standard C library** - For basic operations

### Platform-specific requirements
- **Linux**: `xclip` package for clipboard functionality 📋
- **Windows**: Native clipboard support 🪟
- **macOS**: Native clipboard support via `pbcopy` 🍎

## 🛠️ Installation

### Installing libsodium

#### Ubuntu/Debian 🐧
```bash
sudo apt-get install libsodium-dev
```

#### CentOS/RHEL/Fedora 🔴
```bash
# CentOS/RHEL
sudo yum install libsodium-devel
# Fedora
sudo dnf install libsodium-devel
```

#### macOS 🍎
```bash
# Using Homebrew
brew install libsodium
# Using MacPorts
sudo port install libsodium
```

#### Windows 🪟
Download precompiled binaries from the [libsodium releases page](https://github.com/jedisct1/libsodium/releases) or build from source.

### Installing clipboard support (Linux only) 📋
```bash
sudo apt-get install xclip  # Ubuntu/Debian
sudo yum install xclip      # CentOS/RHEL
sudo dnf install xclip      # Fedora
```

## ⚙️ Compilation

### Linux/macOS 🐧🍎
Make sure libsodium is installed (`sudo apt install libsodium-dev` or `brew install libsodium`), then:
```bash
gcc -o NexCrypt NexCrypt.c -lsodium
```

### Windows (MinGW) 🪟
```bash
gcc main.c -IC:\Libsodium\libsodium-win32\include -LC:\Libsodium\libsodium-win32\lib -lsodium -o NexCrypt.exe
```
📝 Ensure libsodium.dll is either in the same directory as NexCrypt.exe or added to your system PATH.

## 🚀 Usage

### First Time Setup

1. **Run the program** 🏃‍♂️
   ```bash
   ./NexCrypt
   ```

2. **Register a new user** 📝
   - Choose option 1 (Register)
   - Enter a unique username
   - Create a master password meeting these requirements:
     - Minimum 11 characters
     - At least 1 uppercase letter
     - At least 1 special character

⚠️ **CRITICAL**: Store your master password securely. There is no password recovery option.

### Managing Passwords 🔑

After logging in, you can:

1. **Save Password** 💾 - Store a new website/service password
2. **View Saved Websites** 👀 - List all your saved entries
3. **Get Password** 🔍 - Retrieve and copy a password to clipboard
4. **Update Password** 🔄 - Change an existing password
5. **Delete Website** 🗑️ - Remove a saved entry
6. **Delete Account** ❌ - Permanently delete your account and all data
7. **Logout** 🚪 - Exit to main menu

### Password Strength Indicators 💪

The program evaluates password strength and displays:
- **Very Weak** 🔴 - Less than 8 characters
- **Weak** 🟡 - Basic requirements met
- **Medium** 🟠 - Good balance of length and complexity
- **Strong** 🟢 - Excellent security (12+ chars, multiple character types)

## 📁 File Structure

The program creates these files on first use:
- `user_data.txt` - Stores usernames and hashed master passwords
- `user_salts.txt` - Stores cryptographic salts for each user
- `passwords.txt` - Stores encrypted password entries

## 🔒 Security Considerations

### What's Protected ✅
- All stored passwords are encrypted with your master password
- Master passwords are hashed using Argon2 (not stored in plain text)
- Each user has a unique salt for key derivation
- Memory is securely wiped after use

### What's Not Protected ⚠️
- Usernames are stored in plain text
- Website names are stored in plain text
- The program doesn't protect against keyloggers or memory dumps by other processes

### Best Practices 🌟
- Use a strong, unique master password
- Run the program on a secure, trusted system
- Regularly backup your vault files
- Keep your libsodium library updated

## 🌐 Cross-Platform Notes

### Windows 🪟
- Uses native Windows clipboard API
- Password input uses `conio.h` functions

### macOS 🍎
- Uses `pbcopy` for clipboard functionality
- Standard Unix terminal handling

### Linux 🐧
- Requires `xclip` for clipboard support
- Uses termios for secure password input

## 🔧 Troubleshooting

### Common Issues

**"Failed to initialize libsodium"** ❌
- Ensure libsodium is properly installed
- Check that the library is in your system's library path

**"No users registered" on first run** ℹ️
- This is normal - register a new user first

**Clipboard not working on Linux** 📋
- Install xclip: `sudo apt-get install xclip`
- Ensure you're running in a graphical environment

**Permission errors** 🚫
- Ensure you have write permissions in the program directory
- The program creates files in the current working directory

## 🤝 Contributing

This is a simple educational password manager. For production use, consider established solutions like:
- Bitwarden 🔐
- KeePass 🔑
- 1Password 🛡️
- LastPass 📋

## 📄 License
This project is licensed under the MIT License, but is not production-grade software. See LICENSE for details.

## ⚠️ Disclaimer

This software is provided without warranty. The authors are not responsible for any data loss or security breaches. Always maintain backups of important data and use established, audited password managers for critical applications.