# GoCipher

`GoCipher` is a Go package that provides cryptographic functionalities including key generation, encryption, and decryption using AES-256-GCM, as well as key derivation using PBKDF2. This package is designed to be simple and secure, enabling developers to handle encryption tasks with ease.

## Features

- **Key Generation**: Generate a new random 32-byte key for AES-256 encryption.
- **Key Derivation**: Derive a cryptographic key from a user-provided password using PBKDF2.
- **Encryption**: Encrypt plaintext using AES-256-GCM with HMAC for integrity.
- **Decryption**: Decrypt AES-256-GCM encrypted data with HMAC validation.
- **Metadata Handling**: Encrypt and decrypt messages with additional metadata (version and timestamp).

## Installation

To use `GoCipher` in your Go project, you can install it using `go get`:

```bash
go get github.com/j3r1ch0123/gocipher
```

## Usage

Here's a basic example of how to use `GoCipher`:

```go
package main

import (
	"fmt"
	"github.com/j3r1ch0123/gocipher/gocipher"
)

func main() {
	gc := &gocipher.GoCipher{}

	// Generate a new key
	key := gc.GenerateKey()
	fmt.Println("Generated Key:", key)

	// Derive a key from a password
	derivedKey := gc.DeriveKey("password123")
	fmt.Println("Derived Key:", derivedKey)

	// Encrypt plaintext
	plaintext := "This is a secret message."
	encrypted := gc.Encrypt(plaintext, key)
	fmt.Println("Encrypted Message:", encrypted)

	// Decrypt the message
	decrypted := gc.Decrypt(encrypted, key)
	fmt.Println("Decrypted Message:", decrypted)

	// Encrypt with metadata
	encryptedWithMetadata := gc.EncryptWithMetadata(plaintext, key)
	fmt.Println("Encrypted with Metadata:", encryptedWithMetadata)

	// Decrypt with metadata
	decryptedWithMetadata := gc.DecryptWithMetadata(encryptedWithMetadata, key)
	fmt.Println("Decrypted with Metadata:", decryptedWithMetadata)
}
```

## Functions

### `GenerateKey() string`

Generates a new random 32-byte key for AES-256 encryption.

### `DeriveKey(password string) string`

Derives a cryptographic key from a user-provided password using PBKDF2.

### `Encrypt(plaintext string, key string) string`

Encrypts the given plaintext using AES-256-GCM with the specified key.

### `Decrypt(encodedMessage string, key string) string`

Decrypts the given encoded message using AES-256-GCM with the specified key.

### `EncryptWithMetadata(plaintext string, key string) string`

Encrypts the given plaintext with additional metadata (version and timestamp).

### `DecryptWithMetadata(encodedMessage string, key string) string`

Decrypts the given message with metadata (version and timestamp).

## Contributing

Contributions are welcome! If you'd like to contribute to `GoCipher`, please fork the repository and create a pull request. Ensure that your code adheres to the existing style and includes tests where applicable.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

Feel free to customize the content according to your needs or add any additional sections such as a changelog or FAQ.
