package main
/*
function generateKey():
    key = random(32)  // AES-256 requires 32 bytes
    return base64_encode(key)  // Make it safe for storage/transmission

function deriveKey(user_provided_password):
    // Use a Key Derivation Function (KDF) like PBKDF2 to derive a key from a password
    salt = random(16)
    key = pbkdf2(user_provided_password, salt, iterations=100000, key_size=32)
    return base64_encode(key)
function encrypt(plaintext, key):
    // Ensure key is 32 bytes (AES-256)
    key = base64_decode(key)

    // Step 1: Generate a random nonce (IV)
    nonce = random(12)  // 12 bytes is typical for GCM

    // Step 2: Initialize AES-GCM mode with the key and nonce
    cipher = aes.NewCipher(key)  // Create the cipher
    gcm = cipher.NewGCM(cipher)  // Create GCM mode
    
    // Step 3: Encrypt the plaintext and append the nonce
    ciphertext = gcm.Seal(nonce, nonce, plaintext, nil)  // Encrypt
    
    // Step 4: Generate an HMAC for integrity
    hmac_value = hmac_sha256(ciphertext, key)
    
    // Step 5: Combine all parts: nonce + ciphertext + HMAC
    message = nonce + ciphertext + hmac_value

    // Step 6: Base64 encode for transmission/storage
    return base64_encode(message)
function decrypt(encoded_message, key):
    // Decode base64 message
    message = base64_decode(encoded_message)

    // Step 1: Split the message into parts: nonce, ciphertext, and HMAC
    nonce = message[:12]  // First 12 bytes are the nonce
    ciphertext = message[12:-32]  // Everything except the last 32 bytes (HMAC)
    received_hmac = message[-32:]  // Last 32 bytes are the HMAC
    
    // Step 2: Verify HMAC for integrity
    expected_hmac = hmac_sha256(ciphertext, key)
    if received_hmac != expected_hmac:
        return "Error: HMAC validation failed!"
    
    // Step 3: Decrypt the ciphertext
    cipher = aes.NewCipher(key)
    gcm = cipher.NewGCM(cipher)
    plaintext = gcm.Open(nonce, ciphertext)
    
    return plaintext
function hmac_sha256(data, key):
    hmac = new_hmac(sha256, key)
    hmac.update(data)
    return hmac.finalize()
function base64_encode(data):
    return base64.standard_encode(data)

function base64_decode(data):
    return base64.standard_decode(data)
function encrypt_with_metadata(plaintext, key):
    version = "01"  // Version of the encryption format
    timestamp = current_timestamp()  // Unix timestamp
    encrypted_message = encrypt(plaintext, key)

    // Add version and timestamp metadata
    final_message = version + timestamp + encrypted_message
    return final_message

function decrypt_with_metadata(encoded_message, key):
    version = encoded_message[:2]
    timestamp = encoded_message[2:12]
    encrypted_message = encoded_message[12:]
    
    // Proceed with decryption
    return decrypt(encrypted_message, key)

*/
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

type GoCipher struct{}

// GenerateKey generates a new random 32-byte key for AES-256.
func (gc *GoCipher) GenerateKey() string {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(key)
}

// DeriveKey derives a key from a password using PBKDF2.
func (gc *GoCipher) DeriveKey(password string) string {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		log.Fatal(err)
	}
	key := pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)
	return base64.StdEncoding.EncodeToString(key)
}

// Encrypt encrypts plaintext using AES-256-GCM.
func (gc *GoCipher) Encrypt(plaintext string, key string) string {
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		log.Fatal(err)
	}
	nonce := make([]byte, 12)
	_, err = rand.Read(nonce)
	if err != nil {
		log.Fatal(err)
	}

	cipherBlock, err := aes.NewCipher(keyBytes)
	if err != nil {
		log.Fatal(err)
	}
	gcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		log.Fatal(err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	hmacValue := hmacSHA256(ciphertext, keyBytes)
	message := append(nonce, append(ciphertext, hmacValue...)...)

	return base64.StdEncoding.EncodeToString(message)
}

// Decrypt decrypts an encoded message using AES-256-GCM.
func (gc *GoCipher) Decrypt(encodedMessage string, key string) string {
	message, err := base64.StdEncoding.DecodeString(encodedMessage)
	if err != nil {
		log.Fatal(err)
	}

	nonce := message[:12]
	ciphertext := message[12 : len(message)-32]
	receivedHMAC := message[len(message)-32:]

	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		log.Fatal(err)
	}
	expectedHMAC := hmacSHA256(ciphertext, keyBytes)
	if !hmac.Equal(receivedHMAC, expectedHMAC) {
		return "Error: HMAC validation failed!"
	}

	cipherBlock, err := aes.NewCipher(keyBytes)
	if err != nil {
		log.Fatal(err)
	}
	gcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		log.Fatal(err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Fatal(err)
	}

	return string(plaintext)
}

// hmacSHA256 computes the HMAC-SHA256 of data using key.
func hmacSHA256(data, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// EncryptWithMetadata encrypts with metadata (version and timestamp).
func (gc *GoCipher) EncryptWithMetadata(plaintext string, key string) string {
	version := "01"
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	encryptedMessage := gc.Encrypt(plaintext, key)
	finalMessage := version + timestamp + encryptedMessage
	return finalMessage
}

// DecryptWithMetadata decrypts a message with metadata.
func (gc *GoCipher) DecryptWithMetadata(encodedMessage string, key string) string {
	version := encodedMessage[:2]
	timestamp := encodedMessage[2:12]
	encryptedMessage := encodedMessage[12:]
	return gc.Decrypt(encryptedMessage, key)
}
