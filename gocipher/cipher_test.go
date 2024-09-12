package gocipher

import (
    "testing"
)

func TestGenerateKey(t *testing.T) {
    gc := GoCipher{}
    key := gc.GenerateKey()
    if len(key) == 0 {
        t.Error("Expected key to be non-empty")
    }
}

func TestEncryptDecrypt(t *testing.T) {
    gc := GoCipher{}
    key := gc.GenerateKey()
    plaintext := "Hello, World!"
    encrypted := gc.Encrypt(plaintext, key)
    decrypted := gc.Decrypt(encrypted, key)
    if decrypted != plaintext {
        t.Errorf("Expected %s, but got %s", plaintext, decrypted)
    }
}

