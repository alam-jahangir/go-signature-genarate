# Generate Signature by SHA256/SHA512 and JWT Token
Generate Signature by Different Algrorithm

## Generate Signature By SHA with Passphrase
```GO

 fmt.Println("Generate Signature By SHA by Passphrase ...")
 ciphertext := Signature.Encrypt([]byte("Hello World"), "UeURC3&8@")
 fmt.Printf("Encrypted: %x\n", ciphertext)
 plaintext := Signature.Decrypt(ciphertext, "UeURC3&8@")
 fmt.Printf("Decrypted: %s\n", plaintext)
 Signature.EncryptFile("sample.txt", []byte("Hello World"), "UeURC3&8@1")
 fmt.Println(string(Signature.DecryptFile("sample.txt", "UeURC3&8@1")))

```

## Generate Signature By SHA512 with IV
```GO

 key := []byte("sc7/KcdHz~K]=UeURC3&8@RdEZf`=``K") // 32 bytes
 plaintext1 := []byte(":G+7'ap}Dr&-3*BRAgR]Jz%/s=+cqGT_hXfDz!")
 fmt.Printf("%s\n", plaintext1)
 ciphertext1, err := Signature.EncryptByIV(key, plaintext1)
 if err != nil {
  log.Fatal(err)
 }
 fmt.Printf("%0x\n", ciphertext1)
 result, err := Signature.DecryptByIV(key, ciphertext1)
 if err != nil {
  log.Fatal(err)
 }
 fmt.Printf("%s\n", result)
```

## Generate Token By User Information
```GO
 creds := Signature.Credentials{"Test", "jahangir", "jahangir033003@gmail.com"}
 token := Signature.GetToken(creds)
 fmt.Println(token)

 creds1 := Signature.ValidateToken(token)

 fmt.Println(creds1)

```
