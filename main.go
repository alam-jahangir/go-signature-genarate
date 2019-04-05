package main

import (
 "Signature"
 "fmt"
 "log"
)

func main() {

 // Generate Signature By SHP without IV
 fmt.Println("Starting the application...")
 ciphertext := Signature.Encrypt([]byte("Hello World"), "password")
 fmt.Printf("Encrypted: %x\n", ciphertext)
 plaintext := Signature.Decrypt(ciphertext, "password")
 fmt.Printf("Decrypted: %s\n", plaintext)
 Signature.EncryptFile("sample.txt", []byte("Hello World"), "password1")
 fmt.Println(string(Signature.DecryptFile("sample.txt", "password1")))


 // Generate Signature By SHP512 with IV
 key := []byte("sc7/KcdHz~K]=UeURC3&8@RdEZf`=``K") // 32 bytes
 plaintext1 := []byte(":G+7'ap}Dr&-3*BRAgR]Jz%/s=+cqGT_hXfDz!") //"some really really really long plaintext")
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

 // Generate Token By User Information
 creds := Signature.Credentials{"Test", "jahangir", "jahangir033003@gmail.com"}
 token := Signature.GetToken(creds)
 fmt.Println(token)

 creds1 := Signature.ValidateToken(token)

 fmt.Println(creds1)
}

/*
func main() {
 Redis.Add("jahangir033003@gmail.com")
 var PORT string
 if PORT = os.Getenv("PORT"); PORT == "" {
  PORT = "3001"
 }

 http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
  fmt.Fprintf(w, "PORT :%s\n, Hello World from path: %s\n", PORT, r.URL.Path)
 })

 http.ListenAndServe(":" + PORT, nil)
}*/
