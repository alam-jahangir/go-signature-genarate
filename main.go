package main

import (
	"Configuration"
	"Database"
	"Signature"
	"fmt"
	"log"
)

var DB Database.DbAdapter

type Employee struct {
	Id   int
	Name string
	City string
}

func init() {
	config := Configuration.LoadConfiguration("config.json")
	DB, err := Database.Connection(config)
	if err != nil {
		panic(err.Error())
	}

	selDB, err := DB.DbConn.Query("SELECT * FROM employee ORDER BY id DESC")
	if err != nil {
		panic(err.Error())
	}
	emp := Employee{}
	res := []Employee{}

	for selDB.Next() {
		var id int
		var name, city string
		err = selDB.Scan(&id, &name, &city)
		if err != nil {
			panic(err.Error())
		}
		emp.Id = id
		emp.Name = name
		emp.City = city
		res = append(res, emp)
	}
	fmt.Println(res)
	defer DB.DbConn.Close()
}

func main() {

	// Generate Signature By SHP with Passphrase
	ciphertext := Signature.Encrypt([]byte("Generate Signature By SHA and Passphrase"), Configuration.SIGNATURE_PASSPHRASE)
	fmt.Printf("Encrypted: %x\n", ciphertext)

	plaintext := Signature.Decrypt(ciphertext, Configuration.SIGNATURE_PASSPHRASE)
	fmt.Printf("Decrypted: %s\n", plaintext)

	Signature.EncryptFile("sample.txt", []byte("Hello World"), Configuration.SIGNATURE_PASSPHRASE)
	fmt.Println(string(Signature.DecryptFile("sample.txt", Configuration.SIGNATURE_PASSPHRASE)))

	// Generate Signature By SHP512 with IV
	key := []byte(Configuration.SIGNATURE_KEY) // 32 bytes
	plaintext_iv := []byte("Generate Signature By SHA AND IV")
	fmt.Printf("%s\n", plaintext)
	ciphertext_str, err := Signature.EncryptByIV(key, plaintext_iv)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Encrypted:", ciphertext_str)

	plaintext_str, err := Signature.DecryptByIV(key, ciphertext_str)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Decrypted:", plaintext_str)


	// Generate Token By User Information
	Signature.JwtKey = []byte(Configuration.JWT_SECRET_KEY)
	creds := Signature.Credentials{"Test", "jahangir", "jahangir033003@gmail.com"}
	token, err := Signature.GetToken(creds)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Token: ", token)

	credentials, err := Signature.ValidateToken(token)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Token Credentials: ", credentials)
	
	// Generate Key Pair By User Information
	var user = Signature.KeyPairUserInfo{
		UserName: "jahangir",
		UserEmail: "jahangir033003@gmail.com",
		UserIp: "192.168.2.13",
		UserAgent: "Mozilla Firefox",
	}
	keyPair, err := Signature.GenerateKeyPair(user)
	if err != nil {
		panic(err)
	}

	fmt.Println(keyPair)
        
	// Decode App Key and Get Email Address from App Key
	dkeyPair, err := Signature.GetEmailFromAppKey(keyPair.AppKey, keyPair.SecretKey)
	if err != nil {
		panic(err)
	}

	fmt.Println(dkeyPair)
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
