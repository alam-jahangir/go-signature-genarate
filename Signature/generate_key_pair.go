package Signature

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	random "math/rand"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	EMAIL_HASH_SEPARTOR            = "$$$"
	BLOCK_LENGTH_SEPARTOR          = "#"
	EMAIL_HASH_SEPARTOR_TRUNCATION = 1
	KEY_PAIR_BLOCK_SIZE            = 5
	SECURITY_SALT                  = "sc7/KcdHz~K]=UeURC3&8@RdEZf`=``K"
)

var blockLength int

type KeyPair struct {
	AppKey    string
	SecretKey string
	UserEmail string
	Status    bool // true means Encode false means Decode
}

type KeyPairUserInfo struct {
	UserName  string
	UserEmail string
	UserIp    string
	UserAgent string
}

/**
 * Get Unix Time to String
 * @return string
 */
func getUnixTime() string {
	return strconv.Itoa(int(time.Now().Unix()))
}

/**
 * Get Random Number
 * @param int min
 * @param int max
 * @return int
 */
func randomInt(min, max int) int {
	// Seeding with the same value results in the same random sequence each run.
	// For different numbers, seed with a different value, such as
	// time.Now().UnixNano(), which yields a constantly-changing number. Otherwise use a fixed numer Like random.Seed(42)
	random.Seed(time.Now().UnixNano())
	return min + random.Intn(max-min)
}

/*
 * Get Random  Number String
 * @param int len
 * @return string
 */
func randomNumberString(len int) string {
	a := make([]string, len)
	for i := 0; i <= len-1; i++ {
		a[i] = strconv.Itoa(randomInt(1, 10))
	}
	return strings.Join(a, "")
}

/**
 * Get Prefix Int Value by Regular Expression
 * Block variable only need to get Block Length otherwise skip to blank string
 * @param string data
 * @param string block
 * @return int
 * @return error
 */
func getPrefixIntFromString(data string, block string) (int, error) {
	re := regexp.MustCompile(`\d+`)
	matchData := re.FindAllString(data, -1)
	if len(matchData) > 0 {
		intVal, err := strconv.Atoi(matchData[0])
		if block == "app" {
			blockLength, _ = strconv.Atoi(matchData[1])
		}
		return intVal, err
	}
	return 0, nil
}

/**
 * Get Generated Secret Key
 * @param KeyPairUserInfo user
 * @return string
 */
func generateSecretKey(user KeyPairUserInfo) string {

	message := user.UserEmail + ":" + SECURITY_SALT + ":" + getUnixTime()
	//fmt.Println(time.Now().Unix(), " ", keyData)
	//time.Now().Format(time.RFC3339)
	h := hmac.New(sha256.New, []byte(SECURITY_SALT))
	h.Write([]byte(message))

	// Get result and encode as hexadecimal string
	sha := hex.EncodeToString(h.Sum(nil))

	//fmt.Println("Result: " + sha)
	return sha
}

/**
 * Get Generate App Key
 */
func generateAppKey(secretKey string, user KeyPairUserInfo) string {

	message := user.UserName + ":" + user.UserIp + ":" + user.UserAgent + ":" + getUnixTime()
	h := hmac.New(sha256.New, []byte(secretKey))
	h.Write([]byte(message))
	appKey := hex.EncodeToString(h.Sum(nil))

	return appKey
}

/**
 * Encrypt Email Address by Auto Generate IV
 * @param byte text
 * @return byte
 * @return error
 */
func encryptEmail(text []byte) ([]byte, error) {

	block, err := aes.NewCipher([]byte(SECURITY_SALT))
	if err != nil {
		return nil, err
	}

	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

/**
 * Decrypt Email Address by Auto Generate IV
 * @param byte text
 * @return byte
 * @return error
 */
func decryptEmail(text []byte) ([]byte, error) {

	block, err := aes.NewCipher([]byte(SECURITY_SALT))
	if err != nil {
		return nil, err
	}

	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)

	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}

	return data, nil
}

/**
 * Get Email Encryption and Decryption Data
 * @param string userEmailData
 * @param string action
 * @return string
 * @return error
 */
func getEmailDataByAction(userEmailData string, action string) (string, error) {

	output := ""
	if action == "e" {
		plaintext := []byte(userEmailData)
		ciphertext, err := encryptEmail(plaintext)
		if err != nil {
			return output, err
		}
		output = hex.EncodeToString(ciphertext)
	} else if action == "d" {
		ciphertext, _ := hex.DecodeString(userEmailData)
		plaintext, err := decryptEmail(ciphertext);
		if err != nil {
			return output, err
		}
		output = string(plaintext)
	}

	return output, nil

}

/**
 * Get Block Data Length from App Key
 * @param string appKey
 * @param string block
 * @return string
 * @return string
 * @return int
 * @return error
 */
func getBlockLength(appKey string, block string, hashSeparator string) (string, string, int, error) {

	prefixData := ""
	separatorLen := len(hashSeparator)
	prefix := appKey[0:separatorLen]
	if prefix != hashSeparator {
		return appKey, prefixData, 0, errors.New("Invalid key format")
	}
	var calculateBlockLength int

	appKey = appKey[separatorLen:len(appKey)]
	if block == "app" {

		length, err := getPrefixIntFromString(appKey, block)
		if err != nil {
			return appKey, prefixData, length, err
		}
		lengthStr := strconv.Itoa(length) + BLOCK_LENGTH_SEPARTOR + strconv.Itoa(blockLength)
		if strings.HasPrefix(appKey, lengthStr) { // or strings.Index("Australia", "Aus") == 0
			appKey = appKey[len(lengthStr):len(appKey)]
		}

		calculateBlockLength = length

	} else if block == "email" {

		separatorPosition := strings.Index(appKey, "$")
		prefixData = appKey[0:separatorPosition]
		i := 0
		for prefixData[i] == '*' {
			i += 1
		}

		if i > 0 {
			length, err := strconv.Atoi(prefixData[i : i*2])
			if err != nil {
				return appKey, prefixData, length, err
			}
			prefixData = prefixData[i*2 : len(prefixData)]
			calculateBlockLength = length
		} else {
			length, err := getPrefixIntFromString(prefixData, "")
			if err != nil {
				return appKey, prefixData, length, err
			}
			lengthStr := strconv.Itoa(length)
			if strings.HasPrefix(appKey, lengthStr) {
				prefixData = prefixData[len(lengthStr):len(prefixData)]
			}
			calculateBlockLength = length
		}

		if len(prefixData) >= blockLength {
			prefixData = ""
		}

		appKey = appKey[separatorPosition+1 : len(appKey)]

	}

	return appKey, prefixData, calculateBlockLength, nil
}

/**
 * Decode App Key
 * @param string appKey
 * @return string
 * @return string
 * @return error
 */
func getDecodeAppKey(appKey string) (string, string, error) {

	if blockLength <= 0 {
		return appKey, "", nil
	}

	appKey, prefixData, appKeyBlockLength, err := getBlockLength(appKey, "app", EMAIL_HASH_SEPARTOR)
	if err != nil {
		return appKey, "", err
	}

	appKey, prefixData, emailBlockLen, err := getBlockLength(appKey, "email", EMAIL_HASH_SEPARTOR[:len(EMAIL_HASH_SEPARTOR)-EMAIL_HASH_SEPARTOR_TRUNCATION])
	if err != nil {
		return appKey, "", err
	}
	//fmt.Println("appKey: ", appKey, "emailBlockLen: ", emailBlockLen, "prefixData: ", prefixData)

	emailHash := make(map[int]string)
	generatedAppKey := appKey;
	startIndex := 0
	for i := 0; i <= blockLength-1; i++ {
		startIndex = i*emailBlockLen + i*appKeyBlockLength
		emailHash[i+1] = appKey[startIndex : startIndex+emailBlockLen]
		generatedAppKey = strings.Replace(generatedAppKey, emailHash[i+1], "", -1)
	}

	emailHashString := ""
	for i := 0; i <= blockLength-1; i++ {
		emailHashString = emailHashString + emailHash[i+1]
	}

	decodeEmailHash := emailHashString + prefixData

	return generatedAppKey, decodeEmailHash, nil
}

/**
 * Generate Prefix and Return App Key Block Length
 * @param string prefix
 * @param string appKey
 * @param int emailHashBlockSize
 * @return string
 * @return int
 * @return error
 */
func generatePrefix(prefix string, appKey string, emailHashBlockSize int) (string, int, error) {

	if len(prefix) == 0 {
		prefix = randomNumberString(blockLength)
	}

	appKeyDataSize := int(len(appKey) / blockLength)
	emailHashBlock := ""

	prefixNumericVal, err := getPrefixIntFromString(prefix, "")
	if err != nil {
		return prefix, appKeyDataSize, err
	}
	isPrefixNumeric := true
	lengthStr := strconv.Itoa(prefixNumericVal)
	if !strings.HasPrefix(prefix, lengthStr) {
		isPrefixNumeric = false
	}

	//fmt.Println("emailHashBlockSize: ", emailHashBlockSize)
	if isPrefixNumeric {
		prefixLen := len(strconv.Itoa(emailHashBlockSize))
		for i := 1; i <= prefixLen; i++ {
			emailHashBlock = "*" + emailHashBlock
		}
	}
	emailHashBlock = emailHashBlock + strconv.Itoa(emailHashBlockSize)
	// Prefix Last Part
	prefix = EMAIL_HASH_SEPARTOR[:len(EMAIL_HASH_SEPARTOR)-EMAIL_HASH_SEPARTOR_TRUNCATION] + emailHashBlock + prefix + "$"
	// Prefix First Part
	prefix = EMAIL_HASH_SEPARTOR + strconv.Itoa(appKeyDataSize) + BLOCK_LENGTH_SEPARTOR + strconv.Itoa(blockLength) + prefix

	return prefix, appKeyDataSize, nil
}

/**
 * Get Hash App Key after Append Email encryption data
 * @param string appKey
 * @param string emailHash
 * @return string
 * @return error
 */
func getEncodeAppKey(appKey string, emailHash string) (string, error) {

	output := ""
	blockLength = randomInt(1, 10)
	if blockLength <= 0 {
		blockLength = KEY_PAIR_BLOCK_SIZE
	}

	//appKey = "94c44664f9e91ff117a144889e2575b31382e52e300a842d92f31a0c530642c6"
	//emailHash = "8966d59b2f0dff0eead5232849a28812327a668e67dbcc155c9a960794be5da4281842bf15dd25825f5307058850b947"
	//fmt.Println("appKey: ", appKey, "emailHash: ", emailHash)

	emailHashLen := len(emailHash)
	emailHashBlockSize := int(emailHashLen / blockLength)
	prefix := emailHash[blockLength*emailHashBlockSize : len(emailHash)]
	prefix, appKeyDataSize, err := generatePrefix(prefix, appKey, emailHashBlockSize)
	if err != nil {
		return output, err
	}

	emailHash = emailHash[0 : blockLength*emailHashBlockSize]
	var emailHashSplit, appKeyFirstPart, appKeySecondPart string
	for i := 0; i <= blockLength-1; i++ {
		emailHashSplit = emailHash[i*emailHashBlockSize : i*emailHashBlockSize+emailHashBlockSize]
		appKeyFirstPart = appKey[0 : i*emailHashBlockSize+i*appKeyDataSize]
		appKeySecondPart = appKey[len(appKeyFirstPart):len(appKey)]
		appKey = appKeyFirstPart + emailHashSplit + appKeySecondPart
	}

	output = prefix + appKey
	return output, nil

}

/**
 * Get Generated App Key Pair
 * For Encrypt
 * @param KeyPairUserInfo
 * @return KeyPair
 * @return error
 */
func GenerateKeyPair(user KeyPairUserInfo) (KeyPair, error) {

	emailEncryption, err := getEmailDataByAction(strings.TrimSpace(user.UserEmail), "e")
	if err != nil {
		return KeyPair{}, nil
	}

	var keys KeyPair
	keys.SecretKey = generateSecretKey(user)
	keys.UserEmail = user.UserEmail
	keys.Status = true
	generatedAppKey := generateAppKey(keys.SecretKey, user)
	keys.AppKey, err = getEncodeAppKey(generatedAppKey, emailEncryption)
	if err != nil {
		return KeyPair{}, err
	}

	return keys, err

}

/**
 * Decrypt Email Address from App Key
 * @param string appKey
 * @param string secretKey
 * @return KeyPair
 * @return error
 */
func GetEmailFromAppKey(appKey string, secretKey string) (KeyPair, error) {

	var decodeKey KeyPair
	decodeKey.Status = false
	appKey, decodeEmailHash, err := getDecodeAppKey(appKey);
	if err != nil {
		return KeyPair{}, err
	}

	decodeKey.UserEmail, err = getEmailDataByAction(decodeEmailHash, "d");
	if err != nil {
		return KeyPair{}, err
	}
	decodeKey.AppKey = appKey
	decodeKey.SecretKey = secretKey

	return decodeKey, nil

}
