package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	token          = "fashionQueen"
	appID          = "wx6d78c87cbce3f9c6"
	encodingAESKey = "VYFtQEV8r4Fsq0Lm7OnfCLztOrFe5QTUh1pamhom2iF"
)

var aesKey []byte

func encodingAESKey2AESKey(encodingKey string) []byte {
	data, _ := base64.StdEncoding.DecodeString(encodingKey + "=")
	return data
}

func init() {
	aesKey = encodingAESKey2AESKey(encodingAESKey)
}

// TextRequestBody 是请求body
type TextRequestBody struct {
	XMLName      xml.Name `xml:"xml"`
	ToUserName   string
	FromUserName string
	CreateTime   time.Duration
	MsgType      string
	Content      string
	MsgID        int
}

// TextResponseBody 是返回body
type TextResponseBody struct {
	XMLName      xml.Name `xml:"xml"`
	ToUserName   CDATAText
	FromUserName CDATAText
	CreateTime   string
	MsgType      CDATAText
	Content      CDATAText
}

// EncryptRequestBody 加密返回
type EncryptRequestBody struct {
	XMLName    xml.Name `xml:"xml"`
	ToUserName string
	Encrypt    string
}

// EncryptResponseBody 是
type EncryptResponseBody struct {
	XMLName      xml.Name `xml:"xml"`
	Encrypt      CDATAText
	MsgSignature CDATAText
	TimeStamp    string
	Nonce        CDATAText
}

// EncryptResponseBody1 ?
type EncryptResponseBody1 struct {
	XMLName      xml.Name `xml:"xml"`
	Encrypt      string
	MsgSignature string
	TimeStamp    string
	Nonce        string
}

/*
type CDATAText struct {
	Text []byte `xml:",innerxml"`
}
*/

// CDATAText 结构体
type CDATAText struct {
	Text string `xml:",innerxml"`
}

// 使用是时间戳token和随机数生成 signature 用于匹配是否和传如参数相同
func makeSignature(timestamp, nonce string) string {
	sl := []string{token, timestamp, nonce}
	sort.Strings(sl)
	s := sha1.New()
	io.WriteString(s, strings.Join(sl, ""))
	return fmt.Sprintf("%x", s.Sum(nil))
}

// 生成消息签名
func makeMsgSignature(timestamp, nonce, msgEncrypt string) string {
	sl := []string{token, timestamp, nonce, msgEncrypt}
	sort.Strings(sl)
	s := sha1.New()
	io.WriteString(s, strings.Join(sl, ""))
	return fmt.Sprintf("%x", s.Sum(nil))
}

// 判断生成的 signature 是否匹配 请求的 signature
func validateurl(timestamp, nonce, signatureIn string) bool {
	signatureGen := makeSignature(timestamp, nonce)
	if signatureGen != signatureIn {
		return false
	}
	return true
}

// 消息验证判断
func validateMsg(timestamp, nonce, msgEncrypt, msgSignatureIn string) bool {
	msgSignatureGen := makeMsgSignature(timestamp, nonce, msgEncrypt)
	if msgSignatureGen != msgSignatureIn {
		return false
	}
	return true
}

// 解析加密返回结构体
func parseEncryptRequestBody(r *http.Request) *EncryptRequestBody {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
		return nil
	}
	requestBody := &EncryptRequestBody{}
	xml.Unmarshal(body, requestBody)
	return requestBody

}

func parseTextRequestBody(r *http.Request) *TextRequestBody {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
		return nil
	}
	fmt.Println(string(body))
	requestBody := &TextRequestBody{}
	xml.Unmarshal(body, requestBody)
	return requestBody
}

func value2CDATA(v string) CDATAText {
	//return CDATAText{[]byte("<![CDATA[" + v + "]]>")}
	return CDATAText{"<![CDATA[" + v + "]]>"}
}

func makeTextResponseBody(fromUserName, toUserName, content string) ([]byte, error) {
	textResponseBody := &TextResponseBody{}
	textResponseBody.FromUserName = value2CDATA(fromUserName)
	textResponseBody.ToUserName = value2CDATA(toUserName)
	textResponseBody.MsgType = value2CDATA("text")
	textResponseBody.Content = value2CDATA(content)
	textResponseBody.CreateTime = strconv.Itoa(int(time.Duration(time.Now().Unix())))
	return xml.MarshalIndent(textResponseBody, " ", "  ")
}

func makeEncryptResponseBody(fromUserName, toUserName, content, nonce, timestamp string) ([]byte, error) {
	encryptBody := &EncryptResponseBody{}

	encryptXMLData, _ := makeEncryptXMLData(fromUserName, toUserName, timestamp, content)
	encryptBody.Encrypt = value2CDATA(encryptXMLData)
	encryptBody.MsgSignature = value2CDATA(makeMsgSignature(timestamp, nonce, encryptXMLData))
	encryptBody.TimeStamp = timestamp
	encryptBody.Nonce = value2CDATA(nonce)

	return xml.MarshalIndent(encryptBody, " ", "  ")
}

func makeEncryptXMLData(fromUserName, toUserName, timestamp, content string) (string, error) {
	textResponseBody := &TextResponseBody{}
	textResponseBody.FromUserName = value2CDATA(fromUserName)
	textResponseBody.ToUserName = value2CDATA(toUserName)
	textResponseBody.MsgType = value2CDATA("text")
	textResponseBody.Content = value2CDATA(content)
	textResponseBody.CreateTime = timestamp
	body, err := xml.MarshalIndent(textResponseBody, " ", "  ")
	if err != nil {
		return "", errors.New("xml marshal error")
	}

	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.BigEndian, int32(len(body)))
	if err != nil {
		fmt.Println("Binary write err:", err)
	}
	bodyLength := buf.Bytes()

	randomBytes := []byte("abcdefghijklmnop")

	plainData := bytes.Join([][]byte{randomBytes, bodyLength, body, []byte(appID)}, nil)
	cipherData, err := aesEncrypt(plainData, aesKey)
	if err != nil {
		return "", errors.New("aesEncrypt error")
	}

	return base64.StdEncoding.EncodeToString(cipherData), nil
}

// PadLength calculates padding length, from github.com/vgorin/cCCCZZryptogo
func PadLength(sliceLength, blocksize int) (padlen int) {
	padlen = blocksize - sliceLength%blocksize
	if padlen == 0 {
		padlen = blocksize
	}
	return padlen
}

//PKCS7Pad from github.com/vgorin/cryptogo
func PKCS7Pad(message []byte, blocksize int) (padded []byte) {
	// block size must be bigger or equal 2
	if blocksize < 1<<1 {
		panic("block size is too small (minimum is 2 bytes)")
	}
	// block size up to 255 requires 1 byte padding
	if blocksize < 1<<8 {
		// calculate padding length
		padlen := PadLength(len(message), blocksize)

		// define PKCS7 padding block
		padding := bytes.Repeat([]byte{byte(padlen)}, padlen)

		// apply padding
		padded = append(message, padding...)
		return padded
	}
	// block size bigger or equal 256 is not currently supported
	panic("unsupported block size")
}

func aesEncrypt(plainData []byte, aesKey []byte) ([]byte, error) {
	k := len(aesKey)
	if len(plainData)%k != 0 {
		plainData = PKCS7Pad(plainData, k)
	}
	fmt.Printf("aesEncrypt: after padding, plainData length = %d\n", len(plainData))

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	cipherData := make([]byte, len(plainData))
	blockMode := cipher.NewCBCEncrypter(block, iv)
	blockMode.CryptBlocks(cipherData, plainData)

	return cipherData, nil
}

func aesDecrypt(cipherData []byte, aesKey []byte) ([]byte, error) {
	k := len(aesKey) //PKCS#7
	if len(cipherData)%k != 0 {
		return nil, errors.New("crypto/cipher: ciphertext size is not multiple of aes key length")
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	plainData := make([]byte, len(cipherData))
	blockMode.CryptBlocks(plainData, cipherData)
	return plainData, nil
}

func validateAppID(id []byte) bool {
	if string(id) == appID {
		return true
	}
	return false
}

func parseEncryptTextRequestBody(plainText []byte) (*TextRequestBody, error) {
	fmt.Println(string(plainText))

	// Read length
	buf := bytes.NewBuffer(plainText[16:20])
	var length int32
	binary.Read(buf, binary.BigEndian, &length)
	fmt.Println(string(plainText[20 : 20+length]))

	// appID validation
	appIDstart := 20 + length
	id := plainText[appIDstart : int(appIDstart)+len(appID)]
	if !validateAppID(id) {
		log.Println("Wechat Service: appid is invalid!")
		return nil, errors.New("Appid is invalid")
	}
	log.Println("Wechat Service: appid validation is ok!")

	textRequestBody := &TextRequestBody{}
	xml.Unmarshal(plainText[20:20+length], textRequestBody)
	return textRequestBody, nil
}

func parseEncryptResponse(responseEncryptTextBody []byte) {
	textResponseBody := &EncryptResponseBody1{}
	xml.Unmarshal(responseEncryptTextBody, textResponseBody)

	if !validateMsg(textResponseBody.TimeStamp, textResponseBody.Nonce, textResponseBody.Encrypt, textResponseBody.MsgSignature) {
		fmt.Println("msg signature is invalid")
		return
	}

	cipherData, err := base64.StdEncoding.DecodeString(textResponseBody.Encrypt)
	if err != nil {
		log.Println("Wechat Service: Decode base64 error:", err)
		return
	}

	plainText, err := aesDecrypt(cipherData, aesKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(plainText))
}

// 请求
func procRequest(w http.ResponseWriter, r *http.Request) {
	fmt.Println("test")
	r.ParseForm()
	timestamp := strings.Join(r.Form["timestamp"], "")
	nonce := strings.Join(r.Form["nonce"], "")
	signature := strings.Join(r.Form["signature"], "")
	encryptType := strings.Join(r.Form["encrypt_type"], "")
	msgSignature := strings.Join(r.Form["msg_signature"], "")

	fmt.Println("timestamp =", timestamp)
	fmt.Println("nonce =", nonce)
	fmt.Println("signature =", signature)
	fmt.Println("msgSignature =", msgSignature)

	// 判断是否微信推送的，加密值和传入signature 是否相同
	if !validateurl(timestamp, nonce, signature) {
		log.Println("Wechat Service: this http request is not from Wechat platform!")
		w.Write([]byte("Wechat Service: this http request is not from Wechat platform!"))
		return
	}

	if r.Method == "POST" {
		// 判断是否aes加密
		if encryptType == "aes" {
			log.Println("Wechat Service: in safe mode")

			// 获取解析请求主体内容
			encryptRequestBody := parseEncryptRequestBody(r)

			// Validate msg signature
			if !validateMsg(timestamp, nonce, encryptRequestBody.Encrypt, msgSignature) {
				log.Println("Wechat Service: msgSignature is invalid")
				return
			}
			log.Println("Wechat Service: msgSignature validation is ok!")

			// Decode base64
			cipherData, err := base64.StdEncoding.DecodeString(encryptRequestBody.Encrypt)
			if err != nil {
				log.Println("Wechat Service: Decode base64 error:", err)
				return
			}

			// AES Decrypt
			plainData, err := aesDecrypt(cipherData, aesKey)
			if err != nil {
				fmt.Println(err)
				return
			}

			textRequestBody, _ := parseEncryptTextRequestBody(plainData)
			// fmt.Println(textRequestBody)
			fmt.Printf("Wechat Service: Recv text msg [%s] from user [%s]!",
				textRequestBody.Content,
				textRequestBody.FromUserName)

			// 接受到消息后回复消息
			responseEncryptTextBody, _ := makeEncryptResponseBody(textRequestBody.ToUserName,
				textRequestBody.FromUserName,
				"Hello, "+textRequestBody.FromUserName,
				nonce,
				timestamp)
			w.Header().Set("Content-Type", "text/xml")
			fmt.Println("\n", string(responseEncryptTextBody))
			fmt.Fprintf(w, string(responseEncryptTextBody))

			parseEncryptResponse(responseEncryptTextBody)
		} else if encryptType == "raw" {
			log.Println("Wechat Service: in raw mode")
		}
	}
}

func main() {
	log.Println("Wechat Service: Start!")
	http.HandleFunc("/", procRequest)
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("Wechat Service: ListenAndServe failed, ", err)
	}
	log.Println("Wechat Service: Stop!")
}
