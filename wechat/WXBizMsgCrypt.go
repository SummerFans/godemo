package WXBizMsgCrypt

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
	"strings"
	"time"
)

const (
	token          = "fashionQueen"
	appID          = "wx6d78c87cbce3f9c6"
	encodingAESKey = "VYFtQEV8r4Fsq0Lm7OnfCLztOrFe5QTUh1pamhom2iF"
)

var aesKey []byte // 解密需要的aes的key

// EncryptRequestBody 微信传输过来消息的结构体
type EncryptRequestBody struct {
	XMLName    xml.Name `xml:"xml"`
	ToUserName string
	Encrypt    string
}

// TextRequestBody 是请求body
type TextRequestBody struct {
	XMLName      xml.Name `xml:"xml"`
	ToUserName   string
	FromUserName string
	CreateTime   time.Duration
	MsgType      string
	Event        string
	Content      string
	MsgID        int
}

// CDATAText 结构体
type CDATAText struct {
	Text string `xml:",innerxml"`
}

// EncryptResponseBody 是返回输出, 已加密
type EncryptResponseBody struct {
	XMLName      xml.Name `xml:"xml"`
	Encrypt      CDATAText
	MsgSignature CDATAText
	TimeStamp    string
	Nonce        CDATAText
}

// TextResponseBody 是返回输出, 未加密
type TextResponseBody struct {
	XMLName      xml.Name `xml:"xml"`
	ToUserName   CDATAText
	FromUserName CDATAText
	CreateTime   string
	MsgType      CDATAText
	Event        CDATAText
	Content      CDATAText
}

func init() {
	aesKey = encodingAESKey2AESKey(encodingAESKey)
}

// DecryptMsg 获取解密消息
func DecryptMsg(timestamp, nonce, msgSignatureIn string, r *http.Request) (data *TextRequestBody, err error) {
	// 验证是否有效消息

	encryptRequestBody := parseEncryptRequestBody(r)
	// 微信的加密包采用aes-256算法，秘钥长度32B，采用PKCS#7 Padding方式
	// 验证成功后执行 base64解析 aesPKCS#7解密 转xml

	if !validateMsg(timestamp, nonce, encryptRequestBody.Encrypt, msgSignatureIn) {
		err := errors.New(" validate fail")
		fmt.Println(err.Error())
	}

	cipherData, err := base64.StdEncoding.DecodeString(encryptRequestBody.Encrypt)

	plainData, err := aesDecrypt(cipherData, aesKey)
	textRequestBody, _ := parseEncryptTextRequestBody(plainData)

	return textRequestBody, nil
}

// EncryptMsg 加密消息
func EncryptMsg(ToUserName, FromUserName, Content, nonce, timestamp string) ([]byte, error) {
	// 接受到消息后回复消息
	responseEncryptTextBody, _ := makeEncryptResponseBody(ToUserName,
		FromUserName,
		Content,
		nonce,
		timestamp)

	return responseEncryptTextBody, nil
}

// 验证appid是否正确
func validateAppID(id []byte) bool {
	if string(id) == appID {
		return true
	}
	return false
}

func encodingAESKey2AESKey(encodingKey string) []byte {
	data, _ := base64.StdEncoding.DecodeString(encodingKey + "=")
	return data
}

// 生成签名(用于与传输过来的)
func makeMsgSignature(timestamp, nonce, msgEncrypt string) string {
	sl := []string{token, timestamp, nonce, msgEncrypt}
	sort.Strings(sl)
	s := sha1.New()
	io.WriteString(s, strings.Join(sl, ""))
	return fmt.Sprintf("%x", s.Sum(nil))
}

// validateMsg 是验证消息有效性
func validateMsg(timestamp, nonce, msgEncrypt, msgSignatureIn string) bool {
	// 使用 makeMsgSignature 函数创建生成签名
	msgSignatureGen := makeMsgSignature(timestamp, nonce, msgEncrypt)
	if msgSignatureGen != msgSignatureIn {
		return false
	}
	return true
}

// 消息内容结构体(转xml)
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

// 解密消息aes
func aesDecrypt(cipherData []byte, aesKey []byte) ([]byte, error) {
	k := len(aesKey) // PKCS#7
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

	blockModel := cipher.NewCBCDecrypter(block, iv)
	plainData := make([]byte, len(cipherData))
	blockModel.CryptBlocks(plainData, cipherData)
	return plainData, nil
}

// 解密后对appId校验与XML decoding处理
func parseEncryptTextRequestBody(plainText []byte) (*TextRequestBody, error) {
	// fmt.Println(string(plainText))
	// Read length
	buf := bytes.NewBuffer(plainText[16:20])
	var length int32
	binary.Read(buf, binary.BigEndian, &length)
	// fmt.Println(string(plainText[20 : 20+length]))

	// appID validation
	appIDstart := 20 + length
	id := plainText[appIDstart : int(appIDstart)+len(appID)]
	if !validateAppID(id) {
		log.Println("Wechat Service: appid is invalid!")
		return nil, errors.New("Appid is invalid")
	}
	log.Println("Wechat Service: appid validation is ok!")

	// xml Decoding
	textRequestBody := &TextRequestBody{}
	xml.Unmarshal(plainText[20:20+length], textRequestBody)
	return textRequestBody, nil
}

// 转CDATA格式
func value2CDATA(v string) CDATAText {
	//return CDATAText{[]byte("<![CDATA[" + v + "]]>")}
	return CDATAText{"<![CDATA[" + v + "]]>"}
}

// 加密回执消息
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

// aes消息加密
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
