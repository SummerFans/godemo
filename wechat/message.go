package WXBizMsgCrypt

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

const (
	token          = ""
	appID          = ""
	encodingAESKey = ""
)

var aesKey []byte // 解密需要的aes的key

// EncryptRequestBody 微信传输过来消息的结构体
type EncryptRequestBody struct {
	XMLName    xml.Name `xml:"xml"`
	ToUserName string
	Encrypt    string
}

func init() {
	aesKey = encodingAESKey2AESKey(encodingAESKey)
}

// DecryptMsg 获取解密消息
func DecryptMsg(timestamp, nonce, msgEncrypt, msgSignatureIn string, body []byte) (data string, err error) {
	// 验证是否有效消息
	if !validateMsg(timestamp, nonce, msgEncrypt, msgSignatureIn) {
		err := errors.New(" validate fail")
		fmt.Println(err.Error())
	}
	encryptRequestBody := parseEncryptRequestBody(body)
	// 微信的加密包采用aes-256算法，秘钥长度32B，采用PKCS#7 Padding方式
	// 验证成功后执行 base64解析 aesPKCS#7解密 转xml

	cipherData, err := base64.StdEncoding.DecodeString(encryptRequestBody.Encrypt)

	return "body", err
}

// EncryptMsg 加密消息
func EncryptMsg() {

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
func parseEncryptRequestBody(body []byte) *EncryptRequestBody {
	requestBody := &EncryptRequestBody{}
	xml.Unmarshal(body, requestBody)
	return requestBody
}

func aesDecrypt(cipherData []byte)

// encrypt_type = "aes"，说明是加密消息，否则为"raw”，即未加密消息。
// msg_signature=sha1(sort(Token, timestamp, nonce, msg_encrypt))

// make Msg Signature 做消息签名

// validate Msg // 验证消息

// parse Encrypt Request Body 消息内容结构体(转xml)

// Http Request

// encoding AES Key 2AESKey 解析base64

// aes Decrypt 解密aes数据块

// parse Encrypt Text Request Body 解析
// func parseEncryptTextRequestBody(plainText []byte) (*TextRequestBody, error) {
// 	fmt.Println(string(plainText))

// 	// Read length
// 	buf := bytes.NewBuffer(plainText[16:20])
// 	var length int32
// 	binary.Read(buf, binary.BigEndian, &length)
// 	fmt.Println(string(plainText[20 : 20+length]))

// 	// appID validation
// 	appIDstart := 20 + length
// 	id := plainText[appIDstart : int(appIDstart)+len(appID)]
// 	if !validateAppId(id) {
// 		log.Println("Wechat Service: appid is invalid!")
// 		return nil, errors.New("Appid is invalid")
// 	}
// 	log.Println("Wechat Service: appid validation is ok!")

// 	// xml Decoding
// 	textRequestBody := &TextRequestBody{}
// 	xml.Unmarshal(plainText[20:20+length], textRequestBody)
// 	return textRequestBody, nil
// }

// CheckSignature 是校验是否微信平台发送
func CheckSignature(token string, signature string, timestamp string, nonce string) bool {
	// 组合
	signInfo := []string{token, timestamp, nonce}
	// 字符串排序
	sort.Strings(signInfo)
	// 切片转成字符串
	str := strings.Join(signInfo, "")
	// sha1加密
	strToSha := sha1.Sum([]byte(str))

	newSign := hex.EncodeToString(strToSha[:])

	fmt.Printf(`%s == %s`, newSign, signature)

	// 判断是否相等
	return newSign == signature

}
