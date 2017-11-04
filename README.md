package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"godemo/wechat"
	"io"
	// _ "godemo/routers"
	"net/http"
)

// func getHax(data string) string {
// 	t := sha1.New()
// 	io.WriteString(t, data)
// 	return fmt.Sprintf("%x", t.Sum(nil))
// }

// AES 加密
// func AES(keyTxt string, sourceTxt string) string {
// 	// key := []byte(keyTxt)           // appid
// 	// EncodingAESKey := []byte("123") // EncodingAESKey
// 	// plaintext := []byte(sourceTxt)  // 明文

// 	// block, err := aes.NewCipher(EncodingAESKey) //生成加密用的block
// 	// if err != nil {
// 	// 	panic(err)
// 	// }
// 	// mode := cipher.NewCBCEncrypter(plaintext, block)
// 	// // mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

// 	// return mode
// }

// Encrypter 解密
func Encrypter() {

}

func homePage(w http.ResponseWriter, r *http.Request) {
	// signature timestamp nonce
	// wechat.CheckSignature("fashionQueen",r.URL.Query)
	// query := r.URL.Query()
	// signature := query["signature"][0]
	// timestamp := query["timestamp"][0]
	// fmt.Println(timestamp)

	signature := r.FormValue("signature")
	timestamp := r.FormValue("timestamp")
	nonce := r.FormValue("nonce")
	echostr := r.FormValue("echostr")
	if signature == "" || timestamp == "" || nonce == "" || echostr == "" {
		w.Write([]byte("signature,timestamp或nonce参数不存在"))
	} else {
		isWechat := wechat.CheckSignature("fashionQueen", signature, timestamp, nonce)
		if isWechat {
			fmt.Println("成功")
			w.Write([]byte(echostr))
		} else {
			fmt.Println("失败")
			w.Write([]byte("false"))
		}
	}

}

func main() {
	key := []byte("example key 1234")       //秘钥长度需要时AES-128(16bytes)或者AES-256(32bytes)
	plaintext := []byte("exampleplaintext") //原文必须填充至blocksize的整数倍，填充方法可以参见https://tools.ietf.org/html/rfc5246#section-6.2.3.2

	if len(plaintext)%aes.BlockSize != 0 { //块大小在aes.BlockSize中定义
		panic("plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key) //生成加密用的block
	if err != nil {
		panic(err)
	}

	// 对IV有随机性要求，但没有保密性要求，所以常见的做法是将IV包含在加密文本当中
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	//随机一个block大小作为IV
	//采用不同的IV时相同的秘钥将会产生不同的密文，可以理解为一次加密的session
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	// 谨记密文需要认证(i.e. by using crypto/hmac)

	fmt.Printf("%x\n", ciphertext)
	// http.HandleFunc("/", homePage)
	// err := http.ListenAndServe(":8080", nil)
	// if err != nil {
	// 	fmt.Println("run Error")
	// } else {
	// 	fmt.Println("run in :8080")
	// }
}







/// 第二部

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"godemo/wechat"
	"io"
	"log"
	// _ "godemo/routers"
	"net/http"
)

// EncryptRequestBody 微信发送值
type EncryptRequestBody struct {
	XMLName    xml.Name `xml:"xml"`
	ToUserName string
	Encrypt    string
}

const (
	token = "fashionQueen"
	appID = "wx6d78c87cbce3f9c6"
)

var aesKey []byte

var enstr string = "acQNChv4r1LBGH05ZNJMEXAm+vknMR/A005JsYKLCZY9N1ePvcvNprXx5cEkeMdormNH0sOpGEM2VNR3Q8Ym9/B6hplgJqaHXhf06a+HArXTmtHg2VrmoNo2UygzVDA7EHs958i865LJQsOOpRNxgskOlKvDmKj+mtbtWOK0Rofmx+7ZoBUGbs9KYSxSYKYOD7RNuLb1t5FPTigRS8coYlyFHPE7LWzIcKphdjD0igSLMTJaXUPgQQVEb3OF/e/1T4jSV32dvxz6W8rhRT+l4pp9U4LA0hszP3jIcO/q3pYvReEjrCIMwD/434h+ERpaSLuPlSImds8rHO5NMXdGjT5WVtGYrR3ZlJ5DcSn0NW2davVZSqVkwIElw/6xBAST7cbnTxm81pXxYK/cokRsxsdUHLHyL6EmI39iuDpT91U="

// func getHax(data string) string {
// 	t := sha1.New()
// 	io.WriteString(t, data)
// 	return fmt.Sprintf("%x", t.Sum(nil))
// }

// 解码微信
func encodingAESKey2AESKey(encodingKey string) []byte {
	data, _ := base64.StdEncoding.DecodeString(encodingKey + "=")
	return data
}

// func parseEncryptRequestBody(r *http.Request) *EncryptRequestBody {
// 	// 	body, err := ioutil.ReadAll(r.Body)
// 	// 	if err != nil {
// 	// 		log.Fatal(err)
// 	// 		return nil
// 	// 	}
// 	// 	requestBody := &EncryptRequestBody{}
// 	// 	xml.Unmarshal(body, requestBody)
// 	// 	return requestBody
// 	return ""
// }

func homePage(w http.ResponseWriter, r *http.Request) {
	// signature timestamp nonce
	// wechat.CheckSignature("fashionQueen",r.URL.Query)
	// query := r.URL.Query()
	// signature := query["signature"][0]
	// timestamp := query["timestamp"][0]
	// fmt.Println(timestamp)
	// encryptRequestBody := parseEncryptRequestBody(r)
	// fmt.Println(encryptRequestBody.Encrypt)
	// fmt.Println(encryptRequestBody.ToUserName)

	fmt.Println(r.PostFormValue("signature"))
	signature := r.FormValue("signature")
	timestamp := r.FormValue("timestamp")
	nonce := r.FormValue("nonce")
	echostr := r.FormValue("echostr")
	if signature == "" || timestamp == "" || nonce == "" || echostr == "" {
		w.Write([]byte("signature,timestamp或nonce参数不存在"))
	} else {
		isWechat := wechat.CheckSignature("fashionQueen", signature, timestamp, nonce)
		if isWechat {
			fmt.Println("成功")
			w.Write([]byte(echostr))
		} else {
			fmt.Println("失败")
			w.Write([]byte("false"))
		}
	}

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
	if !validateAppId(id) {
		log.Println("Wechat Service: appid is invalid!")
		return nil, errors.New("Appid is invalid")
	}
	log.Println("Wechat Service: appid validation is ok!")

	// xml Decoding
	textRequestBody := &TextRequestBody{}
	xml.Unmarshal(plainText[20:20+length], textRequestBody)
	return textRequestBody, nil
}

func main() {
	// key := []byte("example key 1234")       //秘钥长度需要时AES-128(16bytes)或者AES-256(32bytes)
	// plaintext := []byte("exampleplaintext") //原文必须填充至blocksize的整数倍，填充方法可以参见https://tools.ietf.org/html/rfc5246#section-6.2.3.2

	// if len(plaintext)%aes.BlockSize != 0 { //块大小在aes.BlockSize中定义
	// 	panic("plaintext is not a multiple of the block size")
	// }

	// block, err := aes.NewCipher(key) //生成加密用的block
	// if err != nil {
	// 	panic(err)
	// }

	// // 对IV有随机性要求，但没有保密性要求，所以常见的做法是将IV包含在加密文本当中
	// ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	// //随机一个block大小作为IV
	// //采用不同的IV时相同的秘钥将会产生不同的密文，可以理解为一次加密的session
	// iv := ciphertext[:aes.BlockSize]
	// if _, err := io.ReadFull(rand.Reader, iv); err != nil {
	// 	panic(err)
	// }

	// mode := cipher.NewCBCEncrypter(block, iv)
	// mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	encodingAESKey := "VYFtQEV8r4Fsq0Lm7OnfCLztOrFe5QTUh1pamhom2iF"

	// // 谨记密文需要认证(i.e. by using crypto/hmac)
	// Decode base64
	cipherData, err := base64.StdEncoding.DecodeString(enstr)
	if err != nil {
		log.Println("Wechat Service: Decode base64 error:", err)
		return
	}

	// AES Decrypt
	plainData, err := aesDecrypt(cipherData, encodingAESKey2AESKey(encodingAESKey))
	if err != nil {
		fmt.Println(err)
		return
	}

	//Xml decoding
	textRequestBody, _ := parseEncryptTextRequestBody(plainData)
	fmt.Printf("Wechat Service: Recv text msg [%s] from user [%s]!",
		textRequestBody.Content,
		textRequestBody.FromUserName)

	// fmt.Println(data)
	// fmt.Printf("%x\n", ciphertext)
	// http.HandleFunc("/", homePage)
	// err := http.ListenAndServe(":8080", nil)
	// if err != nil {
	// 	fmt.Println("run Error")
	// }
}
