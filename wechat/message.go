package wechat

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

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
