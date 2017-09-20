package controller

import (
	"godemo/wechat"
	"net/http"
)

// GetUser is controoler
func GetUser(w http.ResponseWriter, r *http.Request) {
	var str string
	isWechat := wechat.CheckSignature("123", "88ea39439e74fa27c09a4fc0bc8ebe6d00978392", "123", "123")
	if isWechat {
		str = "是微信"
	} else {
		str = "不是微信"
	}
	w.Write([]byte(str))
}
