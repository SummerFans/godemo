package controller

import (
	"fmt"
	"godemo/wechat"
	"log"
	"net/http"
	"strings"
)

// ReceiveMessage 是回馈方法
func ReceiveMessage(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	timestamp := strings.Join(r.Form["timestamp"], "")
	nonce := strings.Join(r.Form["nonce"], "")
	// signature := strings.Join(r.Form["signature"], "")
	encryptType := strings.Join(r.Form["encrypt_type"], "")
	msgSignature := strings.Join(r.Form["msg_signature"], "")

	if r.Method == "POST" {
		// 判断是否aes加密
		if encryptType == "aes" {
			log.Println("Wechat Service: in safe mode")

			data, err := WXBizMsgCrypt.DecryptMsg(timestamp, nonce, msgSignature, r)

			if err != nil {
				fmt.Println(err)
			}

			messageContent := "您发送都是:" + data.Content

			responseEncryptTextBody, err := WXBizMsgCrypt.EncryptMsg(data.ToUserName, data.FromUserName, messageContent, nonce, timestamp)
			w.Header().Set("Content-Type", "text/xml")
			fmt.Println(data.MsgType)
			fmt.Println(data.Event)
			// fmt.Println("\n", string(responseEncryptTextBody))
			fmt.Fprintf(w, string(responseEncryptTextBody))
		}
	}
}
