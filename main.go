package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// _ "godemo/routers"

// func getHax(data string) string {
// 	t := sha1.New()
// 	io.WriteString(t, data)
// 	return fmt.Sprintf("%x", t.Sum(nil))
// }

func main() {

	// 获取url参数值
	mm := []string{"token", "timestamp", "nonce"}
	// 字符串排序
	sort.Strings(mm)
	// 转换字符串
	str := strings.Join(mm[:], "")
	// 创建一个sha1
	t := sha1.Sum([]byte(str))

	//打印token
	fmt.Printf("%s\n", str)
	fmt.Printf("%s", hex.EncodeToString(t[:]))

	// err := http.ListenAndServe(":8080", nil)
	// if err != nil {
	// 	fmt.Println("run Error")
	// } else {
	// 	fmt.Println("run in :8080")
	// }
}
