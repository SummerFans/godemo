package main

import (
	"fmt"
	_ "godemo/routers"
	"net/http"
)

// func getHax(data string) string {
// 	t := sha1.New()
// 	io.WriteString(t, data)
// 	return fmt.Sprintf("%x", t.Sum(nil))
// }

func main() {
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println("run Error")
	} else {
		fmt.Println("run in :8080")
	}
}
