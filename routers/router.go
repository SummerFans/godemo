package rouers

import (
	"godemo/controller"
	"net/http"
)

func init() {
	http.HandleFunc("/User", controller.GetUser)
	http.HandleFunc("/", controller.NotFound)
}
