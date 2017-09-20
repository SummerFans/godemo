package controller

import (
	"net/http"
)

// GetUser is controoler
func GetUser(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("My is GetUser"))
}
