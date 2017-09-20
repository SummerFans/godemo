package controller

import "net/http"

// NotFound is not page
func NotFound(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Not Found"))
}
