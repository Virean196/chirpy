package main

import "net/http"

func main() {
	mux := http.NewServeMux()
	httpServer := http.Server{
		Handler: mux,
		Addr:    ":8080",
	}
	mux.Handle("/", http.FileServer(http.Dir(".")))
	httpServer.ListenAndServe()
}
