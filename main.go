package main

import (
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
)

const port = "8080"
const filepathRoot = http.Dir(".")

type apiConfig struct {
	fileserverHits atomic.Int32
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func main() {
	var apiConfig apiConfig
	mux := http.NewServeMux()
	httpServer := http.Server{
		Handler: mux,
		Addr:    ":" + port,
	}
	mux.Handle("/app/", apiConfig.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot)))))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("OK"))
		if err != nil {
			log.Fatal("error writing status code: %w", err)
		}

	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, req *http.Request) {
		metrics := fmt.Sprintf("Hits: %v", apiConfig.fileserverHits.Load())
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(metrics))
	})
	mux.HandleFunc("/reset", func(w http.ResponseWriter, req *http.Request) {
		apiConfig.fileserverHits.Store(0)
		w.WriteHeader(http.StatusOK)
	})
	log.Printf("Serving files from %s on port: %s\n", filepathRoot, port)
	log.Fatal(httpServer.ListenAndServe())
}
