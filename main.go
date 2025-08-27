package main

import (
	"encoding/json"
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
	// Root handle
	mux.Handle("/app/", apiConfig.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot)))))
	// Status handle
	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("OK"))
		if err != nil {
			log.Fatal("error writing status code: %w", err)
		}

	})
	// Metrics handle
	mux.HandleFunc("GET /admin/metrics", func(w http.ResponseWriter, req *http.Request) {
		metrics := fmt.Sprintf("<html><body><h1>Welcome, Chirpy Admin</h1><p>Chirpy has been visited %d times!</p></body></html>", apiConfig.fileserverHits.Load())
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(metrics))
	})

	// Validate Chirpy JSON POST
	mux.HandleFunc("POST /api/validate_chirp", func(w http.ResponseWriter, req *http.Request) {
		type params struct {
			Body string `json:"body"`
		}
		type validResp struct {
			Valid bool `json:"valid"`
		}
		type invalidResp struct {
			Error string `json:"error"`
		}

		dec := json.NewDecoder(req.Body)
		par := params{}
		err := dec.Decode(&par)
		if err != nil {
			log.Printf("error decoding parameters: %s", err)
			resp := invalidResp{Error: "Something went wrong"}
			dat, err := json.Marshal(resp)
			if err != nil {
				log.Printf("error marshalling response: %s", err)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(500)
			w.Write(dat)
			return
		}
		if len(par.Body) <= 140 {
			resp := validResp{Valid: true}
			dat, err := json.Marshal(resp)
			if err != nil {
				log.Printf("error marshalling response: %s", err)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.Write(dat)

		} else {
			resp := invalidResp{Error: "Chirp is too long"}
			dat, err := json.Marshal(resp)
			if err != nil {
				log.Printf("error marshalling response: %s", err)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(400)
			w.Write(dat)
		}
	})

	// Reset metrics handle
	mux.HandleFunc("POST /admin/reset", func(w http.ResponseWriter, req *http.Request) {
		apiConfig.fileserverHits.Store(0)
		w.WriteHeader(http.StatusOK)
	})

	// Start server
	log.Printf("Serving files from %s on port: %s\n", filepathRoot, port)
	log.Fatal(httpServer.ListenAndServe())
}
