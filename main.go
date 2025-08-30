package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/virean196/chirpy/internal/database"
)

const port = "8080"
const filepathRoot = http.Dir(".")

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
}
type params struct {
	Body   string    `json:"body"`
	UserID uuid.UUID `json:"user_id"`
}
type invalidResp struct {
	Error string `json:"error"`
}

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
}
type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	resp := invalidResp{Error: msg}
	dat, err := json.Marshal(resp)
	if err != nil {
		log.Printf("error marshalling response: %s", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(dat)
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	dat, err := json.Marshal(payload)
	if err != nil {
		log.Printf("error marshalling response: %s", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(dat)
}

func filterBadWords(par *params, badWords map[string]bool) {
	splitBody := strings.Split(par.Body, " ")
	for i, word := range splitBody {
		loweredWord := strings.ToLower(word)
		if badWords[loweredWord] {
			splitBody[i] = "****"
		}
	}
	par.Body = strings.Join(splitBody, " ")
}

func main() {
	var apiConfig apiConfig
	// Load ENV
	godotenv.Load()
	dbUrl := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	// Start DB
	db, err := sql.Open("postgres", dbUrl)
	if err != nil {
		log.Fatalf("error opening sql connection: %s", err)
	}
	dbQueries := database.New(db)
	apiConfig.db = dbQueries
	// Start multiplexer and http server
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

	// Reset metrics handle and all users
	mux.HandleFunc("POST /admin/reset", func(w http.ResponseWriter, req *http.Request) {
		if platform != "dev" {
			respondWithJSON(w, 403, "Forbidden")
		} else {
			apiConfig.fileserverHits.Store(0)
			apiConfig.db.DeleteAllUsers(context.Background())
			w.WriteHeader(http.StatusOK)
		}
	})

	// Handle user creation
	mux.HandleFunc("POST /api/users", func(w http.ResponseWriter, req *http.Request) {
		dec := json.NewDecoder(req.Body)
		dbUser := database.User{}
		err := dec.Decode(&dbUser)
		if err != nil {
			log.Fatal("error decoding req")
		}
		dbUser, err = apiConfig.db.CreateUser(req.Context(), dbUser.Email)
		if err != nil {
			log.Fatal("error creating user: %w", err)
		}
		user := User{
			dbUser.ID,
			dbUser.CreatedAt,
			dbUser.UpdatedAt,
			dbUser.Email,
		}
		respondWithJSON(w, 201, user)
	})

	// Handle posting Chips
	mux.HandleFunc("POST /api/chirps", func(w http.ResponseWriter, req *http.Request) {
		badWords := map[string]bool{
			"kerfuffle": true,
			"sharbert":  true,
			"fornax":    true,
		}
		dec := json.NewDecoder(req.Body)
		par := params{}
		err := dec.Decode(&par)
		if err != nil {
			log.Printf("error decoding parameters: %s", err)
			respondWithError(w, 500, "Something went wrong")
			return
		}
		if len(par.Body) <= 140 {
			filterBadWords(&par, badWords)
			user, err := apiConfig.db.GetUserByID(context.Background(), par.UserID)
			if err != nil {
				respondWithError(w, 400, "invalid user id")
			}
			dbChirp, err := apiConfig.db.CreateChirp(req.Context(), database.CreateChirpParams{Body: par.Body, UserID: user.ID})
			if err != nil {
				respondWithError(w, 400, "error creating chirp")
			}
			chirp := Chirp{
				dbChirp.ID,
				dbChirp.CreatedAt,
				dbChirp.UpdatedAt,
				dbChirp.Body,
				dbChirp.UserID,
			}
			respondWithJSON(w, 201, chirp)
		} else {
			respondWithError(w, 400, "Something went wrong")
		}
	})

	// Start server
	log.Printf("Serving files from %s on port: %s\n", filepathRoot, port)
	log.Fatal(httpServer.ListenAndServe())
}
