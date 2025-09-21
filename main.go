package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/virean196/chirpy/internal/auth"
	"github.com/virean196/chirpy/internal/database"
)

const port = "8080"
const filepathRoot = http.Dir(".")

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	jwtSecret      string
	polkaAPIKey    string
}
type params struct {
	Body string `json:"body"`
}
type invalidResp struct {
	Error string `json:"error"`
}
type userReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type response struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	IsChirpRed   bool      `json:"is_chirpy_red"`
}
type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

type polkaReq struct {
	Event string `json:"event"`
	Data  struct {
		UserID uuid.UUID `json:"user_id"`
	}
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
	apiConfig.jwtSecret = os.Getenv("SECRET_KEY")
	apiConfig.polkaAPIKey = os.Getenv("POLKA_KEY")
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
		userReq := userReq{}
		err := dec.Decode(&userReq)
		if err != nil {
			log.Fatal("error decoding req")
		}
		pw, err := auth.HashPassword(userReq.Password)
		if err != nil {
			log.Fatal("error hashing password: %w", err)
		}
		dbUser, err := apiConfig.db.CreateUser(req.Context(), database.CreateUserParams{
			Email:          userReq.Email,
			HashedPassword: pw,
		})
		if err != nil {
			log.Fatal("error creating user: %w", err)
		}
		if err != nil {
			respondWithError(w, 400, "error getting bearer token")
			return
		}
		resp := response{
			dbUser.ID,
			dbUser.CreatedAt,
			dbUser.UpdatedAt,
			dbUser.Email,
			"",
			"",
			dbUser.IsChirpyRed,
		}
		respondWithJSON(w, 201, resp)
	})

	// Handle updating (PUT) users
	mux.HandleFunc("PUT /api/users", func(w http.ResponseWriter, r *http.Request) {
		decoder := json.NewDecoder(r.Body)
		params := userReq{}
		err := decoder.Decode(&params)
		if err != nil {
			respondWithError(w, 401, "invalid request")
			return
		}
		jwt, err := auth.GetBearerToken(r.Header)
		if err != nil {
			respondWithError(w, 401, "invalid authorization header")
			return
		}
		user_id, err := auth.ValidateJWT(jwt, apiConfig.jwtSecret)
		if err != nil {
			respondWithError(w, 401, "no user with token")
			return
		}
		hashed_password, err := auth.HashPassword(params.Password)
		if err != nil {
			respondWithError(w, 400, "error hashing the password")
			return
		}
		err = apiConfig.db.UpdateUserInfo(context.Background(), database.UpdateUserInfoParams{ID: user_id, Email: params.Email, HashedPassword: hashed_password})
		if err != nil {
			respondWithError(w, 401, "error updating user info")
			return
		}
		db_user, err := apiConfig.db.GetUserByID(context.Background(), user_id)
		if err != nil {
			respondWithError(w, 401, "error getting user by id")
			return
		}
		respondWithJSON(w, 200, userReq{Email: db_user.Email, Password: db_user.HashedPassword})
	})

	// Handle POST Login
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, req *http.Request) {
		dec := json.NewDecoder(req.Body)
		par := userReq{}
		err := dec.Decode(&par)
		if err != nil {
			log.Printf("error decoding request body: %s", err)
		}
		dbUser, err := apiConfig.db.GetUserByEmail(req.Context(), par.Email)
		if err != nil {
			respondWithError(w, 401, "Incorrect email or password")
			return
		}
		err = auth.CheckPasswordHash(dbUser.HashedPassword, par.Password)
		//log.Printf("Hashed Password: %s\nPassword being checked: %s\nResult: %s", dbUser.HashedPassword, par.Password, err)
		if err != nil {
			respondWithError(w, 401, "Incorrect email or password")
			return
		} else {
			refresh_token, err := auth.MakeRefreshToken()
			if err != nil {
				respondWithError(w, 400, "error creating refresh token")
				return
			}
			apiConfig.db.CreateRefreshToken(context.Background(), database.CreateRefreshTokenParams{
				Token:  refresh_token,
				UserID: dbUser.ID,
			})
			jwt, err := auth.MakeJWT(dbUser.ID, apiConfig.jwtSecret)
			if err != nil {
				respondWithError(w, 400, "error creating jwt")
				return
			}
			respUser := response{
				dbUser.ID,
				dbUser.CreatedAt,
				dbUser.UpdatedAt,
				dbUser.Email,
				jwt,
				refresh_token,
				dbUser.IsChirpyRed,
			}
			respondWithJSON(w, 200, respUser)
		}
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
			token, err := auth.GetBearerToken(req.Header)
			if err != nil {
				respondWithError(w, 401, "invalid or missing auth token")
				return
			}
			userID, err := auth.ValidateJWT(token, apiConfig.jwtSecret)
			if err != nil {
				respondWithError(w, 401, "invalid auth token")
				return
			}
			dbChirp, err := apiConfig.db.CreateChirp(req.Context(), database.CreateChirpParams{Body: par.Body, UserID: userID})
			if err != nil {
				respondWithError(w, 400, "error creating chirp")
				return
			}
			chirp := Chirp{
				dbChirp.ID,
				dbChirp.CreatedAt,
				dbChirp.UpdatedAt,
				dbChirp.Body,
				dbChirp.UserID,
			}
			respondWithJSON(w, 201, chirp)
			return
		} else {
			respondWithError(w, 400, "Something went wrong")
			return
		}
	})

	// Handle GET Chirps
	mux.HandleFunc("GET /api/chirps", func(w http.ResponseWriter, req *http.Request) {
		author_query := req.URL.Query().Get("author_id")
		sort_query := req.URL.Query().Get("sort")
		var chirpList []Chirp
		if author_query != "" {
			id, err := uuid.Parse(author_query)
			if err != nil {
				respondWithError(w, 401, "error parsing author id")
				return
			}
			chirps, err := apiConfig.db.GetChirpsByAuthor(context.Background(), id)
			if err != nil {
				respondWithError(w, 404, "no chirps found for that author")
				return
			}
			for _, chirp := range chirps {
				chirpList = append(chirpList, Chirp(chirp))
			}
			respondWithJSON(w, 200, chirpList)
			return
		}
		chirps, err := apiConfig.db.GetChirps(context.Background())
		if err != nil {
			respondWithError(w, 400, "error getting chirps")
			return
		}
		if sort_query != "" && strings.ToLower(sort_query) == "desc" {
			sort.Slice(chirps, func(i, j int) bool {
				return chirps[i].CreatedAt.After(chirps[j].CreatedAt)
			})
			for _, chirp := range chirps {
				chirpList = append(chirpList, Chirp(chirp))
			}
			respondWithJSON(w, 200, chirpList)
			return
		}
		for _, chirp := range chirps {
			chirpList = append(chirpList, Chirp(chirp))
		}
		respondWithJSON(w, 200, chirpList)
	})

	// Handle GET Single Chirp
	mux.HandleFunc("GET /api/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("chirpID"))
		if err != nil {
			respondWithError(w, 400, "invalid id")
			return
		}
		dbChirp, err := apiConfig.db.GetChirpById(context.Background(), id)
		if err != nil {
			respondWithError(w, 404, "no chirp with that id found")
			return
		}
		chirp := Chirp{
			dbChirp.ID,
			dbChirp.CreatedAt,
			dbChirp.UpdatedAt,
			dbChirp.Body,
			dbChirp.UserID,
		}

		respondWithJSON(w, 200, chirp)
	})

	// Handle deleting chirps
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", func(w http.ResponseWriter, r *http.Request) {
		chirp_id, err := uuid.Parse(r.PathValue("chirpID"))
		if err != nil {
			respondWithError(w, 400, "invalid chirp id")
			return
		}
		jwt, err := auth.GetBearerToken(r.Header)
		if err != nil {
			respondWithError(w, 401, "invalid bearer header")
			return
		}
		user_id, err := auth.ValidateJWT(jwt, apiConfig.jwtSecret)
		if err != nil {
			respondWithError(w, 404, "user not found for token")
			return
		}
		chirp, err := apiConfig.db.GetChirpById(context.Background(), chirp_id)
		if err != nil {
			respondWithError(w, 404, "chirp not found")
			return
		}
		if chirp.UserID == user_id {
			err = apiConfig.db.DeleteChirpById(context.Background(), chirp_id)
			if err != nil {
				respondWithError(w, 400, "error deleting chirp")
				return
			}
			respondWithJSON(w, 204, "")
		} else {
			respondWithError(w, 403, "user is not owner of chirp")
			return
		}
	})

	// Handle Refresh Tokens
	mux.HandleFunc("POST /api/refresh", func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			respondWithError(w, 400, "error getting bearer token")
			return
		}
		user, err := apiConfig.db.GetUserFromRefreshToken(context.Background(), token)
		if err != nil {
			respondWithError(w, 401, "invalid token")
			return
		}
		refresh_token, err := apiConfig.db.GetRefreshToken(context.Background(), token)
		if err != nil {
			respondWithError(w, 401, "invalid token")
			return
		}
		if refresh_token.RevokedAt.Valid {
			respondWithError(w, 401, "invalid token")
			return
		}
		jwt, err := auth.MakeJWT(user.ID, apiConfig.jwtSecret)
		if err != nil {
			respondWithError(w, 200, "error creating jwt")
			return
		}
		type tokenResp struct {
			Token string `json:"token"`
		}
		respondWithJSON(w, 200, tokenResp{Token: jwt})
	})

	// Handle Revoking Refresh Tokens
	mux.HandleFunc("POST /api/revoke", func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			respondWithError(w, 400, "error getting bearer token")
			return
		}
		err = apiConfig.db.RevokeRefreshToken(context.Background(), token)
		if err != nil {
			respondWithError(w, 400, "error revoking refresh token")
			return
		}
		err = apiConfig.db.UpdateRefreshTokenUpdated_At(context.Background(), token)
		if err != nil {
			respondWithError(w, 400, "error updating token")
			return
		}
		respondWithJSON(w, 204, "")
	})

	// Handle membership upgrade
	mux.HandleFunc("POST /api/polka/webhooks", func(w http.ResponseWriter, r *http.Request) {
		apiKey, err := auth.GetAPIKey(r.Header)
		if err != nil {
			respondWithError(w, 401, "invalid auth header")
			return
		}
		if apiKey == apiConfig.polkaAPIKey {
			polkaRequest := polkaReq{}
			dec := json.NewDecoder(r.Body)
			err = dec.Decode(&polkaRequest)
			if err != nil {
				respondWithError(w, 401, "invalid request body")
				return
			}
			if polkaRequest.Event != "user.upgraded" {
				respondWithError(w, 204, "invalid event")
				return
			}
			dbUser, err := apiConfig.db.GetUserByID(context.Background(), polkaRequest.Data.UserID)
			if err != nil {
				respondWithError(w, 404, "no user found")
				return
			}
			err = apiConfig.db.UpgradeToChirpyRedById(context.Background(), dbUser.ID)
			if err != nil {
				respondWithError(w, 204, "error updating chirp")
				return
			}
			apiConfig.db.UpdateUpdatedAtById(context.Background(), dbUser.ID)
			respondWithJSON(w, 204, "user upgraded")
		} else {
			respondWithError(w, 401, "invalid api key")
			return
		}
	})

	// Start server
	log.Printf("Serving files from %s on port: %s\n", filepathRoot, port)
	log.Fatal(httpServer.ListenAndServe())
}
