package auth

import (
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Print("error encrypting the password: %w", err)
	}
	return string(hashedPassword), err
}

func CheckPasswordHash(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	now := time.Now().UTC()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(expiresIn)),
		Subject:   userID.String(),
	})
	tokenString, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", fmt.Errorf("error signing JWT: %w", err)
	}
	return tokenString, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	parsedToken, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() == jwt.SigningMethodHS256.Alg() {
			return []byte(tokenSecret), nil
		}
		return uuid.UUID{}, fmt.Errorf("invalid signing method")
	})
	if err != nil {
		return uuid.Nil, err
	}
	if !parsedToken.Valid {
		return uuid.Nil, fmt.Errorf("invalid token")
	}
	claims, ok := parsedToken.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return uuid.Nil, fmt.Errorf("invalid claims type")
	}
	userId, err := claims.GetSubject()
	if err != nil {
		return uuid.Nil, err
	}
	parsedId, err := uuid.Parse(userId)
	if err != nil {
		return uuid.Nil, err
	}
	return parsedId, nil

}
