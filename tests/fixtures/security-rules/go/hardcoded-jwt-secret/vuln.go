package main
import "github.com/golang-jwt/jwt"
func sign(a jwt.SigningMethod, c jwt.Claims) (string, error) {
  return jwt.NewWithClaims(a, c).SignedString([]byte("supersecret"))
}
