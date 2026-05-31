package main
import "github.com/golang-jwt/jwt"
func sign(a jwt.SigningMethod, c jwt.Claims, key []byte) (string, error) {
  return jwt.NewWithClaims(a, c).SignedString(key)
}
