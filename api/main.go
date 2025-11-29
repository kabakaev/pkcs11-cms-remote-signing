package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

type SignRequest struct {
	Data      string `json:"file"`
	Mechanism string `json:"mechanism"`
}

type SignResponse struct {
	Signature string `json:"signature"`
	Error     string `json:"error,omitempty"`
}

var privateKey *ecdsa.PrivateKey

func init() {
	// Read private key from file
	pemData, err := os.ReadFile("private_key.pem")
	if err != nil {
		log.Fatalf("Failed to read private key file: %v", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		log.Fatalf("Failed to decode PEM block containing private key")
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			log.Fatalf("Failed to parse EC private key: %v", err)
		}
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			log.Fatalf("Failed to parse PKCS#8 private key: %v", err)
		}
		var ok bool
		privateKey, ok = key.(*ecdsa.PrivateKey)
		if !ok {
			log.Fatalf("Private key is not ECDSA")
		}
	default:
		log.Fatalf("Unsupported key type: %s", block.Type)
	}
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/sign", handleSign)
	mux.HandleFunc("/certificate", handleCertificate)

	handler := authMiddleware(mux)

	log.Println("Starting server on :42180")
	log.Fatal(http.ListenAndServe(":42180", handler))
}

func authMiddleware(next http.Handler) http.Handler {
	authEnv := os.Getenv("PKCS11_SHIM_AUTH")
	if authEnv == "" {
		return next
	}

	// Parse "Name:Value"
	idx := strings.Index(authEnv, ":")
	if idx == -1 {
		log.Printf("Invalid PKCS11_SHIM_AUTH format. Expected 'Name:Value'. Ignoring auth.")
		return next
	}

	headerName := authEnv[:idx]
	headerValue := authEnv[idx+1:]

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(headerName) != headerValue {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		http.Error(w, "Invalid base64 data", http.StatusBadRequest)
		return
	}

	// Write data to temp file
	tmpFile, err := os.CreateTemp("", "tbs")
	if err != nil {
		http.Error(w, "Failed to create temp file", http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.Write(data); err != nil {
		http.Error(w, "Failed to write temp file", http.StatusInternalServerError)
		return
	}
	tmpFile.Close()

	// Sign using openssl pkeyutl
	cmd := exec.Command("openssl", "pkeyutl", "-sign", "-inkey", "private_key.pem", "-in", tmpFile.Name())
	output, err := cmd.Output()
	if err != nil {
		log.Printf("openssl error: %v", err)
		if exitErr, ok := err.(*exec.ExitError); ok {
			log.Printf("openssl stderr: %s", exitErr.Stderr)
		}
		http.Error(w, "Failed to sign", http.StatusInternalServerError)
		return
	}

	rInt, sInt, err := parseECDSASignature(output)
	if err != nil {
		log.Printf("Failed to parse DER signature: %v", err)
		http.Error(w, "Failed to parse signature", http.StatusInternalServerError)
		return
	}

	params := privateKey.Curve.Params()
	curveOrderByteSize := (params.N.BitLen() + 7) / 8

	rBytes := rInt.Bytes()
	sBytes := sInt.Bytes()

	// Pad to curve order size
	signature := make([]byte, 2*curveOrderByteSize)
	copy(signature[curveOrderByteSize-len(rBytes):curveOrderByteSize], rBytes)
	copy(signature[2*curveOrderByteSize-len(sBytes):], sBytes)

	resp := SignResponse{
		Signature: base64.StdEncoding.EncodeToString(signature),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func parseECDSASignature(der []byte) (*big.Int, *big.Int, error) {
	var sig struct {
		R, S *big.Int
	}
	_, err := asn1.Unmarshal(der, &sig)
	return sig.R, sig.S, err
}

type CertificateResponse struct {
	Certificate string `json:"certificate"`
}

func handleCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read public key (certificate) from file
	pemData, err := os.ReadFile("public_key.pem")
	if err != nil {
		log.Printf("Failed to read public key file: %v", err)
		http.Error(w, "Failed to read certificate", http.StatusInternalServerError)
		return
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		log.Printf("Failed to decode PEM block")
		http.Error(w, "Failed to decode certificate", http.StatusInternalServerError)
		return
	}

	// Return base64 encoded DER
	resp := CertificateResponse{
		Certificate: base64.StdEncoding.EncodeToString(block.Bytes),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
