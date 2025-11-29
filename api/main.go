package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
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
	Hash      string `json:"hash"`
	Mechanism string `json:"mechanism"`
}

type SignResponse struct {
	Signature string `json:"signature"`
	Error     string `json:"error,omitempty"`
}

var ecPrivateKey *ecdsa.PrivateKey
var rsaPrivateKey *rsa.PrivateKey

func init() {
	// Load EC private key
	if pemData, err := os.ReadFile("ec_private_key.pem"); err == nil {
		block, _ := pem.Decode(pemData)
		if block != nil {
			switch block.Type {
			case "EC PRIVATE KEY":
				ecPrivateKey, _ = x509.ParseECPrivateKey(block.Bytes)
			case "PRIVATE KEY":
				key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
				if err == nil {
					ecPrivateKey, _ = key.(*ecdsa.PrivateKey)
				}
			}
		}
		if ecPrivateKey != nil {
			log.Println("Loaded EC private key")
		}
	}

	// Load RSA private key
	if pemData, err := os.ReadFile("rsa_private_key.pem"); err == nil {
		block, _ := pem.Decode(pemData)
		if block != nil {
			switch block.Type {
			case "RSA PRIVATE KEY":
				rsaPrivateKey, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
			case "PRIVATE KEY":
				key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
				if err == nil {
					rsaPrivateKey, _ = key.(*rsa.PrivateKey)
				}
			}
		}
		if rsaPrivateKey != nil {
			log.Println("Loaded RSA private key")
		}
	}
}

func main() {
	mux := http.NewServeMux()
	
	// EC endpoints
	mux.HandleFunc("/sign_ec", handleSignEC)
	mux.HandleFunc("/cert_ec", handleCertificateEC)
	
	// RSA endpoints
	mux.HandleFunc("/sign_rsa", handleSignRSA)
	mux.HandleFunc("/cert_rsa", handleCertificateRSA)
	
	// Legacy endpoints (EC for backward compatibility)
	mux.HandleFunc("/sign", handleSignEC)
	mux.HandleFunc("/certificate", handleCertificateEC)

	handler := authMiddleware(mux)

	log.Println("Starting server on :27180")
	log.Fatal(http.ListenAndServe(":27180", handler))
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

func handleSignEC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if ecPrivateKey == nil {
		http.Error(w, "EC private key not loaded", http.StatusInternalServerError)
		return
	}

	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	data, err := base64.StdEncoding.DecodeString(req.Hash)
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
	cmd := exec.Command("openssl", "pkeyutl", "-sign", "-inkey", "ec_private_key.pem", "-in", tmpFile.Name(), "-pkeyopt", "digest:sha512")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("openssl error: %v", err)
		if exitErr, ok := err.(*exec.ExitError); ok {
			log.Printf("openssl stderr: %s", exitErr.Stderr)
		}
		http.Error(w, "Failed to sign", http.StatusInternalServerError)
		return
	}

	// OpenSSL's `pkeyutl -sign` returns ECDSA signatures in DER-encoded ASN.1 format:
	//
	//	SEQUENCE { INTEGER r, INTEGER s }
	//
	// where r and s are variable-length (e.g., 47-49 bytes each for P-384, depending on leading zeros).
	//
	// PKCS#11 (and thus the pkcs11-provider) expects ECDSA signatures in raw format:
	// fixed-size r and s values concatenated together, each padded to the curve's order size.
	// For P-384 (48-byte order): r (48 bytes) || s (48 bytes) = 96 bytes total.
	rInt, sInt, err := parseECDSASignature(output)
	if err != nil {
		log.Printf("Failed to parse DER signature: %v", err)
		http.Error(w, "Failed to parse signature", http.StatusInternalServerError)
		return
	}

	params := ecPrivateKey.Curve.Params()
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

func handleSignRSA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if rsaPrivateKey == nil {
		http.Error(w, "RSA private key not loaded", http.StatusInternalServerError)
		return
	}

	var req SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	data, err := base64.StdEncoding.DecodeString(req.Hash)
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

	// Sign using openssl pkeyutl with RSA PKCS#1 v1.5
	cmd := exec.Command("openssl", "pkeyutl", "-sign", "-inkey", "rsa_private_key.pem", "-in", tmpFile.Name(), "-pkeyopt", "digest:sha512")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("openssl error: %v", err)
		if exitErr, ok := err.(*exec.ExitError); ok {
			log.Printf("openssl stderr: %s", exitErr.Stderr)
		}
		http.Error(w, "Failed to sign", http.StatusInternalServerError)
		return
	}

	// RSA signature is returned as-is (raw bytes)
	resp := SignResponse{
		Signature: base64.StdEncoding.EncodeToString(output),
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

func handleCertificateEC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	serveCertificate(w, "ec_cert.pem")
}

func handleCertificateRSA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	serveCertificate(w, "rsa_cert.pem")
}

func serveCertificate(w http.ResponseWriter, filename string) {
	pemData, err := os.ReadFile(filename)
	if err != nil {
		log.Printf("Failed to read certificate file %s: %v", filename, err)
		http.Error(w, "Failed to read certificate", http.StatusInternalServerError)
		return
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		log.Printf("Failed to decode PEM block from %s", filename)
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
