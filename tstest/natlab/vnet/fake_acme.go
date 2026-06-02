// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vnet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

type fakeACMEServer struct {
	baseURL string

	mu        sync.Mutex
	rootKey   *ecdsa.PrivateKey
	rootDER   []byte
	nextID    int64
	lookupTXT func(string) []string
	orders    map[string]*fakeACMEOrder
	authzs    map[string]*fakeACMEAuthz
	certsPEM  map[string][]byte
}

type fakeACMEOrder struct {
	id          string
	status      string
	identifiers []fakeACMEIdentifier
	authzURLs   []string
	finalizeURL string
	certURL     string
}

type fakeACMEAuthz struct {
	id         string
	status     string
	identifier fakeACMEIdentifier
	challenge  fakeACMEChallenge
}

type fakeACMEIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type fakeACMEChallenge struct {
	URL    string `json:"url"`
	Type   string `json:"type"`
	Token  string `json:"token"`
	Status string `json:"status"`
}

func newFakeACMEServer(baseURL string) *fakeACMEServer {
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		panic(fmt.Sprintf("vnet: generating fake ACME root key: %v", err))
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "natlab fake ACME root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(fmt.Sprintf("vnet: creating fake ACME root: %v", err))
	}
	return &fakeACMEServer{
		baseURL:  strings.TrimRight(baseURL, "/"),
		rootKey:  key,
		rootDER:  der,
		nextID:   1,
		orders:   map[string]*fakeACMEOrder{},
		authzs:   map[string]*fakeACMEAuthz{},
		certsPEM: map[string][]byte{},
	}
}

func (s *fakeACMEServer) directoryURL() string {
	return s.baseURL + "/directory"
}

func (s *fakeACMEServer) rootPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.rootDER})
}

func (s *fakeACMEServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", time.Now().UnixNano()))
	switch {
	case r.Method == "GET" && r.URL.Path == "/directory":
		writeACMEJSON(w, http.StatusOK, map[string]string{
			"newNonce":   s.baseURL + "/new-nonce",
			"newAccount": s.baseURL + "/new-account",
			"newOrder":   s.baseURL + "/new-order",
			"revokeCert": s.baseURL + "/revoke-cert",
		})
	case (r.Method == "HEAD" || r.Method == "GET") && r.URL.Path == "/new-nonce":
		w.WriteHeader(http.StatusOK)
	case r.Method == "POST" && r.URL.Path == "/new-account":
		s.serveNewAccount(w, r)
	case r.Method == "POST" && r.URL.Path == "/new-order":
		s.serveNewOrder(w, r)
	case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/authz/"):
		s.serveAuthz(w, r)
	case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/challenge/"):
		s.serveChallenge(w, r)
	case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/order/") && strings.HasSuffix(r.URL.Path, "/finalize"):
		s.serveFinalize(w, r)
	case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/order/"):
		s.serveOrder(w, r)
	case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/cert/"):
		s.serveCert(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *fakeACMEServer) serveNewAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OnlyReturnExisting bool `json:"onlyReturnExisting"`
	}
	if err := decodeJWSPayload(r, &req); err != nil {
		io.Copy(io.Discard, r.Body)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.OnlyReturnExisting {
		writeACMEJSON(w, http.StatusBadRequest, map[string]any{
			"status": http.StatusBadRequest,
			"type":   "urn:ietf:params:acme:error:accountDoesNotExist",
			"detail": "account does not exist",
		})
		return
	}
	w.Header().Set("Location", s.baseURL+"/account/1")
	writeACMEJSON(w, http.StatusCreated, map[string]string{"status": "valid"})
}

func (s *fakeACMEServer) serveNewOrder(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Identifiers []fakeACMEIdentifier `json:"identifiers"`
	}
	if err := decodeJWSPayload(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	orderID := s.allocIDLocked()
	orderURL := s.baseURL + "/order/" + orderID
	o := &fakeACMEOrder{
		id:          orderID,
		status:      "pending",
		identifiers: req.Identifiers,
		finalizeURL: orderURL + "/finalize",
	}
	for _, ident := range req.Identifiers {
		authzID := s.allocIDLocked()
		chalID := s.allocIDLocked()
		chal := fakeACMEChallenge{
			URL:    s.baseURL + "/challenge/" + chalID,
			Type:   "dns-01",
			Token:  "token-" + chalID,
			Status: "pending",
		}
		az := &fakeACMEAuthz{
			id:         authzID,
			status:     "pending",
			identifier: ident,
			challenge:  chal,
		}
		authzURL := s.baseURL + "/authz/" + authzID
		s.authzs[authzID] = az
		o.authzURLs = append(o.authzURLs, authzURL)
	}
	s.orders[orderID] = o
	w.Header().Set("Location", orderURL)
	writeACMEJSON(w, http.StatusCreated, s.orderResponseLocked(o))
}

func (s *fakeACMEServer) serveAuthz(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/authz/")
	s.mu.Lock()
	defer s.mu.Unlock()
	az := s.authzs[id]
	if az == nil {
		http.NotFound(w, r)
		return
	}
	writeACMEJSON(w, http.StatusOK, s.authzResponseLocked(az))
}

func (s *fakeACMEServer) serveChallenge(w http.ResponseWriter, r *http.Request) {
	// Keep issuance pending long enough for `tailscale cert` to print the
	// cert-pending health warning it is watching for.
	time.Sleep(3 * time.Second)

	id := strings.TrimPrefix(r.URL.Path, "/challenge/")
	s.mu.Lock()
	defer s.mu.Unlock()
	var az *fakeACMEAuthz
	for _, a := range s.authzs {
		if strings.TrimPrefix(a.challenge.URL, s.baseURL+"/challenge/") == id {
			az = a
			break
		}
	}
	if az == nil {
		http.NotFound(w, r)
		return
	}
	name := "_acme-challenge." + strings.TrimPrefix(az.identifier.Value, "*.")
	if s.lookupTXT == nil || len(s.lookupTXT(name)) == 0 {
		writeACMEProblem(w, http.StatusForbidden, "dns TXT record not found")
		return
	}
	az.status = "valid"
	az.challenge.Status = "valid"
	s.updateOrdersLocked()
	writeACMEJSON(w, http.StatusOK, az.challenge)
}

func (s *fakeACMEServer) serveOrder(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/order/")
	id = strings.TrimSuffix(id, "/finalize")
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.orders[id]
	if o == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Location", s.baseURL+"/order/"+id)
	writeACMEJSON(w, http.StatusOK, s.orderResponseLocked(o))
}

func (s *fakeACMEServer) serveFinalize(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/order/"), "/finalize")
	var req struct {
		CSR string `json:"csr"`
	}
	if err := decodeJWSPayload(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	csrDER, err := base64.RawURLEncoding.DecodeString(req.CSR)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := csr.CheckSignature(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.orders[id]
	if o == nil {
		http.NotFound(w, r)
		return
	}
	if o.status != "ready" && o.status != "valid" {
		writeACMEProblem(w, http.StatusForbidden, "order is not ready")
		return
	}
	certPEM, err := s.issueCertLocked(csr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	certID := s.allocIDLocked()
	o.status = "valid"
	o.certURL = s.baseURL + "/cert/" + certID
	s.certsPEM[certID] = certPEM
	w.Header().Set("Location", s.baseURL+"/order/"+id)
	writeACMEJSON(w, http.StatusOK, s.orderResponseLocked(o))
}

func (s *fakeACMEServer) serveCert(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/cert/")
	s.mu.Lock()
	cert := append([]byte(nil), s.certsPEM[id]...)
	s.mu.Unlock()
	if len(cert) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	w.Write(cert)
}

func (s *fakeACMEServer) allocIDLocked() string {
	id := s.nextID
	s.nextID++
	return fmt.Sprint(id)
}

func (s *fakeACMEServer) updateOrdersLocked() {
	for _, o := range s.orders {
		if o.status != "pending" {
			continue
		}
		ready := true
		for _, u := range o.authzURLs {
			id := strings.TrimPrefix(u, s.baseURL+"/authz/")
			if s.authzs[id].status != "valid" {
				ready = false
			}
		}
		if ready {
			o.status = "ready"
		}
	}
}

func (s *fakeACMEServer) orderResponseLocked(o *fakeACMEOrder) any {
	return struct {
		Status         string               `json:"status"`
		Identifiers    []fakeACMEIdentifier `json:"identifiers"`
		Authorizations []string             `json:"authorizations"`
		Finalize       string               `json:"finalize"`
		Certificate    string               `json:"certificate,omitempty"`
	}{
		Status:         o.status,
		Identifiers:    o.identifiers,
		Authorizations: o.authzURLs,
		Finalize:       o.finalizeURL,
		Certificate:    o.certURL,
	}
}

func (s *fakeACMEServer) authzResponseLocked(az *fakeACMEAuthz) any {
	return struct {
		Status     string              `json:"status"`
		Identifier fakeACMEIdentifier  `json:"identifier"`
		Challenges []fakeACMEChallenge `json:"challenges"`
	}{
		Status:     az.status,
		Identifier: az.identifier,
		Challenges: []fakeACMEChallenge{az.challenge},
	}
}

func (s *fakeACMEServer) issueCertLocked(csr *x509.CertificateRequest) ([]byte, error) {
	serial := big.NewInt(time.Now().UnixNano())
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     csr.DNSNames,
	}
	root, err := x509.ParseCertificate(s.rootDER)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, root, csr.PublicKey, s.rootKey)
	if err != nil {
		return nil, err
	}
	var b []byte
	b = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	b = append(b, s.rootPEM()...)
	return b, nil
}

func decodeJWSPayload(r *http.Request, v any) error {
	var jws struct {
		Payload string `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
		return err
	}
	if jws.Payload == "" {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, v)
}

func writeACMEJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeACMEProblem(w http.ResponseWriter, code int, detail string) {
	writeACMEJSON(w, code, map[string]any{
		"status": code,
		"type":   "urn:ietf:params:acme:error:rejectedIdentifier",
		"detail": detail,
	})
}
