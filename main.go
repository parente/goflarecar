// main.go
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	gojose_jwt "github.com/go-jose/go-jose/v4/jwt"
	log "github.com/sirupsen/logrus"
)

const (
	// CF_JWKS_URL_ENV is the environment variable for the Cloudflare JWKS URL, the signing keys
	// for Cloudflare Access JWTs.
	CF_JWKS_URL_ENV = "CF_JWKS_URL"
	// CF_ISSUER_URL_ENV is the environment variable for the issuer URL of the Cloudflare Access
	// team domain, https:// <your-team-name>.cloudflareaccess.com
	CF_ISSUER_URL_ENV = "CF_ISSUER_URL"
	// CF_AUDIENCE_TAG_ENV is the environment variable for the expected audience of the JWT.
	CF_AUDIENCE_TAG_ENV = "CF_AUDIENCE_TAG"
	// UPSTREAM_APP_URL_ENV is the environment variable for the URL of the upstream application
	UPSTREAM_APP_URL_ENV = "UPSTREAM_APP_URL"

	// PROXY_LISTEN_ADDR_ENV is the environment variable for the address where the proxy listens
	// (default: :8080 if unset)
	PROXY_LISTEN_ADDR_ENV = "PROXY_LISTEN_ADDR"
	// PROXY_PASS_JSON_CLAIMS_ENV is the environment variable to control whether the proxy passes
	// validated JWT claims to the upstream application via a JSON header. (default: false if unset)
	PROXY_PASS_JSON_CLAIMS_ENV = "PROXY_PASS_JSON_CLAIMS"

	// JWKS_REFRESH_INTERVAL is how often the proxy will refresh the JWKS from Cloudflare
	JWKS_REFRESH_INTERVAL = 5 * time.Minute
)

var (
	jwtKeySet *jose.JSONWebKeySet // Cached JWKS for validating JWTs
	jwksMutex sync.RWMutex        // Mutex to protect access to jwtKeySet
)

// proxyHandler is a custom HTTP handler that encapsulates the proxy logic,
// including JWT authentication and WebSocket handling.
type proxyHandler struct {
	reverseProxy     *httputil.ReverseProxy
	upstreamURL      *url.URL
	expectedIssuer   *string
	expectedAudience *gojose_jwt.Audience
	passJSONClaims   bool
}

// ServeHTTP handles incoming HTTP requests and WebSocket upgrade requests.
func (h *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Infof("Incoming request: %s %s from %s", r.Method, r.URL, r.RemoteAddr)

	// Perform JWT validation.
	// If this function returns false, it means authentication failed, and
	// the function has already sent an HTTP error response.
	if !h.authenticate(w, r) {
		return // Authentication failed, stop processing
	}

	// Check if it's a WebSocket upgrade request
	if isWebSocketUpgrade(r) {
		log.Infof("Detected WebSocket upgrade request for %s. Handling...", r.URL)
		h.handleWebSocket(w, r)
		return
	}

	// If not a WebSocket upgrade, proceed with standard HTTP proxying
	log.Infof("Request authenticated for user with subject: %s. Proxying HTTP request to upstream.",
		r.Header.Get("X-Authenticated-Claims-Subject"))
	h.reverseProxy.ServeHTTP(w, r)
}

// isWebSocketUpgrade checks if the incoming request is a WebSocket upgrade request.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.ToLower(r.Header.Get("Connection")) == "upgrade" &&
		strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
}

// handleWebSocket proxies WebSocket connections.
func (h *proxyHandler) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Construct the upstream WebSocket URL
	// The scheme needs to be 'ws' or 'wss'
	wsScheme := "ws"
	if h.upstreamURL.Scheme == "https" {
		wsScheme = "wss"
	}
	upstreamWSURL := url.URL{
		Scheme:   wsScheme,
		Host:     h.upstreamURL.Host,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
	}

	// Create a new HTTP request for the upstream WebSocket connection.
	// This request will be sent to the actual WebSocket server.
	upstreamReq, err := http.NewRequest(r.Method, upstreamWSURL.String(), r.Body)
	if err != nil {
		log.Infof("Error creating upstream WebSocket request: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Copy all headers from the original client request to the upstream request,
	// especially the Upgrade and Connection headers for the handshake.
	for key, values := range r.Header {
		for _, value := range values {
			upstreamReq.Header.Add(key, value)
		}
	}

	// Establish a dialer for the upstream connection
	dialer := net.Dialer{}
	upstreamConn, err := dialer.Dial("tcp", h.upstreamURL.Host) // Dial raw TCP to upstream
	if err != nil {
		log.Errorf("Error dialing upstream WebSocket target %s: %v", h.upstreamURL.Host, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer upstreamConn.Close()

	// Send the WebSocket upgrade request to the upstream server
	err = upstreamReq.Write(upstreamConn)
	if err != nil {
		log.Errorf("Error writing WebSocket upgrade request to upstream: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Hijack the client connection. This takes control of the underlying TCP connection
	// and prevents http.Server from automatically closing it.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Error("HTTP server does not support hijacking connection")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Errorf("Error hijacking client connection: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	// Do NOT defer clientConn.Close() here. The goroutines below will manage the connections.
	// The clientConn will be closed when io.Copy on one side finishes or errors.

	// New: Create a buffered reader for the upstream connection
	upstreamReader := bufio.NewReader(upstreamConn)

	// Read the upstream response (WebSocket handshake response)
	resp, err := http.ReadResponse(upstreamReader, upstreamReq)
	if err != nil {
		log.Infof("Error reading upstream WebSocket handshake response: %v", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		err := clientConn.Close() // Close client if upstream handshake fails
		if err != nil {
			log.Warnf("Error closing client connection after upstream handshake failure: %v", err)
		}
		return
	}
	defer resp.Body.Close()

	// Write the upstream's WebSocket handshake response headers to the client
	// This completes the client-side WebSocket handshake.
	err = resp.Write(clientConn) // Use resp.Write to write full response to clientConn
	if err != nil {
		log.Infof("Error writing WebSocket handshake response to client: %v", err)
		err := clientConn.Close()
		if err != nil {
			log.Warnf("Error closing client connection after writing handshake response: %v", err)
		}
		return
	}

	// Now that the handshake is complete, copy data bidirectionally between client and upstream.
	log.Infof("WebSocket handshake successful. Starting bidirectional data streaming between %s and %s", clientConn.RemoteAddr(), upstreamConn.RemoteAddr())

	// Use a WaitGroup to ensure both copy goroutines are done before logging connection close.
	var wg sync.WaitGroup
	wg.Add(2)

	// Client to Upstream
	go func() {
		defer wg.Done()
		defer upstreamConn.Close() // Close upstream when done copying from client
		defer clientConn.Close()   // Close client when done copying from client side (if not already closed)
		_, err := io.Copy(upstreamConn, clientConn)
		if err != nil && err != io.EOF {
			log.Infof("Error copying from client to upstream WebSocket: %v", err)
		}
	}()

	// Upstream to Client
	go func() {
		defer wg.Done()
		defer clientConn.Close()                      // Close client when done copying from upstream
		defer upstreamConn.Close()                    // Close upstream when done copying from upstream side (if not already closed)
		_, err := io.Copy(clientConn, upstreamReader) // Use the buffered reader here
		if err != nil && err != io.EOF {
			log.Infof("Error copying from upstream to client WebSocket: %v", err)
		}
	}()

	wg.Wait() // Wait for both copy operations to finish
	log.Infof("WebSocket connection closed for %s.", r.URL)
}

func main() {
	// --- 1. Load Configuration from Environment Variables ---
	cfIssuerURL := os.Getenv(CF_ISSUER_URL_ENV)
	if cfIssuerURL == "" {
		log.Fatalf("Error: %s environment variable not set. This is the URL to the Cloudflare Access issuer endpoint (e.g., https://<your-team-name>.cloudflareaccess.com)", CF_ISSUER_URL_ENV)
	}
	cfAudTag := os.Getenv(CF_AUDIENCE_TAG_ENV)
	if cfAudTag == "" {
		log.Fatalf("Error: %s environment variable not set. This should be the audience tag for your Cloudflare Access application.", CF_AUDIENCE_TAG_ENV)
	}

	upstreamAppURL := os.Getenv(UPSTREAM_APP_URL_ENV)
	if upstreamAppURL == "" {
		log.Fatalf("Error: %s environment variable not set. This should be the URL of your third-party application (e.g., http://localhost:8081).", UPSTREAM_APP_URL_ENV)
	}
	upstreamURL, err := url.Parse(upstreamAppURL)
	if err != nil {
		log.Fatalf("Error parsing upstream application URL '%s': %v", upstreamAppURL, err)
	}

	proxyPassJSONClaims := false // Default to not passing validated JSON claims
	passClaimsEnv := strings.ToLower(os.Getenv(PROXY_PASS_JSON_CLAIMS_ENV))
	if passClaimsEnv == "yes" || passClaimsEnv == "true" || passClaimsEnv == "1" {
		proxyPassJSONClaims = true
	}
	proxyListenAddr := os.Getenv(PROXY_LISTEN_ADDR_ENV)
	if proxyListenAddr == "" {
		proxyListenAddr = ":8080" // Default listen address for the proxy
	}

	log.Infof("Proxy configured to expect issuer: %s, audience: %s", cfIssuerURL, cfAudTag)
	log.Infof("Proxy configured to pass validated JSON claims to upstream: %t", proxyPassJSONClaims)

	// --- 2. Start Periodic JWKS Fetching ---
	// This goroutine will periodically fetch the latest JWKS from Cloudflare.
	// This is crucial for handling key rotations without restarting the proxy.
	cfJwksURL, err := url.JoinPath(cfIssuerURL, "/cdn-cgi/access/certs")
	if err != nil {
		log.Fatalf("Error constructing JWKS URL from issuer URL '%s': %v", cfIssuerURL, err)
	}
	log.Infof("Starting periodic JWKS fetch every %s from %s", JWKS_REFRESH_INTERVAL, cfJwksURL)
	go fetchJwksPeriodically(cfJwksURL, JWKS_REFRESH_INTERVAL)

	// --- 3. Setup the Reverse Proxy for standard HTTP requests ---
	// Create a new ReverseProxy instance.
	rp := httputil.NewSingleHostReverseProxy(upstreamURL)

	// Preserve the original director for standard HTTP requests.
	originalDirector := rp.Director
	rp.Director = func(req *http.Request) {
		originalDirector(req) // Call the original director first
		// Note: HTTP headers injected by `authenticate` are already on the request.
	}

	// Custom error handler for standard HTTP reverse proxy.
	rp.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		log.Errorf("Standard HTTP reverse proxy error for %s %s: %v", req.Method, req.URL, err)
		http.Error(rw, "Bad Gateway", http.StatusBadGateway)
	}

	// --- 4. Create and Register the custom proxy handler ---
	handler := &proxyHandler{
		reverseProxy:     rp,
		upstreamURL:      upstreamURL,
		expectedIssuer:   &cfIssuerURL,
		expectedAudience: &gojose_jwt.Audience{cfAudTag},
		passJSONClaims:   proxyPassJSONClaims,
	}

	// --- 5. Start the Proxy Server ---
	log.Infof("Proxy starting on %s, proxying to %s", proxyListenAddr, upstreamAppURL)
	log.Fatal(http.ListenAndServe(proxyListenAddr, handler)) // Use the custom handler
}

// fetchJwksPeriodically fetches JWKS from Cloudflare at a regular interval.
func fetchJwksPeriodically(jwksURL string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Fetch immediately on startup to ensure keys are available.
	fetchJwks(jwksURL)

	// Continue fetching at the specified interval.
	for range ticker.C {
		fetchJwks(jwksURL)
	}
}

// fetchJwks fetches the JSON Web Key Set from the given URL and updates the global cache.
func fetchJwks(jwksURL string) {
	log.Infof("Attempting to fetch JWKS from %s ...", jwksURL)

	// Create a context with a timeout for the HTTP request.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		log.Infof("Error creating JWKS request: %v", err)
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Infof("Error fetching JWKS from %s: %v", jwksURL, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Infof("Error fetching JWKS from %s: received unexpected status code %d", jwksURL, resp.StatusCode)
		return
	}

	var newJwks jose.JSONWebKeySet // Use go-jose's JWKS type
	if err := json.NewDecoder(resp.Body).Decode(&newJwks); err != nil {
		log.Infof("Error decoding JWKS from %s: %v", jwksURL, err)
		return
	}

	// Acquire a write lock to update the shared JWKS cache.
	jwksMutex.Lock()
	jwtKeySet = &newJwks
	jwksMutex.Unlock()
	log.Infoln("JWKS fetched and updated successfully.")
}

// authenticate extracts and validates the Cloudflare Access JWT, then injects its claims into headers.
// It returns true if the request is successfully authenticated; otherwise, it sends
// an appropriate HTTP error response and returns false.
func (h *proxyHandler) authenticate(w http.ResponseWriter, r *http.Request) bool {
	// Cloudflare Access JWT is typically in the 'Cf-Access-Jwt-Assertion' header
	// or the 'CF_Authorization' cookie.
	tokenString := r.Header.Get("Cf-Access-Jwt-Assertion")
	if tokenString == "" {
		// If header is not present, check the cookie.
		if cookie, err := r.Cookie("CF_Authorization"); err == nil {
			tokenString = cookie.Value
		}
	}

	if tokenString == "" {
		log.Info("Authentication Failed: No Cloudflare Access JWT found in 'Cf-Access-Jwt-Assertion' header or 'CF_Authorization' cookie.")
		http.Error(w, "Unauthorized: Cloudflare Access JWT missing", http.StatusUnauthorized)
		return false
	}

	// Define allowed signing algorithms for the JWT.
	// Cloudflare Access typically uses RS256 or ES256. Include others if your IdP might use them.
	allowedSignatureAlgorithms := []jose.SignatureAlgorithm{
		jose.RS256, jose.ES256, jose.RS384, jose.ES384, jose.RS512, jose.ES512,
	}

	// Parse the JWT using go-jose/jwt.
	// With v4, it's recommended to provide expected algorithms during parsing.
	parsedJWT, err := gojose_jwt.ParseSigned(tokenString, allowedSignatureAlgorithms)
	if err != nil {
		log.Infof("Authentication Failed: JWT parsing error: %v", err)
		http.Error(w, fmt.Sprintf("Unauthorized: Invalid JWT format or unexpected algorithm: %v", err), http.StatusUnauthorized)
		return false
	}

	// Acquire a read lock to access the cached JWKS for validation.
	jwksMutex.RLock()
	defer jwksMutex.RUnlock()

	if jwtKeySet == nil || len(jwtKeySet.Keys) == 0 {
		log.Warn("Authentication Failed: JWKS not loaded or is empty. Cannot validate JWT.")
		http.Error(w, "Unauthorized: JWKS not available for validation", http.StatusUnauthorized)
		return false
	}

	// Validate the JWT against the cached JWKS and populate the claims struct.
	// This method handles finding the correct key by 'kid' and verifying the signature.
	var claims gojose_jwt.Claims
	if err := parsedJWT.Claims(jwtKeySet, &claims); err != nil {
		log.Infof("Authentication Failed: JWT validation error: %v", err)
		http.Error(w, fmt.Sprintf("Unauthorized: JWT validation failed: %v", err), http.StatusUnauthorized)
		return false
	}

	// Check standard claims for expiration, issuer, audience.
	expected := gojose_jwt.Expected{
		Issuer:      *h.expectedIssuer,
		AnyAudience: *h.expectedAudience,
		Time:        time.Now(),
	}
	if err := claims.Validate(expected); err != nil {
		log.Infof("Authentication Failed: JWT claims validation error: %v", err)
		http.Error(w, fmt.Sprintf("Unauthorized: JWT claims invalid: %v", err), http.StatusUnauthorized)
		return false
	}

	// Add the issuer and subject headers to the origin request to indicate that the claims have
	// been authenticated by the proxy. This alone does not guarantee authentication unless traffic
	// can only reach the upstream application through this proxy.
	r.Header.Set("X-Authenticated-Claims-Issuer", claims.Issuer)
	if claims.Subject != "" {
		r.Header.Set("X-Authenticated-Claims-Subject", claims.Subject)
		log.Infof("Authentication Succeeded for user with subject: %s. JWT Claims injected.", claims.Subject)
	} else {
		log.Infoln("Authentication Succeeded. JWT Claims injected (subject not present).")
	}

	// Optionally marshal the full claims object to JSON and add it to a header.
	// This allows the upstream application to easily access all validated claims if traffic has
	// been restricted to only go through this proxy.
	if h.passJSONClaims {
		claimsJSON, err := json.Marshal(claims)
		if err != nil {
			log.Errorf("Warning: Error marshalling JWT claims to JSON: %v. Skipping X-Authenticated-Claims-JSON header.", err)
		} else {
			// Ensure the headers are set on the *original request* `r`
			// so they are passed to the upstream when `proxy.ServeHTTP` is called.
			r.Header.Set("X-Authenticated-Claims-JSON", string(claimsJSON))
		}
	}

	return true // Authentication successful
}
