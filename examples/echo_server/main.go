package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

// upgrader is a global WebSocket upgrader. It defines how WebSocket connections are handled,
// including read/write buffer sizes and origin checking.
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024, // Buffer size for reading messages from the WebSocket connection
	WriteBufferSize: 1024, // Buffer size for writing messages to the WebSocket connection
	CheckOrigin: func(r *http.Request) bool {
		// IMPORTANT: For production environments, you should implement stricter origin checking
		// to prevent cross-site WebSocket hijacking. For this example, we allow all origins.
		return true
	},
}

// parseJWTClaims extracts and parses JWT claims from HTTP headers.
// It looks for "X-Authenticated-Claims-Subject" and "X-Authenticated-Claims-JSON".
func parseJWTClaims(headers http.Header) (map[string]interface{}, string) {
	// Get the claims subject, defaulting to "N/A" if not found.
	claimsSubject := headers.Get("X-Authenticated-Claims-Subject")
	if claimsSubject == "" {
		claimsSubject = "N/A"
	}

	// Get the JSON string containing the claims.
	claimsJSONStr := headers.Get("X-Authenticated-Claims-JSON")
	if claimsJSONStr != "" {
		var claimsData map[string]interface{}
		// Attempt to unmarshal the JSON string into a map.
		if err := json.Unmarshal([]byte(claimsJSONStr), &claimsData); err != nil {
			log.Errorf("Failed to decode JWT claims: %v", err)
			// Return an error map if JSON decoding fails.
			return map[string]interface{}{"error": fmt.Sprintf("Invalid JWT claims JSON: %v", err)}, claimsSubject
		}
		log.Infof("Parsed JWT claims: %+v", claimsData)
		return claimsData, claimsSubject
	}

	// If no claims JSON string is present, return an empty map.
	return make(map[string]interface{}), claimsSubject
}

// fetchCloudflareIdentity fetches Cloudflare identity details from the Cloudflare Access
// identity endpoint, using authentication information from the request headers.
func fetchCloudflareIdentity(headers http.Header, cfAccessBaseURL string) (map[string]interface{}, error) {
	// Construct the identity endpoint URL.
	identityEndpointURL := fmt.Sprintf("%s/cdn-cgi/access/get-identity", cfAccessBaseURL)
	log.Infof("Fetching identity from: %s", identityEndpointURL)

	// Prepare headers for the identity request.
	reqHeaders := make(http.Header)
	cfAuthHeader := headers.Get("Cf-Access-Jwt-Assertion")
	cfAuthCookieValue := headers.Get("Cookie")

	// Cloudflare's identity endpoint primarily accepts the CF_Authorization cookie.
	// Prioritize the Cf-Access-Jwt-Assertion header if present, converting it to a cookie.
	if cfAuthHeader != "" {
		reqHeaders.Set("Cookie", fmt.Sprintf("CF_Authorization=%s", cfAuthHeader))
		log.Infof("Forwarding Cf-Access-Jwt-Assertion header as CF_Authorization cookie")
	} else if cfAuthCookieValue != "" {
		// If the assertion header is not present, try to extract CF_Authorization from existing cookies.
		re := regexp.MustCompile(`CF_Authorization=([^;]+)`)
		match := re.FindStringSubmatch(cfAuthCookieValue)
		if len(match) > 1 {
			reqHeaders.Set("Cookie", fmt.Sprintf("CF_Authorization=%s", match[1]))
			log.Infof("Forwarding CF_Authorization cookie")
		} else {
			// If CF_Authorization cookie is not found, return an error.
			return nil, fmt.Errorf("CF_Authorization cookie not found in existing cookies")
		}
	} else {
		// If neither a JWT assertion header nor a CF_Authorization cookie is found, return an error.
		return nil, fmt.Errorf("missing Cloudflare Access authentication token")
	}

	// Create an HTTP client with a timeout.
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodGet, identityEndpointURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create identity request: %w", err)
	}
	req.Header = reqHeaders // Set the prepared headers on the request.

	// Execute the HTTP request.
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network error during identity fetch: %w", err)
	}
	defer resp.Body.Close() // Ensure the response body is closed.

	// Check for non-200 HTTP status codes.
	if resp.StatusCode != http.StatusOK {
		// Read a portion of the body for error details if available.
		bodyBytes := make([]byte, 1024)
		n, _ := resp.Body.Read(bodyBytes) // Read up to 1KB for error context.
		return nil, fmt.Errorf("HTTP error %d from identity endpoint, details: %s", resp.StatusCode, string(bodyBytes[:n]))
	}

	// Decode the JSON response into a map.
	var identityData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&identityData); err != nil {
		return nil, fmt.Errorf("failed to decode identity response JSON: %w", err)
	}

	return identityData, nil
}

// processRequest encapsulates common logic for processing both HTTP and WebSocket requests,
// including parsing JWT claims and fetching Cloudflare identity.
func processRequest(headers http.Header) map[string]interface{} {
	claimsData, claimsSubject := parseJWTClaims(headers)

	// Initialize the response data map.
	responseData := map[string]interface{}{
		"message":              fmt.Sprintf("Request processed for subject: %s", claimsSubject),
		"authenticated_claims": claimsData,
	}

	// Get the issuer URL from the header. This is typically provided by the proxy.
	issuerURL := headers.Get("X-Authenticated-Claims-Issuer")
	if issuerURL != "" {
		log.Infof("Using issuer from header: %s", issuerURL)
		parsedIssuer, err := url.Parse(issuerURL)
		if err != nil {
			responseData["cloudflare_identity_error"] = map[string]string{"error": fmt.Sprintf("Invalid issuer URL: %v", err)}
		} else {
			// Construct the base URL for Cloudflare Access.
			cfBaseURL := fmt.Sprintf("%s://%s", parsedIssuer.Scheme, parsedIssuer.Host)
			identityResult, err := fetchCloudflareIdentity(headers, cfBaseURL)
			if err != nil {
				// If there's an error fetching identity, store it in the response.
				responseData["cloudflare_identity_error"] = map[string]string{"error": err.Error()}
			} else {
				// If successful, store the identity data.
				responseData["cloudflare_identity"] = identityResult
				// Log specific identity details if available.
				if email, ok := identityResult["email"].(string); ok {
					if uuid, ok := identityResult["user_uuid"].(string); ok {
						log.Infof("Fetched identity: %s, UUID: %s", email, uuid)
					}
				}
			}
		}
	} else {
		// If the issuer header is missing, note it in the response.
		responseData["cloudflare_identity_info"] = "X-Authenticated-Claims-Issuer header not found"
	}

	return responseData
}

// handleHTTPRequest processes incoming HTTP GET/POST requests.
func handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
	// Process the request headers to get claims and Cloudflare identity.
	responseData := processRequest(r.Header)

	// Convert http.Header (map[string][]string) to a simpler map[string]string
	// for inclusion in the JSON response, joining multiple values with ", ".
	receivedHeaders := make(map[string]string)
	for name, values := range r.Header {
		receivedHeaders[name] = strings.Join(values, ", ")
	}
	responseData["received_headers"] = receivedHeaders

	// Determine the HTTP status code. If there's an error in authenticated claims, return 500.
	statusCode := http.StatusOK
	if claimsError, ok := responseData["authenticated_claims"].(map[string]interface{}); ok {
		if _, hasError := claimsError["error"]; hasError {
			statusCode = http.StatusInternalServerError
		}
	}

	// Set the Content-Type header to application/json.
	w.Header().Set("Content-Type", "application/json")
	// Write the determined status code to the response.
	w.WriteHeader(statusCode)
	// Encode the response data to JSON and write it to the HTTP response body.
	if err := json.NewEncoder(w).Encode(responseData); err != nil {
		log.Errorf("Failed to write HTTP response: %v", err)
	}
}

// websocketEndpoint handles incoming WebSocket connections.
func websocketEndpoint(w http.ResponseWriter, r *http.Request) {
	log.Infof("WebSocket connection request for path: %s", r.URL.Path)

	// Process the request headers to get claims and Cloudflare identity.
	responseData := processRequest(r.Header)
	claimsSubject := r.Header.Get("X-Authenticated-Claims-Subject")
	if claimsSubject == "" {
		claimsSubject = "N/A"
	}

	// Upgrade the HTTP connection to a WebSocket connection.
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Errorf("Failed to upgrade WebSocket connection: %v", err)
		return // Exit if upgrade fails.
	}
	defer conn.Close() // Ensure the WebSocket connection is closed when the function exits.

	// Send initial response data (including claims and identity info) to the WebSocket client as JSON.
	if err := conn.WriteJSON(responseData); err != nil {
		log.Errorf("Failed to send initial info to WebSocket client for subject %s: %v", claimsSubject, err)
		return // Exit if initial send fails.
	}
	log.Infof("Sent initial info to WebSocket client for subject: %s", claimsSubject)

	// Start a loop to continuously read messages from the WebSocket client.
	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			// Check if the error is a normal WebSocket closure.
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Infof("WebSocket disconnected for subject: %s", claimsSubject)
			} else {
				log.Errorf("WebSocket error for subject %s: %v", claimsSubject, err)
			}
			break // Break the loop on any read error (connection closed or broken).
		}
		log.Infof("Received message from %s (type %d): %s", claimsSubject, messageType, string(message))

		// Echo the received message back to the client.
		echoMessage := fmt.Sprintf("Echo from server: %s", string(message))
		if err := conn.WriteMessage(messageType, []byte(echoMessage)); err != nil {
			log.Errorf("Failed to send echo message to subject %s: %v", claimsSubject, err)
			break // Break the loop on any write error.
		}
	}
	log.Infof("WebSocket connection closed for subject: %s", claimsSubject)
}

func main() {
	// Register HTTP request handlers for different paths.
	// handleHTTPRequest will serve all HTTP GET and POST requests to the root path "/".
	http.HandleFunc("/", handleHTTPRequest)
	// websocketEndpoint will handle WebSocket upgrade requests to the "/websocket" path.
	http.HandleFunc("/websocket", websocketEndpoint)

	// Define the server port.
	port := "8081"
	// Construct the full address for the server to listen on.
	addr := fmt.Sprintf("127.0.0.1:%s", port)

	log.Infof("Starting server on %s", addr)
	// Start the HTTP server. http.ListenAndServe blocks until the server stops or an error occurs.
	if err := http.ListenAndServe(addr, nil); err != nil {
		// If the server fails to start (e.g., port already in use), log a fatal error.
		log.Fatalf("Server failed to start: %v", err)
	}
}
