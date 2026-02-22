package main

import (
	"encoding/json"
	"fmt"
	htmpl "html/template"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"log/slog"
	"os"

	"github.com/gorilla/websocket"
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
			slog.Error("Failed to decode JWT claims", "error", err)
			// Return an error map if JSON decoding fails.
			return map[string]interface{}{"error": fmt.Sprintf("Invalid JWT claims JSON: %v", err)}, claimsSubject
		}
		slog.Info("Parsed JWT claims", "claims", claimsData)
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
	slog.Info("Fetching identity", "url", identityEndpointURL)

	// Prepare headers for the identity request.
	reqHeaders := make(http.Header)
	cfAuthHeader := headers.Get("Cf-Access-Jwt-Assertion")
	cfAuthCookieValue := headers.Get("Cookie")

	// Cloudflare's identity endpoint primarily accepts the CF_Authorization cookie.
	// Prioritize the Cf-Access-Jwt-Assertion header if present, converting it to a cookie.
	if cfAuthHeader != "" {
		reqHeaders.Set("Cookie", fmt.Sprintf("CF_Authorization=%s", cfAuthHeader))
		slog.Info("Forwarding Cf-Access-Jwt-Assertion header as CF_Authorization cookie")
	} else if cfAuthCookieValue != "" {
		// If the assertion header is not present, try to extract CF_Authorization from existing cookies.
		re := regexp.MustCompile(`CF_Authorization=([^;]+)`)
		match := re.FindStringSubmatch(cfAuthCookieValue)
		if len(match) > 1 {
			reqHeaders.Set("Cookie", fmt.Sprintf("CF_Authorization=%s", match[1]))
			slog.Info("Forwarding CF_Authorization cookie")
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

// validateCloudflareIssuer checks that a parsed issuer URL is a legitimate Cloudflare Access
// team domain (https://<team>.cloudflareaccess.com). This prevents SSRF attacks where a
// forged X-Authenticated-Claims-Issuer header could direct the server to make requests to
// arbitrary hosts.
func validateCloudflareIssuer(u *url.URL) error {
	if u.Scheme != "https" {
		return fmt.Errorf("issuer scheme must be https, got %q", u.Scheme)
	}
	// Host must be exactly <one-label>.cloudflareaccess.com with no port.
	host := u.Hostname()
	if !strings.HasSuffix(host, ".cloudflareaccess.com") {
		return fmt.Errorf("issuer host %q is not a cloudflareaccess.com subdomain", host)
	}
	// Ensure there is exactly one label before .cloudflareaccess.com (no nested subdomains).
	prefix := strings.TrimSuffix(host, ".cloudflareaccess.com")
	if prefix == "" || strings.Contains(prefix, ".") {
		return fmt.Errorf("issuer host %q has an unexpected subdomain structure", host)
	}
	return nil
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
		slog.Info("Using issuer from header", "issuer_url", issuerURL)
		parsedIssuer, err := url.Parse(issuerURL)
		if err != nil {
			responseData["cloudflare_identity_error"] = map[string]string{"error": fmt.Sprintf("Invalid issuer URL: %v", err)}
		} else if err := validateCloudflareIssuer(parsedIssuer); err != nil {
			// Reject issuer URLs that do not match the expected Cloudflare Access domain shape
			// to prevent SSRF via a forged X-Authenticated-Claims-Issuer header.
			slog.Warn("Rejecting issuer URL", "issuer_url", issuerURL, "error", err)
			responseData["cloudflare_identity_error"] = map[string]string{"error": fmt.Sprintf("Untrusted issuer URL: %v", err)}
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
						slog.Info("Fetched identity", "email", email, "uuid", uuid)
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

// httpResponsePageData holds the data injected into the HTTP response HTML page.
type httpResponsePageData struct {
	DataJSON htmpl.JS
}

// httpResponsePageTmpl is the HTML template for the HTTP response page.
// It shares the same card-based layout and CSS as the WebSocket demo page.
var httpResponsePageTmpl = htmpl.Must(htmpl.New("http").Parse(httpResponsePageTmplStr))

const httpResponsePageTmplStr = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HTTP Echo Demo</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; background: #f5f5f5; color: #222; padding: 1.5rem; }
  h1 { font-size: 1.25rem; margin-bottom: 1rem; }
  .card { background: #fff; border: 1px solid #ddd; border-radius: 6px; padding: 1rem; margin-bottom: 1rem; }
  .card h2 { font-size: 0.9rem; text-transform: uppercase; letter-spacing: 0.05em; color: #666; margin-bottom: 0.5rem; }
  pre { font-size: 0.8rem; white-space: pre-wrap; word-break: break-all; max-height: 300px; overflow-y: auto; background: #f9f9f9; border-radius: 4px; padding: 0.5rem; }
  #loggedInAs { font-size: 0.9rem; color: #374151; }
  .error { color: #991b1b; }
</style>
</head>
<body>
<h1>HTTP Echo Demo</h1>

<div class="card">
  <h2>Cloudflare Identity</h2>
  <p id="loggedInAs" style="margin-bottom:0.5rem;"></p>
  <pre id="identity">Loading…</pre>
</div>

<div class="card">
  <h2>Full Response Data</h2>
  <pre id="responseData"></pre>
</div>

<script>
var DATA = {{.DataJSON}};
(function () {
  var loggedInAsEl  = document.getElementById('loggedInAs');
  var identityEl    = document.getElementById('identity');
  var responseDataEl = document.getElementById('responseData');

  var identity = DATA.cloudflare_identity;
  if (identity) {
    identityEl.textContent = JSON.stringify(identity, null, 2);
    if (identity.email) {
      loggedInAsEl.textContent = 'Logged in as: ' + identity.email;
    }
  } else if (DATA.cloudflare_identity_error) {
    identityEl.className = 'error';
    identityEl.textContent = JSON.stringify(DATA.cloudflare_identity_error, null, 2);
  } else {
    identityEl.textContent = DATA.cloudflare_identity_info || 'No identity data';
  }

  responseDataEl.textContent = JSON.stringify(DATA, null, 2);
}());
</script>
</body>
</html>
`

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

	// Marshal response data to indented JSON for embedding in the HTML page.
	jsonBytes, err := json.MarshalIndent(responseData, "", "  ")
	if err != nil {
		slog.Error("Failed to marshal response data", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)
	if err := httpResponsePageTmpl.Execute(w, httpResponsePageData{DataJSON: htmpl.JS(jsonBytes)}); err != nil {
		slog.Error("Failed to write HTTP response page", "error", err)
	}
}

// demoPage is the HTML page served at /websocket for plain browser GET requests.
// It auto-connects to the same URL as a WebSocket, displays the authenticated
// Cloudflare identity returned as the first message, and provides an echo chat UI.
const demoPage = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebSocket Echo Demo</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; background: #f5f5f5; color: #222; padding: 1.5rem; }
  h1 { font-size: 1.25rem; margin-bottom: 1rem; }
  .card { background: #fff; border: 1px solid #ddd; border-radius: 6px; padding: 1rem; margin-bottom: 1rem; }
  .card h2 { font-size: 0.9rem; text-transform: uppercase; letter-spacing: 0.05em; color: #666; margin-bottom: 0.5rem; }
  #status { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 999px; font-size: 0.85rem; font-weight: 600; }
  #status.connecting { background: #fef3c7; color: #92400e; }
  #status.connected   { background: #d1fae5; color: #065f46; }
  #status.closed      { background: #fee2e2; color: #991b1b; }
  #identity { font-size: 0.8rem; white-space: pre-wrap; word-break: break-all; max-height: 200px; overflow-y: auto; background: #f9f9f9; border-radius: 4px; padding: 0.5rem; }
  #log { list-style: none; font-size: 0.85rem; max-height: 240px; overflow-y: auto; }
  #log li { padding: 0.25rem 0; border-bottom: 1px solid #f0f0f0; }
  #log li.sent   { color: #1d4ed8; }
  #log li.recv   { color: #065f46; }
  #log li.system { color: #6b7280; font-style: italic; }
  .send-row { display: flex; gap: 0.5rem; margin-top: 0.75rem; }
  .send-row input  { flex: 1; padding: 0.4rem 0.6rem; border: 1px solid #ccc; border-radius: 4px; font-size: 0.9rem; }
  .send-row button { padding: 0.4rem 0.9rem; border: none; border-radius: 4px; cursor: pointer; font-size: 0.9rem; }
  #sendBtn { background: #2563eb; color: #fff; }
  #sendBtn:disabled { background: #93c5fd; cursor: not-allowed; }
  #disconnectBtn { background: #e5e7eb; color: #374151; }
  #disconnectBtn:disabled { opacity: 0.5; cursor: not-allowed; }
  #loggedInAs { font-size: 0.9rem; color: #374151; }
</style>
</head>
<body>
<h1>WebSocket Echo Demo</h1>

<div class="card">
  <h2>Connection</h2>
  <span id="status" class="connecting">Connecting…</span>
  <span id="loggedInAs" style="margin-left:1rem;"></span>
</div>

<div class="card">
  <h2>Cloudflare Identity</h2>
  <pre id="identity">Waiting for server…</pre>
</div>

<div class="card">
  <h2>Echo Log</h2>
  <ul id="log"></ul>
  <div class="send-row">
    <input id="msgInput" type="text" placeholder="Type a message…" disabled />
    <button id="sendBtn" disabled>Send</button>
    <button id="disconnectBtn" disabled>Disconnect</button>
  </div>
</div>

<script>
(function () {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const wsURL = proto + '://' + location.host + '/websocket';

  const statusEl      = document.getElementById('status');
  const loggedInAsEl  = document.getElementById('loggedInAs');
  const identityEl    = document.getElementById('identity');
  const logEl         = document.getElementById('log');
  const msgInput      = document.getElementById('msgInput');
  const sendBtn       = document.getElementById('sendBtn');
  const disconnectBtn = document.getElementById('disconnectBtn');

  let firstMessage = true;
  let ws;

  function setStatus(text, cls) {
    statusEl.textContent = text;
    statusEl.className = cls;
  }

  function appendLog(text, cls) {
    const ts = new Date().toLocaleTimeString();
    const li = document.createElement('li');
    li.className = cls;
    li.textContent = ts + '  ' + text;
    logEl.appendChild(li);
    logEl.scrollTop = logEl.scrollHeight;
  }

  function connect() {
    setStatus('Connecting…', 'connecting');
    appendLog('Connecting to ' + wsURL, 'system');
    ws = new WebSocket(wsURL);

    ws.onopen = function () {
      setStatus('Connected', 'connected');
      appendLog('Connection established', 'system');
      msgInput.disabled = false;
      sendBtn.disabled = false;
      disconnectBtn.disabled = false;
      msgInput.focus();
    };

    ws.onmessage = function (evt) {
      if (firstMessage) {
        firstMessage = false;
        try {
          const data = JSON.parse(evt.data);
          identityEl.textContent = JSON.stringify(data, null, 2);
          const email = data.cloudflare_identity && data.cloudflare_identity.email;
          if (email) {
            loggedInAsEl.textContent = 'Logged in as: ' + email;
          }
        } catch (e) {
          identityEl.textContent = evt.data;
        }
        return;
      }
      appendLog(evt.data, 'recv');
    };

    ws.onclose = function (evt) {
      setStatus('Disconnected', 'closed');
      appendLog('Connection closed (code ' + evt.code + ')', 'system');
      msgInput.disabled = true;
      sendBtn.disabled = true;
      disconnectBtn.disabled = true;
    };

    ws.onerror = function () {
      setStatus('Error', 'closed');
      appendLog('WebSocket error', 'system');
    };
  }

  sendBtn.addEventListener('click', function () {
    const msg = msgInput.value.trim();
    if (!msg || !ws || ws.readyState !== WebSocket.OPEN) return;
    ws.send(msg);
    appendLog(msg, 'sent');
    msgInput.value = '';
    msgInput.focus();
  });

  msgInput.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') sendBtn.click();
  });

  disconnectBtn.addEventListener('click', function () {
    if (ws) ws.close(1000, 'user disconnect');
  });

  connect();
}());
</script>
</body>
</html>
`

// websocketEndpoint handles incoming WebSocket connections.
// For plain browser GET requests (no Upgrade header) it serves an interactive
// HTML demo page that connects back to this same endpoint as a WebSocket.
func websocketEndpoint(w http.ResponseWriter, r *http.Request) {
	slog.Info("WebSocket connection request", "path", r.URL.Path)

	// Serve the browser demo page for plain HTTP GET requests.
	if r.Header.Get("Upgrade") != "websocket" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if _, err := fmt.Fprint(w, demoPage); err != nil {
			slog.Error("Failed to write demo page response", "error", err)
		}
		return
	}

	// Process the request headers to get claims and Cloudflare identity.
	responseData := processRequest(r.Header)
	claimsSubject := r.Header.Get("X-Authenticated-Claims-Subject")
	if claimsSubject == "" {
		claimsSubject = "N/A"
	}

	// Upgrade the HTTP connection to a WebSocket connection.
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("Failed to upgrade WebSocket connection", "error", err)
		return // Exit if upgrade fails.
	}
	defer conn.Close() // Ensure the WebSocket connection is closed when the function exits.

	// Send initial response data (including claims and identity info) to the WebSocket client as JSON.
	if err := conn.WriteJSON(responseData); err != nil {
		slog.Error("Failed to send initial info to WebSocket client", "subject", claimsSubject, "error", err)
		return // Exit if initial send fails.
	}
	slog.Info("Sent initial info to WebSocket client", "subject", claimsSubject)

	// Start a loop to continuously read messages from the WebSocket client.
	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			// Check if the error is a normal WebSocket closure.
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				slog.Info("WebSocket disconnected", "subject", claimsSubject)
			} else {
				slog.Error("WebSocket error", "subject", claimsSubject, "error", err)
			}
			break // Break the loop on any read error (connection closed or broken).
		}
		slog.Info("Received WebSocket message", "subject", claimsSubject, "type", messageType, "message", string(message))

		// Echo the received message back to the client.
		echoMessage := fmt.Sprintf("Echo from server: %s", string(message))
		if err := conn.WriteMessage(messageType, []byte(echoMessage)); err != nil {
			slog.Error("Failed to send echo message", "subject", claimsSubject, "error", err)
			break // Break the loop on any write error.
		}
	}
	slog.Info("WebSocket connection closed", "subject", claimsSubject)
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	// Register HTTP request handlers for different paths.
	// handleHTTPRequest will serve all HTTP GET and POST requests to the root path "/".
	http.HandleFunc("/", handleHTTPRequest)
	// websocketEndpoint will handle WebSocket upgrade requests to the "/websocket" path.
	http.HandleFunc("/websocket", websocketEndpoint)

	// Define the server port.
	port := "8081"
	// Construct the full address for the server to listen on.
	addr := fmt.Sprintf("127.0.0.1:%s", port)

	slog.Info("Starting server", "addr", addr)
	// Start the HTTP server. http.ListenAndServe blocks until the server stops or an error occurs.
	if err := http.ListenAndServe(addr, nil); err != nil {
		// If the server fails to start (e.g., port already in use), log a fatal error.
		slog.Error("Server failed to start", "error", err)
		os.Exit(1)
	}
}
