package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// startSSOServer runs a temporary web listener on localhost to capture OAuth token
func startSSOServer(port string) (string, []byte, error) {
	mux := http.NewServeMux()
	
	// Create context that we can cancel to shutdown server on success/error
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var token string
	var encKey []byte
	var serverErr error

	// Listen on port 8500 on all interfaces to support container loopback routing (WSL)
	listener, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		return "", nil, fmt.Errorf("failed to bind local callback port %s: %w", port, err)
	}

	server := &http.Server{
		Handler:      mux,
		WriteTimeout: 10 * time.Second,
		ReadTimeout:  10 * time.Second,
	}

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		// Handle GET redirect from browser (industry standard: GitHub CLI, Azure CLI approach)
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Extract credentials from query parameters
		receivedToken := r.URL.Query().Get("token")
		receivedKey := r.URL.Query().Get("enc_key")

		if receivedToken == "" || receivedKey == "" {
			http.Error(w, "Missing credentials parameters", http.StatusBadRequest)
			serverErr = fmt.Errorf("empty sso parameters received")
			cancel()
			return
		}

		// Decode the encryption key (React sends hex via bytesToHex)
		keyBytes, err := hexDecode(receivedKey)
		if err != nil {
			// Fallback: try base64 decoding
			keyBytes, err = base64Decode(receivedKey)
			if err != nil {
				http.Error(w, "Invalid key encoding", http.StatusBadRequest)
				serverErr = fmt.Errorf("failed to decode encryption key: %w", err)
				cancel()
				return
			}
		}

		token = receivedToken
		encKey = keyBytes

		// Return a friendly HTML success page to the browser
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Xora CLI - Authorized</title>
<style>
body {
	font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
	display: flex;
	align-items: center;
	justify-content: center;
	height: 100vh;
	margin: 0;
	background: #0f111a;
	color: #e2e8f0;
}
.card {
	text-align: center;
	padding: 2.5rem;
	border-radius: 1.25rem;
	background: #181b28;
	border: 1px solid #282f46;
	box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
	max-width: 400px;
	width: 85%;
}
.icon-container {
	position: relative;
	width: 64px;
	height: 64px;
	margin: 0 auto 1.5rem auto;
}
.pulse-circle {
	position: absolute;
	top: 0; left: 0;
	width: 100%; height: 100%;
	border-radius: 50%;
	background: rgba(0, 229, 255, 0.08);
	animation: pulse 2s infinite ease-in-out;
}
.icon {
	position: relative;
	width: 64px;
	height: 64px;
	color: #00e5ff;
	filter: drop-shadow(0 0 8px rgba(0, 229, 255, 0.3));
}
h2 {
	color: #ffffff;
	font-size: 1.5rem;
	font-weight: 700;
	margin: 0 0 0.75rem 0;
}
p {
	color: #94a3b8;
	font-size: 0.9rem;
	line-height: 1.5;
	margin: 0;
}
@keyframes pulse {
	0% { transform: scale(0.9); opacity: 0.6; }
	50% { transform: scale(1.15); opacity: 1; }
	100% { transform: scale(0.9); opacity: 0.6; }
}
</style></head>
<body><div class="card">
<div class="icon-container">
	<div class="pulse-circle"></div>
	<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
		<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
		<path d="M9.5 9.5l5 5"/>
		<path d="M14.5 9.5l-5 5"/>
	</svg>
</div>
<h2>Authentication Complete</h2>
<p>You have logged in to the XoraPass CLI. You can close this window and return to your terminal.</p>
</div></body></html>`))

		// Signal success and trigger server shutdown
		cancel()
	})

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			serverErr = err
			cancel()
		}
	}()

	// Wait for callback handler to signal context completion
	<-ctx.Done()

	// Shutdown the server cleanly
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)

	if serverErr != nil {
		return "", nil, serverErr
	}

	return token, encKey, nil
}

// openBrowser opens the system default web browser
func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		// Check if we are running in WSL
		if _, wsl := os.LookupEnv("WSL_DISTRO_NAME"); wsl {
			err = exec.Command("powershell.exe", "-Command", "Start-Process", fmt.Sprintf(`"%s"`, url)).Start()
		} else {
			err = exec.Command("xdg-open", url).Start()
		}
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	}

	if err != nil {
		fmt.Printf("Could not open browser automatically. Please navigate to:\n%s\n", url)
	}
}
