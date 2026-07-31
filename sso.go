package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// CallbackPayload represents the incoming SSO session parameters from browser redirect
type CallbackPayload struct {
	Token  string `json:"token"`
	EncKey string `json:"enc_key"`
}

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
		// Enable CORS
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var payload CallbackPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Bad request payload", http.StatusBadRequest)
			serverErr = fmt.Errorf("failed to parse callback body: %w", err)
			cancel()
			return
		}

		if payload.Token == "" || payload.EncKey == "" {
			http.Error(w, "Missing credentials parameters", http.StatusBadRequest)
			serverErr = fmt.Errorf("empty sso parameters received")
			cancel()
			return
		}

		// Decode the encryption key
		keyBytes, err := base64Decode(payload.EncKey)
		if err != nil {
			// Fallback: try hex decoding if base64 fails (React frontend might pass hex)
			keyBytes, err = hexDecode(payload.EncKey)
			if err != nil {
				http.Error(w, "Invalid key encoding", http.StatusBadRequest)
				serverErr = fmt.Errorf("failed to decode encryption key: %w", err)
				cancel()
				return
			}
		}

		token = payload.Token
		encKey = keyBytes

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))

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
