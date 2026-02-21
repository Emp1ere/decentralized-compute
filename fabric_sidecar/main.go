// Fabric Sidecar — прокси к Hyperledger Fabric (ADR 001).
// Эндпоинты: POST /chaincode/invoke, GET /chaincode/query
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"google.golang.org/grpc"
)

func main() {
	cryptoPath := os.Getenv("FABRIC_CRYPTO_PATH")
	var gw *client.Gateway
	var conn *grpc.ClientConn
	if cryptoPath != "" {
		var err error
		gw, conn, err = newGatewayClient()
		if err != nil || gw == nil {
			if err != nil {
				log.Printf("Fabric gateway init failed: %v — running in stub mode", err)
			}
			gw, conn = nil, nil
		} else {
			defer conn.Close()
			defer gw.Close()
			log.Println("Fabric gateway connected")
		}
	} else {
		log.Println("FABRIC_CRYPTO_PATH not set — running in stub mode")
	}

	mode := "stub"
	if gw != nil {
		mode = "fabric"
	}

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"mode":    mode,
			"version": "dscm-sidecar-v1",
		})
	})

	http.HandleFunc("/chaincode/invoke", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if gw == nil {
			handleInvokeStub(w, r)
			return
		}
		handleInvoke(gw, w, r)
	})

	http.HandleFunc("/chaincode/query", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if gw == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"stub": true, "message": "Fabric not configured"})
			return
		}
		handleQuery(gw, w, r)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "7051"
	}
	log.Printf("Fabric Sidecar listening on :%s (mode=%s)", port, mode)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
