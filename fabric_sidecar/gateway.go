package main

import (
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/hash"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type invokeRequest struct {
	Contract string   `json:"contract"`
	Function string   `json:"function"`
	Args     []string `json:"args"`
}

type queryRequest struct {
	Contract string   `json:"contract"`
	Function string   `json:"function"`
	Args     []string `json:"args"`
}

func newGatewayClient() (*client.Gateway, *grpc.ClientConn, error) {
	cryptoPath := os.Getenv("FABRIC_CRYPTO_PATH")
	peerEndpoint := os.Getenv("FABRIC_PEER_ENDPOINT")
	gatewayPeer := os.Getenv("FABRIC_GATEWAY_PEER")
	mspID := os.Getenv("FABRIC_MSP_ID")

	if cryptoPath == "" || peerEndpoint == "" {
		return nil, nil, nil
	}
	if gatewayPeer == "" {
		gatewayPeer = "peer0.org1.example.com"
	}
	if mspID == "" {
		mspID = "Org1MSP"
	}

	tlsCertPath := path.Join(cryptoPath, "peers", gatewayPeer, "tls", "ca.crt")
	certificatePEM, err := os.ReadFile(tlsCertPath)
	if err != nil {
		return nil, nil, err
	}
	certificate, err := identity.CertificateFromPEM(certificatePEM)
	if err != nil {
		return nil, nil, err
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(certificate)
	transportCredentials := credentials.NewClientTLSFromCert(certPool, gatewayPeer)

	conn, err := grpc.Dial(peerEndpoint, grpc.WithTransportCredentials(transportCredentials))
	if err != nil {
		return nil, nil, err
	}

	certPath := path.Join(cryptoPath, "users", "User1@org1.example.com", "msp", "signcerts")
	keyPath := path.Join(cryptoPath, "users", "User1@org1.example.com", "msp", "keystore")

	certPEM, err := readFirstFile(certPath)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	cert, err := identity.CertificateFromPEM(certPEM)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	id, err := identity.NewX509Identity(mspID, cert)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	keyPEM, err := readFirstFile(keyPath)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	privateKey, err := identity.PrivateKeyFromPEM(keyPEM)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	gw, err := client.Connect(id,
		client.WithSign(sign),
		client.WithHash(hash.SHA256),
		client.WithClientConnection(conn),
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	return gw, conn, nil
}

func readFirstFile(dirPath string) ([]byte, error) {
	dir, err := os.Open(dirPath)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	names, err := dir.Readdirnames(1)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(names) == 0 {
		return nil, os.ErrNotExist
	}
	return os.ReadFile(path.Join(dirPath, names[0]))
}

func handleInvokeStub(w http.ResponseWriter, r *http.Request) {
	var req invokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
		return
	}
	if req.Contract == "" || req.Function == "" {
		http.Error(w, `{"error":"contract and function required"}`, http.StatusBadRequest)
		return
	}
	// Stub: simulate success for all invoke calls (no Fabric)
	stubResult := map[string]string{
		"status": "stub", "contract": req.Contract, "function": req.Function,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"result": string(mustMarshal(stubResult))})
}

func mustMarshal(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

func handleInvoke(gw *client.Gateway, w http.ResponseWriter, r *http.Request) {
	var req invokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
		return
	}
	if req.Contract == "" || req.Function == "" {
		http.Error(w, `{"error":"contract and function required"}`, http.StatusBadRequest)
		return
	}

	channel := os.Getenv("FABRIC_CHANNEL")
	if channel == "" {
		channel = "public-marketplace"
	}
	chaincode := os.Getenv("FABRIC_CHAINCODE_NAME")
	if chaincode == "" {
		chaincode = "dscm"
	}

	network := gw.GetNetwork(channel)
	// Multi-contract chaincode: "chaincodeName:contractName"
	contractID := chaincode
	if req.Contract != "" {
		contractID = chaincode + ":" + req.Contract
	}
	contract := network.GetContract(contractID)

	args := make([]string, len(req.Args))
	copy(args, req.Args)

	result, err := contract.SubmitTransaction(req.Function, args...)
	if err != nil {
		log.Printf("Invoke error: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"result": string(result)})
}

func handleQuery(gw *client.Gateway, w http.ResponseWriter, r *http.Request) {
	contractName := r.URL.Query().Get("contract")
	function := r.URL.Query().Get("function")
	if contractName == "" || function == "" {
		http.Error(w, `{"error":"contract and function query params required"}`, http.StatusBadRequest)
		return
	}
	var args []string
	if a := r.URL.Query().Get("args"); a != "" {
		json.Unmarshal([]byte(a), &args)
	}

	channel := os.Getenv("FABRIC_CHANNEL")
	if channel == "" {
		channel = "public-marketplace"
	}
	chaincode := os.Getenv("FABRIC_CHAINCODE_NAME")
	if chaincode == "" {
		chaincode = "dscm"
	}

	network := gw.GetNetwork(channel)
	contractID := chaincode
	if contractName != "" {
		contractID = chaincode + ":" + contractName
	}
	contract := network.GetContract(contractID)

	result, err := contract.EvaluateTransaction(function, args...)
	if err != nil {
		log.Printf("Query error: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"result": string(result)})
}
