package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/go-logr/logr"
	"github.com/sigstore/cosign/pkg/cosign/kubernetes"
	"github.com/sozercan/cosign-provider/pkg/provider"
	"go.uber.org/zap"
	"github.com/go-logr/zapr"
)

var log logr.Logger

func main() {
	zapLog, err := zap.NewDevelopment()
	if err != nil {
		panic(fmt.Sprintf("unable to initialize logger: %v", err))
	}
	log = zapr.NewLogger(zapLog)
	log.WithName("cosign-provider")

	log.Info("starting server...")
	http.HandleFunc("/validate", validate)

	if err = http.ListenAndServe(":8090", nil); err != nil {
		panic(err)
	}
}

func validate(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	secretKeyRef := os.Getenv("SECRET_NAME")

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Error(err, "unable to read request body")
		return
	}

	ctx := context.Background()
	cfg, err := kubernetes.GetKeyPairSecret(ctx, secretKeyRef)
	if err != nil {
		log.Error(err, "unable to get key pair secret")
		return
	}

	keys := provider.Keys(cfg.Data)

	if !valid(ctx, string(body), keys) {
		w.WriteHeader(http.StatusOK)
		if err = json.NewEncoder(w).Encode("invalid"); err != nil {
			log.Error(err, "unable to encode output")
			return
		}
	} else {
		w.WriteHeader(http.StatusOK)
		if err = json.NewEncoder(w).Encode("valid"); err != nil {
			log.Error(err, "unable to encode output")
			return
		}
	}
}

func valid(ctx context.Context, img string, keys []*ecdsa.PublicKey) bool {
	for _, k := range keys {
		sps, err := provider.Signatures(ctx, img, k)
		if err != nil {
			fmt.Printf("error while checking signature on image %s. error: %s\n", err, img)
			return false
		}
		if len(sps) > 0 {
			fmt.Printf("valid signatures on image %s with key %s\n", img, k)
			return true
		}
	}
	return false
}
