package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/sigstore/cosign/pkg/cosign/kubernetes"
	"github.com/sozercan/cosign-provider/pkg/provider"
)

func main() {
	fmt.Println("starting server...")
	http.HandleFunc("/validate", validate)

	http.ListenAndServe(":8090", nil)
}

func validate(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	secretKeyRef := "k8s://default/cosign-secret"

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	cfg, err := kubernetes.GetKeyPairSecret(ctx, secretKeyRef)
	if err != nil {
		panic(err)
	}

	keys := provider.Keys(cfg.Data)

	if !valid(ctx, string(body), keys) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode("invalid")
	} else {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode("valid")
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
