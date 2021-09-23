package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"github.com/open-policy-agent/frameworks/constraint/pkg/externaldata"
	"github.com/sigstore/cosign/pkg/cosign/kubernetes"
	"github.com/sozercan/cosign-provider/pkg/cosign"
	"go.uber.org/zap"
)

var log logr.Logger

const (
	timeout    = 3 * time.Second
	apiVersion = "externaldata.gatekeeper.sh/v1alpha1"
)

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
	secretKeyRef := os.Getenv("SECRET_NAME")

	requestBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Error(err, "unable to read request body")
		return
	}

	var providerRequest externaldata.ProviderRequest
	err = json.Unmarshal(requestBody, &providerRequest)
	if err != nil {
		log.Error(err, "unable to unmarshal request body")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cfg, err := kubernetes.GetKeyPairSecret(ctx, secretKeyRef)
	if err != nil {
		log.Error(err, "unable to get key pair secret")
		return
	}

	publicKeys := cosign.Keys(cfg.Data)

	results := make([]externaldata.Item, 0)
	for _, key := range providerRequest.Request.Keys {
		isValid := checkSignature(ctx, key.(string), publicKeys)

		if isValid {
			results = append(results, externaldata.Item{
				Key:   key.(string),
				Value: true,
			})
		} else {
			results = append(results, externaldata.Item{
				Key:   key.(string),
				Value: false,
			})
		}
	}

	response := externaldata.ProviderResponse{
		APIVersion: apiVersion,
		Kind:       "ProviderResponse",
		Response: externaldata.Response{
			Items: results,
		},
	}

	w.WriteHeader(http.StatusOK)
	if err = json.NewEncoder(w).Encode(response); err != nil {
		log.Error(err, "unable to encode output")
		return
	}
}

func checkSignature(ctx context.Context, img string, keys []*ecdsa.PublicKey) bool {
	for _, k := range keys {
		sps, err := cosign.Signatures(ctx, img, k)
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
