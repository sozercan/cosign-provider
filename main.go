package main

import (
	"crypto/ecdsa"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/sozercan/cosign-provider/pkg/provider"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func main() {
	fmt.Println("starting server...")
	http.HandleFunc("/validate", validate)

	http.ListenAndServe(":8090", nil)
}

func validate(w http.ResponseWriter, req *http.Request) {

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		panic(err)
	}

	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	cfg := provider.Config(clientset)

	keys := provider.Keys(cfg.Data)

	if !valid(string(body), keys) {
		fmt.Fprintf(w, "invalid")
	}

	fmt.Fprintf(w, "valid")
}

func valid(img string, keys []*ecdsa.PublicKey) bool {
	for _, k := range keys {
		sps, err := provider.Signatures(img, k)
		if err != nil {
			fmt.Printf("error while checking signature on image %s. error: %s", err, img)
			return false
		}
		if len(sps) > 0 {
			fmt.Printf("valid signatures on image %s with key %s", img, k)
			return true
		}
	}
	return false
}
