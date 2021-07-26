package provider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/sigstore/cosign/cmd/cosign/cli"
	"github.com/sigstore/sigstore/pkg/signature"
	corev1 "k8s.io/api/core/v1"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/fulcio"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func Signatures(img string, key *ecdsa.PublicKey) ([]cosign.SignedPayload, error) {
	ref, err := name.ParseReference(img)
	if err != nil {
		return nil, err
	}

	ecdsaVerifier := &signature.ECDSAVerifier{Key: key, HashAlg: crypto.SHA256}

	return cosign.Verify(context.TODO(), ref, &cosign.CheckOpts{
		Roots:  fulcio.Roots,
		PubKey: ecdsaVerifier,
		Claims: true,
	}, cli.TlogServer())
}

func Config(c *kubernetes.Clientset) *corev1.ConfigMap {
	cm, err := c.CoreV1().ConfigMaps("cosign-provider").Get(context.TODO(), "cosign-config", metav1.GetOptions{})
	if err != nil {
		panic(err)
	}
	return cm
}

func Keys(cfg map[string]string) []*ecdsa.PublicKey {
	keys := []*ecdsa.PublicKey{}

	pems := parsePems([]byte(cfg["keys"]))
	for _, p := range pems {
		// TODO check header
		key, err := x509.ParsePKIXPublicKey(p.Bytes)
		if err != nil {
			panic(err)
		}
		keys = append(keys, key.(*ecdsa.PublicKey))
	}
	return keys
}

func parsePems(b []byte) []*pem.Block {
	p, rest := pem.Decode(b)
	if p == nil {
		return nil
	}
	pems := []*pem.Block{p}

	if rest != nil {
		return append(pems, parsePems(rest)...)
	}
	return pems
}
