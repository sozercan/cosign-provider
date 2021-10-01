module github.com/sozercan/cosign-provider

go 1.16

require (
	github.com/go-logr/logr v0.4.0
	github.com/go-logr/zapr v0.4.0
	github.com/google/go-containerregistry v0.5.1
	github.com/open-policy-agent/frameworks/constraint v0.0.0-20210816184142-2924b2c86f76
	github.com/sigstore/cosign v1.0.1-0.20210728181701-5f1f18426dc3
	github.com/sigstore/sigstore v0.0.0-20210722023421-fd3b69438dba
	go.uber.org/zap v1.18.1
)

// replace github.com/open-policy-agent/frameworks/constraint => github.com/sozercan/frameworks/constraint v0.0.0-20210923005650-dc746bb01f6e
replace github.com/open-policy-agent/frameworks/constraint => /home/sozercan/go/src/github.com/open-policy-agent/frameworks/constraint
