# cosign-provider

cosign-provider is used for validating whether images are signed with [cosign](https://github.com/sigstore/cosign).

> This repo is meant for testing Gatekeeper external data feature. Do not use for production.

## Installation

- Deploy Gatekeeper with external data enabled (`--enable-external-data`)

- `kubectl apply -f manifest`
  - Update `SECRET_NAME` environment variable

- `kubectl apply -f policy/provider.yaml`
  - Update `url` if it's not `http://cosign-provider.cosign-provider:8090`

- `kubectl apply -f policy/template.yaml`

- `kubectl apply -f policy/constraint.yaml`

## Verification

- `kubectl apply -f policy/examples/signed.yaml`
  - Request should be rejected
  ```
  Error from server ([signed-image] Image gcr.io/google_containers/pause-amd64:3.0 does not contain a valid cosign signature): error when creating "policy/examples/unsigned.yaml": admission webhook "validation.gatekeeper.sh" denied the request: [signed-image] Image gcr.io/google_containers/pause-amd64:3.0 does not contain a valid cosign signature
  ```

- `kubectl apply -f policy/examples/unsigned.yaml`
  - Request should be allowed
  ```
  deployment.apps/signed-deployment created
  ```

## Credits

Cosign image verification is based on https://github.com/dlorenc/cosigned
