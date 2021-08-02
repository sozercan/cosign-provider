# cosign-provider

- Deploy Gatekeeper with external data enabled

- `kubectl apply -f manifest`
  - Update `SECRET_NAME` environment variable

- `kubectl apply -f policy/provider.yaml`
  - Update `proxyURL` if it's not `http://cosign-provider.default:8090`

- `kubectl apply -f policy/template.yaml`

- `kubectl apply -f policy/constraint.yaml`
