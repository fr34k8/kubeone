# Hetzner Cloud Controller Manager (CCM)

See more: https://github.com/hetznercloud/hcloud-cloud-controller-manager

basic YAML generated by:

```shell
kubectl kustomize --enable-helm . | yq > ccm-hetzner.yaml
```

**Note:** some manual adjustments are required (e.g. template PARAMS).
