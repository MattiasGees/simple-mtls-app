# simple-mtls-app

This is a simple mTLS application that works together with cert-manager [CSI Driver SPIFFE](https://cert-manager.io/docs/usage/csi-driver-spiffe/). It is based upon the great work of [haoel](https://github.com/haoel/mTLS/tree/main)

## Deploy

* Install cert-manager
* Install cert-manager CSI Driver
* Add the CA chain to the configmap in `deployment.yaml`
* Run `kubectl apply -f deployment.yaml`
