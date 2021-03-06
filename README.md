# acmsync

Sync `kubernetes.io/tls` certificates to AWS ACM.

Annotate your secrets with `experimental.cert-manager.io/acm-sync: "true"`

```shell
kubectl annotate secrets test experimental.cert-manager.io/acm-sync=true
```

Provide ambient credentials (e.g. `AWS_ACCESS_KEY_ID`, `AWS_REGION`, `AWS_SECRET_ACCESS_KEY`)
to the controller.

Run the controller.

```shell
go install sandbox.jakexks.dev/acmsync@latest
export AWS_ACCESS_KEY_ID=...
kind create cluster
acmsync -zap-devel -zap-log-level=10
```
