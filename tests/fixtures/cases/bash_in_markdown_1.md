---
title: Using mtls-auth plugin
---

This guide walks through how to configure the {{site.kic_product_name}} to
verify client certificates using CA certificates and
[mtls-auth](https://docs.konghq.com/hub/kong-inc/mtls-auth/) plugin
for HTTPS requests.

> Note: You need an Enterprise license to use this feature.

## Installation

Please follow the [deployment](/kubernetes-ingress-controller/{{page.kong_version}}/deployment/overview) documentation to install
Kong for Kubernetes Enterprise on your Kubernetes cluster.

## Testing Connectivity to Kong

This guide assumes that the `PROXY_IP` environment variable is
set to contain the IP address or URL pointing to Kong.
Please follow one of the
[deployment guides](/kubernetes-ingress-controller/{{page.kong_version}}/deployment/k4k8s-enterprise) to configure
this environment variable.

If everything is set up correctly, making a request to Kong should return
HTTP 404 Not Found.

```bash
$ curl -i $PROXY_IP
HTTP/1.1 404 Not Found
Date: Fri, 21 Jun 2019 17:01:07 GMT
Content-Type: application/json; charset=utf-8
Connection: keep-alive
Content-Length: 48
Server: kong/1.2.1

{"message":"no Route matched with those values"}
```

This is expected as Kong does not yet know how to proxy the request.

## Provision a CA certificate in Kong

CA certificates in Kong are provisioned by create a `Secret` resource in
Kubernetes.

The secret resource must have a few properties:
- It must have the `konghq.com/ca-cert: "true"` label.
- It must have a `cert` data property which contains a valid CA certificate
  in PEM format.
- It must have an `id` data property which contains a random UUID.
- It must have a `kubernetes.io/ingress.class` annotation whose value matches
  the value of the controller's `--ingress-class` argument. By default, that
  value is "kong".

Note that a self-signed CA certificate is being used for the purpose of this
guide. You should use your own CA certificate that is backed by
your PKI infrastructure.

```bash
$ echo "apiVersion: v1
kind: Secret
metadata:
  name: my-ca-cert
  annotations:
    kubernetes.io/ingress.class: kong
  labels:
    konghq.com/ca-cert: 'true'
type: Opaque
stringData:
  cert: |
    -----BEGIN CERTIFICATE-----
    MIICwTCCAamgAwIBAgIUHGUzUWvHJHrREvIZIcORiFUvze4wDQYJKoZIhvcNAQEL
    BQAwEDEOMAwGA1UEAwwFSGVsbG8wHhcNMjAwNTA4MjExODA1WhcNMjAwNjA3MjEx
    ODA1WjAQMQ4wDAYDVQQDDAVIZWxsbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
    AQoCggEBANCMMBngjuTvqts8ZXtZhqdr181QH/NmytW1KlyqZd6ppXUer+i0OWhP
    1nAyHsBPJljKAFLd8l1EioPFkN78/wJFDJrHOtfniIQPVLdS2cnNQ72dLyQH6smH
    JQDV8ePBQ2GdRP6s61+Da8eoaW6nSLtmEUhxvyteboqwmi2CtUtAfuiU1m5sOdpS
    z+L4D08CE+SFIT4MGD3gxNdg7lccWCHIfk54VRSdGDKEVwed8OQvxD0TdpHY+ym5
    nJ4JSkhiS9XIodnxR3AZ6rIPRqk+MQ4LGTjX2EbM0/Yg4qvnZ7m4fcpK2goDZIVL
    EF8F+ka1RaAYWTsXI1BAkJbb3kdo/yUCAwEAAaMTMBEwDwYDVR0TBAgwBgEB/wIB
    ADANBgkqhkiG9w0BAQsFAAOCAQEAVvB/PeVZpeQ7q2IQQQpADtTd8+22Ma3jNZQD
    EkWGZEQLkRws4EJNCCIvkApzpx1GqRcLLL9lbV+iCSiIdlR5W9HtK07VZ318gpsG
    aTMNrP9/2XWTBzdHWaeZKmRKB04H4z7V2Dl58D+wxjdqNWsMIHeqqPNKGamk/q8k
    YFNqNwisRxMhU6qPOpOj5Swl2jLTuVMAeGWBWmPGU2MUoaJb8sc2Vix9KXcyDZIr
    eidkzkqSrjNzI0yJ2gdCDRS4/Rw9iV3B3SRMs0mJMLBDrsowhNfLAd8I3NHzLwps
    dZFcvZcT/p717K3hlFVdjGnKIgKcG7aYji/XRR87HKnc+cJMCw==
    -----END CERTIFICATE-----
  id: cce8c384-721f-4f58-85dd-50834e3e733a" | kubectl create -f -
secret/my-ca-cert created
```

Please note the ID, you can use this ID one or use a different one but
the ID is important in the next step when we create the plugin.
Each CA certificate that you create needs a unique ID.
Any random UUID will suffice here and it doesn't have an security
implication.

You can use [uuidgen](https://linux.die.net/man/1/uuidgen) (Linux, OS X) or
[New-Guid](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/new-guid)
(Windows) to generate an ID.

For example:
```bash
$ uuidgen
907821fc-cd09-4186-afb5-0b06530f2524
```

## Configure mtls-auth plugin

Next, we are going to create an `mtls-auth` KongPlugin resource which references
CA certificate provisioned in the last step:

```bash
$ echo "
apiVersion: configuration.konghq.com/v1
kind: KongPlugin
metadata:
  name: mtls-auth
config:
  ca_certificates:
  - cce8c384-721f-4f58-85dd-50834e3e733a
  skip_consumer_lookup: true
  revocation_check_mode: SKIP
plugin: mtls-auth
" | kubectl apply -f -
kongplugin.configuration.konghq.com/mtls-auth created
```

## Install a dummy service

Let's deploy an echo service which we wish to protect
using TLS client certificate authentication.

```bash
$ kubectl apply -f https://bit.ly/echo-service
service/echo created
deployment.apps/echo created
```

You can deploy a different service or skip this step if you already
have a service deployed in Kubernetes.

## Set up Ingress

Let's expose the echo service outside the Kubernetes cluster
by defining an Ingress.

```bash
$ echo "
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: demo
  annotations:
    konghq.com/plugins: mtls-auth
    kubernetes.io/ingress.class: kong
spec:
  rules:
  - http:
      paths:
      - path: /foo
        backend:
          serviceName: echo
          servicePort: 80
" | kubectl apply -f -
ingress.extensions/demo created
```

## Test the endpoint

Now, let's test to see if Kong is asking for client certificate
or not when we make the request:

```
$ curl -k https://$PROXY_IP
HTTP/2 401
date: Mon, 11 May 2020 18:15:05 GMT
content-type: application/json; charset=utf-8
content-length: 50
x-kong-response-latency: 0
server: kong/2.0.4.0-enterprise-k8s

{"message":"No required TLS certificate was sent"}
```

As we can see, Kong is restricting the request because it doesn't
have the necessary authentication information.

Two things to note here:
- `-k` is used because Kong is set up to serve a self-signed certificate
  by default. For full mutual authentication in production use cases,
  you must configure Kong to serve a certificate that is signed by a trusted CA.
- For some deployments `$PROXY_IP` might contain a port that points to
  `http` port of Kong. In others, it might happen that it contains a DNS name
  instead of an IP address. If needed, please update the
  command to send an `https` request to the `https` port of Kong or
  the load balancer in front of it.


## Provisioning credential

Next, in order to authenticate against Kong, create the client
certificate and private key with the following content:

```bash
$ cat client.crt
-----BEGIN CERTIFICATE-----
MIIEFTCCAv0CAWUwDQYJKoZIhvcNAQELBQAwEDEOMAwGA1UEAwwFSGVsbG8wHhcN
MjAwNTA4MjE0OTE1WhcNMjEwNTA4MjE0OTE1WjCBkDELMAkGA1UEBhMCQVUxEzAR
BgNVBAgMClNvbWUtU3RhdGUxDTALBgNVBAcMBHNvbWUxETAPBgNVBAoMCHNvbWUg
b3JnMRAwDgYDVQQLDAdvcmd1bml0MRswGQYDVQQDDBJleGFtcGxlLmtvbmdocS5j
b20xGzAZBgkqhkiG9w0BCQEWDGZvb0Bzb21lLmNvbTCCAiIwDQYJKoZIhvcNAQEB
BQADggIPADCCAgoCggIBAM/y80ppzwGYS7zl+A6fx4Xkjwja+ZUK/AoBDazS3TkR
W1tDFZ71koLd60qK2W1d9Wh0/F3iNTcobVefr02mEcLtl+d4zUug+W7RsK/8JSCM
MIDVDYzlTWdd7RJzV1c/0NFZyTRkEVSjGn6eQoC/1aviftiNyfqWtuIDQ5ctSBt8
2fyvDwu/tBR5VyKu7CLnjZ/ffjNT8WDfbO704XeBBId0+L8i8J7ddYlRhZufdjEw
hKx2Su8PZ9RnJYShTBOpD0xdveh16eb7dpCZiPnp1/MOCyIyo1Iwu570VoMde9SW
sPFLdUMiCXw+A4Gp/e9Am+D/98PiL4JChKsiowbzpDfMrVQH4Sblpcgn/Pp+u1be
2Kl/7wqr3TA+w/unLnBnB859v3wDhSW4hhKASoFwyX3VfJ43AkmWFUBX/bpDvHto
rFw+MvbSLsS3QD5KlZmega1pNZtin5KV8H/oJI/CjEc9HHwd27alW9VkUu0WrH0j
c98wLHB/9xXLjunabxSmd+wv25SgYNqpsRNOLgcJraJbaRh4XkbDyuvjF2bRJVP4
pIjntxQHS/oDFFFK3wc7fp/rTAl0PJ7tytYj4urg45N3ts7unwnB8WmKzD9Avcwe
8Kst12cEibS8X2sg8wOqgB0yarC17mBEqONK7Fw4VH+VzZYw0KGF5DWjeSXj/XsD
AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEvTMHe27npmyJUBxQeHcNFniMJUWZf0
i9EGd+XlF+m/l3rh1/mCecV7s32QTZEiFHv4UJPYASbgtx7+mEZuq7dVsxIUICWs
gyRkwvKjMqK2tR5IRkquhK5PuDS0QC3M/ZsDwnTgaezFrplFYf80z1kAAkm/c7eh
ZEjI6+1vuaS+HX1w2unk42PiAEB6oKFi3b8xl4TC6acYfMYiC3cOa/d3ZKHhqXhT
wM0VtDe0Qn1kExe+19XJG5cROelxmMXBm1+/c2KUw1yK8up6kJlEsmd8JLw/wMUp
xcJUKIH1qGBlRlFTYbVell+dB7IkHhadrnw27Z47uHobB/lzN69r63c=
-----END CERTIFICATE-----
```

```bash
$ cat client.pem
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
```

Now, use the key and certificate to authenticate against Kong and use the
service:

```bash
$ curl --key client.key --cert client.crt  https://$PROXY_IP/foo -k -I
HTTP/2 200
content-type: text/plain; charset=UTF-8
date: Mon, 11 May 2020 18:27:22 GMT
server: echoserver
x-kong-upstream-latency: 1
x-kong-proxy-latency: 1
via: kong/2.0.4.0-enterprise-k8s
```

## Conclusion

This guide demonstrates how to implement client TLS authentication
using Kong.
You are free to use other features that mtls-auth plugin in Kong to
achieve more complicated use-cases.
