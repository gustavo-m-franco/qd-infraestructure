# SSL/TLS Certificate Generation Guide for Microservices

This guide outlines the steps to create SSL/TLS certificates for securing communication between microservices using OpenSSL. We'll create a central Certificate Authority (CA) and use it to sign the certificates for each service.

## Prerequisites
- OpenSSL installed on your machine.

## Steps

### 1. Create a Configuration File (san.cnf)
Create a file named `san.cnf` with the following content. Adjust the `[dn]` and `[alt_names]` sections as needed for your environment.

```conf
[ req ]
default_bits       = 4096
prompt             = no
default_md         = sha256
req_extensions     = req_ext
x509_extensions    = v3_ca
distinguished_name = dn

[ dn ]
CN = yourservice.example.com

[ req_ext ]
subjectAltName = @alt_names

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical,CA:TRUE
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = yourservice.example.com
DNS.2 = localhost
```

### 2. Generate the CA Key and Certificate
Generate the CA's private key and self-signed certificate. The CA certificate will be used to sign your microservices' certificates.
```bash
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 1024 -out ca.pem -config san.cnf
```

### 3. Generate Server Certificates for Each Microservice
For each microservice, perform the following steps. Replace yourservice.example.com with your service's domain name or identifier.

#### 3.1 Generate a Private Key for the Microservice
```bash
openssl genrsa -out yourservice.key 4096
```

#### 3.2 Generate a CSR (Certificate Signing Request)
```bash
openssl req -new -key yourservice.key -out yourservice.csr -config san.cnf
```

#### 3.3 Sign the CSR with the CA's Private Key
```bash
openssl x509 -req -in yourservice.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out yourservice.crt -days 800 -sha256 -extensions req_ext -extfile san.cnf
```

### 4. Distribute the Certificates
Place the CA certificate (ca.pem) in all your services to validate other services' certificates.
Each service gets its own certificate (yourservice.crt) and private key (yourservice.key).