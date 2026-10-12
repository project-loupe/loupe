# TLS regression fixtures

`invalid-subject-oid.pem` is the public certificate from continuous fuzzing
crash `dad5baa627946cef8466b57a9de75ef4066f7157`, with its one-byte field
selector removed. The exact 604-byte input is also retained under
`fuzz/test_cases/tls_pem/invalid-subject-oid`.

The certificate reaches rcgen's import path but produces unsupported OID
arcs in its subject name. Rebinding it previously panicked in yasna's OID
writer. The fixture contains no private key; the unit test generates one.

`throwaway-rsa-pkcs1.pem` / `throwaway-rsa-pkcs8.pem` encode the same
unregistered 2048-bit RSA test key. `throwaway-ec-sec1.pem` /
`throwaway-ec-pkcs8.pem` encode the same unregistered P-256 test key.
These are public test fixtures, never deployment credentials. They distinguish
TLS loaders' PKCS#1/PKCS#8/SEC1 support from rcgen CA import's PKCS#8 contract.
Generated on 2026-10-12 with system OpenSSL:

```sh
openssl genrsa -traditional -out throwaway-rsa-pkcs1.pem 2048
openssl pkcs8 -topk8 -nocrypt -in throwaway-rsa-pkcs1.pem -out throwaway-rsa-pkcs8.pem
openssl ecparam -name prime256v1 -genkey -noout -out throwaway-ec-sec1.pem
openssl pkcs8 -topk8 -nocrypt -in throwaway-ec-sec1.pem -out throwaway-ec-pkcs8.pem
```
