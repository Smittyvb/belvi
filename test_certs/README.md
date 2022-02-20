<!-- SPDX-License-Identifier: Apache-2.0 -->
# Testing certs

Certificates for testing purposes.

## Getting certificate from domain
1. Run `openssl s_client -showcerts -servername [domain] -connect [domain]:443 </dev/null`
2. For leaf certfiicate, extra first `-----BEGIN CERTIFICATE-----` block to `[name].pem`
3. `openssl x509 -outform der -in [name].pem -out [name].der`
4. `rm [name].pem`
4. add `.license`
