# caddy-tls-fnmt

This caddy client auth verifier module allows to filter users by the names, or DNIs in their
FNMT certificate.

```Caddyfile
example.com {
  respond "Hello world!" 200
  tls internal {
    client_auth {
      mode require_and_verify
      # The CA certificate file. You can get this from the FNMT website. Make sure it's
      # the PEM format, not CER.
      trust_pool file /data/AC_FNMT_Usuarios.pem
      verifier fnmt {
        # All fields are optional, and case sensitive
        # Allowed user names (a name may be shared by multiple people)
        names "JUAN ESPAÑOL ESPAÑOL" "PEPE GARCIA GARCIA"
        # Allowed DNI numbers
        dnis "12345678Z" "87654321X"
        # Allowed full names (the format is "NAME SURNAME SURNAME - DNI")
        full_names "JUAN ESPAÑOL ESPAÑOL - 12345678Z" "PEPE GARCIA GARCIA - 87654321X"
      }
    }
  }
}
```
