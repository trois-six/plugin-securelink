# Secure Link

This [Traefik](https://github.com/containous/traefik) plugin is as middleware which checks the authenticity of requested links and protects resources from unauthorized access. Authenticity is verified by comparing the checksum value passed in a request with the value computed for the request, using the shared secret.
This middleware is inspired by [this](https://github.com/blake/secure-link-filter) WebAssembly filter.
Traefik sends an HTTP `403 Forbidden` response when the hash doesn't match for protected paths.

## Configuration

To configure this plugin you should add its configuration to the Traefik dynamic configuration as explained [here](https://docs.traefik.io/getting-started/configuration-overview/#the-dynamic-configuration).
The following snippet shows how to configure this plugin with the File provider in TOML and YAML: 

```toml
# Protect /video/ and /playlist paths with a secret "enigma"
[http.middlewares]
  [http.middlewares.my-securelink.securelink]
    secret = "enigma"
    protectedPaths = ["/video/", "/playlist"]
```

```yaml
# Protect /video/ and /playlist paths with a secret "enigma"
http:
  middlewares:
    my-securelink:
      plugin:
        securelink:
          secret: enigma
          protectedPaths:
            - /video/
            - /playlist
```
