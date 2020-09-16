# Secure Link

This [Traefik](https://github.com/traefik/traefik) plugin is as middleware which checks the authenticity of requested links and protects resources from unauthorized access. Authenticity is verified by comparing the checksum value passed in a request with the value computed for the request, using the shared secret.
This middleware is inspired by [this](https://github.com/blake/secure-link-filter) WebAssembly filter.
Traefik sends an HTTP `403 Forbidden` response when the hash doesn't match for protected paths.

## How does it work?

This plugin has two modes: with queries and without. In both modes, you have to set a secret and "protected paths".
The secret is used to create a hash with the path of the request under protected path concatenated with the secret.

### Without queries

Example: Imagine that you would like to request http://localhost/video/foo/bar.mp4, your protected path is "/video", your secret is "enigma".
* To Access to that resource, you will have to request instead http://localhost/video/[hash]/foo/bar.mp4.
* ```shell
  hash=$(echo -n "/foo/bar.mp4enigma" | md5sum | awk '{ print $1 }')
  ```
* In that example, we should request http://localhost/video/9304fce63530f73802183ef436740e58/foo/bar.mp4

### With queries (query: true)

Example: Imagine that you would like to request http://localhost/video/foo/bar.mp4, your protected path is "/video", your secret is "enigma".
* To Access to that resource, you will have to request instead http://localhost/video/foo/bar.mp4?md5=[hash].
* ```shell
  hash=$(echo -n "/foo/bar.mp4enigma" | md5sum | awk '{ print $1 }')
  ```
* In that example, we should request http://localhost/video/foo/bar.mp4?md5=9304fce63530f73802183ef436740e58

With queries activated, you can also activate another feature: checkExpire.
When this feature is activated, you have to add another query parameter to get your resource: expire.
The new url you will have to request, is, for example: http://localhost/video/foo/bar.mp4?md5=[hash]&expire=1597153588.

This time, the hash is computed differently:
```shell
hash=$(echo -n "${path}${expire}${secret}" | md5sum | awk '{ print $1 }')
```
Imagine that you want to expose this resource for 120s, expire will be:
```shell
expire=$(($(date "+%s") + 120))
```
This link will be available only for 120s.

## Configuration

To configure this plugin you should add its configuration to the Traefik dynamic configuration as explained [here](https://docs.traefik.io/getting-started/configuration-overview/#the-dynamic-configuration).
The following snippet shows how to configure this plugin with the File provider in TOML and YAML: 

```toml
# Protect /video/ and /playlist paths with a secret "enigma"
[http.middlewares]
  [http.middlewares.my-securelink.securelink]
    secret = "enigma"
    protectedPaths = ["/video/", "/playlist"]
    query = false
    checkExpire = false
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
          query: false
          checkExpire: false
```
