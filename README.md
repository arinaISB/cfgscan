# cfgscan

`scanner` is a command-line tool for detecting potentially insecure settings in
web-application configurations.

## Supported input

- JSON and YAML configuration documents;
- one document per input stream (multiple YAML documents are not supported);
- configuration file input or standard input. Format is determined by parsing,
  so `--stdin` does not require a filename or extension.

## Checks

- `debug-logging` — `LOW`: debug logging is enabled;
- `plaintext-password` — `HIGH`: a literal password, secret, or token is stored in configuration;
- `unrestricted-bind` — `MEDIUM`: a service binds to `0.0.0.0`;
- `disabled-tls` — `HIGH`: TLS or certificate verification is explicitly disabled;
- `weak-algorithm` — `HIGH`: MD5, SHA-1, DES/3DES, or RC4 is configured.

## Usage

```sh
scanner config.yaml
scanner --stdin < config.yaml
scanner --silent config.yaml
```

`--stdin` reads the document from standard input. `-s` and `--silent` still
print findings, but return success when findings are the only issue.

```text
HIGH [plaintext-password] database.password: a literal secret is stored in the configuration Recommendation: Load this value from a secret manager or an environment variable.
MEDIUM [unrestricted-bind] server.bind_address: service is bound to all network interfaces Recommendation: Bind to a specific private interface or restrict access with a firewall.
```

Exit codes:

- `0` — no findings, or findings were suppressed with `-s` / `--silent`;
- `1` — findings were detected, or reading, parsing, or analysis failed;
- `2` — command-line usage error.
