# cfgscan

`scanner` is a command-line tool for detecting potentially insecure settings in
web-application configurations.

## Supported input

- JSON and YAML configuration documents;
- one document per input stream (multiple YAML documents are not supported);
- a configuration file, a recursively scanned directory, or standard input. Format is determined by parsing,
  so `--stdin` does not require a filename or extension.

When a directory is supplied, only regular `.json`, `.yaml`, and `.yml` files
are scanned recursively, in lexicographic path order. Symbolic links are not
followed or scanned; an explicitly supplied symbolic-link path is rejected.

## Checks

- `debug-logging` — `LOW`: debug logging is enabled;
- `plaintext-password` — `HIGH`: a literal password, secret, or token is stored in configuration;
- `unrestricted-bind` — `MEDIUM`: a service binds to `0.0.0.0`;
- `disabled-tls` — `HIGH`: TLS or certificate verification is explicitly disabled;
- `weak-algorithm` — `HIGH`: MD5, SHA-1, DES/3DES, or RC4 is configured.
- `insecure-file-permissions` — Unix permission-bit check for file input: group
  or world writable is `HIGH`; group or world readable (without write access) is
  `MEDIUM`. Restricted permissions produce no finding; `0600` is a typical safe
  minimum for secret-bearing configuration files.

## Usage

```sh
scanner config.yaml
scanner configs/
scanner --stdin < config.yaml
scanner --silent config.yaml
```

`--stdin` reads the document from standard input. `-s` and `--silent` still
print findings, but return success when findings are the only issue.

```text
configs/prod.yaml: HIGH [plaintext-password] database.password: a literal secret is stored in the configuration Recommendation: Load this value from a secret manager or an environment variable.
configs/prod.yaml: MEDIUM [insecure-file-permissions] permissions: configuration file is readable by group or other users Recommendation: Restrict this configuration file to the minimum necessary permissions, for example 0600.
```

Exit codes:

- `0` — no findings, or findings were suppressed with `-s` / `--silent`;
- `1` — findings were detected, or reading, parsing, or analysis failed;
- `2` — command-line usage error.
