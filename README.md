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
scanner --http-addr :8080
scanner --grpc-addr :9090
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

## HTTP API

Start the API server instead of a CLI analysis with `--http-addr`:

```sh
scanner --http-addr :8080
curl -X POST http://localhost:8080/v1/analyze \
  --data-binary $'database:\n  password: literal-password\n'
```

`POST /v1/analyze` accepts one raw JSON or YAML configuration document. The
request Content-Type may be `application/json`, `application/yaml`, `text/yaml`,
or omitted; the existing parser determines the format. Responses are JSON:

```json
{"problems":[{"source":"request","rule_id":"plaintext-password","severity":"HIGH","path":"database.password","message":"a literal secret is stored in the configuration","recommendation":"Load this value from a secret manager or an environment variable."}]}
```

The endpoint returns `200 OK` for every successfully analyzed document,
including documents with findings. It returns `400 Bad Request` for an empty or
invalid document, `413 Request Entity Too Large` for bodies over 1 MiB, `405
Method Not Allowed` (with `Allow: POST`) for other methods, `404 Not Found` for
other paths, and `500 Internal Server Error` for analysis failures. Error bodies
are JSON in the form `{"error":"..."}`.

## gRPC API

Start the gRPC API server instead of CLI or HTTP analysis:

```sh
scanner --grpc-addr :9090
```

The unary `cfgscan.v1.Scanner/Analyze` endpoint accepts an `AnalyzeRequest`
whose `configuration` field is the raw JSON or YAML document. It returns an
`AnalyzeResponse` with `problems`; each problem has source, rule ID, severity,
path, message, and recommendation. Successful requests return findings in the
response (rather than a gRPC error), with `source` set to `request`.

```sh
grpcurl -plaintext \
  -import-path api/proto \
  -proto cfgscan/v1/scanner.proto \
  -d '{"configuration":"database:\\n  password: literal-password\\n"}' \
  localhost:9090 cfgscan.v1.Scanner/Analyze
```

Empty or invalid configurations return `InvalidArgument`; requests whose
configuration exceeds 1 MiB return `ResourceExhausted`; analysis failures
return `Internal`.

Regenerate the committed Go protobuf files with:

```sh
PATH="/Users/arina/go/bin:$PATH" protoc \
  --proto_path=api/proto \
  --go_out=paths=source_relative:api/gen \
  --go-grpc_out=paths=source_relative:api/gen \
  api/proto/cfgscan/v1/scanner.proto
```
