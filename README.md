# cfgscan

`scanner` — инструмент командной строки для обнаружения потенциально небезопасных
настроек в конфигурациях web applications.

## Требования

- Go 1.25 или новее.

## Быстрый старт

```sh
go test ./...
go build -o scanner ./cmd/scanner
./scanner config.yaml
```

## Архитектура

Потоки CLI, HTTP и gRPC передают конфигурацию в `app`, затем в `parser`, после
чего `analyzer` применяет набор `rules`: `CLI/HTTP/gRPC → app → parser → analyzer/rules`.

## Поддерживаемый вход

- Документы конфигурации JSON и YAML;
- один документ на входной поток (несколько документов YAML не поддерживаются);
- файл конфигурации, рекурсивно сканируемый каталог или standard input. Формат определяется при parsing,
  поэтому для `--stdin` не нужны имя файла или расширение.

При указании каталога рекурсивно сканируются только обычные файлы `.json`,
`.yaml` и `.yml` в лексикографическом порядке путей. Symbolic links не
обходятся и не сканируются; явно переданный путь symbolic link отклоняется.

## Проверки

- `debug-logging` — `LOW`: включено debug logging;
- `plaintext-password` — `HIGH`: в конфигурации хранится literal password, secret или token;
- `unrestricted-bind` — `MEDIUM`: service привязывается к `0.0.0.0`;
- `disabled-tls` — `HIGH`: TLS или certificate verification явно отключены;
- `weak-algorithm` — `HIGH`: настроены MD5, SHA-1, DES/3DES или RC4.
- `insecure-file-permissions` — проверка Unix permission bits для файла: права
  group или world writable имеют уровень `HIGH`; group или world readable (без
  write access) — `MEDIUM`. Ограниченные permissions не создают finding; `0600`
  — типичный безопасный минимум для файлов конфигурации с secret values.

## Использование

```sh
scanner config.yaml
scanner configs/
scanner --stdin < config.yaml
scanner --silent config.yaml
scanner --http-addr :8080
scanner --grpc-addr :9090
```

`--stdin` читает документ из standard input. `-s` и `--silent` по-прежнему
выводят findings, но возвращают успех, если findings — единственная проблема.

```text
configs/prod.yaml: HIGH [plaintext-password] database.password: a literal secret is stored in the configuration Recommendation: Load this value from a secret manager or an environment variable.
configs/prod.yaml: MEDIUM [insecure-file-permissions] permissions: configuration file is readable by group or other users Recommendation: Restrict this configuration file to the minimum necessary permissions, for example 0600.
```

Коды завершения:

- `0` — findings отсутствуют или были подавлены с помощью `-s` / `--silent`;
- `1` — обнаружены findings либо произошла ошибка чтения, parsing или analysis;
- `2` — ошибка использования command line.

## HTTP API

Запустите API server вместо CLI analysis с помощью `--http-addr`:

```sh
scanner --http-addr :8080
curl -X POST http://localhost:8080/v1/analyze \
  --data-binary $'database:\n  password: literal-password\n'
```

Endpoint `POST /v1/analyze` принимает один raw JSON или YAML configuration document.
Request Content-Type может быть `application/json`, `application/yaml`, `text/yaml`
или отсутствовать; формат определяет существующий parser. Responses — JSON:

```json
{"problems":[{"source":"request","rule_id":"plaintext-password","severity":"HIGH","path":"database.password","message":"a literal secret is stored in the configuration","recommendation":"Load this value from a secret manager or an environment variable."}]}
```

Endpoint возвращает `200 OK` для каждого успешно проанализированного документа,
включая документы с findings. Для пустого или invalid document возвращается
`400 Bad Request`, для body более 1 MiB — `413 Request Entity Too Large`, для
других methods — `405 Method Not Allowed` (с `Allow: POST`), для других paths —
`404 Not Found`, а при ошибке analysis — `500 Internal Server Error`. Error bodies
имеют JSON-форму `{"error":"..."}`.

HTTP API запускается без TLS и authentication и предназначен для local development
и demonstration.

## gRPC API

Запустите gRPC API server вместо CLI или HTTP analysis:

```sh
scanner --grpc-addr :9090
```

Unary endpoint `cfgscan.v1.Scanner/Analyze` принимает `AnalyzeRequest`, в котором
field `configuration` содержит raw JSON или YAML document. Он возвращает
`AnalyzeResponse` с `problems`; у каждой problem есть source, rule ID, severity,
path, message и recommendation. Успешные requests возвращают findings в response
(а не gRPC error), при этом `source` имеет значение `request`.

```sh
grpcurl -plaintext \
  -import-path api/proto \
  -proto cfgscan/v1/scanner.proto \
  -d '{"configuration":"database:\\n  password: literal-password\\n"}' \
  localhost:9090 cfgscan.v1.Scanner/Analyze
```

Пустые или invalid configurations возвращают `InvalidArgument`; requests, у которых
configuration превышает 1 MiB, возвращают `ResourceExhausted`; ошибки analysis
возвращают `Internal`.

gRPC API запускается без TLS и authentication и предназначен для local development
и demonstration.

## Как добавить новое правило

1. Создайте тип правила в пакете `internal/analyzer`.
2. Реализуйте интерфейс `Rule`: методы `ID()` и `Check(context.Context, parser.Document)`.
3. В `Check` верните найденные `Problem` с нужными severity, path, message и recommendation.
4. Добавьте экземпляр правила в `DefaultRules` и покройте его tests.

Чтобы заново сгенерировать закоммиченные Go protobuf files, выполните:

```sh
PATH="/Users/arina/go/bin:$PATH" protoc \
  --proto_path=api/proto \
  --go_out=paths=source_relative:api/gen \
  --go-grpc_out=paths=source_relative:api/gen \
  api/proto/cfgscan/v1/scanner.proto
```
