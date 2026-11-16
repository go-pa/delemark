# delemark

[![Go Reference](https://pkg.go.dev/badge/github.com/go-pa/delemark.svg)](https://pkg.go.dev/github.com/go-pa/delemark)

`delemark` is a tiny Go library that detects and redacts API tokens, cloud
credentials, and other secret material in arbitrary text.

> [!NOTE]
> `delemark` is a fork of Docker's [`portcullis`](https://github.com/docker/portcullis).

```go
import "github.com/go-pa/delemark"

clean := delemark.Redact("Run this with token=ghp_1234567890abcdef1234567890abcdef1234 please.")
// → "Run this with token=[REDACTED] please."

delemark.Contains("not a secret")                                   // false
delemark.Contains("token=ghp_1234567890abcdef1234567890abcdef1234") // true
```

## Why

LLM agents, log pipelines, error reporters, and anything else that
echoes user-controlled or tool-produced text back into a third party
need to scrub credentials before they leak. `delemark` is the
extracted, dependency-free core of the redactor used by
[`docker-agent`](https://github.com/docker/docker-agent), built around
two design constraints:

- **Cheap on clean input.** A single Aho–Corasick pass over the input
  yields a bitset of every keyword present, after which each rule's
  keyword check collapses to two `AND` instructions. Most messages
  never pay for a regex.
- **Idempotent.** The default marker `[REDACTED]` is chosen so it does
  not match any built-in rule; redacting an already-redacted string is
  a no-op, and pipelines that scrub at multiple stages don't amplify.

## Install

```sh
# Library dependency:
go get github.com/go-pa/delemark

# CLI tool:
go install github.com/go-pa/delemark/cmd/delemark@latest
```

## CLI Usage

`delemark` reads from standard input (or file arguments) and streams redacted lines directly to standard output:

```sh
# Redact secrets from standard input:
cat server.log | delemark

# Redact secrets and email addresses:
delemark -email < config.env

# Custom replacement placeholder:
delemark -placeholder="***" credentials.json

# Redact credentials only, leaving payment cards, IBANs and US SSNs:
delemark -skip pii < app.log

# Leave out one rule, by its id:
delemark -skip us-ssn < app.log

# List the rule ids and their tags:
delemark -list-rules

# List the tags:
delemark -list-tags

# Live stream monitoring:
tail -f app.log | delemark -email
```

## API

The public library interface provides both in-memory scanning and stream processing:

```go
const Marker = "[REDACTED]"

func Contains(text string) bool                           // detect
func Redact(text string) string                           // scrub
func RedactWith(text string, opts StreamOptions) string   // deprecated: use New
func Stream(r io.Reader, w io.Writer) error               // stream line-by-line
func StreamWithOptions(r io.Reader, w io.Writer, opts StreamOptions) error // deprecated: use New
```

To leave rules out, build a `Redactor` once and use its methods, which
mirror the package-level functions:

```go
r, err := delemark.New(delemark.WithSkip("pii"))
clean := r.Redact(line)

func New(opts ...Option) (*Redactor, error)
func WithSkip(names ...string) Option  // rule ids or tags to leave out
func WithEmail(redact bool) Option     // redact email addresses too
func WithMarker(marker string) Option  // default Marker

func (r *Redactor) Redact(text string) string
func (r *Redactor) Find(text string) []Match
func (r *Redactor) Contains(text string) bool
func (r *Redactor) Stream(reader io.Reader, writer io.Writer) error

func Rules() []Rule   // every rule's ID and Tags, in the order they run
func Tags() []string  // every tag, sorted
```

`New` fails on a name that is neither a rule id nor a tag, so a typo
does not silently leave a rule running. Rule ids follow the gitleaks
ids where there is one. Every rule has at least one tag, and no tag is
also a rule id:

- its vendor's name, such as `github`, `gitlab`, `aws` or `openai`;
- a category, for rules of no one vendor or that share a shape:
  `connection-string`, `webhook`, `crypto-key`, `jwt`,
  `url-credentials`;
- `pii` for payment cards, IBANs and US SSNs. Those are the only rules
  without a keyword, so with `pii` skipped an input without any keyword
  runs no regex at all.

The package-level functions and a `Redactor`'s methods are safe for
concurrent use. The compiled rule set and its Aho–Corasick automaton
are built once on first call and shared by every `Redactor` and
goroutine.

## What it detects

The built-in catalogue covers ~240 patterns spanning:

- Cloud providers — AWS, GCP service accounts, Azure Storage,
  Azure AD client secrets, DigitalOcean, Yandex,
  Akamai, Cloudflare Origin CA & scannable tokens (`cfk_`, `cfut_`, `cfat_`, `cfast_`),
  Exoscale (IAM API keys & HMAC headers), Divio PAK (`divio_pak_`), Nessus / Tenable.
- Databases & Infra — PostgreSQL (connection URIs, `PGPASSWORD`, `POSTGRES_PASSWORD`, `.pgpass`),
  MongoDB, MySQL, Redis, RabbitMQ (AMQP), HTTP Basic Auth URLs.
- Source forges & CI — GitHub (PAT / OAuth / app / fine-grained /
  refresh), GitLab (full token family incl. `glimt-` /
  `glagent-` / `glsoat-` / routable variants), Bitbucket,
  Docker Hub (PAT / OAT), JFrog (key + reference token), Sonar,
  Buildkite, CircleCI, Harness (`pat.` / `sat.`), Authress.
- LLM / AI providers — OpenAI, Anthropic, DeepSeek, Google (AIza),
  xAI / Grok, Cohere, Groq, Perplexity, Replicate, OpenRouter,
  Hugging Face (user `hf_` + organisation `api_org_`),
  AssemblyAI, Deepgram, NVIDIA NIM (`nvapi-`),
  LangSmith (`lsv2_pt_` / `lsv2_sk_`), Pinecone (`pcsk_`).
- Payment processors — Stripe (secret / restricted /
  webhook), Razorpay, Plaid, Square (`sq0atp-` / `sq0csp-`),
  Braintree.
- Communication & ops — Slack (legacy, rotating, webhooks,
  workflow webhooks), Discord (bot & webhook), Telegram, Twilio,
  SendGrid, Mailgun, Mailchimp, Sendinblue, Microsoft Teams
  webhooks, PubNub (publish + subscribe), Tines / Zapier webhooks.
- SaaS & developer tools — Figma, Contentful, HubSpot, LaunchDarkly
  (incl. `sdk-` keys), Doppler (full family), 1Password, Vercel,
  Netlify, Render, Notion, Linear, Trello, ClickUp, Okta, ngrok,
  Cisco Meraki, SettleMint, Fly.io macaroons, Heroku v1/v2,
  OpenShift `sha256~` tokens, Voiceflow, Deno Deploy, Bitbucket
  app passwords (`ATBB`), CircleCI v2 (`CCIPAT_`), Endor Labs,
  Rootly, Sourcegraph Cody, Stripe payment-intent client secrets,
  Nightfall DLP, Ramp, Octopus Deploy, Stytch.
- Infra, web3, databases & PII — HashiCorp Vault (service / batch /
  recovery), Terraform Cloud, Tailscale, PlanetScale, Supabase,
  MongoDB / Postgres / MySQL / Redis / AMQP connection-string
  passwords, Sidekiq Pro/Enterprise gem-server URLs,
  Alchemy / Etherscan / Moralis (web3), payment cards (Luhn-checked),
  IBANs (mod-97-checked), US SSNs, Logz.io, PEM private keys, JWTs,
  and more.

Connection-string rules (MongoDB, Postgres, MySQL, Redis, AMQP, Azure
Storage) redact only the password / key span so log readers can still
tell which host or account was being addressed.

## Development

Common development commands:

```sh
go test ./...                                   # run unit tests
go test -race ./...                             # run tests with race detector
go test -bench=. -benchmem -run=^$ ./...        # run benchmarks
golangci-lint run                               # run linters
golangci-lint fmt                               # format Go source files
go mod tidy                                     # tidy module dependencies
```

The linter configuration lives in [`.golangci.yml`](./.golangci.yml).
The matching CI workflow runs lint + race-enabled tests using the
Go version specified in go.mod (Go 1.27.4) on every PR
— see [`.github/workflows/ci.yml`](./.github/workflows/ci.yml).

## Performance

On a typical clean input the cost is dominated by a single linear scan
over the bytes; the regex engine is never invoked. With a secret, only
the rules whose keywords are present run. Both functions allocate
only when text actually changes.

On an Apple M4 Max scrubbing a 9000-byte clean payload and a
secret-bearing 1.5 KB payload:

```
BenchmarkAhoScanCleanInput-16        257198      4823 ns/op  1865.95 MB/s     0 B/op    0 allocs/op
BenchmarkAhoScanWithKeyword-16      1251084       956.0 ns/op 1636.96 MB/s     0 B/op    0 allocs/op
BenchmarkRedactCleanInput-16         228036      4803 ns/op                    0 B/op    0 allocs/op
BenchmarkContainsCleanInput-16       233336      4782 ns/op                    0 B/op    0 allocs/op
BenchmarkRedactWithSecret-16         565590      2094 ns/op                 1585 B/op    2 allocs/op
BenchmarkContainsWithSecret-16       912943      1312 ns/op                    0 B/op    0 allocs/op
```

The AC scan dominates the clean-input path — `Redact` and `Contains`
add no measurable overhead on top of it because the rule loop
short-circuits on an empty keyword mask. `Contains` allocates zero
bytes even on a secret-bearing input: it only needs the regex
`MatchString`, which uses pooled state machines internally.

## Provenance

The default ruleset is derived from the MIT-licensed
[`github.com/docker/mcp-gateway/pkg/secretsscan`](https://github.com/docker/mcp-gateway)
package, which adapted it from
[`github.com/aquasecurity/trivy/pkg/fanal/secret`](https://github.com/aquasecurity/trivy),
extended with additional patterns for modern AI providers, payment
processors, and infrastructure tokens.

## License

Apache-2.0. See [LICENSE](./LICENSE).
