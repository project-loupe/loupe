# Direct web boundary coverage

The `web_api` and `web_server_response` fuzz targets call the actual router.
Forwarded requests use the closed `AdminRequest` dispatch and the named
Browser/Server owners through their selected HTTP sinks. No public Value-returning
client facade exists.

`fuzz_support` exists only under `cfg(fuzzing)`. It exposes observations and
three fixed Config parser choices, native admission followed by the selected Config read, and the
pure query byte-budget seam. It cannot return an ingress token or marked owner,
select a source, or decode an arbitrary type. The normal-build documentation
test verifies that this module is absent. These fixtures introduce no new
production mint or legacy exit.

## Request target

Byte zero selects a mode modulo 26. Ordinary inputs above 64 KiB are ignored;
compact recipes exercise the larger production limits without large seeds.

| Modes | Actual boundary and independent expectation |
| --- | --- |
| 0–7 | Existing capability, ID, limit, body, Host, Origin, Fetch-Site, and valid-config controls |
| 8 | All six body owners; optional/wrong/JSON/vendor/non-ASCII media, raw JSON |
| 9–10 | Full job-filter and search queries, independent serde schemas and exact character policies |
| 11 | Eleven ID-bearing routes, signed i64 spelling and normalized upstream IDs |
| 12–14 | Actual URL/native path/PEM Clap callbacks, including invalid native UTF-8 |
| 15 | Selected raw/base64/native-file PEM reads, empty fallback, priority, invalid selected values and a raw PEM above 2 MiB |
| 16 | Pure pre-allocation lossy query budget, independently counted at/exceeding 2 MiB; distinct from the smaller URI transport limit |
| 17 | Fetch-Site/Origin/custom-header priority, invalid UTF-8 fallback, safe GET behavior |
| 18 | Streamed body cap−1/cap/cap+1, stamp expansion, read error, cancellation, guard/token/media no-poll controls |
| 19 | Nested JSON depth around the pinned serde boundary |
| 20–21 | Arbitrary search/filter text, percent decoding and independent exact character admission |
| 22 | Cookie-only capability refusal |
| 23–24 | Read routes and outer guarding of document/assets |
| 25 | Arbitrary Content-Type against a populated fake PAT request |

The oracle uses ordinary Value only for fake input and captured fake upstream
requests. It preserves unknown fields, duplicate-last semantics (including
escaped keys), nonobjects, optional media, protocol stamping and exact decoded
credential content. A DTO with mandatory fields would not be equivalent.
Method/path/query ordering, protocol header, and absence of the browser
capability upstream are checked separately. Rejected requests make no upstream
call. A trailing empty ID receives the outer Browser guard and the router's
404, without entering the API token layer. An empty intermediate ID followed
by a static suffix matches the route and receives the fixed 400 path error
after Guard/Token/Path validation. Both cases make no upstream request.

Typed query observations accept only `BoundedText<P, Browser>` and occur before
the selected reqwest query encoder. Body observations inspect the concrete owner
and compare its bytes pointer with the actual validator input while both are
live. They check the owner's real redacted Debug output.

## Response target

Byte zero selects a mode modulo 21. Success/error status, protocol header,
arbitrary JSON/diagnostic bytes, lossy UTF-8, empty/whitespace bodies and stream
framing vary independently through fixed cases. Compact recipes cover chunked
cap−1/cap/cap+1, advertised oversize, truncated Content-Length, cancellation,
oversized error status mapping and the 16 MiB raw → 48 MiB lossy view. A split
recipe emits one-byte chunks. Other padding is streamed in blocks no larger
than 8192 bytes.

The expected side uses the pinned standard lossy UTF-8 conversion and serde
Value grammar. Successful responses preserve status and JSON shape; failures
preserve the deliberate trimmed Server diagnostic and map 401/403 to 502.
Parser/transport failures must match fixed host messages. Protocol validation
must precede collection on successful responses; error responses skip it.
Neither cookies nor the upstream protocol header are forwarded to the browser.

Observations inside `ServerText::decode` compare its retained original pointer
with the real guarded collector result, hash the original bytes, and report
whether a replacement exists and its exact length. Valid UTF-8 requires no
replacement. `ServerJson`'s actual redacted Debug is checked before egress.

## Lifetime and limits

Each target has one persistent listening socket and current-thread runtime.
A mutex serializes iterations sharing that fixture. Each iteration owns its
acceptor and either joins it or aborts and joins it. Actual calls are counted;
timeouts cannot silently become successful observations. The fixtures never
change global process environment.

Under `cfg(fuzzing)`, each web Buffer allocation is counted; completion requires
all counted allocations to have dropped. Drop observations inspect initialized
storage after its real zeroing and before deallocation. Cancellation and read
errors exercise this same owner. Raw transport and kernel copies, and the
shared HTTP collector's private allocation, are outside this observation.
The shared HTTP collector still runs in the actual response path; its separate
tests establish its own cleanup behavior.

The response fixture's browser-output collection allowance is larger than the
input cap: JSON escaping and lossy UTF-8 can expand output. It does not impose
a production output cap. Native paths and PEM inputs gain no new cap, trim,
normalization, HTTPS rule or path policy.

Config callback coverage is not process argv/env or startup coverage. Existing
child-environment precedence, loopback-before-credentials, mTLS/ALPN and
response-budget tests remain unchanged and complementary. No Kani proof or
whole-process erasure claim is introduced.

## Atomic M join

Normal builds retain Browser/Server/Config owners through the final named sinks
listed in `INGRESS.md`. The cfg-only observations remain inside their concrete
validators or just before their selected HTTP/TLS encoders. They do not justify
source casts, arbitrary decoders or raw conversion APIs.

The router fixture admits its upstream URL through actual Clap before passing
ConfigUrl to AdminClient::from_parts. The selected-PEM fixture now also admits
each supplied raw/base64/native-path value through the actual native parser.
Its trace therefore records those supplied-input admissions before the original
Raw/Base64/File selection event. The two ConfigSelected observations still
compare the same live guarded allocation before and after selection. Oracles
check parser and selection observations separately by owner.

Original Server bytes and the compatible lossy view remain source-bound through
transparent forwarding. Consumers that interpret finding fields elsewhere still
require original-token Agent attribution; this proxy assigns none.
