# TLS ownership and compatibility

Private PEM belongs to `Secret<String>` in `Ca` and `CertBundle`; deliberate
consumers borrow it with `expose`. No blanket key/bundle Clone is provided.
The private owned-DER adapter delegates to rustls-pki-types' real zeroize
implementation, covering the owned Vec's current full capacity. Loaders
borrow that guarded DER into ring and preserve `CertifiedKey::keys_match`
handling, including its `Unknown` case, before installing rustls's existing
shared signer resolver. An unrelated global provider is not used.

rcgen retains both an opaque signer and serialized DER. Its private Drop owner
invokes rcgen's optional zeroize method, which clears only serialized DER.
It deliberately does not implement Loupe's stronger all-owned-bytes Zeroise
contract. CA import preserves first-block PKCS#8 parsing and guards the returned
DER. The certificate argument's tag-neutral first-block decoder also hands
completed DER directly to a Secret before borrowed X.509 parsing: a private
first block must be wiped even when certificate parsing then rejects it.
Export borrows serialized DER, reserves checked output space once, and
base64-encodes directly into guarded construction scratch, matching rcgen's
64-column wrapping, platform newline and final newline. There is no mutable
extraction API on Secret.

The original server/client helpers retain first-key selection, private-CA-only
trust and empty ALPN. `reqwest_client_config` preserves the replaced reqwest
path: last private key, all certificates in order, the logical conditional
newline between cert/key PEM, rejection of unsupported recognized sections,
and ignored unknown sections. Every returned private DER and superseded key
has a guard, including unused private sections decoded while scanning mixed
certificate/CA bundles. Those scans preserve certificate order and ignored
public/unknown sections, and discard reflective parser errors. Its roots are
all supplied certificates plus the compiled webpki
roots, with empty CA input allowed. It enables TLS 1.2/1.3, normal verification,
SNI and HTTP/1.1 ALPN, matching the workspace's reqwest features. Early data and
key logging stay disabled. Consumers pass the concrete config to reqwest's
`use_preconfigured_tls`; normal reqwest TLS builder options are bypassed by
that API, while request/proxy/DNS/timeout behavior remains reqwest's concern.

Private parser/import/signing errors discard source chains in favor of fixed
messages. This prevents reflection of malformed private input but does not
wipe dependency parser scratch. P10 excludes opaque ring state, rcgen's
internal generation document, PEM/base64/line/error parser scratch, compiler
temporaries and prior reallocations, OS/transport/TLS session buffers, and
already-exported operator files. Live-buffer cleanup probes and dependency
source review support the stated limits; they do not inspect freed memory.

Raw PEM ownership follows every accepted section, including mixed certificate
and CA inputs. `PemInput` shares one `Arc<Secret<String>>` allocation for the
four process argument parsers' required Clone contract; no Clap dependency or
input precedence moves into TLS. Applications keep raw-over-base64-over-file
selection and the worker's complete-env-or-complete-files rule. A runtime PEM
has its own Secret, with an existing shared argument retired by move where
possible. Unused competing arguments stay guarded until their owners drop.

The private PEM construction buffer decodes base64 into preallocated storage,
validates UTF-8 without retaining a FromUtf8Error, and reads files with guarded
replacement on growth. A populated old allocation is wiped before retirement;
partial decoding, read errors and invalid UTF-8 wipe the current allocation.
PEM base64 export reserves its exact size and encodes directly into that owner.
There is no new input size cap. File growth temporarily retains both old and new
allocations, so this is not a peak-memory bound. OS arguments/environment,
Clap internals, filesystem/kernel and parser scratch remain outside this scope.

`Ca` guards the exact imported certificate PEM, because accepted mixed input
can include a private section. `cert_pem()` remains a borrowed view of those
original bytes; `into_pem()` retires both owned PEMs for init persistence. Server
Config and worker TLS inputs guard all PEM fields. Registration's CA field uses
the same private serde string adapter as its client key. Canonical generated
leaf certificates remain public Strings. The HTTP/pretty JSON/base64 exports
preserve original bytes through the named guarded encoders and explicit sinks;
writing those bytes to stdout, files or the peer is deliberate disclosure.
Those final external copies are not claimed to be wiped by dropping our owner.
