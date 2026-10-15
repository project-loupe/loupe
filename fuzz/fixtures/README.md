# Public test credentials

The PEM pair is an ephemeral self-signed EC P-256 fixture generated for
parser tests. Its private key is deliberately public and is never used
for authentication outside the test harness. Seeds mutate certificates,
keys and trust roots independently so valid inputs reach each parser.
