# Prompt injection corpus

The canonical 40 synthetic raw payloads live in
`fuzz/test_cases/worker_prompt_render/injection-*`. The worker prompt/MCP tests
and both affected fuzz targets consume those same bytes. `catalog.tsv` records
their family, source and exact multiline policy expectation. Preserve CRLF,
NFD, literal markers and control bytes. Metadata is kept outside the corpus.

Actual ingress replay admits 37 fixtures and rejects three forbidden-control
fixtures: bidi-isolate, bidi-override and forbidden-control. These negatives
exercise admission, not a successful renderer. Four additional renderer seeds
cover ordinary text, empty input, candidate collision and three-candidate
exhaustion. Title and path policies have different limits; multiline attacks
enter the exact finding description and MCP query fields.

The fixtures were locally authored on 2026-10-12. They use inert `.invalid`
destinations and synthetic placeholders. They are data, not instructions to
execute, and were not copied from published benchmark payloads.

Source IDs attribute attack families, not observed exploit success:

- O: [OWASP Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html),
  for authority changes, hidden instructions, encoding, hostile markup,
  retrieval and forged tool observations.
- G: [Greshake et al.](https://arxiv.org/abs/2302.12173), for indirect attacks
  through retrieved content. Repository and commit examples are local variants.
- L: Locally authored Loupe role, tag, fence, JSON/MCP, translation and
  prohibited-character boundary cases.
- The selected Delimited/Marked design follows
  [Hines et al., Spotlighting](https://www.microsoft.com/en-us/research/publication/defending-against-indirect-prompt-injection-attacks-with-spotlighting/).
  These checks establish deterministic application properties, not model
  obedience or immunity from prompt injection.

`worker_prompt_render` replays raw original Server bytes through the real
lease owner, then both data modes and the closed verification projection.
Its independent inverse checks static spans, labels, full boundary absence,
exact recovered bytes/JSON values, selection retries and destination bounds.
`worker_mcp_rpc` retains its existing protocol, state, submission and log
oracles while adding hostile source-correct prior details/titles and a fixed
job boundary. Mode bit 4 selects Marked, bit 5 selects a canonical description
using the request byte length modulo 40 (valid JSON whitespace permits every
case). All 40 cases also traverse both real
tool handlers in worker unit tests with explicit admission counts.
