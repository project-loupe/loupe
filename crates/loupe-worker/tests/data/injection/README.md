# Shared injection corpus

The canonical raw payloads are `fuzz/test_cases/worker_prompt_render/injection-*`
at the repository root. Prompt, MCP and report sink tests load those exact
files; do not maintain a second payload copy here. See the corpus source
catalog installed by the sink integration for admission and source details.
