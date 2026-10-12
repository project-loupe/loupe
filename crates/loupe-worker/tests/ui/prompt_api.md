Source-labelled data has a positive typed route:
```rust
use loupe_worker::llm::prompt::{PromptBuilder, PREAMBLE};
use loupe_core::text::{BoundedText, RepoPath, policy::FindingDescription};
use loupe_provenance::{Agent, Repo};
fn build(text: &BoundedText<FindingDescription, Agent>, path: &RepoPath<Repo>) {
    let mut b = PromptBuilder::new(PREAMBLE);
    b.instruction("Static instructions.\n").unwrap();
    b.data("description", text).unwrap();
    b.data_path("file", path).unwrap();
    let _ = b.render();
}
```

Runtime strings cannot become instructions:
```compile_fail,E0521
use loupe_worker::llm::prompt::{PromptBuilder, PREAMBLE};
fn inject(text: &str) { PromptBuilder::new(PREAMBLE).instruction(text).unwrap(); }
```
```compile_fail,E0521
use loupe_worker::llm::prompt::PromptBuilder;
fn inject(text: &str) { let _ = PromptBuilder::new(text); }
```

Raw strings and arbitrary JSON cannot enter data slots:
```compile_fail,E0308
use loupe_worker::llm::prompt::{PromptBuilder, PREAMBLE};
let mut b = PromptBuilder::new(PREAMBLE);
b.data("field", &String::from("hostile")).unwrap();
```
```compile_fail,E0308
use loupe_worker::llm::prompt::{PromptBuilder, PREAMBLE};
let mut b = PromptBuilder::new(PREAMBLE);
b.data_json("field", &serde_json::json!({"hostile": true})).unwrap();
```

The caller cannot choose a different source:
```compile_fail,E0308
use loupe_worker::llm::prompt::{PromptBuilder, PREAMBLE};
use loupe_core::text::{BoundedText, policy::FindingDescription};
use loupe_provenance::{Agent, Repo};
fn change_source(text: &BoundedText<FindingDescription, Agent>) {
    PromptBuilder::new(PREAMBLE).data::<FindingDescription, Repo>("field", text).unwrap();
}
```

Completed prompts have neither a raw constructor nor implicit formatting:
```compile_fail,E0423
use loupe_worker::llm::prompt::Prompt;
let _ = Prompt(String::from("raw"));
```
```compile_fail,E0277
use loupe_worker::llm::prompt::Prompt;
let prompt = Prompt::instruction("static").unwrap();
let _ = format!("{prompt}");
```
