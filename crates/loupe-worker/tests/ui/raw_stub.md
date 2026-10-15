The default library must not turn arbitrary caller strings into Sandbox output
through the synthetic backend. The optional `test-support` feature explicitly
grants fixture authority; it is not part of the default library API.

```compile_fail,E0432
use loupe_worker::llm::{testing::StubLlmBackend, LlmBackend, LlmRequest, LlmResponse};

async fn sync_stub(text: String, request: LlmRequest) -> LlmResponse {
    StubLlmBackend::new("caller", move |_| Ok(text.clone()))
        .run(request).await.unwrap()
}

async fn async_stub(text: String, request: LlmRequest) -> LlmResponse {
    StubLlmBackend::new_async("caller", move |_| {
        let text = text.clone();
        async move { Ok(text) }
    }).run(request).await.unwrap()
}
```
