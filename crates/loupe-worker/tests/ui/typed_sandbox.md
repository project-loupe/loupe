Raw caller paths do not carry checked-out worktree authority.

```compile_fail
use loupe_worker::sandbox::SandboxBuilder;
let arbitrary = std::path::PathBuf::from("/tmp/arbitrary-source");
let config = loupe_worker::config::SandboxLaunchConfig::default();
let _ = SandboxBuilder::new(arbitrary, &config);
```

Raw dynamic strings cannot become sandbox environment operands.

```compile_fail
use loupe_worker::sandbox::SandboxBuilder;
fn inject(builder: SandboxBuilder, text: String) {
    let _ = builder.set_env("PUBLIC_NAME", text);
}
```

Finalized commands cannot accept additional arguments after validation.

```compile_fail
use loupe_worker::sandbox::{SandboxBuilder, SandboxValue};
fn extend(builder: SandboxBuilder) {
    let mut command = builder.build(SandboxValue::r#static("/bin/true"), &[]);
    command.arg("unchecked operand");
}
```

Finalized commands expose neither an environment mutator nor their underlying command.

```compile_fail
use loupe_worker::sandbox::{SandboxBuilder, SandboxValue};
fn extend(builder: SandboxBuilder) {
    let mut command = builder.build(SandboxValue::r#static("/bin/true"), &[]);
    command.env("UNCONTROLLED", "value");
}
```

```compile_fail
use loupe_worker::sandbox::{SandboxBuilder, SandboxValue};
fn extend(builder: SandboxBuilder) {
    let mut command = builder.build(SandboxValue::r#static("/bin/true"), &[]);
    command.as_std_mut().arg("unchecked operand");
}
```

Dynamic text cannot declare itself public configuration or mount authority.

```compile_fail
use loupe_worker::config::ConfigNonSecret;
let value = ConfigNonSecret::from(String::from("unreviewed"));
```

```compile_fail
use loupe_worker::sandbox::SandboxPath;
let source = SandboxPath::from(std::path::PathBuf::from("/tmp/arbitrary"));
```

Secret values cannot become sandbox operands.

```compile_fail
use loupe_worker::sandbox::SandboxBuilder;
fn inject(builder: SandboxBuilder, secret: loupe_provenance::Secret<String>) {
    let _ = builder.set_env("PUBLIC_NAME", secret);
}
```

Child processes cannot be separated from their retained path owners.

```compile_fail
use loupe_worker::sandbox::PreparedChild;
fn detach(first: &mut PreparedChild, second: &mut PreparedChild) {
    std::mem::swap(&mut **first, &mut **second);
}
```

The internal network supervisor requires its dedicated Config argument roles.

```compile_fail
use loupe_worker::sandbox::{run_networked_sandbox, SandboxNetworkMode};
fn inject(raw: Vec<std::ffi::OsString>) {
    let _ = run_networked_sandbox(SandboxNetworkMode::Public, vec![], vec![], raw);
}
```
