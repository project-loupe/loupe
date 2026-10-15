//! Run these opt-in checks inside the worker image. They compile small,
//! dependency-free projects through the same sandbox used by scanner jobs.

#![cfg(target_os = "linux")]

use std::time::Duration;

use loupe_worker::sandbox::{SandboxBuilder, SandboxPath, SandboxValue};

async fn compile_in_sandbox(files: &[(&str, &str)], command: &str) {
	let source = tempfile::tempdir().unwrap();
	for (name, contents) in files {
		let path = source.path().join(name);
		std::fs::create_dir_all(path.parent().unwrap()).unwrap();
		std::fs::write(path, contents).unwrap();
	}
	let script = format!(
		"set -eu\ncp -R /workdir /tmp/project\ncd /tmp/project\n{command}\nprintf 'TOOLCHAIN_OK\\n'"
	);
	std::fs::write(source.path().join("toolchain-check.sh"), script).unwrap();
	let mut process =
		SandboxBuilder::new(SandboxPath::fixture(source.path().to_owned()), &Default::default())
			// Networked worker jobs mount these public certificates. pip reads
			// them even offline, so retain that mount without enabling egress.
			.bind_ro(SandboxPath::fixture("/etc/ssl/certs".into()), "/etc/ssl/certs")
			.set_env(
				"PATH",
				SandboxValue::r#static(
					"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				),
			)
			.set_env("CARGO_TARGET_DIR", SandboxValue::r#static("/tmp/cargo-target"))
			.build(
				SandboxValue::r#static("/bin/sh"),
				&[SandboxValue::r#static("/workdir/toolchain-check.sh")],
			);
	process.kill_on_drop(true);
	let output = tokio::time::timeout(Duration::from_secs(120), process.output())
		.await
		.expect("toolchain check timed out")
		.expect("start sandboxed compiler");
	assert!(
		output.status.success(),
		"sandboxed build failed ({})\nstdout: {}\nstderr: {}",
		output.status,
		String::from_utf8_lossy(&output.stdout),
		String::from_utf8_lossy(&output.stderr),
	);
	assert!(String::from_utf8_lossy(&output.stdout).contains("TOOLCHAIN_OK"));
}

#[tokio::test]
#[ignore = "requires the worker image's development toolchains"]
async fn rust_builds_with_a_fresh_home() {
	compile_in_sandbox(
		&[
			("Cargo.toml", "[package]\nname = \"toolchain-check\"\nversion = \"0.1.0\"\nedition = \"2024\"\nrust-version = \"1.88\"\n"),
			("src/lib.rs", "#[test] fn builds() { assert_eq!(2 + 2, 4); }\n"),
		],
		"cargo test --offline\ncargo fmt --version\ncargo clippy --offline",
	)
	.await;
}

#[tokio::test]
#[ignore = "requires the worker image's development toolchains"]
async fn go_builds_with_a_fresh_home() {
	compile_in_sandbox(
		&[
			("go.mod", "module example.invalid/toolchaincheck\n\ngo 1.23\n"),
			("main_test.go", "package toolchaincheck\nimport \"testing\"\nfunc TestBuild(t *testing.T) { if 2 + 2 != 4 { t.Fatal(\"arithmetic\") } }\n"),
		],
		"GOPROXY=off GOTOOLCHAIN=local go test ./...",
	)
	.await;
}

#[tokio::test]
#[ignore = "requires the worker image's development toolchains"]
async fn java_builds_and_loads_security_configuration() {
	compile_in_sandbox(
		&[(
			"Main.java",
			r#"import java.security.MessageDigest;
import javax.net.ssl.SSLContext;
class Main {
    public static void main(String[] args) throws Exception {
        if (MessageDigest.getInstance("SHA-256").digest(new byte[0]).length != 32)
            throw new AssertionError("digest");
        if (SSLContext.getDefault().getDefaultSSLParameters().getCipherSuites().length == 0)
            throw new AssertionError("TLS configuration");
    }
}
"#,
		)],
		"javac Main.java\njar --create --file main.jar Main.class\njava -cp main.jar Main",
	)
	.await;
}

#[tokio::test]
#[ignore = "requires the worker image's development toolchains"]
async fn python_creates_an_offline_virtual_environment() {
	// venv hides ensurepip's stderr; repeat a failed subprocess for diagnostics.
	compile_in_sandbox(
		&[],
		r#"python3 -m venv /tmp/venv || {
    /tmp/venv/bin/python -Im ensurepip --upgrade --default-pip
    exit 1
}
/tmp/venv/bin/python -c 'import ssl, sqlite3; assert sqlite3.connect(":memory:").execute("select 1").fetchone() == (1,)'
/tmp/venv/bin/pip --version"#,
	)
	.await;
}

#[tokio::test]
#[ignore = "requires the worker image's development toolchains"]
async fn native_build_links_development_libraries() {
	compile_in_sandbox(
		&[
			("CMakeLists.txt", r#"cmake_minimum_required(VERSION 3.22)
project(toolchain_check LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 20)
find_package(Boost 1.74 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(ZLIB REQUIRED)
find_package(Qt6 6.2 REQUIRED COMPONENTS Core Widgets LinguistTools)
find_package(PkgConfig REQUIRED)
pkg_check_modules(NATIVE REQUIRED IMPORTED_TARGET capnp libzmq libevent libqrencode)
add_executable(check main.cpp)
target_link_libraries(check PRIVATE Boost::headers OpenSSL::Crypto SQLite::SQLite3 ZLIB::ZLIB Qt6::Core Qt6::Widgets PkgConfig::NATIVE)
"#),
			("main.cpp", r#"#include <boost/version.hpp>
#include <capnp/message.h>
#include <event2/event.h>
#include <openssl/crypto.h>
#include <qrencode.h>
#include <sqlite3.h>
#include <sys/sdt.h>
#include <zlib.h>
#include <zmq.h>
#include <QCoreApplication>
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    capnp::MallocMessageBuilder message;
    auto* events = event_base_new();
    auto* context = zmq_ctx_new();
    auto* qr = QRcode_encodeString8bit("check", 0, QR_ECLEVEL_L);
    STAP_PROBE(toolchain, check);
    if (!events || !context || !qr || !sqlite3_libversion() || !zlibVersion() || !OpenSSL_version(0)) return 1;
    QRcode_free(qr);
    zmq_ctx_term(context);
    event_base_free(events);
}
"#),
		],
		"cmake -S . -B /tmp/native-build -G Ninja\ncmake --build /tmp/native-build\n/tmp/native-build/check\ncapnp --version",
	)
	.await;
}
