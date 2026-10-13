//! Unit tests for source labels, validation lifetimes and secret ownership.
//!
//! The compile-fail checks (no `Deref`, no `AsRef`, no construction
//! without a token, `Unvalidated` cannot escape) are doc tests on the
//! items themselves; they do not appear here.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::marker::PhantomData;

use crate::{
	Agent, Browser, CarriedFrom, Config, Db, Ingress, Mark, Operator, Provider, Repo, Reporter,
	Sandbox, Secret, Server, Source, Untrusted, Unvalidated, Validate, ValidateCarrying, Worker,
	Zeroise,
};

/// Every byte of this payload is absent from the fixed text the
/// redacting `Debug` and `Display` impls print (lowercase letters,
/// `<>()[]` and the source names), so "no payload byte appears in the
/// output" is a meaningful assertion and not an accident of the
/// alphabet. High bytes and NUL are included so a `Debug` that escaped
/// them would be caught too.
const PAYLOAD: &[u8] = b"0123456789ABCXYZ\xff\x00\x7f";

fn assert_no_payload_byte(output: &str) {
	for byte in PAYLOAD {
		assert!(
			!output.as_bytes().contains(byte),
			"payload byte {byte:#04x} appears in {output:?}"
		);
	}
}

fn wrap<S: Source>(bytes: &[u8]) -> Untrusted<Vec<u8>, S> {
	Untrusted::new(bytes.to_vec(), minted_ingress::<S>())
}

/// A validator the tests share: a one-byte length prefix followed by
/// that many bytes, nothing trailing. Returns the body as an owned
/// `Vec` (the owning path) so it works for any `AsRef<[u8]>` payload.
struct LengthPrefixed;

// debug-ok: test parser error contains only lengths and closed categories.
#[derive(Debug, PartialEq, Eq)]
enum ParseError {
	Empty,
	Short { want: usize, have: usize },
	Trailing(usize),
}

impl<T: AsRef<[u8]>, S: Source> Validate<T, S> for LengthPrefixed {
	type Output = Vec<u8>;
	type Error = ParseError;

	fn validate<'view>(
		self, u: Unvalidated<'view, T>, _: Mark<'view, S>,
	) -> Result<Vec<u8>, ParseError> {
		let bytes = u.get().as_ref();
		let (&n, rest) = bytes.split_first().ok_or(ParseError::Empty)?;
		let want = usize::from(n);
		let body = rest.get(..want).ok_or(ParseError::Short { want, have: rest.len() })?;
		match rest.len().checked_sub(want) {
			Some(0) | None => Ok(body.to_vec()),
			Some(extra) => Err(ParseError::Trailing(extra)),
		}
	}
}

/// The zero-copy shape: the output borrows the input for its original
/// lifetime, not for the duration of `validate`.
struct FirstTwo;

impl<'a, S: Source> Validate<&'a [u8], S> for FirstTwo {
	type Output = &'a [u8];
	type Error = ParseError;

	fn validate<'view>(
		self, u: Unvalidated<'view, &'a [u8]>, _: Mark<'view, S>,
	) -> Result<&'a [u8], ParseError> {
		let bytes: &'a [u8] = u.get();
		bytes.get(..2).ok_or(ParseError::Short { want: 2, have: bytes.len() })
	}
}

#[test]
fn untrusted_debug_contains_no_payload_byte() {
	fn check<S: Source>() {
		let u = wrap::<S>(PAYLOAD);
		let out = format!("{u:?}");
		assert_no_payload_byte(&out);
		assert!(out.contains("[redacted]"), "{out}");
		assert!(out.contains(S::NAME), "{out}");
		// Alternate and pretty forms go through the same impl.
		assert_no_payload_byte(&format!("{u:#?}"));
	}
	check::<Agent>();
	check::<Repo>();
	check::<Sandbox>();
	check::<Worker>();
	check::<Server>();
	check::<Operator>();
	check::<Provider>();
	check::<Reporter>();
	check::<Db>();
	check::<Config>();
	check::<Browser>();
}

#[test]
fn untrusted_debug_does_not_need_the_payload_to_be_debug() {
	// A derived impl would require T: Debug
	// and print it.
	struct Opaque(#[allow(dead_code)] Vec<u8>);
	let u = Untrusted::new(Opaque(PAYLOAD.to_vec()), minted_ingress::<Worker>());
	assert_no_payload_byte(&format!("{u:?}"));
}

#[test]
fn secret_debug_and_display_are_redacted() {
	let s = Secret::new(String::from("0123456789ABCXYZ"));
	assert_eq!(format!("{s:?}"), "[redacted]");
	assert_eq!(format!("{s}"), "[redacted]");
	assert_eq!(format!("{s:#?}"), "[redacted]");

	let v = Secret::new(PAYLOAD.to_vec());
	assert_no_payload_byte(&format!("{v:?}"));
	assert_no_payload_byte(&format!("{v}"));

	let a = Secret::new([b'X', b'Y', b'Z', 0xff]);
	assert_no_payload_byte(&format!("{a:?}"));
	assert_no_payload_byte(&format!("{a}"));
}

#[test]
fn len_and_is_empty_report_the_byte_length() {
	// len and is_empty are total and count bytes, for every
	// AsRef<[u8]> payload including the empty one.
	let v = wrap::<Worker>(PAYLOAD);
	assert_eq!(v.len(), PAYLOAD.len());
	assert!(!v.is_empty());

	let s = Untrusted::new(PAYLOAD, minted_ingress::<Db>());
	assert_eq!(s.len(), PAYLOAD.len());

	let st = Untrusted::new(String::from("héllo"), minted_ingress::<Config>());
	assert_eq!(st.len(), 6, "len is bytes, not chars");

	let arr = Untrusted::new([0u8; 4], minted_ingress::<Sandbox>());
	assert_eq!(arr.len(), 4);

	let empty = wrap::<Agent>(b"");
	assert_eq!(empty.len(), 0);
	assert!(empty.is_empty());
}

#[test]
fn validate_runs_the_validator_and_returns_its_output() {
	let u = wrap::<Worker>(b"\x03abc");
	assert_eq!(u.validate(LengthPrefixed), Ok(b"abc".to_vec()));

	let u = wrap::<Sandbox>(b"\x00");
	assert_eq!(u.validate(LengthPrefixed), Ok(Vec::new()));
}

#[test]
fn validate_returns_the_validators_error_unchanged() {
	// The crate adds no error of its own and never panics on
	// what the validator rejects.
	assert_eq!(wrap::<Worker>(b"").validate(LengthPrefixed), Err(ParseError::Empty));
	assert_eq!(
		wrap::<Worker>(b"\x05ab").validate(LengthPrefixed),
		Err(ParseError::Short { want: 5, have: 2 })
	);
	assert_eq!(wrap::<Worker>(b"\x01abc").validate(LengthPrefixed), Err(ParseError::Trailing(2)));
}

#[test]
fn validate_can_return_a_value_borrowed_from_the_input() {
	// The borrowed output outlives the Untrusted wrapper that was
	// consumed, because it borrows the original buffer, not the view.
	let buffer: Vec<u8> = b"xyz".to_vec();
	let out: &[u8] = {
		let u = Untrusted::new(buffer.as_slice(), minted_ingress::<Repo>());
		u.validate(FirstTwo).unwrap_or(&[])
	};
	assert_eq!(out, b"xy");
}

#[test]
fn map_ref_reslices_without_unwrapping_and_keeps_the_source() {
	let owned = wrap::<Provider>(b"\x03abcTRAILING");
	let view: Untrusted<&[u8], Provider> = owned.map_ref(|v| v.get(..4).unwrap_or(&[]));
	assert_eq!(view.len(), 4);
	// The source parameter is unchanged; this only compiles if `view`
	// is `Untrusted<_, Provider>`.
	fn only_provider<T>(_: &Untrusted<T, Provider>) {}
	only_provider(&view);
	assert_eq!(view.validate(LengthPrefixed), Ok(b"abc".to_vec()));

	// Projection to a different type keeps the wrapper too.
	let s = Untrusted::new(String::from("ab"), minted_ingress::<Operator>());
	let bytes: Untrusted<&[u8], Operator> = s.map_ref(|s| s.as_bytes());
	assert_eq!(bytes.len(), 2);
	let str_view: Untrusted<&str, Operator> = s.map_ref(|s| s.as_str());
	assert_eq!(str_view.len(), 2);
}

#[test]
fn as_bytes_and_split_at_reslice_without_a_closure() {
	// The closed helpers carry the source and never panic; a
	// split past the end is `None`, not a panic.
	let owned = wrap::<Sandbox>(b"\x02abTAIL");
	let view: Untrusted<&[u8], Sandbox> = owned.as_bytes();
	assert_eq!(view.len(), 7);
	let Some((head, tail)) = view.split_at(3) else {
		unreachable!("split inside the slice is Some");
	};
	assert_eq!(head.len(), 3);
	assert_eq!(tail.len(), 4);
	assert_eq!(head.validate(LengthPrefixed), Ok(b"ab".to_vec()));
	assert!(view.split_at(8).is_none());
	assert!(view.split_at(7).is_some_and(|(_, t)| t.is_empty()));
	assert!(view.split_at(0).is_some_and(|(h, _)| h.is_empty()));
	fn only_sandbox<T>(_: &Untrusted<T, Sandbox>) {}
	only_sandbox(&head);
	only_sandbox(&tail);
}

#[test]
fn framing_loop_keeps_the_input_lifetime() {
	// Parsers return values borrowed from the input. Several
	// frames parsed from one buffer all borrow the buffer, not the
	// view, so they outlive the loop's views.
	fn frames(buffer: &Untrusted<Vec<u8>, Worker>) -> Result<Vec<&[u8]>, ParseError> {
		let mut rest = buffer.as_bytes();
		let mut out = Vec::new();
		while !rest.is_empty() {
			let body = rest.validate(FirstTwo)?;
			out.push(body);
			rest = rest
				.split_at(2)
				.map(|(_, t)| t)
				.ok_or(ParseError::Short { want: 2, have: rest.len() })?;
		}
		Ok(out)
	}
	let buffer = wrap::<Worker>(b"abcdef");
	assert_eq!(frames(&buffer), Ok(vec![&b"ab"[..], b"cd", b"ef"]));
	assert_eq!(frames(&wrap::<Worker>(b"")), Ok(Vec::new()));
	assert_eq!(frames(&wrap::<Worker>(b"abc")), Err(ParseError::Short { want: 2, have: 1 }));
}

#[test]
fn untrusted_view_is_copy_and_still_untrusted() {
	// A slice view is `Copy` so a loop can validate it and keep it; the
	// copy is the same opaque type.
	let owned = wrap::<Db>(PAYLOAD);
	let view = owned.as_bytes();
	let again = view;
	assert_eq!(view.len(), again.len());
	assert_no_payload_byte(&format!("{again:?}"));
}

#[test]
fn untrusted_secret_zeroises_without_exposing() {
	// Zeroise for Untrusted: a value can be hostile and secret at once
	// (a provider response carrying a token). Wiping needs no read, and
	// the wrapper stays opaque.
	let mut u = wrap::<Provider>(PAYLOAD);
	u.zeroise();
	assert!(u.is_empty());
	let s = Secret::new(wrap::<Provider>(PAYLOAD));
	assert_eq!(s.expose().len(), PAYLOAD.len());
	assert_eq!(format!("{s}"), "[redacted]");
	assert_no_payload_byte(&format!("{:?}", s.expose()));
}

#[test]
fn clone_of_untrusted_is_still_untrusted() {
	// Clone exists for moving values around; it yields the same
	// opaque type, never the payload.
	let u = wrap::<Agent>(PAYLOAD);
	let c: Untrusted<Vec<u8>, Agent> = u.clone();
	assert_eq!(c.len(), u.len());
	assert_no_payload_byte(&format!("{c:?}"));
}

#[test]
fn source_names_are_the_eleven_sources_and_distinct() {
	let names = [
		Agent::NAME,
		Repo::NAME,
		Sandbox::NAME,
		Worker::NAME,
		Server::NAME,
		Operator::NAME,
		Provider::NAME,
		Reporter::NAME,
		Db::NAME,
		Config::NAME,
		Browser::NAME,
	];
	assert_eq!(
		names,
		[
			"agent", "repo", "sandbox", "worker", "server", "operator", "provider", "reporter",
			"db", "config", "browser"
		]
	);
	for (i, a) in names.iter().enumerate() {
		for b in names.iter().skip(i.saturating_add(1)) {
			assert_ne!(a, b);
		}
	}
}

#[test]
fn untrusted_is_send_and_sync_when_the_payload_is() {
	// The wrapper can be stored and sent across threads. It adds no
	// interior mutability, so it is Send and Sync exactly when the
	// payload is.
	fn assert_send_sync<T: Send + Sync>() {}
	assert_send_sync::<Untrusted<Vec<u8>, Worker>>();
	assert_send_sync::<Untrusted<&'static [u8], Db>>();
	assert_send_sync::<Ingress<Sandbox>>();
	assert_send_sync::<Secret<Vec<u8>>>();
}

#[test]
fn secret_expose_returns_the_value() {
	// expose returns the wrapped value. That it is the only way is
	// proven by the compile_fail doc tests on `Secret`.
	let s = Secret::new(String::from("hunter2"));
	assert_eq!(s.expose(), "hunter2");
	assert_eq!(s.expose().len(), 7);

	let v = Secret::new(vec![1u8, 2, 3]);
	assert_eq!(v.expose().as_slice(), &[1, 2, 3]);
}

/// Captures a buffer the test owns so the bytes can be inspected
/// after the `Secret` that held the borrow is dropped. This observes
/// that `Drop` ran the zeroiser over those bytes. It cannot observe
/// whether the compiler kept the stores; that is what the volatile
/// writes are for and what Miri and inspection of the one `unsafe`
/// module check.
struct Borrowed<'a>(&'a mut [u8]);

impl Zeroise for Borrowed<'_> {
	fn zeroise(&mut self) {
		self.0.zeroise();
	}
}

#[test]
fn secret_drop_zeroises_the_bytes_it_owns() {
	let mut buffer = [0xAAu8; 24];
	{
		let secret = Secret::new(Borrowed(&mut buffer));
		assert!(secret.expose().0.iter().all(|b| *b == 0xAA));
	}
	assert!(buffer.iter().all(|b| *b == 0), "{buffer:?}");

	// An explicit drop in the middle of a scope behaves the same.
	let mut other = [0x55u8; 3];
	let secret = Secret::new(Borrowed(&mut other));
	drop(secret);
	assert_eq!(other, [0, 0, 0]);
}

#[test]
fn zeroise_covers_array_slice_vec_string_and_box() {
	let mut arr = [0xFFu8; 16];
	arr.zeroise();
	assert_eq!(arr, [0; 16]);

	let mut backing = [0xFFu8; 7];
	let slice: &mut [u8] = &mut backing;
	slice.zeroise();
	assert_eq!(backing, [0; 7]);

	let mut v = PAYLOAD.to_vec();
	v.zeroise();
	assert!(v.is_empty());

	let mut s = String::from("hunter2");
	s.zeroise();
	assert!(s.is_empty());

	let mut b: Box<[u8]> = PAYLOAD.to_vec().into_boxed_slice();
	b.zeroise();
	assert_eq!(b.len(), PAYLOAD.len());
	assert!(b.iter().all(|x| *x == 0));
}

#[test]
fn zeroise_of_empty_values_does_nothing_and_does_not_panic() {
	let mut arr: [u8; 0] = [];
	arr.zeroise();
	let mut v: Vec<u8> = Vec::new();
	v.zeroise();
	assert_eq!(v.capacity(), 0);
	let mut s = String::new();
	s.zeroise();
	assert_eq!(s.capacity(), 0);
	let mut b: Box<[u8]> = Box::default();
	b.zeroise();
	assert!(b.is_empty());
	drop(Secret::new(Vec::<u8>::new()));
	drop(Secret::new(String::new()));
}

#[test]
fn vec_and_string_zeroise_keep_their_capacity() {
	// The whole allocation is wiped in place, not freed and
	// replaced; the capacity staying put is the observable sign that
	// the same buffer was written.
	let mut v = Vec::with_capacity(64);
	v.extend_from_slice(PAYLOAD);
	let cap = v.capacity();
	v.zeroise();
	assert_eq!(v.len(), 0);
	assert_eq!(v.capacity(), cap);

	let mut s = String::with_capacity(64);
	s.push_str("hunter2");
	let cap = s.capacity();
	s.zeroise();
	assert_eq!(s.len(), 0);
	assert_eq!(s.capacity(), cap);
}

#[test]
fn ingress_token_is_a_copyable_zero_sized_marker() {
	// An ingress module keeps one token and reuses it; the token
	// carries no data, only the right to construct.
	let token = minted_ingress::<Worker>();
	let a = Untrusted::new(vec![1u8], token);
	let b = Untrusted::new(vec![2u8, 3], token);
	assert_eq!(a.len().saturating_add(b.len()), 3);
	assert_eq!(core::mem::size_of::<Ingress<Worker>>(), 0);
	assert_eq!(
		core::mem::size_of::<Untrusted<Vec<u8>, Worker>>(),
		core::mem::size_of::<Vec<u8>>(),
		"the label costs nothing at runtime"
	);
}

#[test]
fn to_vec_keeps_the_source_and_the_bytes() {
	// An owned copy of a view is still labelled and still unread.
	let owned = wrap::<Worker>(b"\x02ab");
	let copy: Untrusted<Vec<u8>, Worker> = owned.as_bytes().to_vec();
	assert_eq!(copy.len(), 3);
	assert_eq!(copy.validate(LengthPrefixed), Ok(b"ab".to_vec()));
	assert_no_payload_byte(&format!("{:?}", wrap::<Worker>(PAYLOAD).as_bytes().to_vec()));
}

/// Carries the body of a length-prefixed record on as `Agent`.
struct BodyAsAgent;

impl<'a, S: Source> ValidateCarrying<&'a [u8], S> for BodyAsAgent
where
	Agent: CarriedFrom<S>,
{
	type Output = Untrusted<&'a [u8], Agent>;
	type Error = ParseError;

	fn validate(self, u: Unvalidated<'_, &'a [u8], S>) -> Result<Self::Output, ParseError> {
		let (&n, _) = u.get().split_first().ok_or(ParseError::Empty)?;
		let end = usize::from(n).saturating_add(1);
		u.carry::<Agent>(1..end).ok_or(ParseError::Short {
			want: usize::from(n),
			have: u.get().len().saturating_sub(1),
		})
	}
}

fn carried<S: Source>(bytes: &[u8]) -> Result<Vec<u8>, ParseError>
where
	Agent: CarriedFrom<S>,
{
	let input = wrap::<S>(bytes);
	let body = input.as_bytes().validate_carrying(BodyAsAgent)?;
	// The carried view is agent text: still unread, parsed by a
	// validator for `Agent` like any other.
	let mut framed = vec![u8::try_from(body.len()).unwrap_or(u8::MAX)];
	framed.extend_from_slice(&body.validate(Copied)?);
	Untrusted::new(framed, minted_ingress::<Agent>()).validate(LengthPrefixed)
}

/// Copies a view's bytes out; the test's stand-in for a parser.
struct Copied;

impl<S: Source> Validate<&[u8], S> for Copied {
	type Output = Vec<u8>;
	type Error = ParseError;

	fn validate<'view>(
		self, u: Unvalidated<'view, &[u8]>, _: Mark<'view, S>,
	) -> Result<Vec<u8>, ParseError> {
		Ok(u.get().to_vec())
	}
}

#[test]
fn carry_relabels_a_sub_slice_to_agent() {
	// Worker, Sandbox, Db and Server bytes may be carried on as Agent.
	assert_eq!(carried::<Worker>(b"\x02abc"), Ok(b"ab".to_vec()));
	assert_eq!(carried::<Worker>(b"\x00"), Ok(Vec::new()));
	assert_eq!(carried::<Sandbox>(b"\x02abc"), Ok(b"ab".to_vec()));
	assert_eq!(carried::<Db>(b"\x02abc"), Ok(b"ab".to_vec()));
	assert_eq!(carried::<Server>(b"\x02abc"), Ok(b"ab".to_vec()));
	assert_eq!(carried::<Db>(b"\x05ab"), Err(ParseError::Short { want: 5, have: 2 }));
}

#[test]
fn carry_out_of_range_is_none() {
	// A range past the end or reversed is refused, without panicking.
	assert_eq!(carried::<Worker>(b"\x05ab"), Err(ParseError::Short { want: 5, have: 2 }));
	struct Reversed;
	impl<'a> ValidateCarrying<&'a [u8], Worker> for Reversed {
		type Output = bool;
		type Error = ();
		#[allow(clippy::reversed_empty_ranges)]
		fn validate(self, u: Unvalidated<'_, &'a [u8], Worker>) -> Result<bool, ()> {
			Ok(u.carry::<Agent>(2..1).is_none() && u.carry::<Agent>(0..usize::MAX).is_none())
		}
	}
	assert_eq!(wrap::<Worker>(b"abc").as_bytes().validate_carrying(Reversed), Ok(true));
}

#[test]
fn receive_buffer_operations_keep_the_label() {
	// A receive buffer can grow, split and drop its front
	// without its bytes leaving the label.
	let mut buf = Untrusted::new(Vec::new(), minted_ingress::<Sandbox>());
	assert!(buf.is_empty());
	buf.extend(wrap::<Sandbox>(b"\x02a").as_bytes());
	buf.extend(wrap::<Sandbox>(b"b\x01c").as_bytes());
	assert_eq!(buf.len(), 5);
	let tail = buf.split_off(3);
	assert!(buf.split_off(9).is_none());
	assert_eq!(buf.len(), 3);
	assert_eq!(buf.clone().validate(LengthPrefixed), Ok(b"ab".to_vec()));
	assert_eq!(tail.map(|t| t.validate(LengthPrefixed)), Some(Ok(b"c".to_vec())));
	buf.discard_front(1);
	assert_eq!(buf.len(), 2);
	buf.discard_front(10);
	assert!(buf.is_empty());
}

/// A test-only typed output whose constructor needs the actual source mark.
struct CheckedText<S: Source> {
	text: String,
	source: PhantomData<S>,
}

impl<S: Source> CheckedText<S> {
	fn new(text: &str, _: &Mark<'_, S>) -> Self {
		Self { text: String::from(text), source: PhantomData }
	}
}

struct TextFields;

impl<T: AsRef<[u8]>, S: Source> Validate<T, S> for TextFields {
	type Output = (CheckedText<S>, CheckedText<S>);
	type Error = core::str::Utf8Error;

	fn validate<'view>(
		self, u: Unvalidated<'view, T>, mark: Mark<'view, S>,
	) -> Result<Self::Output, Self::Error> {
		let text = core::str::from_utf8(u.get().as_ref())?;
		Ok((CheckedText::new(text, &mark), CheckedText::new(text, &mark)))
	}
}

#[test]
fn plain_marks_construct_owned_outputs_of_the_actual_source() {
	// Both outputs own their bytes and outlive the validation call.
	fn check<S: Source>(bytes: &[u8]) {
		let (first, second): (CheckedText<S>, CheckedText<S>) =
			wrap::<S>(bytes).validate(TextFields).expect("valid UTF-8 fixture");
		assert_eq!(first.text.as_bytes(), bytes);
		assert_eq!(second.text, first.text);
	}
	check::<Config>(b"settings");
	check::<Operator>(b"operator");
	check::<Repo>(b"src/lib.rs");
	// Authenticated emptiness is legitimate; it must still supply a mark.
	check::<Operator>(b"");
}

#[test]
fn carrying_marks_keep_the_source_and_nested_validation_uses_agent() {
	// The carrying mark is Worker; only the carried span is Agent.
	struct Record;
	impl<'a> ValidateCarrying<&'a [u8], Worker> for Record {
		type Output = (CheckedText<Worker>, Untrusted<Vec<u8>, Agent>);
		type Error = ();
		fn validate(self, u: Unvalidated<'_, &'a [u8], Worker>) -> Result<Self::Output, ()> {
			let metadata = core::str::from_utf8(u.get().get(..2).ok_or(())?).map_err(|_| ())?;
			let worker = CheckedText::new(metadata, &u.mark());
			let agent = u.carry::<Agent>(2..u.get().len()).ok_or(())?.to_vec();
			Ok((worker, agent))
		}
	}
	let (worker, agent) = {
		let input = wrap::<Worker>(b"idagent text");
		input.as_bytes().validate_carrying(Record).expect("record fixture")
	};
	assert_eq!(worker.text, "id");
	let (first, second): (CheckedText<Agent>, CheckedText<Agent>) =
		agent.validate(TextFields).expect("carried UTF-8");
	assert_eq!(first.text, "agent text");
	assert_eq!(second.text, first.text);
}

/// Labelled input for this test. Only synthetic fixture bytes may be minted.
#[allow(unsafe_code)]
fn minted_ingress<S: crate::Source>() -> crate::Ingress<S> {
	// SAFETY: test fixture: the label marks bytes this test made up; no
	// production path receives them.
	unsafe { crate::Ingress::new() }
}
