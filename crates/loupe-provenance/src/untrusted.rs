//! `Untrusted<T, S>`, the token that creates it, the view a validator
//! sees, and the `Validate` trait.
//!
//! The API is deliberately small; every method is a way for untrusted
//! bytes to get out, so each one has one reason to exist, stated in
//! its doc. The guarantees of the form "there is no way to do X" are
//! proven by the compile-fail tests in `src/compile_fail.rs`.

use core::fmt;
use core::marker::PhantomData;
use core::ops::Range;

use crate::Source;

/// Permission to construct validated outputs retaining the current source.
///
/// A plain [`Validate`] receives this alongside its unlabelled view;
/// a [`ValidateCarrying`] obtains it from [`Unvalidated::mark`]. The
/// lifetime is the current validation borrow, even for borrowed input,
/// so the mark cannot escape as reusable construction authority. Owned
/// validated outputs may outlive that borrow.
///
/// No public constructor, `Default`, `Clone`, source conversion or
/// relabelling operation exists. Constructors in consuming crates borrow
/// the mark so one validator can build several fields of the same source.
/// A mark identifies the source; the named validator's review must still
/// establish that each field was derived from the appropriate input.
pub struct Mark<'view, S: Source>(PhantomData<&'view S>);

impl<'view, S: Source> Mark<'view, S> {
	fn new<T>(_: &'view T) -> Self {
		Self(PhantomData)
	}
}

/// The right to construct an [`Untrusted`] value from source `S`.
///
/// Zero-sized and `Copy`: an ingress module keeps one and reuses it.
/// Its constructor, `Ingress::new`, exists only under the `ingress`
/// feature, which only the ingress modules' crates and test harnesses
/// enable.
///
/// The feature alone does not keep the constructor out of other
/// crates: Cargo unifies features across a build, so every crate in a
/// workspace build can name it. What keeps it to ingress is that it is
/// an `unsafe fn`: the workspace denies `unsafe_code`, so every call
/// needs an `#[allow(unsafe_code)]` that `ci/check.sh` accepts only in
/// the files listed in `ci/unsafe-allow.txt`.
pub struct Ingress<S: Source>(PhantomData<S>);

impl<S: Source> Ingress<S> {
	/// The constructor. Exists under the `ingress` feature, and for
	/// this crate's own unit tests and Kani harnesses.
	///
	/// # Safety
	///
	/// `unsafe` marks a security contract the compiler cannot check,
	/// as `unsafe trait Send` does in std, not a memory-safety one:
	/// calling this asserts that the value about to be wrapped really
	/// arrived from source `S` at an ingress point. Only an ingress
	/// module may call it, right after the read it labels (the
	/// module's docs name the read: the mTLS middleware, a socket
	/// accept loop, a file read); test fixtures and fuzz harnesses may
	/// call it for bytes they made up. Every call site carries
	/// `#[allow(unsafe_code)]` and is listed with its reason in
	/// `ci/unsafe-allow.txt`, so the compiler, not a text search, finds
	/// them all.
	#[cfg(any(feature = "ingress", test, kani))]
	#[allow(clippy::new_without_default)] // one named constructor, on purpose
	#[must_use]
	#[allow(unsafe_code)] // declares the contract; see # Safety
	pub const unsafe fn new() -> Self {
		Ingress(PhantomData)
	}
}

impl<S: Source> Clone for Ingress<S> {
	fn clone(&self) -> Self {
		*self
	}
}

impl<S: Source> Copy for Ingress<S> {}

impl<S: Source> fmt::Debug for Ingress<S> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "Ingress<{}>", S::NAME)
	}
}

/// A value from source `S` that has not been parsed. Cannot be read.
///
/// The wrapper has no `Deref`, no `AsRef`, no `Borrow`, no `From`
/// into `T`, no `PartialEq`, no `Display`, no public field, and its
/// `Debug` prints the source and `[redacted]` without requiring
/// `T: Debug`. It can be moved, copied or cloned when `T` can, stored,
/// and sent across threads or a socket. The label costs
/// nothing: `Untrusted<T, S>` has the size of `T`.
///
/// The ways out are [`validate`](Self::validate), which runs a parser,
/// and [`map_ref`](Self::map_ref), which projects through a closure.
/// [`as_bytes`](Self::as_bytes) and [`split_at`](Self::split_at)
/// reslice without showing bytes to anyone.
pub struct Untrusted<T, S: Source> {
	value: T,
	source: PhantomData<S>,
}

impl<T, S: Source> Untrusted<T, S> {
	/// For `Zeroise`, which writes and never reads.
	pub(crate) const fn value_mut(&mut self) -> &mut T {
		&mut self.value
	}

	/// Wrap a value that just arrived from source `S`. Callable only
	/// with an [`Ingress<S>`] token, so only at ingress.
	#[must_use]
	pub const fn new(value: T, _token: Ingress<S>) -> Self {
		Untrusted { value, source: PhantomData }
	}

	/// The length in bytes of the wrapped value. The one inspection
	/// allowed before parsing, so a caller can check a cap or size a
	/// buffer. Never panics.
	pub fn len(&self) -> usize
	where
		T: AsRef<[u8]>,
	{
		self.value.as_ref().len()
	}

	/// Whether the wrapped value has zero bytes. Reveals nothing that
	/// [`len`](Self::len) does not. Never panics.
	pub fn is_empty(&self) -> bool
	where
		T: AsRef<[u8]>,
	{
		self.len() == 0
	}

	/// The wrapped value as a byte-slice view with the same source.
	/// The projection every parser needs, written once here so that
	/// call sites carry no closure. Never panics.
	#[must_use]
	pub fn as_bytes(&self) -> Untrusted<&[u8], S>
	where
		T: AsRef<[u8]>,
	{
		Untrusted { value: self.value.as_ref(), source: PhantomData }
	}

	/// Parse the value. The validator sees an [`Unvalidated`] view
	/// that lives only for this call and returns its own typed output
	/// or error; this crate adds nothing to either.
	///
	/// For a zero-copy parse, validate a byte-slice view
	/// (`Untrusted<&'a [u8], S>`, from [`as_bytes`](Self::as_bytes) or
	/// from ingress) and have the output borrow `'a`. This example is
	/// compile-checked only, because no token exists outside the
	/// `ingress` feature; the unit test
	/// `validate_runs_the_validator_and_returns_its_output` runs the
	/// same shape and `framing_loop_keeps_the_input_lifetime` runs the
	/// loop below.
	///
	/// ```
	/// use loupe_provenance::{Mark, Untrusted, Unvalidated, Validate, Worker};
	///
	/// /// One length-prefixed record: a byte `n`, then `n` bytes.
	/// struct Record;
	///
	/// #[derive(Debug, PartialEq)]
	/// enum Error {
	/// 	Empty,
	/// 	Short,
	/// }
	///
	/// impl<'a> Validate<&'a [u8], Worker> for Record {
	/// 	type Output = (&'a [u8], usize);
	/// 	type Error = Error;
	///
	/// 	fn validate<'view>(
	/// 		self, u: Unvalidated<'view, &'a [u8]>, _: Mark<'view, Worker>,
	/// 	) -> Result<Self::Output, Error> {
	/// 		let bytes: &'a [u8] = u.get();
	/// 		let (&n, rest) = bytes.split_first().ok_or(Error::Empty)?;
	/// 		let body = rest.get(..usize::from(n)).ok_or(Error::Short)?;
	/// 		Ok((body, body.len().saturating_add(1)))
	/// 	}
	/// }
	///
	/// /// Every record in the buffer, borrowed from it.
	/// fn parse_all(buffer: &Untrusted<Vec<u8>, Worker>) -> Result<Vec<&[u8]>, Error> {
	/// 	let mut rest = buffer.as_bytes();
	/// 	let mut out = Vec::new();
	/// 	while !rest.is_empty() {
	/// 		let (body, consumed) = rest.validate(Record)?;
	/// 		out.push(body);
	/// 		rest = rest.split_at(consumed).map(|(_, tail)| tail).ok_or(Error::Short)?;
	/// 	}
	/// 	Ok(out)
	/// }
	/// ```
	pub fn validate<V: Validate<T, S>>(self, validator: V) -> Result<V::Output, V::Error> {
		validator.validate(Unvalidated(&self.value, PhantomData), Mark::new(&self.value))
	}

	/// Parse the value with a validator that may hand parts of it on
	/// under another source ([`ValidateCarrying`]). As
	/// [`validate`](Self::validate), except that the view carries `S`.
	pub fn validate_carrying<V: ValidateCarrying<T, S>>(
		self, validator: V,
	) -> Result<V::Output, V::Error> {
		validator.validate(Unvalidated(&self.value, PhantomData))
	}

	/// Project the value through a closure without unwrapping it. The
	/// result carries the same source. For bytes, prefer
	/// [`as_bytes`](Self::as_bytes) and [`split_at`](Self::split_at),
	/// which need no closure; this is for everything else (a field of
	/// a struct, `String` to `str`).
	///
	/// The closure sees `&T`. It is a validation-class review site,
	/// like a [`Validate::validate`] body: the rule is to project a
	/// field or take a sub-slice and nothing else. What a reviewer
	/// looks for is a closure that captures `v` or copies its bytes
	/// into something it captured; that is the same laundering as a
	/// `Validate` impl that returns its input, and neither can be
	/// stopped by the type system. `grep 'map_ref('` together with
	/// `grep 'Unvalidated<'` lists every place in the tree where
	/// untrusted bytes are looked at.
	///
	/// ```
	/// use loupe_provenance::{Config, Untrusted};
	///
	/// fn as_str(text: &Untrusted<String, Config>) -> Untrusted<&str, Config> {
	/// 	text.map_ref(|s| s.as_str())
	/// }
	/// ```
	#[must_use]
	pub fn map_ref<'a, U: ?Sized>(&'a self, f: impl FnOnce(&'a T) -> &'a U) -> Untrusted<&'a U, S> {
		Untrusted { value: f(&self.value), source: PhantomData }
	}
}

impl<S: Source> Untrusted<alloc::vec::Vec<u8>, S> {
	/// Appends bytes from the same source. Shows them to no one.
	pub fn extend(&mut self, more: Untrusted<&[u8], S>) {
		self.value.extend_from_slice(more.value);
	}

	/// Splits the buffer at `at`: `self` keeps `..at`, the result holds
	/// `at..`, both with the source. `None` (and `self` unchanged) if
	/// `at` is past the end. Never panics.
	#[must_use]
	pub fn split_off(&mut self, at: usize) -> Option<Self> {
		if at > self.value.len() {
			return None;
		}
		Some(Untrusted { value: self.value.split_off(at), source: PhantomData })
	}

	/// Drops the first `n` bytes (all of them if `n` is past the end),
	/// for a receive buffer whose front was consumed. Never panics.
	pub fn discard_front(&mut self, n: usize) {
		let n = n.min(self.value.len());
		self.value.drain(..n);
	}
}

impl<S: Source> Untrusted<&[u8], S> {
	/// An owned copy of the viewed bytes with the same source, for a
	/// value that must outlive the buffer it was framed from (a
	/// request body handed to a handler). Copies; shows the bytes to
	/// no one.
	#[must_use]
	pub fn to_vec(&self) -> Untrusted<alloc::vec::Vec<u8>, S> {
		Untrusted { value: self.value.to_vec(), source: PhantomData }
	}

	/// Split a byte-slice view at `mid` into `(head, tail)`, both with
	/// the original lifetime and source, so a framing loop can hand
	/// one frame to a parser and keep the rest. `None` if `mid` is
	/// past the end. Never panics.
	#[must_use]
	pub fn split_at(self, mid: usize) -> Option<(Self, Self)> {
		let (head, tail) = self.value.split_at_checked(mid)?;
		Some((
			Untrusted { value: head, source: PhantomData },
			Untrusted { value: tail, source: PhantomData },
		))
	}
}

impl<T: Clone, S: Source> Clone for Untrusted<T, S> {
	fn clone(&self) -> Self {
		Untrusted { value: self.value.clone(), source: PhantomData }
	}
}

impl<T: Copy, S: Source> Copy for Untrusted<T, S> {}

impl<T, S: Source> fmt::Debug for Untrusted<T, S> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "Untrusted<{}>([redacted])", S::NAME)
	}
}

/// The view a [`Validate`] impl gets of the value it is parsing.
///
/// Exists only inside [`Validate::validate`] and
/// [`ValidateCarrying::validate`]: it borrows the [`Untrusted`] that
/// the call consumed, so it cannot be returned, stored, built anywhere
/// else, or printed. Searching for `Unvalidated<` finds every place in
/// the tree where untrusted bytes are looked at.
///
/// `S` is the source the view's value came from when the validator
/// is allowed to know it: a [`ValidateCarrying`] impl sees the real
/// source and may [`carry`](Unvalidated::carry) sub-slices on under a
/// new label; a plain [`Validate`] impl sees [`Unlabelled`] and
/// cannot.
pub struct Unvalidated<'a, T, S = Unlabelled>(&'a T, PhantomData<fn() -> S>);

/// The source parameter of the [`Unvalidated`] view a plain
/// [`Validate`] impl gets: not a [`Source`], so nothing that needs one
/// (relabelling with [`Unvalidated::carry`]) is available there.
/// Uninhabited; it only ever appears as a type.
// debug-ok: uninhabited marker has neither values nor content.
#[derive(Debug, Clone, Copy)]
pub enum Unlabelled {}

impl<'a, T, S> Unvalidated<'a, T, S> {
	/// The value being validated. Returns the borrow `validate` holds
	/// of the consumed `Untrusted`, so for an owned `T` the result
	/// lives only inside the call; for `T = &'x [u8]` the inner
	/// reference can be copied out with its own lifetime `'x`, which
	/// is the zero-copy path.
	pub const fn get(&self) -> &'a T {
		self.0
	}
}

impl<T, S: Source> Unvalidated<'_, T, S> {
	/// A constructor mark for this view's actual source, tied to the
	/// borrow of the view. Only sourced carrying views have this method;
	/// a plain validator receives its same-source mark separately.
	#[must_use]
	pub fn mark(&self) -> Mark<'_, S> {
		Mark::new(self)
	}
}

impl<'a, S: Source> Unvalidated<'_, &'a [u8], S> {
	/// The bytes at `range` of the value being validated, labelled
	/// with source `D` instead of `S`, with the input's own lifetime.
	/// `None` if the range is out of bounds or reversed. Never panics.
	///
	/// This is the one relabelling in the tree, for the places where
	/// bytes from one source are, by the protocol, bytes from another:
	/// the text fields of a phase payload a worker relays are agent
	/// text, not worker protocol. `D` must be [`CarriedFrom<S>`], which
	/// is sealed and implemented only for [`Agent`](crate::Agent)
	/// carried from [`Worker`](crate::Worker) (phase payload text),
	/// [`Sandbox`](crate::Sandbox) (tool-call arguments, CLI output),
	/// [`Db`](crate::Db) (stored agent text read back), and
	/// [`Server`](crate::Server) (stored agent text in server responses); every other
	/// pair is a compile error, and so is a call from a plain
	/// [`Validate`] body or from outside a validator. A `carry` call is
	/// a validation-class review site: the range must be one the
	/// validator's own parse found to hold content of source `D`.
	#[must_use]
	pub fn carry<D: CarriedFrom<S>>(&self, range: Range<usize>) -> Option<Untrusted<&'a [u8], D>> {
		let bytes: &'a [u8] = self.0;
		bytes.get(range).map(|value| Untrusted { value, source: PhantomData })
	}
}

mod sealed {
	pub trait Carried<S> {}
}

/// The relabellings [`Unvalidated::carry`] allows: `D: CarriedFrom<S>`
/// means bytes from source `S` may be handed on as bytes from source
/// `D`. Sealed; implemented only for [`Agent`](crate::Agent) from
/// [`Worker`](crate::Worker) (the text fields of a phase payload a
/// worker relays), from [`Sandbox`](crate::Sandbox) (tool-call
/// arguments and CLI output), from [`Db`](crate::Db) (stored agent
/// text read back), and from [`Server`](crate::Server) (stored agent
/// text in server responses). Trust-asserting labels are never carried into.
/// Each further pair is added with its consumer, its review and a
/// compile-fail test. Both ends stay hostile: relabelling changes
/// which parsers may take the bytes, never whether they must be
/// parsed.
pub trait CarriedFrom<S: Source>: Source + sealed::Carried<S> {}

macro_rules! carried {
    ($($to:ident from $from:ident;)*) => {
        $(
            impl sealed::Carried<crate::$from> for crate::$to {}
            impl CarriedFrom<crate::$from> for crate::$to {}
        )*
    };
}

carried! {
	Agent from Worker;
	Agent from Sandbox;
	Agent from Db;
	Agent from Server;
}

/// A parser: turns an untrusted `T` from source `S` into a typed
/// value or an error. Every parser in the tree is one of these, and
/// [`Untrusted::validate`] is the only way to run it on wrapped bytes.
///
/// `self` is the parser's configuration (limits, options); a unit
/// struct when it has none. The source parameter lets a parser be
/// written for one source only, or for all with a blanket impl.
///
/// # Egress without parsing
///
/// Some sinks need the raw bytes of an `Untrusted` without parsing
/// them: streaming a provider response into the sandbox, writing raw
/// bytes into the store. The way to do that is a `Validate` impl whose
/// output is the bytes, named for the sink (`ToSandbox`, `StoreRaw`),
/// one per sink
/// and written where the sink is. The `impl Validate` grep then lists
/// every egress as well as every parser. There is deliberately no
/// generic passthrough type in this crate: one nameable laundering
/// primitive is worse than a few deliberate local ones.
pub trait Validate<T, S: Source> {
	/// The validated, typed result.
	type Output;
	/// The parser's error. Per the workspace conventions, an enum that
	/// carries an offset at most, never input bytes.
	type Error;

	/// Parse the value. The unlabelled view and same-source constructor
	/// mark share this call's lifetime. Neither can escape the call.
	fn validate<'view>(
		self, u: Unvalidated<'view, T>, mark: Mark<'view, S>,
	) -> Result<Self::Output, Self::Error>;
}

/// A parser that also hands parts of its input on under another
/// source label: a [`Validate`] whose view knows the source `S`, so
/// its body may call [`Unvalidated::carry`]. Run with
/// [`Untrusted::validate_carrying`].
///
/// A separate trait, not a method every validator gets, so the
/// relabelling sites are their own grep (`impl ValidateCarrying`) and
/// a validator that only parses cannot relabel by accident. Name the
/// impl for the sink, as for an egress `Validate` impl
/// (`PhasePayloadText`).
///
/// ```
/// use loupe_provenance::{Agent, Untrusted, Unvalidated, ValidateCarrying, Worker};
///
/// /// The body of a record `n` then `n` bytes, handed on as agent
/// /// text.
/// struct RecordBody;
///
/// impl<'a> ValidateCarrying<&'a [u8], Worker> for RecordBody {
/// 	type Output = Untrusted<&'a [u8], Agent>;
/// 	type Error = ();
///
/// 	fn validate(self, u: Unvalidated<'_, &'a [u8], Worker>) -> Result<Self::Output, ()> {
/// 		let n = usize::from(*u.get().first().ok_or(())?);
/// 		u.carry::<Agent>(1..n.saturating_add(1)).ok_or(())
/// 	}
/// }
/// ```
pub trait ValidateCarrying<T, S: Source> {
	/// The validated, typed result.
	type Output;
	/// The parser's error, as for [`Validate::Error`].
	type Error;

	/// Parse the value. The view lives only for this call and knows
	/// its source.
	fn validate(self, u: Unvalidated<'_, T, S>) -> Result<Self::Output, Self::Error>;
}
