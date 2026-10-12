//! Compile-fail doc tests: one item per guarantee of the form "there
//! is no way to do X". They are collected by `cargo test` (rustdoc
//! sets `cfg(doctest)`) and never appear in the rendered docs. Each
//! snippet pins the error code where the error has one, so a snippet
//! failing for an unrelated reason is caught.

/// `Untrusted` has no `Deref`, so `**u` is not dereferenceable:
///
/// ```compile_fail,E0614
/// use loupe_provenance::{Untrusted, Worker};
///
/// fn peek(u: &Untrusted<Vec<u8>, Worker>) -> usize {
///     (**u).len()
/// }
/// ```
///
/// and auto-deref finds no method on the payload:
///
/// ```compile_fail,E0599
/// use loupe_provenance::{Untrusted, Worker};
///
/// fn peek(u: &Untrusted<Vec<u8>, Worker>) -> Option<&u8> {
///     u.first()
/// }
/// ```
pub struct UntrustedHasNoDeref;

/// `Untrusted` has no `AsRef`:
///
/// ```compile_fail,E0599
/// use loupe_provenance::{Untrusted, Worker};
///
/// fn peek(u: &Untrusted<Vec<u8>, Worker>) -> &[u8] {
///     u.as_ref()
/// }
/// ```
pub struct UntrustedHasNoAsRef;

/// `Untrusted` has no `Display`, so a `{}` in a log line does not
/// compile:
///
/// ```compile_fail,E0277
/// use loupe_provenance::{Untrusted, Worker};
///
/// fn log(u: &Untrusted<Vec<u8>, Worker>) -> String {
///     format!("{u}")
/// }
/// ```
pub struct UntrustedHasNoDisplay;

/// `Untrusted` has no `PartialEq`, so bytes cannot be probed by
/// comparison:
///
/// ```compile_fail,E0369
/// use loupe_provenance::{Untrusted, Worker};
///
/// fn same(a: &Untrusted<Vec<u8>, Worker>, b: &Untrusted<Vec<u8>, Worker>) -> bool {
///     a == b
/// }
/// ```
pub struct UntrustedHasNoPartialEq;

/// `Untrusted`'s field is private:
///
/// ```compile_fail,E0616
/// use loupe_provenance::{Untrusted, Worker};
///
/// fn peek(u: Untrusted<Vec<u8>, Worker>) -> Vec<u8> {
///     u.value
/// }
/// ```
pub struct UntrustedHasNoPublicField;

/// `Untrusted::new` needs an `Ingress` token:
///
/// ```compile_fail,E0061
/// use loupe_provenance::{Untrusted, Worker};
///
/// let u: Untrusted<Vec<u8>, Worker> = Untrusted::new(vec![1, 2, 3]);
/// ```
pub struct UntrustedNeedsAToken;

/// Even an empty buffer needs an actual ingress token:
///
/// ```compile_fail,E0599
/// use loupe_provenance::{Operator, Untrusted};
/// let _: Untrusted<Vec<u8>, Operator> = Untrusted::empty();
/// ```
pub struct EmptyNeedsAToken;

/// `Ingress` cannot be built by hand; the field is private:
///
/// ```compile_fail,E0423
/// use loupe_provenance::{Ingress, Worker};
///
/// let token: Ingress<Worker> = Ingress(core::marker::PhantomData);
/// ```
///
/// And without feature `ingress` there is no constructor at all. The
/// next snippet is a `compile_fail` test when the feature is off and
/// an ordinary test when it is on (the fence is chosen by `cfg_attr`,
/// which is why it is the last thing in this comment):
#[cfg_attr(not(feature = "ingress"), doc = "```compile_fail,E0599")]
#[cfg_attr(feature = "ingress", doc = "```")]
/// use loupe_provenance::{Ingress, Untrusted, Worker};
///
/// // SAFETY: a doctest's own bytes.
/// let token: Ingress<Worker> = unsafe { Ingress::new() };
/// let value = Untrusted::new(vec![0u8; 4], token);
/// assert_eq!(value.len(), 4);
/// ```
pub struct IngressOnlyUnderTheFeature;

/// With the feature, the constructor is an `unsafe fn`, so
/// a call outside an `unsafe` block does not compile, whatever path or
/// alias names it (without the feature the error is E0599 instead; the
/// code is pinned only when the feature is on):
#[cfg_attr(feature = "ingress", doc = "```compile_fail,E0133")]
#[cfg_attr(not(feature = "ingress"), doc = "```compile_fail")]
/// use loupe_provenance::{Ingress as I, Worker};
///
/// type T = I<Worker>;
/// let _ = <T>::new();
/// ```
pub struct IngressIsUnsafe;

/// `Unvalidated` has no public constructor:
///
/// ```compile_fail,E0423
/// use loupe_provenance::Unvalidated;
///
/// let bytes = vec![1u8, 2, 3];
/// let u: Unvalidated<'_, Vec<u8>> = Unvalidated(&bytes);
/// ```
pub struct UnvalidatedHasNoConstructor;

/// `Unvalidated` cannot be smuggled out as a validator's output,
/// because the lifetime it carries ends with the call (the error is
/// "lifetime may not live long enough", which has no code):
///
/// ```compile_fail
/// use loupe_provenance::{Mark, Unvalidated, Validate, Worker};
///
/// struct Leak;
///
/// impl Validate<Vec<u8>, Worker> for Leak {
///     type Output = Unvalidated<'static, Vec<u8>>;
///     type Error = ();
///
///     fn validate<'view>(self, u: Unvalidated<'view, Vec<u8>>, _: Mark<'view, Worker>) -> Result<Self::Output, ()> {
///         Ok(u)
///     }
/// }
/// ```
///
/// Nor can the borrow it hands out of an owned `T`:
///
/// ```compile_fail
/// use loupe_provenance::{Mark, Unvalidated, Validate, Worker};
///
/// struct Leak;
///
/// impl Validate<Vec<u8>, Worker> for Leak {
///     type Output = &'static [u8];
///     type Error = ();
///
///     fn validate<'view>(self, u: Unvalidated<'view, Vec<u8>>, _: Mark<'view, Worker>) -> Result<Self::Output, ()> {
///         Ok(u.get().as_slice())
///     }
/// }
/// ```
pub struct UnvalidatedCannotEscape;

/// `Unvalidated` has no `Debug`, so it cannot be logged by accident:
///
/// ```compile_fail,E0277
/// use loupe_provenance::Unvalidated;
///
/// fn log(u: &Unvalidated<'_, Vec<u8>>) -> String {
///     format!("{u:?}")
/// }
/// ```
pub struct UnvalidatedHasNoDebug;

/// `Secret` has no `Deref`:
///
/// ```compile_fail,E0599
/// use loupe_provenance::Secret;
///
/// let s = Secret::new(String::from("hunter2"));
/// let n = s.len();
/// ```
///
/// and no `AsRef`:
///
/// ```compile_fail,E0599
/// use loupe_provenance::Secret;
///
/// fn peek(s: &Secret<Vec<u8>>) -> &[u8] {
///     s.as_ref()
/// }
/// ```
pub struct SecretHasNoDerefOrAsRef;

/// `Secret` has no `Clone`, so a secret is never silently multiplied:
///
/// ```compile_fail,E0599
/// use loupe_provenance::Secret;
///
/// let s = Secret::new(vec![1u8, 2, 3]);
/// let t = s.clone();
/// ```
pub struct SecretHasNoClone;

/// `Secret` has no `PartialEq`, so it cannot be probed by comparison:
///
/// ```compile_fail,E0369
/// use loupe_provenance::Secret;
///
/// fn same(a: &Secret<Vec<u8>>, b: &Secret<Vec<u8>>) -> bool {
///     a == b
/// }
/// ```
pub struct SecretHasNoPartialEq;

/// `Secret`'s field is private:
///
/// ```compile_fail,E0616
/// use loupe_provenance::Secret;
///
/// fn peek(s: &Secret<Vec<u8>>) -> &Vec<u8> {
///     &s.value
/// }
/// ```
pub struct SecretHasNoPublicField;

/// [`Unvalidated::carry`](crate::Unvalidated::carry) relabels only to
/// `Agent`; carrying worker bytes to any other source does not
/// compile:
///
/// ```compile_fail,E0277
/// use loupe_provenance::{Operator, Untrusted, Unvalidated, ValidateCarrying, Worker};
///
/// struct Launder;
///
/// impl<'a> ValidateCarrying<&'a [u8], Worker> for Launder {
///     type Output = Option<Untrusted<&'a [u8], Operator>>;
///     type Error = ();
///
///     fn validate(self, u: Unvalidated<'_, &'a [u8], Worker>) -> Result<Self::Output, ()> {
///         Ok(u.carry::<Operator>(0..1))
///     }
/// }
/// ```
///
/// and only from `Worker`, `Sandbox`, `Db` and `Server`; a repository's bytes do
/// not become agent text:
///
/// ```compile_fail,E0277
/// use loupe_provenance::{Agent, Repo, Untrusted, Unvalidated, ValidateCarrying};
///
/// struct Launder;
///
/// impl<'a> ValidateCarrying<&'a [u8], Repo> for Launder {
///     type Output = Option<Untrusted<&'a [u8], Agent>>;
///     type Error = ();
///
///     fn validate(self, u: Unvalidated<'_, &'a [u8], Repo>) -> Result<Self::Output, ()> {
///         Ok(u.carry::<Agent>(0..1))
///     }
/// }
/// ```
pub struct CarryOnlyForTheSealedPairs;

/// A plain `Validate` body sees an `Unlabelled` view and cannot
/// carry:
///
/// ```compile_fail,E0599
/// use loupe_provenance::{Agent, Mark, Untrusted, Unvalidated, Validate, Worker};
///
/// struct Launder;
///
/// impl<'a> Validate<&'a [u8], Worker> for Launder {
///     type Output = Option<Untrusted<&'a [u8], Agent>>;
///     type Error = ();
///
///     fn validate<'view>(self, u: Unvalidated<'view, &'a [u8]>, _: Mark<'view, Worker>) -> Result<Self::Output, ()> {
///         Ok(u.carry::<Agent>(0..1))
///     }
/// }
/// ```
///
/// and outside a validator there is no view to carry from:
///
/// ```compile_fail,E0599
/// use loupe_provenance::{Agent, Untrusted, Worker};
///
/// fn launder(u: Untrusted<&[u8], Worker>) -> Option<Untrusted<&[u8], Agent>> {
///     u.carry::<Agent>(0..1)
/// }
/// ```
pub struct CarryOnlyInsideAValidator;

/// No other crate can add a relabelling. Both type parameters must be
/// `Source`s, which are this crate's types only, so a downstream impl is
/// an orphan impl (E0117); the private `sealed::Carried` supertrait is
/// defence in depth on top of that:
///
/// ```compile_fail,E0117
/// use loupe_provenance::{Agent, CarriedFrom, Repo};
///
/// impl CarriedFrom<Repo> for Agent {}
/// ```
pub struct CarriedFromIsSealed;

/// Trust-asserting labels are never carried into: nothing becomes
/// `Operator` or `Server` by relabelling, whatever it came from:
///
/// ```compile_fail,E0277
/// use loupe_provenance::{Sandbox, Server, Untrusted, Unvalidated, ValidateCarrying};
///
/// struct Launder;
///
/// impl<'a> ValidateCarrying<&'a [u8], Sandbox> for Launder {
///     type Output = Option<Untrusted<&'a [u8], Server>>;
///     type Error = ();
///     fn validate(self, u: Unvalidated<'_, &'a [u8], Sandbox>) -> Result<Self::Output, ()> {
///         Ok(u.carry::<Server>(0..1))
///     }
/// }
/// ```
///
/// ```compile_fail,E0277
/// use loupe_provenance::{Browser, Operator, Untrusted, Unvalidated, ValidateCarrying};
///
/// struct Launder;
///
/// impl<'a> ValidateCarrying<&'a [u8], Browser> for Launder {
///     type Output = Option<Untrusted<&'a [u8], Operator>>;
///     type Error = ();
///     fn validate(self, u: Unvalidated<'_, &'a [u8], Browser>) -> Result<Self::Output, ()> {
///         Ok(u.carry::<Operator>(0..1))
///     }
/// }
/// ```
pub struct TrustIsNeverCarriedInto;

/// Constructor marks cannot be manufactured outside validation:
///
/// ```compile_fail,E0423
/// use loupe_provenance::{Mark, Operator};
/// let _: Mark<'static, Operator> = Mark(core::marker::PhantomData);
/// ```
///
/// The internal constructor is private too:
///
/// ```compile_fail,E0624
/// use loupe_provenance::{Mark, Operator};
/// let _: Mark<'_, Operator> = Mark::new(&());
/// ```
///
/// ```compile_fail,E0277
/// use loupe_provenance::{Mark, Operator};
/// let _: Mark<'static, Operator> = Default::default();
/// ```
///
/// An ingress token is not a constructor mark:
///
/// ```compile_fail,E0277
/// use loupe_provenance::{Ingress, Mark, Operator};
/// fn convert(token: Ingress<Operator>) -> Mark<'static, Operator> {
///     token.into()
/// }
/// ```
pub struct MarkCannotBeConstructed;

/// Marks cannot be cloned:
///
/// ```compile_fail,E0599
/// use loupe_provenance::{Mark, Worker};
/// fn duplicate(mark: Mark<'_, Worker>) {
///     let _ = mark.clone();
/// }
/// ```
pub struct MarkHasNoClone;

/// A constructor requiring Operator cannot accept a Worker mark:
///
/// ```compile_fail,E0308
/// use loupe_provenance::{Mark, Operator, Unvalidated, Validate, Worker};
/// fn operator_text(_: &str, _: &Mark<'_, Operator>) {}
/// struct Launder;
/// impl Validate<String, Worker> for Launder {
///     type Output = ();
///     type Error = ();
///     fn validate<'view>(self, u: Unvalidated<'view, String>, mark: Mark<'view, Worker>) -> Result<(), ()> {
///         operator_text(u.get(), &mark);
///         Ok(())
///     }
/// }
/// ```
///
/// Nor can a mark be converted to an unrelated source:
///
/// ```compile_fail,E0277
/// use loupe_provenance::{Mark, Operator, Worker};
/// fn convert<'a>(mark: Mark<'a, Worker>) -> Mark<'a, Operator> {
///     mark.into()
/// }
/// ```
///
/// A sourced view cannot select another source when obtaining its mark:
///
/// ```compile_fail,E0107
/// use loupe_provenance::{Operator, Unvalidated, Worker};
/// fn launder(u: Unvalidated<'_, &[u8], Worker>) {
///     let _ = u.mark::<Operator>();
/// }
/// ```
pub struct MarkKeepsTheActualSource;

/// A plain view remains Unlabelled; it has no sourced mark method:
///
/// ```compile_fail,E0599
/// use loupe_provenance::{Mark, Unvalidated, Validate, Worker};
/// struct Inspect;
/// impl Validate<String, Worker> for Inspect {
///     type Output = ();
///     type Error = ();
///     fn validate<'view>(self, u: Unvalidated<'view, String>, _: Mark<'view, Worker>) -> Result<(), ()> {
///         let _ = u.mark();
///         Ok(())
///     }
/// }
/// ```
pub struct PlainViewStaysUnlabelled;

/// A plain mark cannot escape its validation call, even when the input
/// itself has a static lifetime (the lifetime error has no code):
///
/// ```compile_fail
/// use loupe_provenance::{Mark, Unvalidated, Validate, Worker};
/// struct Leak;
/// impl Validate<&'static [u8], Worker> for Leak {
///     type Output = Mark<'static, Worker>;
///     type Error = ();
///     fn validate<'view>(self, _: Unvalidated<'view, &'static [u8]>, mark: Mark<'view, Worker>) -> Result<Self::Output, ()> {
///         Ok(mark)
///     }
/// }
/// ```
///
/// A sourced view's mark borrows that view, not the input's lifetime:
///
/// ```compile_fail,E0515
/// use loupe_provenance::{Mark, Unvalidated, ValidateCarrying, Worker};
/// struct Leak;
/// impl ValidateCarrying<&'static [u8], Worker> for Leak {
///     type Output = Mark<'static, Worker>;
///     type Error = ();
///     fn validate(self, u: Unvalidated<'_, &'static [u8], Worker>) -> Result<Self::Output, ()> {
///         Ok(u.mark())
///     }
/// }
/// ```
///
/// Even within a carrying validator a mark cannot outlive its view:
///
/// ```compile_fail,E0505
/// use loupe_provenance::{Unvalidated, Worker};
/// fn keep(u: Unvalidated<'_, &[u8], Worker>) {
///     let mark = u.mark();
///     drop(u);
///     drop(mark);
/// }
/// ```
pub struct MarkCannotEscape;

/// Mark is not itself a relabelling operation:
///
/// ```compile_fail,E0599
/// use loupe_provenance::{Agent, Mark, Worker};
/// fn launder(mark: Mark<'_, Worker>) {
///     let _ = mark.carry::<Agent>(0..1);
/// }
/// ```
pub struct MarkCannotCarry;
