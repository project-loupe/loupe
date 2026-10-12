//! Closed encoders for DTOs that deliberately deliver credentials.
//!
//! Count actual JSON escaping before allocating. The writing pass cannot grow
//! a populated allocation, and every partial/error buffer has a wiping owner.
//! Transport callers must retain the returned owner rather than reserialize it.

use std::io::{self, Write};

use loupe_provenance::{Secret, Zeroise};
use serde::Serialize;

use crate::{
	LeaseResponse, RegisterRepoRequest, RegisterWorkerResponse, RotateRepoPatRequest,
	SetGithubAppRequest, SetRepoGithubReportingRequest,
};

// Keep serialization generic only inside this module. The immutable closed DTOs
// have deterministic serializers; no public arbitrary-Serialize contract exists.
macro_rules! credential_encoder {
	($($dto:ty),+ $(,)?) => { $(
		impl $dto {
			/// Encode the existing compact wire format into a wiping owner.
			///
			/// Deliberately delivers plaintext credentials. Retain this owner
			/// through the authenticated transport's last body clone.
			pub fn credential_json(&self) -> serde_json::Result<Secret<Vec<u8>>> {
				encode(self, false)
			}
		}
	)+ };
}

credential_encoder!(
	LeaseResponse,
	RegisterWorkerResponse,
	RegisterRepoRequest,
	RotateRepoPatRequest,
	SetRepoGithubReportingRequest,
	SetGithubAppRequest,
);

impl RegisterWorkerResponse {
	/// Encode the operator's pretty worker bundle into a wiping owner.
	/// Deliberate file/stdout export retains the existing JSON format.
	pub fn credential_json_pretty(&self) -> serde_json::Result<Secret<Vec<u8>>> {
		encode(self, true)
	}
}

/// Encode the operator's server certificate bundle with its existing two-field
/// pretty JSON shape. Retain the returned owner through deliberate file/stdout
/// export; certificate input can itself be a mixed PEM bundle.
pub fn server_certificate_json_pretty(
	server_cert_pem: &str, server_key_pem: &Secret<String>,
) -> serde_json::Result<Secret<Vec<u8>>> {
	#[derive(Serialize)]
	struct ServerCertificate<'a> {
		server_cert_pem: &'a str,
		#[serde(serialize_with = "crate::secret_serde::string::serialize")]
		server_key_pem: &'a Secret<String>,
	}
	encode(&ServerCertificate { server_cert_pem, server_key_pem }, true)
}

struct Count(usize);

impl Write for Count {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		self.0 = self
			.0
			.checked_add(bytes.len())
			.ok_or_else(|| io::Error::other("credential JSON size overflow"))?;
		Ok(bytes.len())
	}

	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

struct JsonBuffer {
	bytes: Vec<u8>,
	used: usize,
}

impl JsonBuffer {
	fn new(size: usize) -> Self {
		Self { bytes: vec![0; size], used: 0 }
	}

	fn finish(mut self) -> serde_json::Result<Secret<Vec<u8>>> {
		if self.used != self.bytes.len() {
			return Err(serde_json::Error::io(io::Error::other("credential JSON size changed")));
		}
		Ok(Secret::new(std::mem::take(&mut self.bytes)))
	}
}

impl Write for JsonBuffer {
	fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
		if bytes.len() > self.bytes.len() - self.used {
			return Err(io::Error::other("credential JSON size changed"));
		}
		self.bytes[self.used..self.used + bytes.len()].copy_from_slice(bytes);
		self.used += bytes.len();
		Ok(bytes.len())
	}

	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

impl Drop for JsonBuffer {
	fn drop(&mut self) {
		// Full capacity is initialized without reallocating before the volatile
		// overwrite. The test observer reads live storage after that overwrite.
		self.bytes.resize(self.bytes.capacity(), 0);
		self.bytes.as_mut_slice().zeroise();
		#[cfg(test)]
		CLEANUPS.with(|seen| {
			seen.borrow_mut().push((self.bytes.len(), self.bytes.iter().all(|byte| *byte == 0)));
		});
	}
}

fn write_json(value: &impl Serialize, writer: impl Write, pretty: bool) -> serde_json::Result<()> {
	if pretty {
		serde_json::to_writer_pretty(writer, value)
	} else {
		serde_json::to_writer(writer, value)
	}
}

fn encode(value: &impl Serialize, pretty: bool) -> serde_json::Result<Secret<Vec<u8>>> {
	let mut count = Count(0);
	write_json(value, &mut count, pretty)?;
	let mut buffer = JsonBuffer::new(count.0);
	write_json(value, &mut buffer, pretty)?;
	buffer.finish()
}

#[cfg(test)]
thread_local! {
	static CLEANUPS: std::cell::RefCell<Vec<(usize, bool)>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
#[path = "credential_wire_tests.rs"]
mod tests;
