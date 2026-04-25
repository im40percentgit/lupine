//! X.509 ASN.1 structures for certificate encoding and decoding.
//!
//! Implements the core RFC 5280 types needed for X.509v3 certificates:
//!
//! - [`AlgorithmIdentifier`] — Algorithm OID with optional parameters
//! - [`Validity`] — Not-before / not-after time window
//! - [`SubjectPublicKeyInfo`] — Public key wrapped with algorithm identifier
//! - [`TbsCertificate`] — The to-be-signed certificate body
//! - [`X509Certificate`] — Complete certificate (TBS + signature)
//!
//! Distinguished Name (DN) encoding uses manual DER construction for the
//! nested `RDNSequence > SET > SEQUENCE > { OID, UTF8String }` structure,
//! since `der 0.8` derive macros do not cleanly support SET-OF wrappers.
//!
//! @decision DEC-CERT-001
//! @title Manual DER for DN encoding vs der 0.8 derive
//! @status accepted
//! @rationale The X.509 Name type is `SEQUENCE OF SET OF AttributeTypeAndValue`.
//!   der 0.8's `#[derive(Sequence)]` handles SEQUENCE well but has no SET-OF
//!   derive. Rather than pulling in additional crate dependencies (x509-cert is
//!   RC-only), we encode the simple CN-only DN case with ~30 lines of manual
//!   tag/length/value construction. This is sufficient for self-signed and
//!   CA-signed certificates. Full RDN support can be added later.

use der::{
    asn1::{BitString, ObjectIdentifier},
    Decode, Encode, Sequence,
};
use lupine_core::{Error, Result, SerializationError};

// ---------------------------------------------------------------------------
// OID constants
// ---------------------------------------------------------------------------

/// OID for commonName (2.5.4.3) — used in Distinguished Name encoding.
const OID_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

// ---------------------------------------------------------------------------
// AlgorithmIdentifier
// ---------------------------------------------------------------------------

/// `AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters NULL OPTIONAL }`
///
/// PQC algorithms carry no parameters, so `parameters` is always `None`.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct AlgorithmIdentifier {
    /// The algorithm OID (e.g. ML-DSA-65, hybrid Ed25519+ML-DSA-65).
    pub algorithm: ObjectIdentifier,
    /// Optional parameters — always `None` for PQC algorithms.
    pub parameters: Option<()>,
}

// ---------------------------------------------------------------------------
// Validity
// ---------------------------------------------------------------------------

/// `Validity ::= SEQUENCE { notBefore GeneralizedTime, notAfter GeneralizedTime }`
///
/// Uses `der::DateTime` which encodes as ASN.1 GeneralizedTime (RFC 5280 format:
/// `YYYYMMDDHHMMSSZ`).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Validity {
    /// Certificate validity start time.
    pub not_before: der::DateTime,
    /// Certificate validity end time.
    pub not_after: der::DateTime,
}

// ---------------------------------------------------------------------------
// SubjectPublicKeyInfo
// ---------------------------------------------------------------------------

/// `SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct SubjectPublicKeyInfo {
    /// Algorithm identifier for the public key.
    pub algorithm: AlgorithmIdentifier,
    /// The public key as a BIT STRING (0 unused bits).
    pub subject_public_key: BitString,
}

// ---------------------------------------------------------------------------
// TbsCertificate — manual Encode/Decode for [0] EXPLICIT version tag
// ---------------------------------------------------------------------------

/// The to-be-signed portion of an X.509v3 certificate (RFC 5280 Section 4.1.2).
///
/// ```text
/// TBSCertificate ::= SEQUENCE {
///     version         [0] EXPLICIT INTEGER DEFAULT v1,
///     serialNumber    INTEGER,
///     signature       AlgorithmIdentifier,
///     issuer          Name,
///     validity        Validity,
///     subject         Name,
///     subjectPublicKeyInfo SubjectPublicKeyInfo,
///     ...
/// }
/// ```
///
/// The `version` field uses `[0] EXPLICIT` context-specific tagging.
/// `issuer` and `subject` are stored as pre-encoded DER bytes (see [`encode_cn`]).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TbsCertificate {
    /// Certificate version — always 2 (v3) for our certificates.
    pub version: u8,
    /// Serial number (positive integer, stored as raw bytes).
    pub serial_number: Vec<u8>,
    /// Signature algorithm used by the issuer to sign this certificate.
    pub signature_algorithm: AlgorithmIdentifier,
    /// Issuer distinguished name (pre-encoded DER bytes).
    pub issuer: Vec<u8>,
    /// Validity period.
    pub validity: Validity,
    /// Subject distinguished name (pre-encoded DER bytes).
    pub subject: Vec<u8>,
    /// Subject's public key information.
    pub subject_public_key_info: SubjectPublicKeyInfo,
}

impl TbsCertificate {
    /// Encode this TbsCertificate to DER bytes.
    ///
    /// Handles the `[0] EXPLICIT INTEGER` version tag manually since
    /// der 0.8's derive macros don't support context-specific tagging inline.
    pub fn to_der_bytes(&self) -> Result<Vec<u8>> {
        // Encode each field to DER individually, then wrap in SEQUENCE.
        let mut body = Vec::new();

        // version [0] EXPLICIT INTEGER
        // Inner: INTEGER encoding of self.version
        let version_int = encode_integer(self.version)?;
        // Wrap in [0] EXPLICIT (constructed, context-specific tag 0)
        // Tag byte: 0xA0 (context-specific, constructed, tag 0)
        body.push(0xA0);
        push_der_length(&mut body, version_int.len());
        body.extend_from_slice(&version_int);

        // serialNumber INTEGER
        let serial = encode_integer_bytes(&self.serial_number)?;
        body.extend_from_slice(&serial);

        // signature AlgorithmIdentifier
        let sig_algo = self
            .signature_algorithm
            .to_der()
            .map_err(|_| ser_err("failed to encode signature AlgorithmIdentifier"))?;
        body.extend_from_slice(&sig_algo);

        // issuer Name (pre-encoded DER)
        body.extend_from_slice(&self.issuer);

        // validity Validity
        let validity = self
            .validity
            .to_der()
            .map_err(|_| ser_err("failed to encode Validity"))?;
        body.extend_from_slice(&validity);

        // subject Name (pre-encoded DER)
        body.extend_from_slice(&self.subject);

        // subjectPublicKeyInfo SubjectPublicKeyInfo
        let spki = self
            .subject_public_key_info
            .to_der()
            .map_err(|_| ser_err("failed to encode SubjectPublicKeyInfo"))?;
        body.extend_from_slice(&spki);

        // Wrap body in outer SEQUENCE
        let mut out = Vec::new();
        out.push(0x30); // SEQUENCE tag
        push_der_length(&mut out, body.len());
        out.extend_from_slice(&body);

        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// X509Certificate
// ---------------------------------------------------------------------------

/// A complete X.509 certificate: TBS + signature algorithm + signature value.
///
/// ```text
/// Certificate ::= SEQUENCE {
///     tbsCertificate      TBSCertificate,
///     signatureAlgorithm  AlgorithmIdentifier,
///     signatureValue      BIT STRING
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct X509Certificate {
    /// The to-be-signed certificate body.
    pub tbs_certificate: TbsCertificate,
    /// The algorithm used to produce the signature.
    pub signature_algorithm: AlgorithmIdentifier,
    /// The signature over the DER-encoded TBS certificate.
    pub signature_value: BitString,
}

impl X509Certificate {
    /// Encode this certificate to DER bytes.
    pub fn to_der_bytes(&self) -> Result<Vec<u8>> {
        let mut body = Vec::new();

        // tbsCertificate (already a SEQUENCE)
        let tbs = self.tbs_certificate.to_der_bytes()?;
        body.extend_from_slice(&tbs);

        // signatureAlgorithm
        let sig_algo = self
            .signature_algorithm
            .to_der()
            .map_err(|_| ser_err("failed to encode certificate signatureAlgorithm"))?;
        body.extend_from_slice(&sig_algo);

        // signatureValue BIT STRING
        let sig_bits = self
            .signature_value
            .to_der()
            .map_err(|_| ser_err("failed to encode signatureValue BIT STRING"))?;
        body.extend_from_slice(&sig_bits);

        // Wrap in outer SEQUENCE
        let mut out = Vec::new();
        out.push(0x30);
        push_der_length(&mut out, body.len());
        out.extend_from_slice(&body);

        Ok(out)
    }

    /// Parse an X.509 certificate from DER bytes.
    ///
    /// Parses the outer SEQUENCE, then extracts TbsCertificate,
    /// signatureAlgorithm, and signatureValue.
    pub fn from_der(input: &[u8]) -> Result<Self> {
        // Parse outer SEQUENCE
        let (tag, body) = parse_tlv(input)?;
        if tag != 0x30 {
            return Err(ser_err("expected SEQUENCE for Certificate"));
        }

        let mut pos = 0;

        // tbsCertificate — a SEQUENCE
        let tbs_start = pos;
        let (_tag, _body) = parse_tlv(&body[pos..])?;
        let tbs_total_len = tlv_total_len(&body[pos..])?;
        let tbs_der = &body[tbs_start..tbs_start + tbs_total_len];
        let tbs = parse_tbs_certificate(tbs_der)?;
        pos += tbs_total_len;

        // signatureAlgorithm
        let sig_algo_len = tlv_total_len(&body[pos..])?;
        let sig_algo = AlgorithmIdentifier::from_der(&body[pos..pos + sig_algo_len])
            .map_err(|_| ser_err("failed to decode certificate signatureAlgorithm"))?;
        pos += sig_algo_len;

        // signatureValue BIT STRING
        let sig_value = BitString::from_der(&body[pos..])
            .map_err(|_| ser_err("failed to decode signatureValue BIT STRING"))?;

        Ok(X509Certificate {
            tbs_certificate: tbs,
            signature_algorithm: sig_algo,
            signature_value: sig_value,
        })
    }
}

// ---------------------------------------------------------------------------
// Distinguished Name encoding (manual DER)
// ---------------------------------------------------------------------------

/// Encode a commonName (CN) value as an X.501 Name (RDNSequence) in DER.
///
/// Produces:
/// ```text
/// SEQUENCE {                  -- RDNSequence
///   SET {                     -- RelativeDistinguishedName
///     SEQUENCE {              -- AttributeTypeAndValue
///       OID 2.5.4.3,          -- commonName
///       UTF8String "value"
///     }
///   }
/// }
/// ```
pub fn encode_cn(cn: &str) -> Result<Vec<u8>> {
    let cn_bytes = cn.as_bytes();

    // Encode OID 2.5.4.3 to DER
    let oid_der = OID_COMMON_NAME
        .to_der()
        .map_err(|_| ser_err("failed to encode CN OID"))?;

    // UTF8String: tag 0x0C + length + value
    let mut utf8_string = Vec::new();
    utf8_string.push(0x0C);
    push_der_length(&mut utf8_string, cn_bytes.len());
    utf8_string.extend_from_slice(cn_bytes);

    // AttributeTypeAndValue SEQUENCE: tag 0x30 + length + (OID + UTF8String)
    let atv_content_len = oid_der.len() + utf8_string.len();
    let mut atv = Vec::new();
    atv.push(0x30);
    push_der_length(&mut atv, atv_content_len);
    atv.extend_from_slice(&oid_der);
    atv.extend_from_slice(&utf8_string);

    // RelativeDistinguishedName SET: tag 0x31 + length + ATV
    let mut rdn = Vec::new();
    rdn.push(0x31);
    push_der_length(&mut rdn, atv.len());
    rdn.extend_from_slice(&atv);

    // RDNSequence SEQUENCE: tag 0x30 + length + RDN
    let mut name = Vec::new();
    name.push(0x30);
    push_der_length(&mut name, rdn.len());
    name.extend_from_slice(&rdn);

    Ok(name)
}

/// Extract the commonName (CN) string from a DER-encoded Name (RDNSequence).
///
/// Walks the nested SEQUENCE > SET > SEQUENCE > { OID, UTF8String } structure
/// and returns the UTF8String value if the OID is 2.5.4.3 (commonName).
/// Returns `None` if no CN attribute is found or the structure is malformed.
pub fn decode_cn(der_bytes: &[u8]) -> Option<String> {
    // Outer SEQUENCE (RDNSequence)
    let (tag, seq_body) = parse_tlv(der_bytes).ok()?;
    if tag != 0x30 {
        return None;
    }

    let mut seq_pos = 0;
    while seq_pos < seq_body.len() {
        // SET (RelativeDistinguishedName)
        let (set_tag, set_body) = parse_tlv(&seq_body[seq_pos..]).ok()?;
        let set_total = tlv_total_len(&seq_body[seq_pos..]).ok()?;
        seq_pos += set_total;

        if set_tag != 0x31 {
            continue;
        }

        let mut set_pos = 0;
        while set_pos < set_body.len() {
            // SEQUENCE (AttributeTypeAndValue)
            let (atv_tag, atv_body) = parse_tlv(&set_body[set_pos..]).ok()?;
            let atv_total = tlv_total_len(&set_body[set_pos..]).ok()?;
            set_pos += atv_total;

            if atv_tag != 0x30 {
                continue;
            }

            // First element: OID
            let oid_total = tlv_total_len(atv_body).ok()?;
            let oid = ObjectIdentifier::from_der(&atv_body[..oid_total]).ok()?;

            if oid == OID_COMMON_NAME {
                // Second element: the value (UTF8String, PrintableString, etc.)
                let val_bytes = &atv_body[oid_total..];
                let (val_tag, val_body) = parse_tlv(val_bytes).ok()?;
                // Accept UTF8String (0x0C) or PrintableString (0x13)
                if val_tag == 0x0C || val_tag == 0x13 {
                    return String::from_utf8(val_body.to_vec()).ok();
                }
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// DER helper utilities
// ---------------------------------------------------------------------------

/// Encode a u8 value as a DER INTEGER.
fn encode_integer(value: u8) -> Result<Vec<u8>> {
    // INTEGER tag (0x02) + length + value bytes
    // If the high bit is set, prepend a 0x00 byte to keep it positive.
    let mut out = vec![0x02]; // INTEGER tag
    if value > 127 {
        out.push(0x02); // length = 2
        out.push(0x00); // padding
        out.push(value);
    } else {
        out.push(0x01); // length = 1
        out.push(value);
    }
    Ok(out)
}

/// Encode raw bytes as a DER INTEGER (positive).
///
/// Strips leading zeros, adds a 0x00 padding byte if needed to keep the
/// value positive (high bit of first byte must be 0).
fn encode_integer_bytes(bytes: &[u8]) -> Result<Vec<u8>> {
    // Strip leading zeros (but keep at least one byte)
    let stripped = match bytes.iter().position(|&b| b != 0) {
        Some(pos) => &bytes[pos..],
        None => &[0u8],
    };

    let needs_padding = !stripped.is_empty() && (stripped[0] & 0x80) != 0;
    let content_len = stripped.len() + if needs_padding { 1 } else { 0 };

    let mut out = vec![0x02]; // INTEGER tag
    push_der_length(&mut out, content_len);
    if needs_padding {
        out.push(0x00);
    }
    out.extend_from_slice(stripped);
    Ok(out)
}

/// Push a DER length encoding onto a byte vector.
///
/// Uses short form (1 byte) for lengths < 128, long form otherwise.
fn push_der_length(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else if len < 256 {
        buf.push(0x81);
        buf.push(len as u8);
    } else if len < 65536 {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xFF) as u8);
    } else if len < 16_777_216 {
        buf.push(0x83);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xFF) as u8);
    } else {
        buf.push(0x84);
        buf.push((len >> 24) as u8);
        buf.push((len >> 16) as u8);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xFF) as u8);
    }
}

/// Parse a DER TLV (Tag-Length-Value), returning `(tag, value_bytes)`.
///
/// Does not recurse into constructed types — returns the raw body bytes.
pub(crate) fn parse_tlv(input: &[u8]) -> Result<(u8, &[u8])> {
    if input.is_empty() {
        return Err(ser_err("empty input in parse_tlv"));
    }
    let tag = input[0];
    let (len, header_len) = parse_der_length(&input[1..])?;
    let total_header = 1 + header_len;
    if input.len() < total_header + len {
        return Err(ser_err("truncated TLV"));
    }
    Ok((tag, &input[total_header..total_header + len]))
}

/// Compute the total byte length of a TLV element (tag + length + value).
pub(crate) fn tlv_total_len(input: &[u8]) -> Result<usize> {
    if input.is_empty() {
        return Err(ser_err("empty input in tlv_total_len"));
    }
    let (len, header_len) = parse_der_length(&input[1..])?;
    Ok(1 + header_len + len)
}

/// Parse a DER length field, returning `(length_value, bytes_consumed)`.
fn parse_der_length(input: &[u8]) -> Result<(usize, usize)> {
    if input.is_empty() {
        return Err(ser_err("empty length field"));
    }
    let first = input[0];
    if first < 128 {
        Ok((first as usize, 1))
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 {
            return Err(ser_err("unsupported DER length encoding"));
        }
        if input.len() < 1 + num_bytes {
            return Err(ser_err("truncated DER length"));
        }
        let mut len: usize = 0;
        for i in 0..num_bytes {
            len = (len << 8) | (input[1 + i] as usize);
        }
        Ok((len, 1 + num_bytes))
    }
}

/// Parse a TbsCertificate from its outer SEQUENCE DER bytes.
fn parse_tbs_certificate(input: &[u8]) -> Result<TbsCertificate> {
    let (tag, body) = parse_tlv(input)?;
    if tag != 0x30 {
        return Err(ser_err("expected SEQUENCE for TbsCertificate"));
    }

    let mut pos = 0;

    // version [0] EXPLICIT INTEGER (optional, default v1)
    let version = if !body.is_empty() && body[pos] == 0xA0 {
        // Parse the [0] EXPLICIT wrapper
        let (_tag, version_body) = parse_tlv(&body[pos..])?;
        let version_total = tlv_total_len(&body[pos..])?;
        pos += version_total;
        // Parse the inner INTEGER
        let (int_tag, int_body) = parse_tlv(version_body)?;
        if int_tag != 0x02 || int_body.is_empty() {
            return Err(ser_err("invalid version INTEGER"));
        }
        int_body[int_body.len() - 1]
    } else {
        0 // default v1
    };

    // serialNumber INTEGER
    let serial_total = tlv_total_len(&body[pos..])?;
    let (_int_tag, serial_body) = parse_tlv(&body[pos..])?;
    let serial_number = serial_body.to_vec();
    pos += serial_total;

    // signature AlgorithmIdentifier
    let sig_algo_total = tlv_total_len(&body[pos..])?;
    let signature_algorithm = AlgorithmIdentifier::from_der(&body[pos..pos + sig_algo_total])
        .map_err(|_| ser_err("failed to decode TBS signature AlgorithmIdentifier"))?;
    pos += sig_algo_total;

    // issuer Name
    let issuer_total = tlv_total_len(&body[pos..])?;
    let issuer = body[pos..pos + issuer_total].to_vec();
    pos += issuer_total;

    // validity Validity
    let validity_total = tlv_total_len(&body[pos..])?;
    let validity = Validity::from_der(&body[pos..pos + validity_total])
        .map_err(|_| ser_err("failed to decode Validity"))?;
    pos += validity_total;

    // subject Name
    let subject_total = tlv_total_len(&body[pos..])?;
    let subject = body[pos..pos + subject_total].to_vec();
    pos += subject_total;

    // subjectPublicKeyInfo
    let spki_total = tlv_total_len(&body[pos..])?;
    let subject_public_key_info = SubjectPublicKeyInfo::from_der(&body[pos..pos + spki_total])
        .map_err(|_| ser_err("failed to decode SubjectPublicKeyInfo"))?;

    Ok(TbsCertificate {
        version,
        serial_number,
        signature_algorithm,
        issuer,
        validity,
        subject,
        subject_public_key_info,
    })
}

// ---------------------------------------------------------------------------
// Shared error helper
// ---------------------------------------------------------------------------

fn ser_err(message: &'static str) -> Error {
    Error::Serialization(SerializationError { message })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_cn_roundtrip() {
        let cn = "Test Subject";
        let der = encode_cn(cn).unwrap();
        assert!(!der.is_empty());
        // Must start with SEQUENCE tag
        assert_eq!(der[0], 0x30);
        let decoded = decode_cn(&der).unwrap();
        assert_eq!(decoded, cn);
    }

    #[test]
    fn encode_cn_empty_string() {
        let der = encode_cn("").unwrap();
        let decoded = decode_cn(&der).unwrap();
        assert_eq!(decoded, "");
    }

    #[test]
    fn encode_cn_unicode() {
        let cn = "Test \u{1F512} Lock";
        let der = encode_cn(cn).unwrap();
        let decoded = decode_cn(&der).unwrap();
        assert_eq!(decoded, cn);
    }

    #[test]
    fn decode_cn_garbage_returns_none() {
        assert!(decode_cn(b"not DER").is_none());
        assert!(decode_cn(&[]).is_none());
    }

    #[test]
    fn algorithm_identifier_roundtrip() {
        let oid = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
        let algo = AlgorithmIdentifier {
            algorithm: oid,
            parameters: None,
        };
        let der = algo.to_der().unwrap();
        let parsed = AlgorithmIdentifier::from_der(&der).unwrap();
        assert_eq!(parsed.algorithm, oid);
        assert_eq!(parsed.parameters, None);
    }

    #[test]
    fn validity_roundtrip() {
        let not_before = der::DateTime::new(2026, 1, 1, 0, 0, 0).unwrap();
        let not_after = der::DateTime::new(2027, 1, 1, 0, 0, 0).unwrap();
        let validity = Validity {
            not_before,
            not_after,
        };
        let encoded = validity.to_der().unwrap();
        let parsed = Validity::from_der(&encoded).unwrap();
        assert_eq!(parsed.not_before, not_before);
        assert_eq!(parsed.not_after, not_after);
    }

    #[test]
    fn spki_roundtrip() {
        let oid = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
        let fake_key = b"fake_public_key_bytes";
        let spki = SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                algorithm: oid,
                parameters: None,
            },
            subject_public_key: BitString::new(0, fake_key).unwrap(),
        };
        let encoded = spki.to_der().unwrap();
        let parsed = SubjectPublicKeyInfo::from_der(&encoded).unwrap();
        assert_eq!(parsed.algorithm.algorithm, oid);
        assert_eq!(parsed.subject_public_key.as_bytes().unwrap(), fake_key);
    }

    #[test]
    fn tbs_certificate_encode_decode() {
        let oid = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
        let issuer = encode_cn("Test Issuer").unwrap();
        let subject = encode_cn("Test Subject").unwrap();
        let not_before = der::DateTime::new(2026, 1, 1, 0, 0, 0).unwrap();
        let not_after = der::DateTime::new(2027, 1, 1, 0, 0, 0).unwrap();

        let tbs = TbsCertificate {
            version: 2, // v3
            serial_number: vec![1],
            signature_algorithm: AlgorithmIdentifier {
                algorithm: oid,
                parameters: None,
            },
            issuer,
            validity: Validity {
                not_before,
                not_after,
            },
            subject,
            subject_public_key_info: SubjectPublicKeyInfo {
                algorithm: AlgorithmIdentifier {
                    algorithm: oid,
                    parameters: None,
                },
                subject_public_key: BitString::new(0, b"fake_key").unwrap(),
            },
        };

        let der = tbs.to_der_bytes().unwrap();
        assert!(!der.is_empty());
        // Should start with SEQUENCE tag
        assert_eq!(der[0], 0x30);

        // Parse it back
        let parsed = parse_tbs_certificate(&der).unwrap();
        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.serial_number, vec![1]);
        assert_eq!(parsed.signature_algorithm.algorithm, oid);
    }

    #[test]
    fn x509_certificate_roundtrip() {
        let oid = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
        let issuer = encode_cn("Test CA").unwrap();
        let subject = encode_cn("Test Cert").unwrap();
        let not_before = der::DateTime::new(2026, 1, 1, 0, 0, 0).unwrap();
        let not_after = der::DateTime::new(2027, 1, 1, 0, 0, 0).unwrap();

        let cert = X509Certificate {
            tbs_certificate: TbsCertificate {
                version: 2,
                serial_number: vec![42],
                signature_algorithm: AlgorithmIdentifier {
                    algorithm: oid,
                    parameters: None,
                },
                issuer,
                validity: Validity {
                    not_before,
                    not_after,
                },
                subject,
                subject_public_key_info: SubjectPublicKeyInfo {
                    algorithm: AlgorithmIdentifier {
                        algorithm: oid,
                        parameters: None,
                    },
                    subject_public_key: BitString::new(0, b"test_key").unwrap(),
                },
            },
            signature_algorithm: AlgorithmIdentifier {
                algorithm: oid,
                parameters: None,
            },
            signature_value: BitString::new(0, b"fake_signature").unwrap(),
        };

        let der = cert.to_der_bytes().unwrap();
        assert!(!der.is_empty());

        let parsed = X509Certificate::from_der(&der).unwrap();
        assert_eq!(parsed.tbs_certificate.version, 2);
        assert_eq!(parsed.tbs_certificate.serial_number, vec![42]);
        assert_eq!(parsed.signature_algorithm.algorithm, oid);
        assert_eq!(
            parsed.signature_value.as_bytes().unwrap(),
            b"fake_signature"
        );
    }

    #[test]
    fn der_length_encoding() {
        // Short form: < 128
        let mut buf = Vec::new();
        push_der_length(&mut buf, 5);
        assert_eq!(buf, [5]);

        // Long form: 128..255
        buf.clear();
        push_der_length(&mut buf, 200);
        assert_eq!(buf, [0x81, 200]);

        // Long form: 256..65535
        buf.clear();
        push_der_length(&mut buf, 1000);
        assert_eq!(buf, [0x82, 0x03, 0xE8]);
    }

    #[test]
    fn encode_integer_values() {
        // Value 0
        let der = encode_integer(0).unwrap();
        assert_eq!(der, [0x02, 0x01, 0x00]);

        // Value 2 (v3)
        let der = encode_integer(2).unwrap();
        assert_eq!(der, [0x02, 0x01, 0x02]);

        // Value 128 (needs padding)
        let der = encode_integer(128).unwrap();
        assert_eq!(der, [0x02, 0x02, 0x00, 0x80]);
    }

    #[test]
    fn parse_tlv_basic() {
        // INTEGER 42
        let input = [0x02, 0x01, 0x2A];
        let (tag, body) = parse_tlv(&input).unwrap();
        assert_eq!(tag, 0x02);
        assert_eq!(body, [0x2A]);
    }

    #[test]
    fn parse_tlv_rejects_empty() {
        assert!(parse_tlv(&[]).is_err());
    }
}
