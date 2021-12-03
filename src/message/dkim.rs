use crate::message::{header::HeaderName, Headers, Message};
use base64::{decode, encode};
use ed25519_dalek::Signer;
use once_cell::sync::Lazy;
use regex::{bytes::Regex as BRegex, Regex};
use rsa::{pkcs1::FromRsaPrivateKey, Hash, PaddingScheme, RsaPrivateKey};
use sha2::{Digest, Sha256};
use std::fmt::Display;
use std::time::SystemTime;

/// Describe Dkim Canonicalization to apply to either body or headers
#[derive(Copy, Clone, Debug)]
pub enum DkimCanonicalizationType {
    Simple,
    Relaxed,
}

impl Display for DkimCanonicalizationType {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        match self {
            DkimCanonicalizationType::Simple => write!(fmt, "simple"),
            DkimCanonicalizationType::Relaxed => write!(fmt, "relaxed"),
        }
    }
}

/// Describe Canonicalization to be applied before signing
#[derive(Copy, Clone, Debug)]
pub struct DkimCanonicalization {
    pub header: DkimCanonicalizationType,
    pub body: DkimCanonicalizationType,
}

impl Default for DkimCanonicalization {
    fn default() -> Self {
        DkimCanonicalization {
            header: DkimCanonicalizationType::Simple,
            body: DkimCanonicalizationType::Relaxed,
        }
    }
}

/// Format canonicalization to be shown in Dkim header
impl Display for DkimCanonicalization {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(fmt, "{}/{}", self.header, self.body)
    }
}

/// Describe the algorithm used for signing the message
#[derive(Copy, Clone, Debug)]
pub enum DkimSigningAlgorithm {
    Rsa,
    Ed25519,
}

impl Display for DkimSigningAlgorithm {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        match self {
            DkimSigningAlgorithm::Rsa => write!(fmt, "rsa"),
            DkimSigningAlgorithm::Ed25519 => write!(fmt, "ed25519"),
        }
    }
}

/// Describe DkimSigning key error
#[derive(Debug)]
pub enum DkimSigningKeyError {
    DecodeError(base64::DecodeError),
    RsaError(rsa::pkcs1::Error),
    Ed25519Error(ed25519_dalek::ed25519::Error),
}

impl From<rsa::pkcs1::Error> for DkimSigningKeyError {
    fn from(err: rsa::pkcs1::Error) -> DkimSigningKeyError {
        DkimSigningKeyError::RsaError(err)
    }
}

impl From<base64::DecodeError> for DkimSigningKeyError {
    fn from(err: base64::DecodeError) -> DkimSigningKeyError {
        DkimSigningKeyError::DecodeError(err)
    }
}

impl From<ed25519_dalek::ed25519::Error> for DkimSigningKeyError {
    fn from(err: ed25519_dalek::ed25519::Error) -> DkimSigningKeyError {
        DkimSigningKeyError::Ed25519Error(err)
    }
}

/// Describe a signing key to be carried by DkimConfig struct
#[derive(Debug)]
pub enum DkimSigningKey {
    Rsa(RsaPrivateKey),
    Ed25519(ed25519_dalek::Keypair),
}

impl DkimSigningKey {
    pub fn new(
        private_key: &str,
        algorithm: DkimSigningAlgorithm,
    ) -> Result<DkimSigningKey, DkimSigningKeyError> {
        match algorithm {
            DkimSigningAlgorithm::Rsa => Ok(DkimSigningKey::Rsa(RsaPrivateKey::from_pkcs1_pem(
                private_key,
            )?)),
            DkimSigningAlgorithm::Ed25519 => Ok(DkimSigningKey::Ed25519(
                ed25519_dalek::Keypair::from_bytes(&decode(private_key)?)?,
            )),
        }
    }
    fn get_signing_algorithm(&self) -> DkimSigningAlgorithm {
        match self {
            DkimSigningKey::Rsa(_) => DkimSigningAlgorithm::Rsa,
            DkimSigningKey::Ed25519(_) => DkimSigningAlgorithm::Ed25519,
        }
    }
}

/// A struct to describe Dkim configuration applied when signing a message
/// selector: the name of the key publied in DNS
/// domain: the domain for which we sign the message
/// private_key: private key in PKCS1 string format
/// headers: a list of headers name to be included in the signature. Signing of more than one
/// header with same name is not supported
/// canonicalization: the canonicalization to be applied on the message
/// pub signing_algorithm: the signing algorithm to be used when signing
#[derive(Debug)]
pub struct DkimConfig {
    selector: String,
    domain: String,
    private_key: DkimSigningKey,
    headers: Vec<String>,
    canonicalization: DkimCanonicalization,
}

impl DkimConfig {
    /// Create a default signature configuration with a set of headers and "simple/relaxed"
    /// canonicalization
    pub fn default_config(
        selector: String,
        domain: String,
        private_key: DkimSigningKey,
    ) -> DkimConfig {
        DkimConfig {
            selector,
            domain,
            private_key,
            headers: vec![
                "From".to_string(),
                "Subject".to_string(),
                "To".to_string(),
                "Date".to_string(),
            ],
            canonicalization: DkimCanonicalization {
                header: DkimCanonicalizationType::Simple,
                body: DkimCanonicalizationType::Relaxed,
            },
        }
    }
    /// Set the signing key with given signing algorithm for a DkimConfig
    pub fn set_signing_key(&mut self, private_key: DkimSigningKey) {
        self.private_key = private_key;
    }
    /// Create a DkimConfig
    pub fn new(
        selector: String,
        domain: String,
        private_key: DkimSigningKey,
        headers: Vec<String>,
        canonicalization: DkimCanonicalization,
    ) -> DkimConfig {
        DkimConfig {
            selector,
            domain,
            private_key,
            headers,
            canonicalization,
        }
    }
}

/// Create a Headers struct with a Dkim-Signature Header created from given parameters
fn dkim_header_format(
    config: &DkimConfig,
    timestamp: String,
    headers_list: String,
    body_hash: String,
    signature: String,
) -> Headers {
    let mut headers = Headers::new();
    let header_name =
        dkim_canonicalize_header_tag("DKIM-Signature".to_string(), config.canonicalization.header);
    let header_name = HeaderName::new_from_ascii(header_name).unwrap();
    headers.append_raw(header_name, format!("v=1; a={signing_algorithm}-sha256; d={domain}; s={selector}; c={canon}; q=dns/txt; t={timestamp}; h={headers_list}; bh={body_hash}; b={signature}",domain=config.domain, selector=config.selector,canon=config.canonicalization,timestamp=timestamp,headers_list=headers_list,body_hash=body_hash,signature=signature,signing_algorithm=config.private_key.get_signing_algorithm()));
    headers
}

/// Canonicalize the body of an email
fn dkim_canonicalize_body(body: &[u8], canonicalization: DkimCanonicalizationType) -> Vec<u8> {
    static RE: Lazy<BRegex> = Lazy::new(|| BRegex::new("(\r\n)+$").unwrap());
    static RE_DOUBLE_SPACE: Lazy<BRegex> = Lazy::new(|| BRegex::new("[\\t ]+").unwrap());
    static RE_SPACE_EOL: Lazy<BRegex> = Lazy::new(|| BRegex::new("[\t ]\r\n").unwrap());
    match canonicalization {
        DkimCanonicalizationType::Simple => RE.replace(body, &b"\r\n"[..]).into_owned(),
        DkimCanonicalizationType::Relaxed => {
            let body = RE_DOUBLE_SPACE.replace_all(body, &b" "[..]).into_owned();
            let body = RE_SPACE_EOL.replace_all(&body, &b"\r\n"[..]).into_owned();
            RE.replace(&body, &b"\r\n"[..]).into_owned()
        }
    }
}

fn dkim_canonicalize_headers_relaxed(
    headers: &str,
) -> String {
    static RE_LINE_CONTINUATION: Lazy<Regex> = Lazy::new(|| Regex::new("\r\n([ \t])").unwrap());
    static RE_WHITESPACE: Lazy<Regex> = Lazy::new(|| Regex::new("[\\t ]+").unwrap());
    static RE_HEADER_NAME: Lazy<Regex> = Lazy::new(|| Regex::new("(?m)^([^:]*:) ").unwrap());
    static RE_TRAILING: Lazy<Regex> = Lazy::new(|| Regex::new(" \r").unwrap());

    let v = headers;
    let v = RE_LINE_CONTINUATION.replace_all(v, "$1");
    let v = RE_WHITESPACE.replace_all(&v, " ");
    let v = RE_HEADER_NAME.replace_all(&v, "$1");
    let v = RE_TRAILING.replace_all(&v, "\r");
    v.to_string()
}

/// Canonicalize header tag
fn dkim_canonicalize_header_tag(
    name: String,
    canonicalization: DkimCanonicalizationType,
) -> String {
    match canonicalization {
        DkimCanonicalizationType::Simple => name,
        DkimCanonicalizationType::Relaxed => name.to_lowercase(),
    }
}

/// Canonicalize signed headers passed as headers_list among mail_headers using canonicalization
fn dkim_canonicalize_headers(
    headers_list: Vec<String>,
    mail_headers: &Headers,
    canonicalization: DkimCanonicalizationType,
) -> String {
    let mut covered_headers = Headers::new();
    for h in headers_list {
        let h = dkim_canonicalize_header_tag(h, canonicalization);
        if let Some(value) = mail_headers.get_raw(&h) {
            covered_headers.append_raw(HeaderName::new_from_ascii(h).unwrap(), value.to_string());
        }
    }

    let serialized = covered_headers.to_string();

    match canonicalization {
        DkimCanonicalizationType::Simple => serialized,
        DkimCanonicalizationType::Relaxed => dkim_canonicalize_headers_relaxed(&serialized),
    }
}

/// Sign with Dkim a message by adding Dkim-Signture header created with configuration expressed by
/// dkim_config

pub fn dkim_sign(message: &mut Message, dkim_config: &DkimConfig) {
    dkim_sign_fixed_time(message, dkim_config, SystemTime::now())
}

fn dkim_sign_fixed_time(
    message: &mut Message,
    dkim_config: &DkimConfig,
    timestamp: SystemTime,
) {
    let timestamp = timestamp
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();
    let headers = message.headers();
    let body_hash = Sha256::digest(&dkim_canonicalize_body(
        &message.body_raw(),
        dkim_config.canonicalization.body,
    ));
    let bh = encode(body_hash);
    let signed_headers_list = match dkim_config.canonicalization.header {
        DkimCanonicalizationType::Simple => dkim_config.headers.join(":"),
        DkimCanonicalizationType::Relaxed => dkim_config.headers.join(":").to_lowercase(),
    };
    let dkim_header = dkim_header_format(
        dkim_config,
        timestamp.clone(),
        signed_headers_list.clone(),
        bh.clone(),
        "".to_string(),
    );
    let signed_headers = dkim_canonicalize_headers(
        dkim_config.headers.clone(),
        headers,
        dkim_config.canonicalization.header,
    );
    let canonicalized_dkim_header = dkim_canonicalize_headers(
        vec!["DKIM-Signature".to_string()],
        &dkim_header,
        dkim_config.canonicalization.header,
    );
    let to_be_signed = signed_headers + &canonicalized_dkim_header;
    let to_be_signed = to_be_signed.trim_end();
    let hashed_headers = Sha256::digest(to_be_signed.as_bytes());
    let signature = match &dkim_config.private_key {
        DkimSigningKey::Rsa(private_key) => encode(
            private_key
                .sign(
                    PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256)),
                    &hashed_headers,
                )
                .unwrap(),
        ),
        DkimSigningKey::Ed25519(private_key) => {
            encode(private_key.sign(&hashed_headers).to_bytes())
        }
    };
    let dkim_header =
        dkim_header_format(dkim_config, timestamp, signed_headers_list, bh, signature);
    message.headers.append_raw(
        HeaderName::new_from_ascii_str("DKIM-Signature"),
        dkim_header.get_raw("DKIM-Signature").unwrap().to_string(),
    );
}

#[cfg(test)]
mod test {
    use super::{
        super::header::HeaderName,
        super::{Header, Message}, dkim_canonicalize_headers,
        dkim_sign_fixed_time,
        DkimCanonicalization, DkimCanonicalizationType, DkimConfig, DkimSigningAlgorithm, DkimSigningKey,
    };
    use crate::StdError;
    
    

    const KEY_RSA: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwOsW7UFcWn1ch3UM8Mll5qZH5hVHKJQ8Z0tUlebUECq0vjw6
VcsIucZ/B70VpCN63whyi7oApdCIS1o0zad7f0UaW/BfxXADqdcFL36uMaG0RHer
uSASjQGnsl9Kozt/dXiDZX5ngjr/arLJhNZSNR4/9VSwqbE2OPXaSaQ9BsqneD0P
8dCVSfkkDZCcfC2864z7hvC01lFzWQKF36ZAoGBERHScHtFMAzUOgGuqqPiP5khw
DQB3Ffccf+BsWLU2OOteshUwTGjpoangbPCYj6kckwNm440lQwuqTinpC92yyIE5
Ol8psNMW49DLowAeZb6JrjLhD+wY9bghTaOkcwIDAQABAoIBAHTZ8LkkrdvhsvoZ
XA088AwVC9fBa6iYoT2v0zw45JomQ/Q2Zt8wa8ibAradQU56byJI65jWwS2ucd+y
c+ldWOBt6tllb50XjCCDrRBnmvtVBuux0MIBOztNlVXlgj/8+ecdZ/lB51Bqi+sF
ACsF5iVmfTcMZTVjsYQu5llUseI6Lwgqpx6ktaXD2PVsVo9Gf01ssZ4GCy69wB/3
20CsOz4LEpSYkq1oE98lMMGCfD7py3L9kWHYNNisam78GM+1ynRxRGwEDUbz6pxs
fGPIAwHLaZsOmibPkBB0PJTW742w86qQ8KAqC6ZbRYOF19rSMj3oTfRnPMHn9Uu5
N8eQcoECgYEA97SMUrz2hqII5i8igKylO9kV8pjcIWKI0rdt8MKj4FXTNYjjO9I+
41ONOjhUOpFci/G3YRKi8UiwbKxIRTvIxNMh2xj6Ws3iO9gQHK1j8xTWxJdjEBEz
EuZI59Mi5H7fxSL1W+n8nS8JVsaH93rvQErngqTUAsihAzjxHWdFwm0CgYEAx2Dh
claESJP2cOKgYp+SUNwc26qMaqnl1f37Yn+AflrQOfgQqJe5TRbicEC+nFlm6XUt
3st1Nj29H0uOMmMZDmDCO+cOs5Qv5A9pG6jSC6wM+2KNHQDtrxlakBFygePEPVVy
GXaY9DRa9Q4/4ataxDR2/VvIAWfEEtMTJIBDtl8CgYAIXEuwLziS6r0qJ8UeWrVp
A7a97XLgnZbIpfBMBAXL+JmcYPZqenos6hEGOgh9wZJCFvJ9kEd3pWBvCpGV5KKu
IgIuhvVMQ06zfmNs1F1fQwDMud9aF3qF1Mf5KyMuWynqWXe2lns0QvYpu6GzNK8G
mICf5DhTr7nfhfh9aZLtMQKBgCxKsmqzG5n//MxhHB4sstVxwJtwDNeZPKzISnM8
PfBT/lQSbqj1Y73japRjXbTgC4Ore3A2JKjTGFN+dm1tJGDUT/H8x4BPWEBCyCfT
3i2noA6sewrJbQPsDvlYVubSEYNKmxlbBmmhw98StlBMv9I8kX6BSDI/uggwid0e
/WvjAoGBAKpZ0UOKQyrl9reBiUfrpRCvIMakBMd79kNiH+5y0Soq/wCAnAuABayj
XEIBhFv+HxeLEnT7YV+Zzqp5L9kKw/EU4ik3JX/XsEihdSxEuGX00ZYOw05FEfpW
cJ5Ku0OTwRtSMaseRPX+T4EfG1Caa/eunPPN4rh+CSup2BVVarOT
-----END RSA PRIVATE KEY-----";

    #[derive(Clone)]
    struct TestHeader(String);

    impl Header for TestHeader {
        fn name() -> HeaderName {
            HeaderName::new_from_ascii_str("Test")
        }

        fn parse(s: &str) -> Result<Self, Box<dyn StdError + Send + Sync>> {
            Ok(Self(s.into()))
        }

        fn display(&self) -> String {
            self.0.clone()
        }
    }

    fn test_message() -> Message {
        Message::builder()
            .from("Test <test+ezrz@example.net>".parse().unwrap())
            .to("Test2 <test2@example.org>".parse().unwrap())
            .date(std::time::UNIX_EPOCH)
            .header(TestHeader("test  test very very long with spaces and extra spaces   \twill be folded to several lines ".to_string()))
            .subject("Test with utf-8 ë")
            .body("test\r\n\r\ntest   \ttest\r\n\r\n\r\n".to_string()).unwrap()
    }

    #[test]
    fn test_headers_simple_canonicalize() {
        let message = test_message();
        assert_eq!(dkim_canonicalize_headers(vec!["From".to_string(), "Test".to_string()], &message.headers, DkimCanonicalizationType::Simple),"From: Test <test+ezrz@example.net>\r\nTest: test  test very very long with spaces and extra spaces   \twill be \r\n folded to several lines \r\n")
    }
    #[test]
    fn test_headers_relaxed_canonicalize() {
        let message = test_message();
        assert_eq!(dkim_canonicalize_headers(vec!["From".to_string(), "Test".to_string()], &message.headers, DkimCanonicalizationType::Relaxed),"from:Test <test+ezrz@example.net>\r\ntest:test test very very long with spaces and extra spaces will be folded to several lines\r\n")
    }
    #[test]
    fn test_signature_rsa_simple() {
        let mut message = test_message();
        let signing_key = DkimSigningKey::new(KEY_RSA, DkimSigningAlgorithm::Rsa).unwrap();
        dkim_sign_fixed_time(
            &mut message,
            &DkimConfig::new(
                "dkimtest".to_string(),
                "example.org".to_string(),
                signing_key,
                vec![
                    "Date".to_string(),
                    "From".to_string(),
                    "Subject".to_string(),
                    "To".to_string(),
                ],
                DkimCanonicalization{
                    header: DkimCanonicalizationType::Simple,
                    body: DkimCanonicalizationType::Simple,
                }),
            std::time::UNIX_EPOCH);
        let signed = message.formatted();
        let signed = std::str::from_utf8(&signed).unwrap();
        assert_eq!(signed, std::concat!(
            "From: Test <test+ezrz@example.net>\r\n",
            "To: Test2 <test2@example.org>\r\n",
            "Date: Thu, 01 Jan 1970 00:00:00 -0000\r\n",
            "Test: test  test very very long with spaces and extra spaces   \twill be \r\n",
            " folded to several lines \r\n",
            "Subject: Test with utf-8 =?utf-8?b?w6s=?=\r\n",
            "Content-Transfer-Encoding: 7bit\r\n",
            "DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=dkimtest; \r\n",
            " c=simple/simple; q=dns/txt; t=0; h=Date:From:Subject:To; \r\n",
            " bh=f3Zksdcjqa/xRBwdyFzIXWCcgP7XTgxjCgYsXOMKQl4=; b=sIosy56i62OqWVw7febnYuT0\r\n",
            " 3Y0bcU6xpB5deSCeEj2Xr6PLmHY/XLwyREzYXy8fDy5YmOcrlWsdvRj8KdScusyRu3fY3cMHbaZ\r\n",
            " 5RnZhoYqYT0lAuEkFXnlM5+4mnvorMnmMLkzhdk4C47DBi4A5sNb621cKZ5UA6BX2EQCz3adE/9\r\n",
            " UzNSrdxKQEkvA0XfeSJQ7R9wPQgGvWRS+5HiF6vJV52srZ3N1u6S2bWM9RMfVYHjxFvPIuaPMEd\r\n",
            " zM4yOo7ZPriyFxxlnnmMdFyRXA1IX4xDU2MwBu3/46COBz38Amr8jo/cwxgyfBBWyKK1/EnQw6G\r\n",
            " 66lC3NPMHjrvvTjabw==\r\n",
            "\r\n",
            "test\r\n\r\ntest   \ttest\r\n\r\n\r\n"));
    }

    #[test]
    fn test_signature_rsa_relaxed() {
        let mut message = test_message();
        let signing_key = DkimSigningKey::new(KEY_RSA, DkimSigningAlgorithm::Rsa).unwrap();
        dkim_sign_fixed_time(
            &mut message,
            &DkimConfig::new(
                "dkimtest".to_string(),
                "example.org".to_string(),
                signing_key,
                vec![
                    "Date".to_string(),
                    "From".to_string(),
                    "Subject".to_string(),
                    "To".to_string(),
                ],
                DkimCanonicalization{
                    header: DkimCanonicalizationType::Relaxed,
                    body: DkimCanonicalizationType::Relaxed,
                }),
            std::time::UNIX_EPOCH);
        let signed = message.formatted();
        let signed = std::str::from_utf8(&signed).unwrap();
        println!("{}", signed);
        assert_eq!(signed, std::concat!(
            "From: Test <test+ezrz@example.net>\r\n",
            "To: Test2 <test2@example.org>\r\n",
            "Date: Thu, 01 Jan 1970 00:00:00 -0000\r\n",
            "Test: test  test very very long with spaces and extra spaces   \twill be \r\n",
            " folded to several lines \r\n",
            "Subject: Test with utf-8 =?utf-8?b?w6s=?=\r\n",
            "Content-Transfer-Encoding: 7bit\r\n",
            "DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=dkimtest; \r\n",
            " c=relaxed/relaxed; q=dns/txt; t=0; h=date:from:subject:to; \r\n",
            " bh=qN8je6qJgWFGSnN2MycC/XKPbN6BOrMJyAX2h4m19Ss=; b=ktuUxPQQxAO+TU7rYcIjC3Vv\r\n",
            " S8XqRdldLgVRZLsp+tHT7pxnxXYVeZc1tZ4uVoxL76V5zzjpjxImDGdebs4U8ie22aBxuOjY0/Z\r\n",
            " /AZ52C+icy2hGpBUg7IiEqlF3DQOHMHP66YxjNWdTCJFZzfEn4moHMhstMcpvO7s4GxkUbjJ4j4\r\n",
            " WoFLkPUiEKlAeHkwPYT5kHhKeA2294h1VFO9erY/Nr/GdNq/QZSFIHu2tOHRWKKzEPrPLAHqm2b\r\n",
            " iAFwc3MlHOo1VyZukdYNF2UirJ1ObqgzEYsA6VK5MKEAPHKRyBpA1nNbey4wx2HtuUjiankjB51\r\n",
            " f+sqRgQvupV1WSC5qw==\r\n",
            "\r\n",
            "test\r\n",
            "\r\n",
            "test   \ttest\r\n\r\n\r\n"));
    }
}
