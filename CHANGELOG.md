# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## [0.8.3]

### Security

- Set `default-features = false` on `aws-sdk-kms` and select `default-https-client`
  instead. The default feature set pulled in the deprecated `rustls` feature, which
  resolves to `aws-smithy-http-client`'s `legacy-rustls-ring` and transitively to
  `rustls` 0.21 / `rustls-webpki` 0.101 — the latter affected by GHSA-82j2-j2ch-gfr8
  (panic on a malformed CRL `issuingDistributionPoint` BIT STRING). Downstream crates
  could not drop `rustls-webpki` 0.101 while depending on a released `envelopers`,
  because feature unification re-enabled it.
- Patch `aws-lc-sys` to 0.38.0.
- Patch AWS SDK crates for GHSA-g59m-gf8j-gjf5.

### Changed

- Replace unmaintained `async-mutex` with `async-lock` 3.4 (internal only; no public
  API change).
- Bump `aws-sdk-kms` to 1.114, `aws-config` to 1.10, `aws-smithy-runtime` to 1.13.
- Bump `tokio` to 1.38.2, `ring` to 0.17.13, `h2` to 0.3.26, `mio` to 0.8.11,
  `tracing-subscriber` to 0.3.22.

### Note

This is the first release since 0.8.2 (published 2024-01-09). Releases 0.6.x through
0.8.2 were published without changelog entries; this entry covers only the changes
between 0.8.2 and 0.8.3.

## [0.5.1]

- Add `tokio` feature which enabled `rt-tokio` in `aws-sdk-kms`

## [0.5.0]

## Changed

- Updated `KeyProvider` trait to pass through bytes to be encrypted
- Updated `CachingKeyWrapper` to implement `KeyProvider`
- Made `aws-kms` and `cache` features on by default

## [0.4.1]

## Changed

- Increased retry config to 5 attempts

## [0.4.0]

## Changed

- AWS KMS KeyProvider must now be enabled with the aws-kms feature

