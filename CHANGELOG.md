# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

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

