# Envelopers

Very simple envelope encryption library in Rust using [aes-gcm](https://crates.io/crates/aes-gcm) and a `KeyProvider`
trait. KeyProviders can be implemented for AWS KMS, Azure KeyVault, Hashicorp Vault etc but this library just comes with
a `SimpleKeyProvider` that can be used with a local key.

**NOTE: This library is very alpha and not yet suitable for production use**


