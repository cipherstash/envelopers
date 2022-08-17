# Envelopers

Very simple envelope encryption library in Rust using [aes-gcm](https://crates.io/crates/aes-gcm) and a `KeyProvider`
trait. KeyProviders can be implemented for AWS KMS, Azure KeyVault, Hashicorp Vault etc but this library just comes with
a `SimpleKeyProvider` that can be used with a local key.

**NOTE: This library is very alpha and not yet suitable for production use**

## Examples

### AWS Key Management Service

In order to run the AWS KMS examples you need to ensure the correct environment variables or config options are set to connect to your AWS account.

Follow the AWS [getting started](https://docs.aws.amazon.com/sdk-for-rust/latest/dg/getting-started.html) docs for help.

## Need help?

Head over to our [support forum](https://discuss.cipherstash.com/), and we'll get back to you super quick! 
