use aes_gcm::aes::cipher::consts::U16;
use aes_gcm::Key;
use lru::LruCache;
use std::cell::RefCell;
use std::time::{Duration, Instant};
use zeroize::ZeroizeOnDrop;

use crate::errors::{KeyDecryptionError, KeyGenerationError};
use crate::key_provider::DataKey;
use crate::KeyProvider;

#[derive(ZeroizeOnDrop)]
struct CachedEncryptionEntry {
    #[zeroize(skip)]
    created_at: Instant,
    key: DataKey,
    bytes_encrypted: usize,
    messages_encrypted: usize,
}

#[derive(ZeroizeOnDrop)]
struct CachedDecryptionEntry {
    key: Key<U16>,
    #[zeroize(skip)]
    created_at: Instant,
}

/// The options for configuring a [`CachingKeyWrapper`]'s cache
pub struct CacheOptions {
    max_age: Duration,
    max_bytes: usize,
    max_messages: usize,
    max_entries: usize,
}

impl CacheOptions {
    /// Configure the maximum time a key can remain in the cache
    pub fn with_max_age(mut self, max_age: Duration) -> Self {
        self.max_age = max_age;
        self
    }

    /// Configure the maximum number of bytes a key can encrypt
    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// Configure the maximum number of messages a key can encrypt
    pub fn with_max_messages(mut self, max_messages: usize) -> Self {
        self.max_messages = max_messages;
        self
    }

    /// Configure the maximum number of keys that can be in the cache
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries;
        self
    }
}

impl Default for CacheOptions {
    fn default() -> Self {
        // These defaults are based on the aws-encryption-sdk-javascript examples
        Self {
            max_age: Duration::from_secs(60),
            max_bytes: 100,
            max_messages: 10,
            max_entries: 10,
        }
    }
}

/// A wrapper for a [`KeyProvider`] that supports caching.
///
/// Caching can be configured using [`CacheOptions`] to work based on:
/// - max messages encrypted per key
/// - max bytes encrypted per key
/// - max time key can be cached for
pub struct CachingKeyWrapper<K> {
    encryption_cache: RefCell<Vec<CachedEncryptionEntry>>,
    decryption_cache: RefCell<LruCache<Vec<u8>, CachedDecryptionEntry>>,
    options: CacheOptions,
    provider: K,
}

impl<K> CachingKeyWrapper<K>
where
    K: KeyProvider,
{
    /// Create a new CachingKeyWrapper from a certain key provider and caching options
    pub fn new(provider: K, options: CacheOptions) -> Self {
        Self {
            provider,
            decryption_cache: RefCell::new(LruCache::new(options.max_entries)),
            encryption_cache: Default::default(),
            options,
        }
    }

    fn has_exceeded_limits(&self, entry: &CachedEncryptionEntry) -> bool {
        entry.created_at.elapsed() > self.options.max_age
            || entry.messages_encrypted > self.options.max_messages
            || entry.bytes_encrypted > self.options.max_bytes
    }

    fn maybe_prune_last_decryption_entry(
        &self,
        cache: &mut LruCache<Vec<u8>, CachedDecryptionEntry>,
    ) {
        let should_pop = cache
            .peek_lru()
            .map(|(_, entry)| entry.created_at.elapsed() > self.options.max_age)
            .unwrap_or(false);

        if should_pop {
            let popped = cache.pop_lru();
            // Zero out old data key here?
            drop(popped);
        }
    }

    fn get_and_increment_cached_encryption_key(
        &self,
        bytes: usize,
    ) -> Result<Option<DataKey>, KeyGenerationError> {
        let mut cached = self
            .encryption_cache
            .try_borrow_mut()
            .map_err(|_| KeyGenerationError::Other("Failed to borrow cached key".into()))?;

        while let Some(mut cached_entry) = cached.pop() {
            cached_entry.messages_encrypted += 1;
            cached_entry.bytes_encrypted += bytes;

            if !self.has_exceeded_limits(&cached_entry) {
                // Cloning here could be bad for zeroing memory + performance.
                // Maybe change this method to be a "with_data_key_for_bytes" so that
                // we can borrow the key instead.
                let key = cached_entry.key.clone();

                // Since the entry is fine to keep, add it back to the stack
                cached.push(cached_entry);

                return Ok(Some(key));
            }
        }

        Ok(None)
    }

    fn get_cached_decryption_key(
        &self,
        encrypted_key: &Vec<u8>,
    ) -> Result<Option<Key<U16>>, KeyDecryptionError> {
        let mut decryption_cache = self
            .decryption_cache
            .try_borrow_mut()
            .map_err(|_| KeyDecryptionError::Other("Failed to borrow decryption cache".into()))?;

        if let Some(cached_key) = decryption_cache.get(encrypted_key) {
            // Only return the cached key if the age is less than the max_age param.
            // I don't think this is strictly necessary, but it's what the JS AWS SDK does.
            if cached_key.created_at.elapsed() <= self.options.max_age {
                return Ok(Some(cached_key.key));
            }
        }

        self.maybe_prune_last_decryption_entry(&mut decryption_cache);

        Ok(None)
    }

    fn cache_encryption_key(&self, bytes: usize, key: DataKey) -> Result<(), KeyGenerationError> {
        let mut cached = self
            .encryption_cache
            .try_borrow_mut()
            .map_err(|_| KeyGenerationError::Other("Failed to borrow cached key".into()))?;

        // If the encryption cache has too many entries, remove the first one.
        // This operation needs to shift all the elements in the Vec, but should
        // be negligible since the "max_entries" option on the cache will most
        // likely be <1000.
        if cached.len() >= self.options.max_entries {
            cached.remove(0);
        }

        cached.push(CachedEncryptionEntry {
            key: key.clone(),
            bytes_encrypted: bytes,
            messages_encrypted: 1,
            created_at: Instant::now(),
        });

        let mut decryption_cache = self
            .decryption_cache
            .try_borrow_mut()
            .map_err(|_| KeyGenerationError::Other("Failed to borrow decryption cache".into()))?;

        self.maybe_prune_last_decryption_entry(&mut decryption_cache);

        decryption_cache.put(
            key.encrypted_key.clone(),
            CachedDecryptionEntry {
                key: key.key,
                created_at: Instant::now(),
            },
        );

        Ok(())
    }

    fn cache_decryption_key(
        &self,
        encrypted_key: &Vec<u8>,
        plaintext_key: Key<U16>,
    ) -> Result<(), KeyDecryptionError> {
        self.decryption_cache
            .try_borrow_mut()
            .map_err(|_| KeyDecryptionError::Other("Failed to borrow decryption cache".into()))?
            .put(
                // Sucks that you have to clone here - surely they can hash from a reference
                encrypted_key.clone(),
                CachedDecryptionEntry {
                    key: plaintext_key,
                    created_at: Instant::now(),
                },
            );

        Ok(())
    }

    /// Get a cached data key or generate one for a certain number of bytes
    ///
    /// Note: the bytes field is used to determine when keys should be expired. It's important that
    /// this is the number of bytes the key will be used to encrypt.
    pub async fn get_or_generate_data_key_for_bytes(
        &self,
        bytes: usize,
    ) -> Result<DataKey, KeyGenerationError> {
        if let Some(cached_key) = self.get_and_increment_cached_encryption_key(bytes)? {
            return Ok(cached_key);
        }

        let key = self.provider.generate_data_key().await?;

        self.cache_encryption_key(bytes, key.clone())?;

        Ok(key)
    }

    pub async fn decrypt_data_key(
        &self,
        encrypted_key: &Vec<u8>,
    ) -> Result<Key<U16>, KeyDecryptionError> {
        if let Some(cached_key) = self.get_cached_decryption_key(encrypted_key)? {
            return Ok(cached_key);
        }

        let plaintext_key = self.provider.decrypt_data_key(encrypted_key).await?;

        self.cache_decryption_key(encrypted_key, plaintext_key)?;

        Ok(plaintext_key)
    }
}

#[cfg(test)]
mod tests {
    use super::{CacheOptions, CachingKeyWrapper};
    use crate::{DataKey, Key, KeyDecryptionError, KeyGenerationError, KeyProvider, U16};
    use aes_gcm::{
        aead::{Aead, Payload},
        Aes128Gcm, NewAead,
    };
    use async_trait::async_trait;
    use std::{
        sync::atomic::{AtomicU8, Ordering},
        time::Duration,
    };

    fn test_encrypt_bytes(bytes: &[u8]) -> Vec<u8> {
        let cipher = Aes128Gcm::new(Key::from_slice(&[1; 16]));

        cipher
            .encrypt(
                Key::from_slice(&[2; 12]),
                Payload {
                    msg: bytes,
                    aad: &[],
                },
            )
            .expect("Failed to encrypt")
    }

    fn test_decrypt_bytes(bytes: &[u8]) -> Vec<u8> {
        let cipher = Aes128Gcm::new(Key::from_slice(&[1; 16]));
        cipher
            .decrypt(
                Key::from_slice(&[2; 12]),
                Payload {
                    msg: bytes,
                    aad: &[],
                },
            )
            .expect("Failed to decrypt")
    }

    #[derive(Default)]
    struct TestKeyProvider {
        generate_counter: AtomicU8,
        decrypt_counter: AtomicU8,
    }

    impl TestKeyProvider {
        fn get_decrypt_count(&self) -> usize {
            self.decrypt_counter.load(Ordering::Relaxed) as usize
        }

        fn get_generate_count(&self) -> usize {
            self.generate_counter.load(Ordering::Relaxed) as usize
        }
    }

    #[async_trait(?Send)]
    impl KeyProvider for TestKeyProvider {
        async fn decrypt_data_key(
            &self,
            encrypted_key: &Vec<u8>,
        ) -> Result<Key<U16>, KeyDecryptionError> {
            self.decrypt_counter.fetch_add(1, Ordering::Relaxed);
            Ok(Key::clone_from_slice(&test_decrypt_bytes(encrypted_key)))
        }

        async fn generate_data_key(&self) -> Result<DataKey, KeyGenerationError> {
            let count = self.generate_counter.fetch_add(1, Ordering::Relaxed);
            // Generate a data key that is just the current count for all bytes
            let key = Key::clone_from_slice(&[count; 16]);
            let encrypted_key = test_encrypt_bytes(&key);
            Ok(DataKey {
                key,
                encrypted_key,
                key_id: "test".into(),
            })
        }
    }

    fn create_test_cache() -> CachingKeyWrapper<TestKeyProvider> {
        CachingKeyWrapper::new(
            TestKeyProvider::default(),
            CacheOptions::default()
                .with_max_age(Duration::from_millis(10))
                .with_max_bytes(100)
                .with_max_entries(10)
                .with_max_messages(10),
        )
    }

    #[tokio::test]
    async fn test_generate_uses_cached_key() {
        let cache = create_test_cache();

        assert_eq!(cache.provider.get_generate_count(), 0);

        assert!(cache.get_or_generate_data_key_for_bytes(10).await.is_ok());

        assert_eq!(cache.provider.get_generate_count(), 1);

        assert!(cache.get_or_generate_data_key_for_bytes(10).await.is_ok());

        // Not incremented because cache was used
        assert_eq!(cache.provider.get_generate_count(), 1);
    }

    #[tokio::test]
    async fn test_generate_expires_after_10_messages() {
        let cache = create_test_cache();

        assert_eq!(cache.provider.get_generate_count(), 0);

        assert!(cache.get_or_generate_data_key_for_bytes(1).await.is_ok());

        assert_eq!(cache.provider.get_generate_count(), 1);

        for _ in 0..9 {
            assert!(cache.get_or_generate_data_key_for_bytes(1).await.is_ok());
        }

        assert_eq!(cache.provider.get_generate_count(), 1);

        assert!(cache.get_or_generate_data_key_for_bytes(1).await.is_ok());

        // Incremented because 11th message needed new data key
        assert_eq!(cache.provider.get_generate_count(), 2);
    }

    #[tokio::test]
    async fn test_generate_expires_after_100_bytes() {
        let cache = create_test_cache();

        assert_eq!(cache.provider.get_generate_count(), 0);

        assert!(cache.get_or_generate_data_key_for_bytes(10).await.is_ok()); // 10
        assert!(cache.get_or_generate_data_key_for_bytes(30).await.is_ok()); // 40
        assert!(cache.get_or_generate_data_key_for_bytes(60).await.is_ok()); // 100

        assert_eq!(cache.provider.get_generate_count(), 1);

        assert!(cache.get_or_generate_data_key_for_bytes(1).await.is_ok()); // 101

        assert_eq!(cache.provider.get_generate_count(), 2);
    }

    #[tokio::test]
    async fn test_generate_expires_after_10_ms() {
        let cache = create_test_cache();

        assert_eq!(cache.provider.get_generate_count(), 0);

        assert!(cache.get_or_generate_data_key_for_bytes(10).await.is_ok());
        assert_eq!(cache.provider.get_generate_count(), 1);

        std::thread::sleep(Duration::from_millis(8));

        assert_eq!(cache.provider.get_generate_count(), 1);

        std::thread::sleep(Duration::from_millis(8));

        assert!(cache.get_or_generate_data_key_for_bytes(10).await.is_ok());
        assert_eq!(cache.provider.get_generate_count(), 2);
    }

    #[tokio::test]
    async fn test_generate_caches_for_decrypt() {
        let cache = create_test_cache();

        assert_eq!(cache.provider.get_generate_count(), 0);

        let DataKey { encrypted_key, .. } = cache
            .get_or_generate_data_key_for_bytes(10)
            .await
            .expect("Expected generate to succeed");

        assert_eq!(cache.provider.get_generate_count(), 1);

        assert!(cache.decrypt_data_key(&encrypted_key).await.is_ok());

        // No keys were decrypted because they were in the cache
        assert_eq!(cache.provider.get_decrypt_count(), 0);
    }

    #[tokio::test]
    async fn test_caches_decryption() {
        let cache = create_test_cache();

        let key: Key<U16> = Key::clone_from_slice(&[1; 16]);

        assert!(cache
            .decrypt_data_key(&test_encrypt_bytes(&key))
            .await
            .is_ok());

        assert_eq!(cache.provider.get_decrypt_count(), 1);

        assert!(cache
            .decrypt_data_key(&test_encrypt_bytes(&key))
            .await
            .is_ok());

        // Used cached key so not incremented
        assert_eq!(cache.provider.get_decrypt_count(), 1);
    }

    #[tokio::test]
    async fn test_expires_decryption_key_after_10ms() {
        // Note: this is what the JS SDK does but I don't think it's necessary.
        // If we have a key cached and it is being used there shouldn't be a need
        // to refetch it. This will just result in uncessary calls to the key provider
        // to return the same value to the cache.

        let cache = create_test_cache();

        let key: Key<U16> = Key::clone_from_slice(&[1; 16]);

        assert!(cache
            .decrypt_data_key(&test_encrypt_bytes(&key))
            .await
            .is_ok());

        assert_eq!(cache.provider.get_decrypt_count(), 1);

        std::thread::sleep(Duration::from_millis(8));

        assert!(cache
            .decrypt_data_key(&test_encrypt_bytes(&key))
            .await
            .is_ok());

        assert_eq!(cache.provider.get_decrypt_count(), 1);

        std::thread::sleep(Duration::from_millis(8));

        assert!(cache
            .decrypt_data_key(&test_encrypt_bytes(&key))
            .await
            .is_ok());

        // Time is past 10ms so it refetches
        assert_eq!(cache.provider.get_decrypt_count(), 2);
    }
}
