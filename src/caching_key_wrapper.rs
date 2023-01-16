use std::time::{Duration, Instant};

use aes_gcm::{Key, KeySizeUser};
use async_mutex::Mutex as AsyncMutex;
use async_trait::async_trait;
use lru::LruCache;
use zeroize::ZeroizeOnDrop;

use crate::errors::{KeyDecryptionError, KeyGenerationError};
use crate::key_provider::DataKey;
use crate::KeyProvider;

#[derive(ZeroizeOnDrop)]
struct CachedEncryptionEntry<S: KeySizeUser> {
    #[zeroize(skip)]
    created_at: Instant,
    key: DataKey<S>,
    bytes_encrypted: usize,
    messages_encrypted: usize,
}

#[derive(ZeroizeOnDrop)]
struct CachedDecryptionEntry<S: KeySizeUser> {
    #[zeroize(skip)]
    created_at: Instant,
    key: Key<S>,
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
pub struct CachingKeyWrapper<S: KeySizeUser, K> {
    encryption_cache: AsyncMutex<LruCache<Vec<u8>, Vec<CachedEncryptionEntry<S>>>>,
    decryption_cache: AsyncMutex<LruCache<Vec<u8>, CachedDecryptionEntry<S>>>,
    options: CacheOptions,
    provider: K,
}

impl<S: KeySizeUser + Clone, K> CachingKeyWrapper<S, K>
where
    Key<S>: Copy,
{
    /// Create a new CachingKeyWrapper from a certain key provider and caching options
    pub fn new(provider: K, options: CacheOptions) -> Self {
        Self {
            provider,
            decryption_cache: AsyncMutex::new(LruCache::new(options.max_entries)),
            encryption_cache: AsyncMutex::new(LruCache::new(options.max_entries)),
            options,
        }
    }

    fn has_exceeded_limits(&self, entry: &CachedEncryptionEntry<S>) -> bool {
        entry.created_at.elapsed() > self.options.max_age
            || entry.messages_encrypted > self.options.max_messages
            || entry.bytes_encrypted > self.options.max_bytes
    }

    fn maybe_prune_last_decryption_entry(
        &self,
        cache: &mut LruCache<Vec<u8>, CachedDecryptionEntry<S>>,
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

    async fn get_and_increment_cached_encryption_key(
        &self,
        bytes: usize,
        aad: Option<&str>,
    ) -> Option<DataKey<S>> {
        let mut encryption_cache = self.encryption_cache.lock().await;

        let cache_key = aad.unwrap_or_default().as_bytes();
        if let Some(cached_entries) = encryption_cache.get_mut(cache_key) {
            while let Some(mut cached_encryption_entry) = cached_entries.pop() {
                cached_encryption_entry.messages_encrypted += 1;
                cached_encryption_entry.bytes_encrypted += bytes;

                if !self.has_exceeded_limits(&cached_encryption_entry) {
                    // Cloning here could be bad for zeroing memory + performance.
                    // Maybe change this method to be a "with_data_key_for_bytes" so that
                    // we can borrow the key instead.
                    let key = cached_encryption_entry.key.clone();

                    // Since the entry is fine to keep, add it back to the stack
                    cached_entries.push(cached_encryption_entry);

                    return Some(key);
                }
            }
        }

        None
    }

    async fn get_cached_decryption_key(
        &self,
        encrypted_key: &[u8],
        aad: Option<&str>,
    ) -> Option<Key<S>> {
        let mut decryption_cache = self.decryption_cache.lock().await;

        let cache_key = [encrypted_key, aad.unwrap_or_default().as_bytes()].concat();

        if let Some(cached_decryption_entry) = decryption_cache.get(&cache_key) {
            // Only return the cached key if the age is less than the max_age param.
            // I don't think this is strictly necessary, but it's what the JS AWS SDK does.
            if cached_decryption_entry.created_at.elapsed() <= self.options.max_age {
                return Some(cached_decryption_entry.key);
            }
        }

        self.maybe_prune_last_decryption_entry(&mut decryption_cache);

        None
    }

    async fn cache_encryption_key(&self, bytes: usize, key: DataKey<S>, aad: Option<&str>) {
        let mut encryption_cache = self.encryption_cache.lock().await;
        let mut decryption_cache = self.decryption_cache.lock().await;

        let cache_key = aad.unwrap_or_default().as_bytes();
        let cached_encryption_entry = CachedEncryptionEntry {
            key: key.clone(),
            bytes_encrypted: bytes,
            messages_encrypted: 1,
            created_at: Instant::now(),
        };

        if let Some(cached_encryption_entries) = encryption_cache.get_mut(cache_key) {
            // If the encryption cache has too many entries, remove the first one.
            // This operation needs to shift all the elements in the Vec, but should
            // be negligible since the "max_entries" option on the cache will most
            // likely be <1000.
            if cached_encryption_entries.len() >= self.options.max_entries {
                cached_encryption_entries.remove(0);
            }

            cached_encryption_entries.push(cached_encryption_entry);
        } else {
            let cached_encryption_entries = vec![cached_encryption_entry];
            encryption_cache.put(cache_key.to_vec(), cached_encryption_entries);
        }

        self.maybe_prune_last_decryption_entry(&mut decryption_cache);

        let dec_cache_key = [&key.encrypted_key, aad.unwrap_or_default().as_bytes()].concat();
        decryption_cache.put(
            dec_cache_key,
            CachedDecryptionEntry {
                key: key.key,
                created_at: Instant::now(),
            },
        );
    }

    async fn cache_decryption_key(
        &self,
        encrypted_key: &[u8],
        plaintext_key: Key<S>,
        aad: Option<&str>,
    ) {
        let cache_key = [encrypted_key, aad.unwrap_or_default().as_bytes()].concat();
        self.decryption_cache.lock().await.put(
            cache_key,
            CachedDecryptionEntry {
                key: plaintext_key,
                created_at: Instant::now(),
            },
        );
    }
}

#[async_trait]
impl<S: KeySizeUser + Clone, K: KeyProvider<Cipher = S>> KeyProvider for CachingKeyWrapper<S, K>
where
    Key<S>: Copy,
{
    type Cipher = S;

    async fn generate_data_key(
        &self,
        bytes: usize,
        aad: Option<&str>,
    ) -> Result<DataKey<S>, KeyGenerationError> {
        if let Some(cached_key) = self
            .get_and_increment_cached_encryption_key(bytes, aad)
            .await
        {
            return Ok(cached_key);
        }

        let key = self.provider.generate_data_key(bytes, aad).await?;

        self.cache_encryption_key(bytes, key.clone(), aad).await;

        Ok(key)
    }

    async fn decrypt_data_key(
        &self,
        encrypted_key: &[u8],
        aad: Option<&str>,
    ) -> Result<Key<S>, KeyDecryptionError> {
        if let Some(cached_key) = self.get_cached_decryption_key(encrypted_key, aad).await {
            return Ok(cached_key);
        }

        let plaintext_key = self.provider.decrypt_data_key(encrypted_key, aad).await?;

        self.cache_decryption_key(encrypted_key, plaintext_key, aad)
            .await;

        Ok(plaintext_key)
    }
}

#[cfg(test)]
mod tests {
    use super::{CacheOptions, CachingKeyWrapper};
    use crate::{DataKey, Key, KeyDecryptionError, KeyGenerationError, KeyProvider};
    use aes_gcm::{
        aead::{Aead, Payload},
        aes::Aes128,
        Aes128Gcm, KeyInit, Nonce,
    };
    use async_trait::async_trait;
    use std::{
        sync::atomic::{AtomicU8, Ordering},
        time::Duration,
    };

    fn test_encrypt_bytes(bytes: &[u8], aad: Option<&str>) -> Vec<u8> {
        let cipher = Aes128Gcm::new_from_slice(&[1; 16]).unwrap();

        cipher
            .encrypt(
                Nonce::from_slice(&[2; 12]),
                Payload {
                    msg: bytes,
                    aad: aad.unwrap_or_default().as_bytes(),
                },
            )
            .expect("Failed to encrypt")
    }

    fn test_decrypt_bytes(bytes: &[u8], aad: Option<&str>) -> Vec<u8> {
        let cipher = Aes128Gcm::new_from_slice(&[1; 16]).unwrap();
        cipher
            .decrypt(
                Nonce::from_slice(&[2; 12]),
                Payload {
                    msg: bytes,
                    aad: aad.unwrap_or_default().as_bytes(),
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

    #[async_trait]
    impl KeyProvider for TestKeyProvider {
        type Cipher = Aes128Gcm;

        async fn decrypt_data_key(
            &self,
            encrypted_key: &[u8],
            aad: Option<&str>,
        ) -> Result<Key<Aes128Gcm>, KeyDecryptionError> {
            self.decrypt_counter.fetch_add(1, Ordering::Relaxed);
            Ok(Key::<Aes128>::clone_from_slice(&test_decrypt_bytes(
                encrypted_key,
                aad,
            )))
        }

        async fn generate_data_key(
            &self,
            _bytes_to_encrypt: usize,
            aad: Option<&str>,
        ) -> Result<DataKey<Aes128Gcm>, KeyGenerationError> {
            let count = self.generate_counter.fetch_add(1, Ordering::Relaxed);
            // Generate a data key that is just the current count for all bytes
            let key = Key::<Aes128>::clone_from_slice(&[count; 16]);
            let encrypted_key = test_encrypt_bytes(&key, aad);
            Ok(DataKey {
                key,
                encrypted_key,
                key_id: "test".into(),
            })
        }
    }

    fn create_test_cache() -> CachingKeyWrapper<Aes128Gcm, TestKeyProvider> {
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

        assert!(cache.generate_data_key(10, None).await.is_ok());

        assert_eq!(cache.provider.get_generate_count(), 1);

        assert!(cache.generate_data_key(10, None).await.is_ok());

        // Not incremented because cache was used
        assert_eq!(cache.provider.get_generate_count(), 1);

        // with aad
        assert!(cache.generate_data_key(10, Some("abcde")).await.is_ok());

        // Should increment because aad is different
        assert_eq!(cache.provider.get_generate_count(), 2);

        assert!(cache.generate_data_key(10, Some("abcde")).await.is_ok());

        // Not incremented because cache was used
        assert_eq!(cache.provider.get_generate_count(), 2);
    }

    #[tokio::test]
    async fn test_generate_expires_after_10_messages() {
        let cache = create_test_cache();

        assert_eq!(cache.provider.get_generate_count(), 0);

        assert!(cache.generate_data_key(1, None).await.is_ok());

        assert_eq!(cache.provider.get_generate_count(), 1);

        for _ in 0..9 {
            assert!(cache.generate_data_key(1, None).await.is_ok());
        }

        assert_eq!(cache.provider.get_generate_count(), 1);

        assert!(cache.generate_data_key(1, None).await.is_ok());

        // Incremented because 11th message needed new data key
        assert_eq!(cache.provider.get_generate_count(), 2);
    }

    #[tokio::test]
    async fn test_generate_expires_after_100_bytes() {
        let cache = create_test_cache();

        assert_eq!(cache.provider.get_generate_count(), 0);

        assert!(cache.generate_data_key(10, None).await.is_ok()); // 10
        assert!(cache.generate_data_key(30, None).await.is_ok()); // 40
        assert!(cache.generate_data_key(60, None).await.is_ok()); // 100

        assert_eq!(cache.provider.get_generate_count(), 1);

        assert!(cache.generate_data_key(1, None).await.is_ok()); // 101

        assert_eq!(cache.provider.get_generate_count(), 2);
    }

    #[tokio::test]
    async fn test_generate_expires_after_10_ms() {
        let cache = create_test_cache();

        assert_eq!(cache.provider.get_generate_count(), 0);

        assert!(cache.generate_data_key(10, None).await.is_ok());
        assert_eq!(cache.provider.get_generate_count(), 1);

        std::thread::sleep(Duration::from_millis(8));

        assert_eq!(cache.provider.get_generate_count(), 1);

        std::thread::sleep(Duration::from_millis(8));

        assert!(cache.generate_data_key(10, None).await.is_ok());
        assert_eq!(cache.provider.get_generate_count(), 2);
    }

    #[tokio::test]
    async fn test_generate_caches_for_decrypt() {
        let cache = create_test_cache();

        assert_eq!(cache.provider.get_generate_count(), 0);

        let data_key = cache
            .generate_data_key(10, None)
            .await
            .expect("Expected generate to succeed");

        assert_eq!(cache.provider.get_generate_count(), 1);

        assert!(cache
            .decrypt_data_key(&data_key.encrypted_key, None)
            .await
            .is_ok());

        // No keys were decrypted because they were in the cache
        assert_eq!(cache.provider.get_decrypt_count(), 0);
    }

    #[tokio::test]
    async fn test_caches_decryption() {
        let cache = create_test_cache();

        let key: Key<Aes128> = Key::<Aes128>::clone_from_slice(&[1; 16]);

        assert!(cache
            .decrypt_data_key(&test_encrypt_bytes(&key, None), None)
            .await
            .is_ok());

        assert_eq!(cache.provider.get_decrypt_count(), 1);

        assert!(cache
            .decrypt_data_key(&test_encrypt_bytes(&key, None), None)
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

        let key: Key<Aes128> = Key::<Aes128>::clone_from_slice(&[1; 16]);

        assert!(cache
            .decrypt_data_key(&test_encrypt_bytes(&key, None), None)
            .await
            .is_ok());

        assert_eq!(cache.provider.get_decrypt_count(), 1);

        std::thread::sleep(Duration::from_millis(8));

        assert!(cache
            .decrypt_data_key(&test_encrypt_bytes(&key, None), None)
            .await
            .is_ok());

        assert_eq!(cache.provider.get_decrypt_count(), 1);

        std::thread::sleep(Duration::from_millis(8));

        assert!(cache
            .decrypt_data_key(&test_encrypt_bytes(&key, None), None)
            .await
            .is_ok());

        // Time is past 10ms so it refetches
        assert_eq!(cache.provider.get_decrypt_count(), 2);
    }
}
