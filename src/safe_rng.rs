use rand::{RngCore, SeedableRng};

pub trait SafeRng: SeedableRng + RngCore + Send {}

impl<T> SafeRng for T where T: SeedableRng + RngCore + Send {}
