use md5::{Digest, Md5};
use sha1::{Sha1};
use sha2::{Sha256};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    MD5,
    SHA1,
    SHA256
}

pub struct HashSignature {
    algorithm: HashAlgorithm,
    hash: Vec<u8>
}

impl HashSignature {
    fn from_hash(algorithm: HashAlgorithm, hash: Vec<u8>) -> Self {
        return Self { 
            hash,
            algorithm
        }
    }

    fn from_data(algorithm: HashAlgorithm, data: &[u8]) -> Self {
        let hash = match algorithm {
            HashAlgorithm::MD5 => {
                let hasher = Md5::new_with_prefix(&data);
                hasher.finalize().to_vec()
            },
            HashAlgorithm::SHA1 => {
                let hasher = Sha1::new_with_prefix(&data);
                hasher.finalize().to_vec()
            },
            HashAlgorithm::SHA256 => {
                let hasher = Sha256::new_with_prefix(&data);
                hasher.finalize().to_vec()
            }
        };
        
        Self {
            hash,
            algorithm
        }
    }

    fn get_hash(&self) -> &[u8] {
        self.hash.as_slice()
    }

    fn get_algorithm(&self) -> HashAlgorithm {
        self.algorithm.clone()
    }
}