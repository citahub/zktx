use incrementalmerkletree::Hashable;
use super::pedersen_hash_root;
use rand::{Rng,SeedableRng,StdRng};

impl Hashable for PedersenDigest {
    fn combine(left: &Self, right: &Self) -> PedersenDigest {
        PedersenDigest(pedersen_hash_root(left.0.clone(), right.0.clone()))
    }

    fn blank() -> PedersenDigest {
        PedersenDigest([0, 0, 0, 0])
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct PedersenDigest(pub [u64; 4]);

impl PedersenDigest {
    pub fn rand(seed: usize) -> PedersenDigest {
        let seed: [usize; 1] = [seed];

        let mut rng = StdRng::from_seed(&seed);

        PedersenDigest([rng.gen(), rng.gen(), rng.gen(), rng.gen()])
    }
}
