extern crate bellman;
extern crate jubjub;
extern crate pairing;
extern crate rand;
#[macro_use]
extern crate lazy_static;

pub mod base;

pub mod b2c;

pub mod c2b;

pub mod c2p;

pub mod p2c;

pub mod common_verify;

pub mod contract;

pub mod incrementalmerkletree;

pub mod pedersen;

pub mod convert;

pub use convert::{sk2str, str2point, str2u644, str2value, u6442str};

pub fn pedersen_hash(bits: &[bool]) -> [u64; 4] {
    assert_eq!(bits.len(), base::PHIN);
    jubjub::pedersen_hash_real(bits, &base::ph_generator())
        .unwrap()
        .serial()
}

pub fn build_coin(address: String, va: [u64; 2], rcm: [u64; 2]) -> String {
    let coin = pedersen_hash(
        {
            let addr = str2point(address).0;
            let mut v = Vec::with_capacity(256);
            for num in addr.into_iter() {
                let mut num = *num;
                for _ in 0..64 {
                    v.push(num & 1 == 1);
                    num >>= 1;
                }
            }
            let addr = v;
            let mut node = Vec::with_capacity(256);
            for num in rcm.into_iter() {
                let mut num = *num;
                for _ in 0..64 {
                    node.push(num & 1 == 1);
                    num >>= 1;
                }
            }
            for num in va.into_iter() {
                let mut num = *num;
                for _ in 0..64 {
                    node.push(num & 1 == 1);
                    num >>= 1;
                }
            }
            for b in addr.iter() {
                node.push(*b);
            }
            node
        }
        .as_slice(),
    );
    u6442str(coin)
}

pub fn pedersen_hash_root(c0: [u64; 4], c1: [u64; 4]) -> [u64; 4] {
    let mut v = Vec::with_capacity(512);
    for num in c0.into_iter() {
        let mut num = *num;
        for _ in 0..64 {
            v.push(num & 1 == 1);
            num >>= 1;
        }
    }
    for num in c1.into_iter() {
        let mut num = *num;
        for _ in 0..64 {
            v.push(num & 1 == 1);
            num >>= 1;
        }
    }
    jubjub::pedersen_hash_real(v.as_slice(), &base::ph_generator())
        .unwrap()
        .serial()
}

use b2c::gen_b2c_param;
use base::gen_ph_generator;
pub use base::set_param_path;
use c2b::gen_c2b_param;
use c2p::gen_c2p_param;
use common_verify::range::gen_range_param;
use p2c::gen_p2c_param;

pub fn gen_params(path: &str) {
    use std::fs::{create_dir, remove_dir_all};
    use std::path::Path;

    {
        let path = Path::new(path);
        if path.exists() {
            remove_dir_all(path).unwrap();
        }
        create_dir(path).unwrap();
    }

    set_param_path(path);
    gen_ph_generator();
    gen_b2c_param();
    gen_c2b_param();
    gen_c2p_param();
    gen_p2c_param();
    gen_range_param();
}
