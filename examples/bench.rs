extern crate rand;
extern crate zktx;

use rand::{Rng, thread_rng};
use zktx::base::*;
use zktx::b2c::b2c_info;
use zktx::b2c::b2c_verify;
use zktx::c2b::c2b_info;
use zktx::c2b::c2b_verify;
use zktx::p2c::p2c_info;
use zktx::p2c::p2c_verify;
use zktx::common_verify::range::range_info;
use zktx::common_verify::range::range_verify;

fn test_b2c(samples:u32) {
    println!("test_b2c");

    use std::time::{Duration, Instant};
    let mut total = Duration::new(0, 0);
    let mut total2 = Duration::new(0, 0);

    println!("Creating {} proofs and averaging the time spent creating them.", samples);

    let rng = &mut thread_rng();

    for _ in 0..samples {
        let rcm = [rng.gen(),rng.gen()];
        //从addr0出钱给addr1
        let addr_sk0 = zktx::sk2str((0..ADSK).map(|_| rng.gen()).collect::<Vec<bool>>());
        let addr0 = address(addr_sk0.clone());
        let addr_sk1 = zktx::sk2str((0..ADSK).map(|_| rng.gen()).collect::<Vec<bool>>());
        let addr1 = address(addr_sk1.clone());
        let random:[u64;4] = [rng.gen(),rng.gen(),rng.gen(),rng.gen()];
        let va:[u64;2] = [10,0];
        let now = Instant::now();
        let (proof, coin,enc) = b2c_info(rcm, va, addr1,addr_sk0,random).unwrap();
//        println!("H_B   = {:?}", bn);
//        println!("coin  = {:?}", coin);
//        println!("proof  = {:?}", proof);
        total += now.elapsed();

        let now = Instant::now();
        let res = b2c_verify(va, coin, enc,addr0,proof).unwrap();
        total2 += now.elapsed();
        assert!(res);
    }
    println!("average proving time: {:?}", total / samples);
    println!("average verifying time: {:?}", total2 / samples);
}

fn test_c2b(samples:u32){
    println!("test_c2b");

    use std::time::{Duration,Instant};
    let mut total = Duration::new(0, 0);
    let mut total2 = Duration::new(0, 0);

    println!("Creating {} proofs and averaging the time spent creating them.", samples);

    for _ in 0..samples{
        let rng = &mut thread_rng();
        let rcm :[u64;2]= [rng.gen(),rng.gen()];
        let addr_sk = zktx::sk2str((0..ADSK).map(|_| rng.gen()).collect::<Vec<bool>>());
        let ba :[u64;2]= [1000,0];
        let va :[u64;2]= [10,0];
        let path = (0..TREEDEPTH).map(|_| {
            let mut v:[u64;4] = [0;4];
            for i in 0..4{
                v[i] = rng.gen();
            }
            zktx::u6442str(v)
        }).collect();
        let locs = (0..TREEDEPTH).map(|_| rng.gen()).collect::<Vec<bool>>();
        let now = Instant::now();
        let (proof,nullifier,root) = c2b_info(rcm,ba,va,addr_sk,path,locs).unwrap();
//        println!("H_B   = {:?}",bn);
//        println!("nullifier  = {:?}",nullifier);
//        println!("root = {:?}",root);
//        println!("proof  = {:?}", proof);
        total += now.elapsed();

        let now = Instant::now();
        let res = c2b_verify(ba,va,nullifier,root,proof).unwrap();
        total2 += now.elapsed();
        assert!(res);
    }
    println!("average proving time: {:?}", total / samples);
    println!("average verifying time: {:?}", total2 / samples);
}

fn test_c2p(samples:u32){
    println!("test_c2p");
    use zktx::c2p::*;
    use zktx::{pedersen_hash,pedersen_hash_root};

    use std::time::{Duration,Instant};
    let mut total = Duration::new(0, 0);
    let mut total2 = Duration::new(0, 0);

    println!("Creating {} proofs and averaging the time spent creating them.", samples);

    for _ in 0..samples{
        //倒序：359=101100111 -> [1,1,1,0,0,1,1,0,1]
        let rng = &mut thread_rng();
        let rcm :[u64;2]= [rng.gen(),rng.gen()];
        let rcm_new:[u64;2]=[rng.gen(),rng.gen()];
        let addr_sk = zktx::sk2str((0..ADSK).map(|_| rng.gen()).collect::<Vec<bool>>());
        let va :[u64;2]= [10,0];
        let path:Vec<String> = (0..TREEDEPTH).map(|_| {
            let mut v:[u64;4] = [0;4];
            for i in 0..4{
                v[i] = rng.gen();
            }
            zktx::u6442str(v)
        }).collect();
        let locs:Vec<bool> = (0..TREEDEPTH).map(|_| rng.gen()).collect::<Vec<bool>>();
        let coin = pedersen_hash({
            let addr = zktx::str2point(address(addr_sk.clone())).0;
            let mut v = Vec::with_capacity(256);
            for num in addr.into_iter(){
                let mut num = *num;
                for _ in 0..64{
                    v.push(num&1==1);
                    num>>=1;
                }
            }
            let addr = v;
            let mut node = Vec::with_capacity(256);
            for num in rcm.into_iter(){
                let mut num = *num;
                for _ in 0..64{
                    node.push(num&1==1);
                    num>>=1;
                }
            }
            let mut va = [false;128];
            va[1]=true;
            va[3]=true;//10
            for b in va.iter(){
                node.push(*b);
            }
            for b in addr.iter(){
                node.push(*b);
            }
            node
        }.as_slice());
        let path2 = path.clone();
        let loc2 = locs.clone();
        let now = Instant::now();
        let (proof,nullifier,_root,delt_ba) = c2p_info(rcm,rcm_new,va,addr_sk,path,locs).unwrap();
//        println!("H_B   = {:?}",hb);
//        println!("nullifier  = {:?}",nullifier);
//        println!("H_B-n = {:?}",hbn);
//        println!("root = {:?}",root);
//        println!("proof  = {:?}", proof);
        total += now.elapsed();

        let root = {
            let mut root = coin;
            for i in 0..TREEDEPTH{
                if loc2[i]{
                    root = pedersen_hash_root(zktx::str2u644(path2[i].clone()), root);
                }else{
                    root = pedersen_hash_root(root, zktx::str2u644(path2[i].clone()));
                }
            }
            root
        };

        let now = Instant::now();
        let res = c2p_verify(nullifier,zktx::u6442str(root),delt_ba,proof).unwrap();
        total2 += now.elapsed();
        assert!(res);
    }
    println!("average proving time: {:?}", total / samples);
    println!("average verifying time: {:?}", total2 / samples);
}

fn test_p2c(samples:u32){
    println!("test_p2c");

    use std::time::{Duration,Instant};
    let mut total = Duration::new(0, 0);
    let mut total2 = Duration::new(0, 0);

    println!("Creating {} proofs and averaging the time spent creating them.", samples);

    for _ in 0..samples{
        //倒序：359=101100111 -> [1,1,1,0,0,1,1,0,1]
        let rng = &mut thread_rng();
        let rh:[u64;4] = [rng.gen(),rng.gen(),rng.gen(),0];
        let rcm :[u64;2]= [rng.gen(),rng.gen()];
        //从addr0出钱给addr1
        let addr_sk0 = zktx::sk2str((0..ADSK).map(|_| rng.gen()).collect::<Vec<bool>>());
        let addr0 = address(addr_sk0.clone());
        let addr_sk1 = zktx::sk2str((0..ADSK).map(|_| rng.gen()).collect::<Vec<bool>>());
        let addr1 = address(addr_sk1.clone());
        let random:[u64;4] = [rng.gen(),rng.gen(),rng.gen(),rng.gen()];
        let ba :[u64;2]= [1000,0];
        let va :[u64;2]= [10,0];
        let now = Instant::now();
        let (proof,hb,coin,delt_ba,enc) = p2c_info(rh,rcm,ba,va,addr1,addr_sk0,random).unwrap();
//        println!("H_B   = {:?}",hb);
//        println!("coin  = {:?}",coin);
//        println!("H_B-n = {:?}",hbn);
//        println!("proof  = {:?}", proof);
        total += now.elapsed();

        let now = Instant::now();
        let res = p2c_verify(hb,coin,delt_ba,enc,addr0,proof).unwrap();
        total2 += now.elapsed();
        assert!(res);
    }
    println!("average proving time: {:?}", total / samples);
    println!("average verifying time: {:?}", total2 / samples);
}

fn test_range(){
    const SAMPLES:usize = 12;
    println!("test_range");

    use std::time::{Duration,Instant};
    let mut total = Duration::new(0, 0);
    let mut total2 = Duration::new(0, 0);

    println!("Creating {} proofs and averaging the time spent creating them.", SAMPLES);

    let up : [([u64;2],bool); SAMPLES] = [([20,0], true),([20,0], true),([20,0], true),([10,0],false),([20,0], true),([20,0], true),([20,0], true),([20,0], true),([20,0], true),([10,0],false),([10,0],false),([10,0],false)];
    let va : [([u64;2],bool); SAMPLES] = [([10,0], true),([10,0], true),([10,0],false),([15,0],false),([30,0], true),([ 5,0], true),([ 5,0],false),([15,0],false),([25,0], true),([25,0],false),([ 5,0],false),([ 5,0], true)];
    let low :[([u64;2],bool); SAMPLES] = [([ 5,0], true),([ 5,0],false),([20,0],false),([20,0],false),([10,0], true),([10,0], true),([10,0], true),([ 5,0],false),([ 5,0],false),([20,0],false),([20,0],false),([20,0],false)];
    let expres :       [bool; SAMPLES] = [         true ,         true ,         true ,         true ,        false ,        false ,        false ,        false ,        false ,        false ,        false ,        false ];

    let rng = &mut thread_rng();
    for i in 0..SAMPLES {
        let now = Instant::now();
        let up :([u64;2],bool)= up[i];
        let va :([u64;2],bool)= va[i];
        let rh :[u64;2]= [rng.gen(),rng.gen()];
        let low :([u64;2],bool)= low[i];
        let (proof,hv) = range_info(up,va,rh,low).unwrap();
        total += now.elapsed();

        let now = Instant::now();
        let res = range_verify(up,hv,low,proof).unwrap();
        total2 += now.elapsed();
        assert_eq!(res,expres[i]);
    }
    println!("average proving time: {:?}", total / SAMPLES as u32);
    println!("average verifying time: {:?}", total2 / SAMPLES as u32);
}

fn main(){
    zktx::set_param_path("PARAMS");
    test_range();
    test_b2c(10);
    test_p2c(10);
    test_c2b(5);
    test_c2p(5);
}
