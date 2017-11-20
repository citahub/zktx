extern crate rand;
extern crate zktx;

use rand::{Rng, thread_rng};
use zktx::base::*;
use zktx::b2c::*;
use zktx::c2b::*;
use zktx::p2c::*;
use zktx::c2p::*;
use zktx::*;

use std::env;
use std::u64;

fn main(){
    let mut argv:Vec<String> = vec![];
    for arg in env::args(){
        argv.push(arg);
    }
    let func:&str = argv[1].as_ref();
    let mut nums = vec![];
    for arg in argv.iter().skip(2){
        let num:u64 = arg.trim().parse().unwrap();
        nums.push(num);
    }

    let res = match func{
        "v_p1_add_r_p2"=>{
            v_p1_add_r_p2(nums)
        },
        "encrypt"=>{
            encrypt(nums)
        },
        "decrypt"=>{
            decrypt(nums)
        }
        _=>{
            let mut v = vec![];
            v.push(0 as u64);
            v
        }
    };

    for num in res.iter(){
        print!("{} ",num);
    }
    print!("\n");
}

fn v_p1_add_r_p2(nums:Vec<u64>)->Vec<u64>{
    assert_eq!(nums.len(),4);
    let res = base::v_p1_add_r_p2([nums[0],nums[1]],[nums[2],nums[3]]);
    {
        let mut v = vec![];
        for i in 0..4{
            v.push(res.0[i]);
        }
        for i in 0..4{
            v.push(res.1[i]);
        }
        v
    }
}

fn encrypt(nums:Vec<u64>)->Vec<u64>{
    assert_eq!(nums.len(),16);
    let res = base::encrypt([nums[0],nums[1],nums[2],nums[3]],[nums[4],nums[5],nums[6],nums[7]],
                            ([nums[8],nums[9],nums[10],nums[11]],[nums[12],nums[13],nums[14],nums[15]]));
    {
        let mut v = vec![];
        for i in 0..4{
            v.push(res.0[i]);
        }
        for i in 0..4{
            v.push((res.1).0[i]);
        }
        for i in 0..4{
            v.push((res.1).1[i]);
        }
        v
    }
}

fn decrypt(nums:Vec<u64>)->Vec<u64>{
    assert_eq!(nums.len(),16);
    let sk:Vec<bool> = {
        let mut v = vec![];
        for i in 12..16{
            let mut num = nums[i];
            for _ in 0..64{
                v.push(num&1==1);
                num>>=1;
            }
        }
        v
    };
    let res = base::decrypt([nums[0],nums[1],nums[2],nums[3]],([nums[4],nums[5],nums[6],nums[7]],[nums[8],nums[9],nums[10],nums[11]]),sk);
    {
        let mut v = vec![];
        for i in 0..4{
            v.push(res.0[i]);
        }
        for i in 0..4{
            v.push(res.1[i]);
        }
        v
    }
}

fn address(nums:Vec<u64>)->Vec<u64>{
    assert_eq!(nums.len(),4);
    let sk:Vec<bool> = {
        let mut v = vec![];
        for i in 0..4{
            let mut num = nums[i];
            for _ in 0..64{
                v.push(num&1==1);
                num>>=1;
            }
        }
        v
    };
    let res = base::address(&sk);
    {
        let mut v = vec![];
        for i in 0..4{
            v.push(res.0[i]);
        }
        for i in 0..4{
            v.push(res.1[i]);
        }
        v
    }
}