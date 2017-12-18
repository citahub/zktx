extern crate hex;

#[inline(always)]
pub fn u64to8(mut num: u64) -> [u8; 8] {
    let mut out: [u8; 8] = [0; 8];
    for i in 0..8 {
        out[i] = (num & 0b11111111) as u8;
        num >>= 8;
    }
    out
}

#[inline(always)]
pub fn u8to64(nums: [u8; 8]) -> u64 {
    let mut res: u64 = 0;
    for i in 0..8 {
        res <<= 8;
        res |= nums[7 - i] as u64;
    }
    res
}

pub fn proof2str(proof:(([u64; 6], [u64; 6], bool),
                        (([u64; 6], [u64; 6]), ([u64; 6], [u64; 6]), bool),
                        ([u64; 6], [u64; 6], bool)))->String{
    let mut res = String::with_capacity(770);
    for i in 0..6{
        res.push_str(hex::encode(u64to8(((proof.0).0)[i]).as_ref()).as_ref());
    }
    for i in 0..6{
        res.push_str(hex::encode(u64to8(((proof.0).1)[i]).as_ref()).as_ref());
    }
    for i in 0..6{
        res.push_str(hex::encode(u64to8((((proof.1).0).0)[i]).as_ref()).as_ref());
    }
    for i in 0..6{
        res.push_str(hex::encode(u64to8((((proof.1).0).1)[i]).as_ref()).as_ref());
    }
    for i in 0..6{
        res.push_str(hex::encode(u64to8((((proof.1).1).0)[i]).as_ref()).as_ref());
    }
    for i in 0..6{
        res.push_str(hex::encode(u64to8((((proof.1).1).1)[i]).as_ref()).as_ref());
    }
    for i in 0..6{
        res.push_str(hex::encode(u64to8(((proof.2).0)[i]).as_ref()).as_ref());
    }
    for i in 0..6{
        res.push_str(hex::encode(u64to8(((proof.2).1)[i]).as_ref()).as_ref());
    }
    let mut b:u8 =0;
    if (proof.0).2 {b+=1;}
    b<<=1;
    if (proof.1).2 {b+=1;}
    b<<=1;
    if (proof.2).2 {b+=1;}
    res.push_str(hex::encode([b].as_ref()).as_ref());
    res
}

#[inline(always)]
pub fn u8sto64(nums: &[u8]) -> u64 {
    let mut res: u64 = 0;
    for i in 0..8 {
        res <<= 8;
        res |= nums[7 - i] as u64;
    }
    res
}
pub fn str2proof(serial:String)->(([u64; 6], [u64; 6], bool),
                                  (([u64; 6], [u64; 6]), ([u64; 6], [u64; 6]), bool),
                                  ([u64; 6], [u64; 6], bool)){
    let mut proof:(([u64; 6], [u64; 6], bool),
                   (([u64; 6], [u64; 6]), ([u64; 6], [u64; 6]), bool),
                   ([u64; 6], [u64; 6], bool)) =
        (([0; 6], [0; 6], false),
         (([0; 6], [0; 6]), ([0; 6], [0; 6]), false),
         ([0; 6], [0; 6], false));
    let v:Vec<u8> = hex::decode(serial).unwrap();
    for i in 0..6{
        ((proof.0).0)[i] = u8sto64(&v[i*8..(i+1)*8]);
    }
    for i in 6..12{
        ((proof.0).1)[i-6] = u8sto64(&v[i*8..(i+1)*8]);
    }
    for i in 12..18{
        (((proof.1).0).0)[i-12] = u8sto64(&v[i*8..(i+1)*8]);
    }
    for i in 18..24{
        (((proof.1).0).1)[i-18] = u8sto64(&v[i*8..(i+1)*8]);
    }
    for i in 24..30{
        (((proof.1).1).0)[i-24] = u8sto64(&v[i*8..(i+1)*8]);
    }
    for i in 30..36{
        (((proof.1).1).1)[i-30] = u8sto64(&v[i*8..(i+1)*8]);
    }
    for i in 36..42{
        ((proof.2).0)[i-36] = u8sto64(&v[i*8..(i+1)*8]);
    }
    for i in 42..48{
        ((proof.2).1)[i-42] = u8sto64(&v[i*8..(i+1)*8]);
    }
    let b =v[384];
    (proof.0).2 = b&0b00000100 != 0;
    (proof.1).2 = b&0b00000010 != 0;
    (proof.2).2 = b&0b00000001 != 0;
    proof
}

use std::num::ParseIntError;
pub fn str2value(st:String)->Result<([u64;2],bool),ParseIntError>{
    let st:&str = st.as_ref();
    let mut res:([u64;2],bool) = ([0;2],true);
    if st.get(0..1) == Some("-") {
        res.1 = false;
        res.0[0] = u64::from_str_radix(&st[1..],10)?;
    }else{
        res.0[0] = u64::from_str_radix(st,10)?;
    }
    Ok(res)
}

pub fn u6442str(u644:[u64;4]) ->String{
    let mut res = String::with_capacity(64);
    for i in 0..4{
        res.push_str(hex::encode(u64to8(u644[i]).as_ref()).as_ref());
    }
    res
}

pub fn str2u644(serial:String) ->[u64;4]{
    let mut coin:[u64;4] = [0;4];
    let v:Vec<u8> = hex::decode(serial).unwrap();
    for i in 0..4{
        coin[i] = u8sto64(&v[i*8..(i+1)*8]);
    }
    coin
}

pub fn point2str(point:([u64;4],[u64;4]))->String{
    let mut res = String::with_capacity(128);
    for i in 0..4{
        res.push_str(hex::encode(u64to8((point.0)[i]).as_ref()).as_ref());
    }
    for i in 0..4{
        res.push_str(hex::encode(u64to8((point.1)[i]).as_ref()).as_ref());
    }
    res
}

pub fn str2point(serial:String)->([u64;4],[u64;4]){
    let mut point:([u64;4],[u64;4]) = ([0;4],[0;4]);
    let v:Vec<u8> = hex::decode(serial).unwrap();
    for i in 0..4{
        (point.0)[i] = u8sto64(&v[i*8..(i+1)*8]);
    }
    for i in 4..8{
        (point.1)[i-4] = u8sto64(&v[i*8..(i+1)*8]);
    }
    point
}

pub fn enc2str(enc:([u64;4],[u64;4],[u64;4]))->String{
    let mut res = String::with_capacity(192);
    for i in 0..4{
        res.push_str(hex::encode(u64to8((enc.0)[i]).as_ref()).as_ref());
    }
    for i in 0..4{
        res.push_str(hex::encode(u64to8((enc.1)[i]).as_ref()).as_ref());
    }
    for i in 0..4{
        res.push_str(hex::encode(u64to8((enc.2)[i]).as_ref()).as_ref());
    }
    res
}

pub fn str2enc(serial:String)->([u64;4],[u64;4],[u64;4]){
    let mut enc:([u64;4],[u64;4],[u64;4]) = ([0;4],[0;4],[0;4]);
    let v:Vec<u8> = hex::decode(serial).unwrap();
    for i in 0..4{
        (enc.0)[i] = u8sto64(&v[i*8..(i+1)*8]);
    }
    for i in 4..8{
        (enc.1)[i-4] = u8sto64(&v[i*8..(i+1)*8]);
    }
    for i in 8..12{
        (enc.2)[i-8] = u8sto64(&v[i*8..(i+1)*8]);
    }
    enc
}

pub fn sk2str(sk:Vec<bool>)->String{
    assert_eq!(sk.len(),256);
    let mut u8s:Vec<u8> = Vec::with_capacity(32);
    for u in sk.chunks(8){
        let mut num:u8 = 0;
        for i in 0..8{
            num<<=1;
            num += {
                if u[i]{1}
                    else{0}
            };
        }
        u8s.push(num);
    }
    hex::encode(u8s)
}

pub fn str2sk(serial:String)->Vec<bool>{
    let serial:Vec<u8> = hex::decode(serial).unwrap();
    let mut res:Vec<bool> = Vec::with_capacity(256);
    for u in serial.iter(){
        let mut num = *u;
        for _ in 0..8{
            res.push(num & 0b10000000 == 0b10000000);
            num<<=1;
        }
    }
    res
}