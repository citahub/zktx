use pairing::bls12_381::{Fr, FrRepr};
use pairing::{Field, PrimeField};
use rand::{SeedableRng, XorShiftRng};
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Mutex;

use jubjub::*;

pub const VBIT: usize = 128;
pub const RHBIT: usize = 256;
pub const RCMBIT: usize = 128;
pub const PHOUT: usize = 256;
pub const PHIN: usize = 512;
pub const ADSK: usize = 256;
pub const TREEDEPTH: usize = 60;

lazy_static! {
    pub static ref PARAMPATH: Mutex<String> = Mutex::new("PARAMS".to_string());
}

pub fn set_param_path(path: &str) {
    *PARAMPATH.lock().unwrap() = path.to_string();
}

pub(crate) fn generator_path() -> PathBuf {
    let param_path = PARAMPATH.lock().unwrap().to_owned();
    Path::new(&param_path).join("generators")
}

pub(crate) fn c2b_param_path() -> PathBuf {
    let param_path = PARAMPATH.lock().unwrap().to_owned();
    Path::new(&param_path).join("c2bparams")
}

pub(crate) fn p2c_param_path() -> PathBuf {
    let param_path = PARAMPATH.lock().unwrap().to_owned();
    Path::new(&param_path).join("p2cparams")
}

pub(crate) fn b2c_param_path() -> PathBuf {
    let param_path = PARAMPATH.lock().unwrap().to_owned();
    Path::new(&param_path).join("b2cparams")
}

pub(crate) fn c2p_param_path() -> PathBuf {
    let param_path = PARAMPATH.lock().unwrap().to_owned();
    Path::new(&param_path).join("c2pparams")
}

pub(crate) fn range_param_path() -> PathBuf {
    let param_path = PARAMPATH.lock().unwrap().to_owned();
    Path::new(&param_path).join("rangeparams")
}

use super::convert::*;

pub(crate) fn gen_ph_generator() {
    let generator_path = generator_path();
    let generator_path = generator_path.to_str().unwrap();

    const SEED: [u32; 4] = [0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654];
    let mut generator_rng = XorShiftRng::from_seed(SEED);
    let generators = generate_constant_table(&mut generator_rng, &JubJub::new());
    drop(generator_rng);

    let mut writer = File::create(generator_path).unwrap();

    for tup in generators.iter() {
        match tup {
            &(ref frxs, ref frys) => {
                for x in frxs.iter() {
                    for unit in x.serial().iter() {
                        writer.write_all(&u64to8(*unit)).unwrap();
                    }
                }
                for y in frys.iter() {
                    for unit in y.serial().iter() {
                        writer.write_all(&u64to8(*unit)).unwrap();
                    }
                }
            }
        }
    }
}

pub(crate) fn ph_generator() -> Vec<(Vec<Fr>, Vec<Fr>)> {
    let generator_path = generator_path();
    let generator_path = generator_path.to_str().unwrap();

    let mut reader = File::open(generator_path).unwrap();

    let mut serial = vec![];
    for _ in 0..128 {
        let mut xs = vec![];
        let mut ys = vec![];
        for _ in 0..16 {
            let mut nums: [u64; 4] = [0; 4];
            for i in 0..4 {
                let mut num: [u8; 8] = [0; 8];
                reader.read(&mut num).unwrap();
                nums[i] = u8to64(num);
            }
            xs.push(Fr::from_serial(nums));
        }
        for _ in 0..16 {
            let mut nums: [u64; 4] = [0; 4];
            for i in 0..4 {
                let mut num: [u8; 8] = [0; 8];
                reader.read(&mut num).unwrap();
                nums[i] = u8to64(num);
            }
            ys.push(Fr::from_serial(nums));
        }
        serial.push((xs, ys));
    }
    serial
}

pub fn address(addr_sk: String) -> String {
    let addr_sk = str2sk(addr_sk);
    assert_eq!(addr_sk.len(), ADSK);
    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]); //TODO:choose the seed
    let j = JubJub::new();
    let (mut xp, mut yp) = Point::rand(&mut rng, &j).coordinate();
    let mut x0 = Fr::zero();
    let mut y0 = Fr::one();

    for i in 0..addr_sk.len() {
        if addr_sk[i] {
            let res = point_add(&x0, &y0, &xp, &yp, &j);
            x0 = res.0;
            y0 = res.1;
        }
        if i != addr_sk.len() - 1 {
            let res = point_double(xp, yp, &j);
            xp = res.0;
            yp = res.1;
        }
    }

    point2str((x0.into_repr().serial(), y0.into_repr().serial()))
}

fn point_double(x: Fr, y: Fr, j: &JubJub) -> (Fr, Fr) {
    point_add(&x, &y, &x, &y, j)
}

fn point_add(x0: &Fr, y0: &Fr, xp: &Fr, yp: &Fr, j: &JubJub) -> (Fr, Fr) {
    let mut y1y2 = y0.clone();
    y1y2.mul_assign(yp);
    let mut x1x2 = x0.clone();
    x1x2.mul_assign(xp);
    let mut dx1x2y1y2 = j.d;
    dx1x2y1y2.mul_assign(&y1y2);
    dx1x2y1y2.mul_assign(&x1x2);

    let mut d1 = dx1x2y1y2;
    d1.add_assign(&Fr::one());
    d1 = d1.inverse().unwrap();

    let mut d2 = dx1x2y1y2;
    d2.negate();
    d2.add_assign(&Fr::one());
    d2 = d2.inverse().unwrap();

    let mut x1y2 = x0.clone();
    x1y2.mul_assign(yp);

    let mut y1x2 = y0.clone();
    y1x2.mul_assign(xp);

    let mut x = x1y2;
    x.add_assign(&y1x2);
    x.mul_assign(&d1);

    let mut y = y1y2;
    y.add_assign(&x1x2);
    y.mul_assign(&d2);

    (x.clone(), y.clone())
}

pub fn ecc_add(point1: String, point2: String) -> String {
    let point1 = str2point(point1);
    let point2 = str2point(point2);
    let (xfr, yfr) = point_add(
        &Fr::from_repr(FrRepr::from_serial(point1.0)).unwrap(),
        &Fr::from_repr(FrRepr::from_serial(point1.1)).unwrap(),
        &Fr::from_repr(FrRepr::from_serial(point2.0)).unwrap(),
        &Fr::from_repr(FrRepr::from_serial(point2.1)).unwrap(),
        &JubJub::new(),
    );
    let x = xfr.into_repr().serial();
    let y = yfr.into_repr().serial();
    point2str((x, y))
}

pub fn ecc_sub(point1: String, point2: String) -> String {
    let point1 = str2point(point1);
    let point2 = str2point(point2);
    let mut temp = Fr::from_repr(FrRepr::from_serial(point2.0)).unwrap();
    temp.negate();
    let (xfr, yfr) = point_add(
        &Fr::from_repr(FrRepr::from_serial(point1.0)).unwrap(),
        &Fr::from_repr(FrRepr::from_serial(point1.1)).unwrap(),
        &temp,
        &Fr::from_repr(FrRepr::from_serial(point2.1)).unwrap(),
        &JubJub::new(),
    );
    let x = xfr.into_repr().serial();
    let y = yfr.into_repr().serial();
    point2str((x, y))
}

pub fn v_p1_add_r_p2(v: [u64; 2], r: [u64; 2]) -> String {
    let v = {
        let mut vec = Vec::with_capacity(128);
        let mut num = v[0];
        for _ in 0..64 {
            vec.push(num & 1 == 1);
            num >>= 1;
        }
        let mut num = v[1];
        for _ in 0..64 {
            vec.push(num & 1 == 1);
            num >>= 1;
        }
        vec
    };
    let r = {
        let mut vec = Vec::with_capacity(128);
        let mut num = r[0];
        for _ in 0..64 {
            vec.push(num & 1 == 1);
            num >>= 1;
        }
        let mut num = r[1];
        for _ in 0..64 {
            vec.push(num & 1 == 1);
            num >>= 1;
        }
        vec
    };

    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]); //TODO:choose the seed
    let j = JubJub::new();

    let (mut xp, mut yp) = Point::rand(&mut rng, &j).coordinate();
    let mut x0 = Fr::zero();
    let mut y0 = Fr::one();

    for i in 0..v.len() {
        if v[i] {
            let res = point_add(&x0, &y0, &xp, &yp, &j);
            x0 = res.0;
            y0 = res.1;
        }
        if i != v.len() - 1 {
            let res = point_double(xp, yp, &j);
            xp = res.0;
            yp = res.1;
        }
    }

    let (mut xp, mut yp) = Point::rand(&mut rng, &j).coordinate();
    for i in 0..r.len() {
        if r[i] {
            let res = point_add(&x0, &y0, &xp, &yp, &j);
            x0 = res.0;
            y0 = res.1;
        }
        if i != r.len() - 1 {
            let res = point_double(xp, yp, &j);
            xp = res.0;
            yp = res.1;
        }
    }

    point2str((x0.into_repr().serial(), y0.into_repr().serial()))
}

fn point_mul(point: ([u64; 4], [u64; 4]), num: Vec<bool>) -> (Fr, Fr) {
    let (mut xp, mut yp) = (
        Fr::from_repr(FrRepr::from_serial(point.0)).unwrap(),
        Fr::from_repr(FrRepr::from_serial(point.1)).unwrap(),
    );
    let mut x0 = Fr::zero();
    let mut y0 = Fr::one();
    let j = JubJub::new();

    for i in 0..num.len() {
        if num[i] {
            let res = point_add(&x0, &y0, &xp, &yp, &j);
            x0 = res.0;
            y0 = res.1;
        }
        if i != num.len() - 1 {
            let res = point_double(xp, yp, &j);
            xp = res.0;
            yp = res.1;
        }
    }

    (x0, y0)
}

pub fn encrypt(message: [u64; 4], random: [u64; 4], address: String) -> String {
    let address = str2point(address);
    let random = Fr::from_serial(random).into_repr().serial();
    let random = {
        let mut v = vec![];
        for i in 0..4 {
            let mut num = random[i];
            for _ in 0..64 {
                v.push(num & 1 == 1);
                num >>= 1;
            }
        }
        v
    };
    let rq = point_mul(address, random.clone());
    let mut enc = Fr::from_repr(FrRepr::from_serial(message)).unwrap();
    enc.add_assign(&rq.0);

    let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]); //TODO:choose the seed
    let j = JubJub::new();
    let (mut xp, mut yp) = Point::rand(&mut rng, &j).coordinate();
    let mut x0 = Fr::zero();
    let mut y0 = Fr::one();
    for i in 0..random.len() {
        if random[i] {
            let res = point_add(&x0, &y0, &xp, &yp, &j);
            x0 = res.0;
            y0 = res.1;
        }
        if i != random.len() - 1 {
            let res = point_double(xp, yp, &j);
            xp = res.0;
            yp = res.1;
        }
    }

    enc2str((
        x0.into_repr().serial(),
        y0.into_repr().serial(),
        enc.into_repr().serial(),
    ))
}

pub fn decrypt(secret: String, sk: String) -> ([u64; 2], [u64; 2]) {
    let sk = str2sk(sk);
    let secret = str2enc(secret);
    let rqx = point_mul((secret.0, secret.1), sk).0;
    let mut message = Fr::from_repr(FrRepr::from_serial(secret.2)).unwrap();
    message.sub_assign(&rqx);
    let message = message.into_repr().serial();
    let va = [message[2], message[3]];
    let rcm = [message[0], message[1]];
    (va, rcm)
}

pub fn u644add(num1: [u64; 4], num2: [u64; 4]) -> [u64; 4] {
    let mut fr1 = Fr::from_repr(FrRepr::from_serial(num1)).unwrap();
    let fr2 = Fr::from_repr(FrRepr::from_serial(num2)).unwrap();
    fr1.add_assign(&fr2);
    fr1.into_repr().serial()
}

pub fn u644sub(num1: [u64; 4], num2: [u64; 4]) -> [u64; 4] {
    let mut fr1 = Fr::from_repr(FrRepr::from_serial(num1)).unwrap();
    let fr2 = Fr::from_repr(FrRepr::from_serial(num2)).unwrap();
    fr1.sub_assign(&fr2);
    fr1.into_repr().serial()
}

pub fn check(coin: String, enc: String, sk: String) -> bool {
    let (va, rcm) = decrypt(enc, sk.clone());
    let coin2 = super::build_coin(address(sk), va, rcm);
    coin2 == coin
}
