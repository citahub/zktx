use bellman::groth16::*;
use pairing::*;
use pairing::bls12_381::{Fr, FrRepr, Bls12};
use bellman::*;
use rand::thread_rng;

use jubjub::*;

use base::*;
use convert::*;

use std::fs::File;
use std::path::Path;

struct P2Ccircuit<'a> {
    generators: &'a [(Vec<Fr>, Vec<Fr>)],
    j: &'a JubJub,

    //r_h
    rh: Assignment<Fr>,
    //r_cm
    rcm: Assignment<Fr>,
    //Balance
    ba: Assignment<Fr>,
    //value
    va: Assignment<Fr>,
    //addr
    addr: (Assignment<Fr>, Assignment<Fr>),
    //random number,
    random: Assignment<Fr>,
    //addr_sk
    addr_sk: Vec<Assignment<bool>>,
    //result
    res: &'a mut Vec<FrRepr>
}

impl<'a> P2Ccircuit<'a> {
    fn blank(
        generators: &'a [(Vec<Fr>, Vec<Fr>)],
        j: &'a JubJub,
        res: &'a mut Vec<FrRepr>
    ) -> P2Ccircuit<'a> {
        P2Ccircuit {
            generators,
            j,
            rh: Assignment::unknown(),
            rcm: Assignment::unknown(),
            ba: Assignment::unknown(),
            va: Assignment::unknown(),
            addr: (Assignment::unknown(), Assignment::unknown()),
            random: Assignment::unknown(),
            addr_sk: (0..ADSK).map(|_| Assignment::unknown()).collect(),
            res,
        }
    }
    fn new(
        generators: &'a [(Vec<Fr>, Vec<Fr>)],
        j: &'a JubJub,
        rh: Fr,
        rcm: Fr,
        ba: Fr,
        va: Fr,
        addr: (Fr, Fr),
        random: Fr,
        addr_sk: Vec<bool>,
        res: &'a mut Vec<FrRepr>
    ) -> P2Ccircuit<'a> {
        assert_eq!(res.len(), 0);
        P2Ccircuit {
            generators,
            j,
            rh: Assignment::known(rh),
            rcm: Assignment::known(rcm),
            ba: Assignment::known(ba),
            va: Assignment::known(va),
            addr: (Assignment::known(addr.0), Assignment::known(addr.1)),
            random: Assignment::known(random),
            addr_sk: addr_sk.iter().map(|&b| Assignment::known(b)).collect(),
            res,
        }
    }
}

struct P2CcircuitInput {
    //ba*P1+rh*P2
    hb: (Num<Bls12>, Num<Bls12>),
    //coin
    coin: Num<Bls12>,
    //delta_balance,
    delt_ba: (Num<Bls12>, Num<Bls12>),
    //rP
    rp: (Num<Bls12>, Num<Bls12>),
    //enc
    enc: Num<Bls12>,
    //addr
    addr: (Num<Bls12>, Num<Bls12>)
}

impl<'a> Input<Bls12> for P2CcircuitInput {
    fn synthesize<CS: PublicConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), Error> {
        let delt_x_input = cs.alloc_input(|| Ok(*self.delt_ba.0.getvalue().get()?))?;
        let delt_y_input = cs.alloc_input(|| Ok(*self.delt_ba.1.getvalue().get()?))?;
        let hb_x_input = cs.alloc_input(|| Ok(*self.hb.0.getvalue().get()?))?;
        let hb_y_input = cs.alloc_input(|| Ok(*self.hb.1.getvalue().get()?))?;
        let coin_input = cs.alloc_input(|| Ok(*self.coin.getvalue().get()?))?;
        let rpx_input = cs.alloc_input(|| Ok(*self.rp.0.getvalue().get()?))?;
        let rpy_input = cs.alloc_input(|| Ok(*self.rp.1.getvalue().get()?))?;
        let enc_input = cs.alloc_input(|| Ok(*self.enc.getvalue().get()?))?;
        let addrx_input = cs.alloc_input(|| Ok(*self.addr.0.getvalue().get()?))?;
        let addry_input = cs.alloc_input(|| Ok(*self.addr.1.getvalue().get()?))?;

        cs.enforce(
            LinearCombination::zero() + self.delt_ba.0.getvar(),
            LinearCombination::zero() + CS::one(),
            LinearCombination::zero() + delt_x_input,
        );
        cs.enforce(
            LinearCombination::zero() + self.delt_ba.1.getvar(),
            LinearCombination::zero() + CS::one(),
            LinearCombination::zero() + delt_y_input,
        );
        cs.enforce(
            LinearCombination::zero() + self.hb.0.getvar(),
            LinearCombination::zero() + CS::one(),
            LinearCombination::zero() + hb_x_input,
        );
        cs.enforce(
            LinearCombination::zero() + self.hb.1.getvar(),
            LinearCombination::zero() + CS::one(),
            LinearCombination::zero() + hb_y_input,
        );
        cs.enforce(
            LinearCombination::zero() + self.coin.getvar(),
            LinearCombination::zero() + CS::one(),
            LinearCombination::zero() + coin_input,
        );
        cs.enforce(
            LinearCombination::zero() + self.rp.0.getvar(),
            LinearCombination::zero() + CS::one(),
            LinearCombination::zero() + rpx_input,
        );
        cs.enforce(
            LinearCombination::zero() + self.rp.1.getvar(),
            LinearCombination::zero() + CS::one(),
            LinearCombination::zero() + rpy_input,
        );
        cs.enforce(
            LinearCombination::zero() + self.enc.getvar(),
            LinearCombination::zero() + CS::one(),
            LinearCombination::zero() + enc_input,
        );
        cs.enforce(
            LinearCombination::zero() + self.addr.0.getvar(),
            LinearCombination::zero() + CS::one(),
            LinearCombination::zero() + addrx_input,
        );
        cs.enforce(
            LinearCombination::zero() + self.addr.1.getvar(),
            LinearCombination::zero() + CS::one(),
            LinearCombination::zero() + addry_input,
        );

        Ok(())
    }
}

impl<'a> Circuit<Bls12> for P2Ccircuit<'a> {
    type InputMap = P2CcircuitInput;

    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<Self::InputMap, Error> {
        let rh_num = Num::new(cs, self.rh)?;
        let rh = rh_num.unpack_sized(cs, RHBIT)?;
        let rcm_num = Num::new(cs, self.rcm)?;
        let mut rcm = rcm_num.unpack_sized(cs, RCMBIT)?;
        let random_num = Num::new(cs, self.random)?;
        let random = random_num.unpack_sized(cs, 256)?;

        let addr_x_num = Num::new(cs, self.addr.0)?;
        let addr_x_bit = addr_x_num.unpack_sized(cs, PHOUT)?;
        let addr_y_num = Num::new(cs, self.addr.1)?;

        let bit_ba = Num::new(cs, self.ba)?.unpack_sized(cs, VBIT)?;
        let va = Num::new(cs, self.va)?;
        let bit_va = va.unpack_sized(cs, VBIT)?;
        assert_eq!(bit_ba.len(), VBIT);
        assert_eq!(bit_va.len(), VBIT);

        assert_nonless_than(&bit_ba, &bit_va, cs)?;

        //prepare table
        let p1 = Point::enc_point_table(256, 1, cs)?;
        let p2 = Point::enc_point_table(256, 2, cs)?;

        //ba*P1+rh*P2
        let hb = Point::encrypt((&p1, &p2), &bit_ba, &rh, cs)?;
        if let (Ok(x), Ok(y)) = (hb.0.getvalue().get(), hb.1.getvalue().get()) {
            self.res.push(x.into_repr());
            self.res.push(y.into_repr());
        }

        //coin = PH(addr|value|rcm)
        let rcm2 = rcm.clone();
        let vin = {
            for b in bit_va.iter() {
                rcm.push(*b);
            }
            for b in addr_x_bit.iter() {
                rcm.push(*b);
            }
            rcm
        };
        assert_eq!(vin.len(), PHIN);
        let coin = pedersen_hash(cs, &vin, self.generators, self.j)?;
        if let Ok(x) = coin.getvalue().get() {
            self.res.push(x.into_repr());
        }

        //delta_ba
        let rcm = rcm2;
        let p0 = Point::encrypt((&p1, &p2), &bit_va, &rcm, cs)?;
        if let (Ok(x), Ok(y)) = (p0.0.getvalue().get(), p0.1.getvalue().get()) {
            self.res.push(x.into_repr());
            self.res.push(y.into_repr());
        }
        let delt_ba = (p0.0, p0.1);

        //Enc
        let message = {
            let b128 =
                Num::new(
                    cs,
                    Assignment::known(Fr::from_repr(FrRepr::from_serial([0, 0, 1, 0])).unwrap()),
                )?;
            va.mul(cs, &b128)?.add(cs, &rcm_num)
        }?;
        let qtable = Point::point_mul_table((&addr_x_num, &addr_y_num), 256, cs)?;
        let rp = Point::multiply(&p1, &random, cs)?;
        let rq = Point::multiply(&qtable, &random, cs)?;
        if let (Ok(x), Ok(y)) = (rp.0.getvalue().get(), rp.1.getvalue().get()) {
            self.res.push(x.into_repr());
            self.res.push(y.into_repr());
        }
        let key = rq.0;
        let enc = key.add(cs, &message)?;
        if let Ok(x) = enc.getvalue().get() {
            self.res.push(x.into_repr());
        }

        let mut addr_sk = Vec::with_capacity(ADSK);
        for b in self.addr_sk.iter() {
            addr_sk.push(Bit::alloc(cs, *b)?);
        }
        let p1 = Point::enc_point_table(ADSK, 1, cs)?;
        let addr = Point::multiply(&p1, &addr_sk, cs)?;

        Ok(P2CcircuitInput {
            hb,
            coin,
            delt_ba,
            rp,
            enc,
            addr
        })
    }
}

pub fn p2c_info(
    rh: [u64; 4],
    rcm: [u64; 2],
    ba: [u64; 2],
    va: [u64; 2],
    addr: String,
    addr_sk: String,
    enc_random: [u64; 4],
) -> Result<(String,String,String,String,String), Error> {
    let addr = str2point(addr);
    let addr_sk = str2sk(addr_sk);
    let rng = &mut thread_rng();
    let j = JubJub::new();
    //TODO:Balance&value<2^vbit
    let mut res: Vec<FrRepr> = vec![];
    let proof = create_random_proof::<Bls12, _, _, _>(
        P2Ccircuit::new(
            &ph_generator(),
            &j,
            Fr::from_repr(FrRepr(rh)).unwrap(),
            Fr::from_repr(FrRepr([rcm[0], rcm[1], 0, 0])).unwrap(),
            Fr::from_repr(FrRepr([ba[0], ba[1], 0, 0])).unwrap(),
            Fr::from_repr(FrRepr([va[0], va[1], 0, 0])).unwrap(),
            (
                Fr::from_repr(FrRepr(addr.0)).unwrap(),
                Fr::from_repr(FrRepr(addr.1)).unwrap(),
            ),
            Fr::from_serial(enc_random),
            addr_sk,
            &mut res
        ),
        p2c_param()?,
        rng,
    )?.serial();
    let hb = (res[0].serial(), res[1].serial());
    let coin = res[2].serial();
    let delt_ba = (res[3].serial(), res[4].serial());
    let enc = (res[5].serial(), res[6].serial(),res[7].serial());
    Ok((proof2str(proof), point2str(hb), u6442str(coin), point2str(delt_ba), enc2str(enc)))
}

pub fn p2c_verify(
    hb: String,
    coin: String,
    delt_ba: String,
    enc: String,
    address:String,
    proof: String) -> Result<bool, Error> {
    let hb = str2point(hb);
    let coin = str2u644(coin);
    let delt_ba = str2point(delt_ba);
    let enc = str2enc(enc);
    let address = str2point(address);
    let proof = str2proof(proof);
    verify_proof(&p2c_vk()?, &Proof::from_serial(proof), |cs| {
        let delt_x = Fr::from_repr(FrRepr::from_serial(delt_ba.0)).unwrap();
        let delt_y = Fr::from_repr(FrRepr::from_serial(delt_ba.1)).unwrap();
        let hb_x = Fr::from_repr(FrRepr::from_serial(hb.0)).unwrap();
        let hb_y = Fr::from_repr(FrRepr::from_serial(hb.1)).unwrap();
        let coin = Fr::from_repr(FrRepr::from_serial(coin)).unwrap();
        let rpx = Fr::from_repr(FrRepr::from_serial(enc.0)).unwrap();
        let rpy = Fr::from_repr(FrRepr::from_serial(enc.1)).unwrap();
        let enc = Fr::from_repr(FrRepr::from_serial(enc.2)).unwrap();
        let addrx = Fr::from_repr(FrRepr::from_serial(address.0)).unwrap();
        let addry = Fr::from_repr(FrRepr::from_serial(address.1)).unwrap();
        Ok(P2CcircuitInput {
            hb: (
                Num::new(cs, Assignment::known(hb_x))?,
                Num::new(cs, Assignment::known(hb_y))?,
            ),
            coin: Num::new(cs, Assignment::known(coin))?,
            delt_ba: (
                Num::new(cs, Assignment::known(delt_x))?,
                Num::new(cs, Assignment::known(delt_y))?,
            ),
            rp: (
                Num::new(cs, Assignment::known(rpx))?,
                Num::new(cs, Assignment::known(rpy))?,
            ),
            enc: Num::new(cs, Assignment::known(enc))?,
            addr:(
                Num::new(cs, Assignment::known(addrx))?,
                Num::new(cs, Assignment::known(addry))?
            )
        })
    })
}

pub fn ensure_p2c_param() -> Result<(), Error> {
    if !Path::new(PARAMPATH).exists() {
        use std::fs::create_dir;
        create_dir(Path::new(PARAMPATH)).unwrap();
    }
    if !Path::new(P2CPARAMPATH).exists() {
        println!("Creating the parameters");
        let rng = &mut thread_rng();
        let params = generate_random_parameters::<Bls12, _, _>(
            P2Ccircuit::blank(&ph_generator(), &JubJub::new(), &mut vec![]),
            rng,
        )?;
        params
            .write(&mut File::create(P2CPARAMPATH).unwrap())
            .unwrap();
        println!("Just wrote the parameters to disk!");
    }
    Ok(())
}

pub fn p2c_param() -> Result<ProverStream, Error> {
    ensure_p2c_param()?;
    let params = ProverStream::new(P2CPARAMPATH).unwrap();
    Ok(params)
}

pub fn p2c_vk() -> Result<(PreparedVerifyingKey<Bls12>), Error> {
    ensure_p2c_param()?;
    let mut params = ProverStream::new(P2CPARAMPATH)?;
    let vk2 = params.get_vk(11)?;
    let vk = prepare_verifying_key(&vk2);
    Ok(vk)
}
