use bellman::groth16::*;
use bellman::*;
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use pairing::*;
use rand::thread_rng;

use jubjub::*;

use base::*;
use convert::*;

use std::fs::File;

struct C2Pcircuit<'a> {
    generators: &'a [(Vec<Fr>, Vec<Fr>)],
    j: &'a JubJub,

    //r_cm
    rcm: Assignment<Fr>,
    //r_cm_new
    rcm_new: Assignment<Fr>,
    //value
    va: Assignment<Fr>,
    //addr_sk
    addr_sk: Vec<Assignment<bool>>,
    //coin path
    path: Vec<Vec<Assignment<bool>>>,
    //path location
    loc: Vec<Assignment<bool>>,
    //result
    res: &'a mut Vec<FrRepr>,
}

impl<'a> C2Pcircuit<'a> {
    fn blank(
        generators: &'a [(Vec<Fr>, Vec<Fr>)],
        j: &'a JubJub,
        res: &'a mut Vec<FrRepr>,
    ) -> C2Pcircuit<'a> {
        C2Pcircuit {
            generators,
            j,
            rcm: Assignment::unknown(),
            rcm_new: Assignment::unknown(),
            va: Assignment::unknown(),
            addr_sk: (0..ADSK).map(|_| Assignment::unknown()).collect(),
            path: (0..TREEDEPTH)
                .map(|_| (0..PHOUT).map(|_| Assignment::unknown()).collect())
                .collect(),
            loc: (0..TREEDEPTH).map(|_| Assignment::unknown()).collect(),
            res,
        }
    }

    fn new(
        generators: &'a [(Vec<Fr>, Vec<Fr>)],
        j: &'a JubJub,
        rcm: Fr,
        rcm_new: Fr,
        va: Fr,
        addr_sk: Vec<bool>,
        path: Vec<[u64; 4]>,
        loc: Vec<bool>,
        res: &'a mut Vec<FrRepr>,
    ) -> C2Pcircuit<'a> {
        assert_eq!(addr_sk.len(), ADSK);
        assert_eq!(res.len(), 0);
        assert_eq!(path.len(), TREEDEPTH);
        assert_eq!(loc.len(), TREEDEPTH);
        let path: Vec<Vec<bool>> = path
            .into_iter()
            .map(|u644| {
                let mut v = Vec::with_capacity(PHOUT);
                for u in u644.into_iter() {
                    let mut u = *u;
                    v.push((u & 1) == 1);
                    for _ in 0..63 {
                        u >>= 1;
                        v.push((u & 1) == 1);
                    }
                }
                v
            })
            .collect();
        C2Pcircuit {
            generators,
            j,
            rcm: Assignment::known(rcm),
            rcm_new: Assignment::known(rcm_new),
            va: Assignment::known(va),
            addr_sk: addr_sk.iter().map(|&b| Assignment::known(b)).collect(),
            path: path
                .iter()
                .map(|ref ph| ph.iter().map(|&b| Assignment::known(b)).collect())
                .collect(),
            loc: loc.iter().map(|&b| Assignment::known(b)).collect(),
            res,
        }
    }
}

struct C2PcircuitInput {
    //delta(Balance)
    delt_ba: (Num<Bls12>, Num<Bls12>),
    //nullifier
    nullifier: Num<Bls12>,
    //root
    root: Num<Bls12>,
}

impl<'a> Input<Bls12> for C2PcircuitInput {
    fn synthesize<CS: PublicConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), Error> {
        let delt_x_input = cs.alloc_input(|| Ok(*self.delt_ba.0.getvalue().get()?))?;
        let delt_y_input = cs.alloc_input(|| Ok(*self.delt_ba.1.getvalue().get()?))?;
        let nullifier_input = cs.alloc_input(|| Ok(*self.nullifier.getvalue().get()?))?;
        let root_input = cs.alloc_input(|| Ok(*self.root.getvalue().get()?))?;

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
            LinearCombination::zero() + self.nullifier.getvar(),
            LinearCombination::zero() + CS::one(),
            LinearCombination::zero() + nullifier_input,
        );
        cs.enforce(
            LinearCombination::zero() + self.root.getvar(),
            LinearCombination::zero() + CS::one(),
            LinearCombination::zero() + root_input,
        );

        Ok(())
    }
}

impl<'a> Circuit<Bls12> for C2Pcircuit<'a> {
    type InputMap = C2PcircuitInput;

    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<Self::InputMap, Error> {
        let rcm_num = Num::new(cs, self.rcm)?;
        let mut rcm = rcm_num.unpack_sized(cs, RCMBIT)?;
        let rcm_new = Num::new(cs, self.rcm_new)?.unpack_sized(cs, RCMBIT)?;
        let mut addr_sk = Vec::with_capacity(ADSK);
        for b in self.addr_sk.iter() {
            addr_sk.push(Bit::alloc(cs, *b)?);
        }

        let va = Num::new(cs, self.va)?;
        let bit_va = va.unpack_sized(cs, VBIT)?;
        assert_eq!(bit_va.len(), VBIT);

        //nullifier = PH(addr_sk|value|rcm)
        let mut rcm2 = rcm.clone();
        let vin = {
            for b in bit_va.iter() {
                rcm.push(*b);
            }
            for b in addr_sk.iter() {
                rcm.push(*b);
            }
            rcm
        };
        assert_eq!(vin.len(), PHIN);
        let nullifier = pedersen_hash(cs, &vin, self.generators, self.j)?;
        if let Ok(x) = nullifier.getvalue().get() {
            self.res.push(x.into_repr());
        }

        let p1 = Point::enc_point_table(ADSK, 1, cs)?;
        let p2 = Point::enc_point_table(RCMBIT, 2, cs)?;
        let addr = Point::multiply(&p1, &addr_sk, cs)?;
        let addr = addr.0.unpack_sized(cs, PHOUT)?; //取x

        //coin = PH(addr|value|rcm)
        let vin = {
            for b in bit_va.iter() {
                rcm2.push(*b);
            }
            for b in addr.iter() {
                rcm2.push(*b);
            }
            rcm2
        };
        assert_eq!(vin.len(), PHIN);
        let mut phout = pedersen_hash(cs, &vin, self.generators, self.j)?;

        let mut locs = Vec::with_capacity(TREEDEPTH);
        for b in self.loc.iter() {
            locs.push(Bit::alloc(cs, *b)?);
        }

        for (loc, sib) in locs.iter().zip(self.path.iter()) {
            let phbits = phout.unpack_sized(cs, PHOUT)?;

            let mut vin = vec![];
            for (a, b) in sib.iter().zip(phbits.iter()) {
                let bit_ph = &b; //phbits
                let bit_sib = &Bit::alloc(cs, *a)?; //ph
                let bit_out = loc.choose_bit(cs, bit_ph, bit_sib)?;
                vin.push(bit_out);
            }
            for (a, b) in sib.iter().zip(phbits.iter()) {
                let bit_ph = &b; //phbits
                let bit_sib = &Bit::alloc(cs, *a)?; //ph
                let bit_out = loc.choose_bit(cs, bit_sib, bit_ph)?;
                vin.push(bit_out);
            }
            assert_eq!(vin.len(), PHIN);

            phout = pedersen_hash(cs, &vin, self.generators, self.j)?;
        }
        if let Ok(x) = phout.getvalue().get() {
            self.res.push(x.into_repr());
        }

        //delta_ba
        let delt_ba = Point::encrypt((&p1, &p2), &bit_va, &rcm_new, cs)?;
        if let (Ok(x), Ok(y)) = (delt_ba.0.getvalue().get(), delt_ba.1.getvalue().get()) {
            self.res.push(x.into_repr());
            self.res.push(y.into_repr());
        }

        Ok(C2PcircuitInput {
            delt_ba,
            nullifier,
            root: phout,
        })
    }
}

pub fn c2p_info(
    rcm: [u64; 2],
    rcm_new: [u64; 2],
    va: [u64; 2],
    addr_sk: String,
    path: Vec<String>,
    loc: Vec<bool>,
) -> Result<(String, String, String, String), Error> {
    let rng = &mut thread_rng();
    let j = JubJub::new();
    let path = path.iter().map(|p| str2u644(p.clone())).collect();
    let addr_sk = str2sk(addr_sk);
    let mut res: Vec<FrRepr> = vec![];
    let proof = create_random_proof::<Bls12, _, _, _>(
        C2Pcircuit::new(
            &ph_generator(),
            &j,
            Fr::from_repr(FrRepr([rcm[0], rcm[1], 0, 0])).unwrap(),
            Fr::from_repr(FrRepr([rcm_new[0], rcm_new[1], 0, 0])).unwrap(),
            Fr::from_repr(FrRepr([va[0], va[1], 0, 0])).unwrap(),
            addr_sk,
            path,
            loc,
            &mut res,
        ),
        c2p_param()?,
        rng,
    )?
    .serial();
    let nullifier = res[0].serial();
    let root = res[1].serial();
    let delt_ba = (res[2].serial(), res[3].serial());
    Ok((
        proof2str(proof),
        u6442str(nullifier),
        u6442str(root),
        point2str(delt_ba),
    ))
}

pub fn c2p_verify(
    nullifier: String,
    root: String,
    delt_ba: String,
    proof: String,
) -> Result<bool, Error> {
    let nullifier = str2u644(nullifier);
    let root = str2u644(root);
    let delt_ba = str2point(delt_ba);
    let proof = str2proof(proof);
    verify_proof(&c2p_vk()?, &Proof::from_serial(proof), |cs| {
        let nullifier = Fr::from_repr(FrRepr::from_serial(nullifier)).unwrap();
        let delt_x = Fr::from_repr(FrRepr::from_serial(delt_ba.0)).unwrap();
        let delt_y = Fr::from_repr(FrRepr::from_serial(delt_ba.1)).unwrap();
        let root = Fr::from_repr(FrRepr::from_serial(root)).unwrap();
        Ok(C2PcircuitInput {
            nullifier: Num::new(cs, Assignment::known(nullifier))?,
            delt_ba: (
                Num::new(cs, Assignment::known(delt_x))?,
                Num::new(cs, Assignment::known(delt_y))?,
            ),
            root: Num::new(cs, Assignment::known(root))?,
        })
    })
}

pub(crate) fn gen_c2p_param() {
    let c2p_param_path = c2p_param_path();
    let c2p_param_path = c2p_param_path.to_str().unwrap();

    let rng = &mut thread_rng();
    let params = generate_random_parameters::<Bls12, _, _>(
        C2Pcircuit::blank(&ph_generator(), &JubJub::new(), &mut vec![]),
        rng,
    )
    .unwrap();
    params
        .write(&mut File::create(c2p_param_path).unwrap())
        .unwrap();
}

pub fn c2p_param() -> Result<ProverStream, Error> {
    let c2p_param_path = c2p_param_path();
    let c2p_param_path = c2p_param_path.to_str().unwrap();
    let params = ProverStream::new(c2p_param_path).unwrap();
    Ok(params)
}

pub fn c2p_vk() -> Result<(PreparedVerifyingKey<Bls12>), Error> {
    let c2p_param_path = c2p_param_path();
    let c2p_param_path = c2p_param_path.to_str().unwrap();
    let mut params = ProverStream::new(c2p_param_path)?;
    let vk2 = params.get_vk(5)?;
    let vk = prepare_verifying_key(&vk2);
    Ok(vk)
}
