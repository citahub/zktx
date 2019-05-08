use bellman::groth16::*;
use bellman::*;
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use pairing::*;
use rand::thread_rng;

use jubjub::*;

use convert::*;

use std::fs::File;

use base::range_param_path;

struct RangeCircuit<'a> {
    //upper bound
    up: Assignment<Fr>,
    //value
    va: Assignment<Fr>,
    //r_h
    rh: Assignment<Fr>,
    //lower bound
    low: Assignment<Fr>,
    //result
    res: &'a mut Vec<FrRepr>,
}

impl<'a> RangeCircuit<'a> {
    fn blank(res: &'a mut Vec<FrRepr>) -> RangeCircuit {
        RangeCircuit {
            up: Assignment::unknown(),
            va: Assignment::unknown(),
            rh: Assignment::unknown(),
            low: Assignment::unknown(),
            res,
        }
    }

    fn new(up: Fr, va: Fr, rh: Fr, low: Fr, res: &'a mut Vec<FrRepr>) -> RangeCircuit {
        RangeCircuit {
            up: Assignment::known(up),
            va: Assignment::known(va),
            rh: Assignment::known(rh),
            low: Assignment::known(low),
            res,
        }
    }
}

struct RangeCircuitInput {
    //upper bound
    up: Num<Bls12>,
    //lower bound
    low: Num<Bls12>,
    //hash value
    hv: (Num<Bls12>, Num<Bls12>),
}

impl<'a> Input<Bls12> for RangeCircuitInput {
    fn synthesize<CS: PublicConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), Error> {
        let up_input = cs.alloc_input(|| Ok(*self.up.getvalue().get()?))?;
        let low_input = cs.alloc_input(|| Ok(*self.low.getvalue().get()?))?;
        let hvx = cs.alloc_input(|| Ok(*self.hv.0.getvalue().get()?))?;
        let hvy = cs.alloc_input(|| Ok(*self.hv.1.getvalue().get()?))?;

        cs.enforce(
            LinearCombination::zero() + self.up.getvar(),
            LinearCombination::zero() + CS::one(),
            LinearCombination::zero() + up_input,
        );
        cs.enforce(
            LinearCombination::zero() + self.low.getvar(),
            LinearCombination::zero() + CS::one(),
            LinearCombination::zero() + low_input,
        );
        cs.enforce(
            LinearCombination::zero() + self.hv.0.getvar(),
            LinearCombination::zero() + CS::one(),
            LinearCombination::zero() + hvx,
        );
        cs.enforce(
            LinearCombination::zero() + self.hv.1.getvar(),
            LinearCombination::zero() + CS::one(),
            LinearCombination::zero() + hvy,
        );

        Ok(())
    }
}

impl<'a> Circuit<Bls12> for RangeCircuit<'a> {
    type InputMap = RangeCircuitInput;

    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<Self::InputMap, Error> {
        let up_num = Num::new(cs, self.up)?;
        let up = up_num.unpack_sized(cs, 256)?;
        let low_num = Num::new(cs, self.low)?;
        let low = low_num.unpack_sized(cs, 256)?;

        let va_num = Num::new(cs, self.va)?;
        let va = va_num.unpack_sized(cs, 256)?;

        let mp = Num::new(
            cs,
            Assignment::known(Fr::from_repr(FrRepr::from_serial([0, 0, 1, 0])).unwrap()),
        )?
        .unpack_sized(cs, 256)?;
        let mut mm = Fr::from_repr(FrRepr::from_serial([0, 0, 1, 0])).unwrap();
        mm.negate();
        let mm = Num::new(cs, Assignment::known(mm))?.unpack_sized(cs, 256)?;

        assert_nonless_with_minus(&up, &va, &mp, &mm, cs)?;
        assert_nonless_with_minus(&va, &low, &mp, &mm, cs)?;

        //prepare table
        let p1 = Point::enc_point_table(256, 1, cs)?;
        let p2 = Point::enc_point_table(256, 2, cs)?;

        //va*P1+rh*P2
        let rh = Num::new(cs, self.rh)?.unpack_sized(cs, 256)?;
        let hv = Point::encrypt((&p1, &p2), &va, &rh, cs)?;
        if let (Ok(x), Ok(y)) = (hv.0.getvalue().get(), hv.1.getvalue().get()) {
            self.res.push(x.into_repr());
            self.res.push(y.into_repr());
        }

        Ok(RangeCircuitInput {
            up: up_num,
            low: low_num,
            hv,
        })
    }
}

pub fn range_info(
    up: ([u64; 2], bool),
    va: ([u64; 2], bool),
    rh: [u64; 2],
    low: ([u64; 2], bool),
) -> Result<(String, String), Error> {
    let rng = &mut thread_rng();
    let up = {
        let mut res = Fr::from_repr(FrRepr::from_serial([(up.0)[0], (up.0)[1], 0, 0])).unwrap();
        if !up.1 {
            res.negate();
        }
        res
    };
    let va = {
        let mut res = Fr::from_repr(FrRepr::from_serial([(va.0)[0], (va.0)[1], 0, 0])).unwrap();
        if !va.1 {
            res.negate();
        }
        res
    };
    let rh = Fr::from_repr(FrRepr::from_serial([rh[0], rh[1], 0, 0])).unwrap();
    let low = {
        let mut res = Fr::from_repr(FrRepr::from_serial([(low.0)[0], (low.0)[1], 0, 0])).unwrap();
        if !low.1 {
            res.negate();
        }
        res
    };
    let mut res: Vec<FrRepr> = vec![];
    let proof = create_random_proof::<Bls12, _, _, _>(
        RangeCircuit::new(up, va, rh, low, &mut res),
        range_param()?,
        rng,
    )?
    .serial();
    let hv = (res[0].serial(), res[1].serial());
    Ok((proof2str(proof), point2str(hv)))
}

pub fn range_verify(
    up: ([u64; 2], bool),
    hv: String,
    low: ([u64; 2], bool),
    proof: String,
) -> Result<bool, Error> {
    let hv = str2point(hv);
    let proof = str2proof(proof);
    verify_proof(&range_vk()?, &Proof::from_serial(proof), |cs| {
        let up = {
            let mut res = Fr::from_repr(FrRepr::from_serial([(up.0)[0], (up.0)[1], 0, 0])).unwrap();
            if !up.1 {
                res.negate();
            }
            res
        };
        let low = {
            let mut res =
                Fr::from_repr(FrRepr::from_serial([(low.0)[0], (low.0)[1], 0, 0])).unwrap();
            if !low.1 {
                res.negate();
            }
            res
        };
        let hv = (
            Fr::from_repr(FrRepr::from_serial(hv.0)).unwrap(),
            Fr::from_repr(FrRepr::from_serial(hv.1)).unwrap(),
        );
        Ok(RangeCircuitInput {
            up: Num::new(cs, Assignment::known(up))?,
            hv: (
                Num::new(cs, Assignment::known(hv.0))?,
                Num::new(cs, Assignment::known(hv.1))?,
            ),
            low: Num::new(cs, Assignment::known(low))?,
        })
    })
}

pub(crate) fn gen_range_param() {
    let range_param_path = range_param_path();
    let range_param_path = range_param_path.to_str().unwrap();
    let rng = &mut thread_rng();
    let params =
        generate_random_parameters::<Bls12, _, _>(RangeCircuit::blank(&mut vec![]), rng).unwrap();
    params
        .write(&mut File::create(range_param_path).unwrap())
        .unwrap();
}

fn range_param() -> Result<ProverStream, Error> {
    let range_param_path = range_param_path();
    let range_param_path = range_param_path.to_str().unwrap();
    let params = ProverStream::new(range_param_path).unwrap();
    Ok(params)
}

fn range_vk() -> Result<(PreparedVerifyingKey<Bls12>), Error> {
    let range_param_path = range_param_path();
    let range_param_path = range_param_path.to_str().unwrap();
    let mut params = ProverStream::new(range_param_path)?;
    let vk2 = params.get_vk(5)?;
    let vk = prepare_verifying_key(&vk2);
    Ok(vk)
}
