use bellman::groth16::*;
use pairing::*;
use pairing::bls12_381::{Fr, FrRepr, Bls12};
use bellman::*;
use rand::thread_rng;

use jubjub::*;

use common_verify::*;

use std::fs::File;
use std::path::Path;

struct GreaterCircuit {
    //r_cm
    ba: Assignment<Fr>,
    //value
    va: Assignment<Fr>,
}

impl GreaterCircuit{
    fn blank() -> GreaterCircuit {
        GreaterCircuit {
            ba: Assignment::unknown(),
            va: Assignment::unknown(),
        }
    }

    fn new(
        ba: Fr,
        va: Fr,
    ) -> GreaterCircuit {
        GreaterCircuit {
            ba: Assignment::known(ba),
            va: Assignment::known(va),
        }
    }
}

struct GreaterCircuitInput {
    //va
    va: Num<Bls12>,
}

impl<'a> Input<Bls12> for GreaterCircuitInput {
    fn synthesize<CS: PublicConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), Error> {
        let va_input = cs.alloc_input(|| Ok(*self.va.getvalue().get()?))?;

        cs.enforce(
            LinearCombination::zero() + self.va.getvar(),
            LinearCombination::zero() + CS::one(),
            LinearCombination::zero() + va_input,
        );

        Ok(())
    }
}

impl<'a> Circuit<Bls12> for GreaterCircuit {
    type InputMap = GreaterCircuitInput;

    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<Self::InputMap, Error> {
        let ba = Num::new(cs, self.ba)?.unpack_sized(cs,128)?;

        let va_num = Num::new(cs, self.va)?;
        let va = va_num.unpack_sized(cs,128)?;

        assert_nonless_than(&ba,&va,cs)?;

        Ok(GreaterCircuitInput {va:va_num})
    }
}

pub fn greater_info(
    ba: [u64; 2],
    va: [u64; 2],
) -> Result<
    (([u64; 6], [u64; 6], bool),
      (([u64; 6], [u64; 6]), ([u64; 6], [u64; 6]), bool),
      ([u64; 6], [u64; 6], bool)),
    Error>
{
    let rng = &mut thread_rng();
    let proof = create_random_proof::<Bls12, _, _, _>(
        GreaterCircuit::new(
            Fr::from_repr(FrRepr([ba[0], ba[1], 0, 0])).unwrap(),
            Fr::from_repr(FrRepr([va[0], va[1], 0, 0])).unwrap(),
        ),
        greater_param()?,
        rng,
    )?.serial();
    Ok(proof)
}

pub fn greater_verify(
    va: [u64; 2],
    proof: (([u64; 6], [u64; 6], bool),
            (([u64; 6], [u64; 6]), ([u64; 6], [u64; 6]), bool),
            ([u64; 6], [u64; 6], bool)),
) -> Result<bool, Error> {
    verify_proof(&greater_vk()?, &Proof::from_serial(proof), |cs| {
        let va = Fr::from_repr(FrRepr::from_serial([va[0], va[1], 0, 0])).unwrap();
        Ok(GreaterCircuitInput {
            va: Num::new(cs, Assignment::known(va))?,
        })
    })
}

pub fn ensure_greater_param() -> Result<(), Error> {
    if !Path::new(PARAMPATH).exists() {
        use std::fs::create_dir;
        create_dir(Path::new(PARAMPATH)).unwrap();
    }
    if !Path::new(GREATERPARAMPATH).exists() {
        println!("Creating the parameters");
        let rng = &mut thread_rng();
        let params = generate_random_parameters::<Bls12, _, _>(
            GreaterCircuit::blank(),
            rng,
        )?;
        params
            .write(&mut File::create(GREATERPARAMPATH).unwrap())
            .unwrap();
        println!("Just wrote the parameters to disk!");
    }
    Ok(())
}

fn greater_param() -> Result<ProverStream, Error> {
    ensure_greater_param()?;
    let params = ProverStream::new(GREATERPARAMPATH).unwrap();
    Ok(params)
}

fn greater_vk() -> Result<(PreparedVerifyingKey<Bls12>), Error> {
    ensure_greater_param()?;
    let mut params = ProverStream::new(GREATERPARAMPATH)?;
    let vk2 = params.get_vk(2)?;
    let vk = prepare_verifying_key(&vk2);
    Ok(vk)
}
