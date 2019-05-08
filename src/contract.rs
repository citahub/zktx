use base::*;
use c2p::*;
use convert::*;
use incrementalmerkletree::*;
use p2c::*;
use pedersen::PedersenDigest;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;

#[derive(Clone)]
pub struct SenderProof {
    pub proof: String,
    //hb:([u64;4],[u64;4]),
    pub coin: String,
    pub delt_ba: String,
    pub enc: String,
    pub block_number: u64,
}

#[derive(Clone)]
pub struct ReceiverProof {
    pub proof: String,
    pub nullifier: String,
    pub root: String,
    pub delt_ba: String,
}

pub struct PrivacyContract {
    balances: HashMap<String, String>,
    last_spent: HashMap<String, u64>,
    coins: HashSet<String>,
    nullifier_set: HashSet<String>,
    tree: IncrementalMerkleTree<PedersenDigest>,
}

impl PrivacyContract {
    pub fn new() -> Self {
        PrivacyContract {
            balances: HashMap::new(),
            last_spent: HashMap::new(),
            coins: HashSet::new(),
            nullifier_set: HashSet::new(),
            tree: IncrementalMerkleTree::new(60 as usize),
        }
    }

    pub fn set_banlance(&mut self, address: String, balance: String) {
        self.balances.insert(address, balance);
    }

    pub fn get_banlance(&mut self, address: String) -> String {
        self.balances.get(&address).unwrap().clone()
    }

    pub fn send_verify(
        &mut self,
        address: String,
        message: SenderProof,
    ) -> (bool, Option<MerklePath<PedersenDigest>>) {
        if self.coins.contains(&message.coin) {
            println!("Dup coin");
            return (false, None);
        }

        // compare block number
        if let Some(block_number) = self.last_spent.get_mut(&address) {
            if *block_number >= message.block_number {
                println!("invalid block number");
                return (false, None);
            }
        }

        let balance = self.balances.get_mut(&address).unwrap();
        assert!(p2c_verify(
            balance.clone(),
            message.coin.clone(),
            message.delt_ba.clone(),
            message.enc,
            address.clone(),
            message.proof
        )
        .unwrap());

        self.last_spent.insert(address, message.block_number);
        self.coins.insert(message.coin.clone());
        self.tree
            .append(PedersenDigest(str2u644(message.coin.clone())));
        *balance = ecc_sub(balance.clone(), message.delt_ba);
        println!(
            "sender proof verify ok! root {:?} coin {:?}",
            self.tree.root(),
            message.coin
        );
        (true, Some(self.tree.path(VecDeque::new())))
    }

    pub fn receive_verify(&mut self, address: String, message: ReceiverProof) -> bool {
        if str2u644(message.root.clone()) != self.tree.root().0 {
            println!(
                "invalid root, message.root {:?}, tree.root {:?}",
                message.root,
                self.tree.root()
            );
            return false;
        }

        if self.nullifier_set.contains(&message.nullifier) {
            println!("Dup nullifier");
            return false;
        }

        assert!(c2p_verify(
            message.nullifier.clone(),
            message.root,
            message.delt_ba.clone(),
            message.proof
        )
        .unwrap());

        self.nullifier_set.insert(message.nullifier);
        let balance = self.balances.get_mut(&address).unwrap();
        *balance = ecc_add(balance.clone(), message.delt_ba);
        true
    }
}
