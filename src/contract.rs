use std::collections::HashMap;
use std::collections::HashSet;
use incrementalmerkletree::*;
use pedersen::PedersenDigest;
use base::*;
use c2p::*;
use p2c::*;
use std::collections::VecDeque;

#[derive(Clone)]
pub struct SenderProof {
    pub proof:(([u64; 6], [u64; 6], bool), (([u64; 6], [u64; 6]), ([u64; 6], [u64; 6]), bool), ([u64; 6], [u64; 6], bool)),
    //hb:([u64;4],[u64;4]),
    pub coin:[u64;4],
    pub delt_ba:([u64;4],[u64;4]),
    pub rp:([u64;4],[u64;4]),
    pub enc:[u64;4],
    pub block_number: u64,
}

#[derive(Clone)]
pub struct ReceiverProof{
    pub proof:(([u64; 6], [u64; 6], bool), (([u64; 6], [u64; 6]), ([u64; 6], [u64; 6]), bool), ([u64; 6], [u64; 6], bool)),
    pub nullifier:[u64;4],
    pub root:[u64;4],
    pub delt_ba:([u64;4],[u64;4])
}

pub struct PrivacyContract {
    balances: HashMap<([u64; 4], [u64; 4]), ([u64;4],[u64;4])>,
    last_spent: HashMap<([u64; 4], [u64; 4]), u64>,
    coins: HashSet<[u64; 4]>,
    nullifier_set: HashSet<[u64; 4]>,
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

    pub fn set_banlance(&mut self, address: ([u64;4],[u64;4]), balance: ([u64;4],[u64;4])) {
        self.balances.insert(address, balance);
    }

    pub fn get_banlance(&mut self, address: ([u64;4],[u64;4])) -> ([u64;4],[u64;4]) {
        self.balances.get(&address).unwrap().clone()
    }

    pub fn send_verify(&mut self, address: ([u64;4],[u64;4]), message: SenderProof) -> (bool, Option<MerklePath<PedersenDigest>>) {
        let balance = self.balances.get_mut(&address).unwrap();
        assert!(p2c_verify(balance.clone(),message.coin,message.delt_ba,message.rp,message.enc,message.proof).unwrap());
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
        self.last_spent.insert(address, message.block_number);
        self.tree.append(PedersenDigest(message.coin));
        *balance = ecc_sub(balance.clone(), message.delt_ba);
        println!("sender proof verify ok! root {:?} coin {:?}", self.tree.root(), message.coin);
        (true, Some(self.tree.path(VecDeque::new())))
    }

    pub fn receive_verify(&mut self, address: ([u64;4],[u64;4]), message: ReceiverProof) -> bool {
        if message.root != self.tree.root().0 {
            println!("invalid root, message.root {:?}, tree.root {:?}", message.root, self.tree.root());
            return false;
        }
        let balance = self.balances.get_mut(&address).unwrap();
        assert!(c2p_verify(message.nullifier,message.root,message.delt_ba,message.proof).unwrap());
        if self.nullifier_set.contains(&message.nullifier) {
            println!("Dup nullifier");
            return false;
        }

        self.nullifier_set.insert(message.nullifier);
        *balance = ecc_add(balance.clone(), message.delt_ba);
        true
    }
}