extern crate zktx;

use zktx::incrementalmerkletree::*;
use zktx::pedersen::PedersenDigest;
use std::collections::VecDeque;
use zktx::pedersen_hash_root;

fn path_and_root() {
    let mut tree = IncrementalMerkleTree::new(60);
    let coin = PedersenDigest([1, 2, 3, 4]);
    tree.append(coin);
    let path = tree.path(VecDeque::new());
    let tree_root = tree.root();

    let path2 : Vec<[u64; 4]> = path.authentication_path.iter().map(|p| p.0).collect();
    let loc2 = path.index;

    let root = {
        let mut root = coin.0;
        for i in 0..60 {
            if loc2[i]{
                root = pedersen_hash_root(path2[i],root);
            }else{
                root = pedersen_hash_root(root,path2[i]);
            }
        }
        root
    };

    if root != tree_root.0 {
        println!("path_and_root failed! root {:?} tree_root {:?}", root, tree_root.0);
        return
    }
}


fn main(){
    path_and_root();
}