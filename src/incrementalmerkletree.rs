extern crate rand;

use std::collections::VecDeque;

pub trait Hashable: Clone + Copy {
    fn combine(&Self, &Self) -> Self;
    fn blank() -> Self;
}

#[derive(Debug)]
pub struct MerklePath<T: Hashable> {
    pub authentication_path: Vec<T>,
    pub index: Vec<bool>,
}

impl<T: Hashable> MerklePath<T> {
    fn new(authentication_path: Vec<T>, index: Vec<bool>) -> Self {
        MerklePath {
            authentication_path,
            index,
        }
    }
}

#[derive(Clone)]
struct EmptyMerkleRoots<T: Hashable> {
    empty_roots: Vec<T>,
}

impl<T: Hashable> EmptyMerkleRoots<T> {
    fn new(d: usize) -> Self {
        let mut empty_roots = vec![T::blank(); d+1];
        empty_roots[0] = T::blank();
        for i in 1..(d + 1) {
            empty_roots[i] = T::combine(&empty_roots[i - 1], &empty_roots[i - 1]);
        }
        EmptyMerkleRoots {
            empty_roots,
        }
    }

    fn empty_root(&self, d: usize) -> T {
        self.empty_roots.get(d).unwrap().clone()
    }
}


struct PathFiller<T: Hashable> {
    queue: VecDeque<T>,
    emptyroots: EmptyMerkleRoots<T>,
}

impl<T: Hashable> PathFiller<T> {
    fn new(d: usize) -> Self {
        let emptyroots = EmptyMerkleRoots::new(d);
        PathFiller {
            queue: VecDeque::new(),
            emptyroots,
        }
    }

    fn new_with_deque(d: usize, deque: VecDeque<T>) -> Self {
        let emptyroots = EmptyMerkleRoots::new(d);
        PathFiller {
            queue: deque,
            emptyroots,
        }
    }

    fn next(&mut self, d: usize) -> T {
        if self.queue.is_empty() {
            self.emptyroots.empty_root(d)
        } else {
            self.queue.pop_front().unwrap()
        }
    }
}

#[derive(Clone)]
pub struct IncrementalMerkleTree<T: Hashable> {
    emptyroots: EmptyMerkleRoots<T>,
    left: Option<T>,
    right: Option<T>,
    parents: Vec<Option<T>>,
    depth: usize,
}

impl<T: Hashable> IncrementalMerkleTree<T> {
    pub fn new(d: usize) -> Self {
        let emptyroots = EmptyMerkleRoots::new(d);
        IncrementalMerkleTree {
            emptyroots,
            left: None,
            right: None,
            parents: Vec::new(),
            depth: d,
        }
    }

    pub fn size(&self) -> usize {
        let mut ret = 0;
        if self.left.is_some() {
            ret = ret + 1;
        }
        if self.right.is_some() {
            ret = ret + 1;
        }
        for i in 0..self.parents.len() {
            if self.parents[i].is_some() {
                ret = ret + (1 << (i + 1));
            }
        }
        ret
    }

    pub fn is_complete(&self, d: usize) -> bool {
        if self.left.is_none() || self.right.is_none() {
            return false;
        }
        if self.parents.len() != (d - 1) {
            return false;
        }
        for parent in &self.parents {
            if parent.is_none() {
                return false;
            }
        }
        return true;
    }

    pub fn append(&mut self, obj: T) {
        if self.is_complete(self.depth) {
            panic!("tree is full")
        }

        if self.left.is_none() {
            self.left = Some(obj);
        } else if self.right.is_none() {
            self.right = Some(obj);
        } else {
            let mut combined = T::combine(&self.left.unwrap(), &self.right.unwrap());
            self.left = Some(obj);
            self.right = None;
            for i in 0..self.depth {
                if i < self.parents.len() {
                    if self.parents[i].is_some() {
                        combined = T::combine(&self.parents[i].unwrap(), &combined);
                        self.parents[i] = None;
                    } else {
                        self.parents[i] = Some(combined);
                        break;
                    }
                } else {
                    self.parents.push(Some(combined));
                    break;
                }
            }
        }
    }

    pub fn root_depth(&self, depth: usize, filler_hashes: VecDeque<T>) -> T {
        let mut filler = PathFiller::new_with_deque(self.depth, filler_hashes);
        let combine_left = self.left.unwrap_or(filler.next(0));
        let combine_right = self.right.unwrap_or(filler.next(0));

        let mut root = T::combine(&combine_left, &combine_right);

        let mut d = 1 as usize;

        for parent in &self.parents {
            if parent.is_none() {
                root = T::combine(&root, &filler.next(d));
            } else {
                root = T::combine(&parent.unwrap(), &filler.next(d));
            }
            d = d + 1;
        }

        while d < depth {
            root = T::combine(&root, &filler.next(d));
            d = d + 1;
        }

        root
    }

    pub fn root(&self) -> T {
        self.root_depth(self.depth, VecDeque::new())
    }

    pub fn last(&self) -> T {
        self.right.unwrap_or(self.left.unwrap())
    }

    pub fn empty_root(&self) -> T {
        self.emptyroots.empty_root(self.depth)
    }

    pub fn next_depth(&self, mut skip: usize) -> usize {
        if self.left.is_none() {
            if skip > 0 {
                skip = skip - 1;
            } else {
                return 0;
            }
        }

        if self.right.is_none() {
            if skip > 0 {
                skip = skip - 1;
            } else {
                return 0;
            }
        }

        let mut d = 1;

        for parent in &self.parents {
            if parent.is_none() {
                if skip > 0 {
                    skip = skip - 1;
                } else {
                    return d;
                }
            }
            d = d + 1;
        }

        d + skip
    }

    pub fn path(&self, filler_hashes: VecDeque<T>) -> MerklePath<T> {
        if self.left.is_none() {
            panic!("can't create an authentication path for the beginning of the tree")
        }

        let mut filler = PathFiller::new_with_deque(self.depth, filler_hashes);

        let mut path = Vec::<T>::new();
        let mut index = Vec::<bool>::new();

        if self.right.is_some() {
            index.push(true);
            path.push(self.left.unwrap())
        } else {
            index.push(false);
            path.push(filler.next(0));
        }

        let mut d = 1;

        for parent in &self.parents {
            if parent.is_none() {
                index.push(false);
                path.push(filler.next(d));
            } else {
                index.push(true);
                path.push(parent.unwrap())
            }
            d = d + 1;
        }

        while d < self.depth {
            index.push(false);
            path.push(filler.next(d));
            d = d + 1;
        }

        path.reverse();
        index.reverse();
        MerklePath::new(path, index)
    }

    pub fn witness(self) -> IncrementalWitness<T> {
        IncrementalWitness::new_with_tree(self.depth, self)
    }
}

pub struct IncrementalWitness<T: Hashable> {
    tree: IncrementalMerkleTree<T>,
    filled: Vec<T>,
    cursor: Option<IncrementalMerkleTree<T>>,
    cursor_depth: usize,
    depth: usize,
}

impl<T: Hashable> IncrementalWitness<T> {
    pub fn new(d: usize) -> Self {
        IncrementalWitness {
            tree: IncrementalMerkleTree::new(d),
            filled: Vec::new(),
            cursor: None,
            cursor_depth: 0,
            depth: d,
        }
    }

    fn new_with_tree(d: usize, tree: IncrementalMerkleTree<T>) -> Self {
        IncrementalWitness {
            tree,
            filled: Vec::new(),
            cursor: None,
            cursor_depth: 0,
            depth: d,
        }
    }

    fn partial_path(&self) -> VecDeque<T> {
        let n = self.filled.len();
        let mut uncles = VecDeque::with_capacity(n + 1);
        for hash in &self.filled {
            uncles.push_back(hash.clone())
        }

        if self.cursor.is_some() {
            uncles.push_back(self.cursor.as_ref().unwrap().root());
        }

        uncles
    }

    pub fn path(&self) -> MerklePath<T> {
        self.tree.path(self.partial_path())
    }

    pub fn element(&self) -> T {
        self.tree.last()
    }

    pub fn root(&self) -> T {
        self.tree.root_depth(self.depth, self.partial_path())
    }

    pub fn append(&mut self, obj: T) {
        if self.cursor.is_some() {
            self.cursor.as_mut().unwrap().append(obj);

            if self.cursor.as_ref().unwrap().is_complete(self.cursor_depth) {
                self.filled.push(self.cursor.as_ref().unwrap().root_depth(self.cursor_depth, VecDeque::new()));
                self.cursor = None;
            }
        } else {
            self.cursor_depth = self.tree.next_depth(self.filled.len());

            if self.cursor_depth >= self.depth {
                panic!("tree is full");
            }

            if self.cursor_depth == 0 {
                self.filled.push(obj);
            } else {
                self.cursor = Some(IncrementalMerkleTree::new(self.depth));
                self.cursor.as_mut().unwrap().append(obj);
            }
        }
    }
}