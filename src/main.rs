use alloy::primitives::keccak256;
use blake3::Hash;

enum HashType {
    Keccak256,
    Blake3,
}

struct MerkleMountainRange {
    // 存储各层节点
    layers: Vec<Vec<Hash>>,
    // 最大层数
    max_height: usize,
    // 哈希算法
    hash_type: HashType,
}

impl MerkleMountainRange {
    // 创建新的MMR，指定最大高度
    pub fn new(max_height: usize, hash_type: HashType) -> Self {
        // 创建max_height
        let mut layers = Vec::with_capacity(max_height);
        for _ in 0..max_height {
            layers.push(Vec::new());
        }
        MerkleMountainRange {
            layers,
            max_height,
            hash_type,
        }
    }

    pub fn compute_hash(&self, data: &[u8]) -> Hash {
        match self.hash_type {
            HashType::Keccak256 => {
                let hash = keccak256(data);
                let bytes: [u8; 32] = hash.into();
                Hash::from(bytes)
            }
            HashType::Blake3 => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(data);
                hasher.finalize()
            }
        }
    }

    // 向MMR添加叶子节点哈希值
    pub fn append_leaf(&mut self, hash: Hash) {
        // 将叶子节点哈希值添加到第0层
        self.layers[0].push(hash);

        // 尝试构建高层节点
        self.build_peaks();
    }

    // 向MMR添加叶子节点（含原始数据）
    pub fn append_data(&mut self, data: &[u8]) {
        let hash = self.compute_hash(data);
        self.append_leaf(hash);
    }

    // 构建更高层节点（山峰）
    fn build_peaks(&mut self) {
        // 从第0层开始向上构建
        for level in 0..self.max_height {
            let current_level_size = self.layers[level].len();

            // 如果当前层有偶数个节点，则构建上一层新节点
            if current_level_size >= 2 && current_level_size % 2 == 0 {
                // 获取最后两个节点
                let left_child = self.layers[level][current_level_size - 2];
                let right_child = self.layers[level][current_level_size - 1];

                // 计算父节点哈希值
                let parent_hash = self.hash_node_pair(left_child, right_child);

                // 将父节点添加到上一层
                self.layers[level + 1].push(parent_hash);
            } else {
                // 如果当前层没有足够的节点构建父节点，说明已到达最高层，需跳出循环
                break;
            }
        }
    }

    // 计算两个节点上供后形成的父节点的哈希值
    fn hash_node_pair(&self, left: Hash, right: Hash) -> Hash {
        // 预分配固定大小数组（64字节 = 32 + 32）
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(left.as_bytes());
        combined[32..].copy_from_slice(right.as_bytes());

        self.compute_hash(&combined)
    }

    // 获取指定层级的节点
    pub fn get_node(&self, level: usize, index: usize) -> Option<Hash> {
        // 超出最大高度
        if level > self.max_height {
            return None;
        }

        if index < self.layers[level].len() {
            Some(self.layers[level][index])
        } else {
            None
        }
    }

    // 获取指定层级的所有节点
    pub fn get_level(&self, level: usize) -> Option<&Vec<Hash>> {
        // 超出最大高度
        if level > self.max_height {
            return None;
        }

        Some(&self.layers[level])
    }

    // 获取MMR的根节点（如果存在）
    pub fn compute_root(&self) -> Option<Hash> {
        // 从最高层开始，找到第一个非空层，返回其最后一个节点
        let mut peak: Vec<&Hash> = Vec::new();
        if !self.layers[0].is_empty() {
            for level in 0..self.max_height {
                if self.layers[level].len() % 2 == 1 {
                    peak.push(self.layers[level].last().unwrap());
                }
            }
            println!(
                "peak: {:?}",
                peak.iter()
                    .map(|hash| hex::encode(&hash.as_bytes()[0..6]))
                    .collect::<Vec<_>>()
            );
            let mut root = peak[0].clone();
            for i in 1..peak.len() {
                root = self.hash_node_pair(root, peak[i].clone());
            }
            return Some(root);
        }
        None
    }

    // 生成指定叶子节点的包含证明（返回构建证明所需的哈希值）
    pub fn generate_proof(&self, leaf_index: usize) -> Option<Vec<Hash>> {
        // 索引超出范围
        if leaf_index >= self.layers[0].len() {
            return None;
        }

        let mut proof = Vec::new();
        let mut current_index = leaf_index;

        // 从叶子层开始向上构建证明
        for level in 0..self.max_height {
            // 若当前索引对应本层的peak节点，则退出循环
            if current_index == self.layers[level].len() - 1 && current_index % 2 == 0 {
                break;
            }
            // 确定兄弟节点的索引，要么在左边，要么在右边
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            proof.push(self.layers[level][sibling_index]);
            // 计算父节点的索引
            current_index = current_index / 2;
        }

        Some(proof)
    }

    // 验证包含证明
    pub fn verify_proof(
        &self,
        root: Hash,
        peaks: &[Hash],
        proof: &[Hash],
        leaf: Hash,
        leaf_index: i32,
    ) -> bool {
        let mut current_hash = leaf;
        let mut current_root: Hash = peaks[0].clone();
        let mut current_index = leaf_index;
        for &sibling_hash in proof {
            // 确定与兄弟哈希值之间的顺序
            let (left, right) = if current_index % 2 == 0 {
                (current_hash, sibling_hash)
            } else {
                (sibling_hash, current_hash)
            };

            // 计算父节点的索引与哈希值
            current_index = current_index / 2;
            current_hash = self.hash_node_pair(left, right);
        }
        for i in 1..peaks.len() {
            current_root = self.hash_node_pair(current_root, peaks[i].clone());
        }
        // 验证最终哈希值是否与根哈希值匹配
        peaks.contains(&current_hash) && root == current_root
    }

    // 打印MMR结构，用于调试
    pub fn print_tree(&self) {
        println!("Merkle Mountain Range:");
        for level in 0..self.max_height {
            if !self.layers[level].is_empty() {
                print!("Level {}: ", level);
                for (idx, hash) in self.layers[level].iter().enumerate() {
                    // 只显示前N个字节的十六进制表示
                    let hash_str = hex::encode(&hash.as_bytes()[0..6]);
                    print!("{}#{}: {} ", level, idx, hash_str);
                }
                println!();
            }
        }
    }

    fn get_peak_hash(&self) -> Option<Vec<Hash>> {
        let mut peak: Vec<Hash> = Vec::new();
        if !self.layers[0].is_empty() {
            for level in 0..self.max_height {
                if self.layers[level].len() % 2 == 1 {
                    peak.push(self.layers[level].last().unwrap().clone());
                }
            }
            return Some(peak);
        }
        None
    }
}

// 示例用法
fn main() {
    // 创建一个最大高度为9的MMR
    let mut mmr = MerkleMountainRange::new(9, HashType::Blake3);

    // 添加一些叶子节点
    for i in 1..16 {
        let v = i.to_string();
        let data = v.as_bytes();
        mmr.append_data(data);
    }

    // 打印MMR结构
    mmr.print_tree();

    // 获取根节点
    if let Some(root) = mmr.compute_root() {
        println!("Root: {}", hex::encode(&root.as_bytes()[0..6]));
    }

    // 生成第N个叶子节点的包含证明
    let leaf_index = 5;
    if let Some(proof) = mmr.generate_proof(leaf_index) {
        println!("Proof for leaf {}:", leaf_index);
        for (i, hash) in proof.iter().enumerate() {
            println!("Proof item {}: {}", i, hex::encode(&hash.as_bytes()[0..6]));
        }
        let peaks = mmr.get_peak_hash().unwrap();
        // 验证证明
        let leaf = mmr.get_node(0, leaf_index).unwrap();
        let root = mmr.compute_root().unwrap();
        let is_valid = mmr.verify_proof(root, &peaks, &proof, leaf, leaf_index as i32);
        println!(
            "Proof verification: {}",
            if is_valid { "Valid" } else { "Invalid" }
        );
    }
}
