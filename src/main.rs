use merkle_mountain_range::{HashType, MerkleMountainRange};

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
        let peaks = mmr.get_peaks().unwrap();
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
