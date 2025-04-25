use alloy::primitives::keccak256;
use blake3::Hash;

pub enum HashType {
    Keccak256,
    Blake3,
}

pub struct MerkleMountainRange {
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

    pub fn top_level(&self) -> Option<u32> {
        let n = self.layers[0].len();
        if n == 0 {
            None
        } else {
            Some(usize::BITS - n.leading_zeros() - 1)
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
        println!(
            "Merkle Mountain Range With Top Level: {:?}",
            self.top_level()
        );
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

    pub fn get_peaks(&self) -> Option<Vec<Hash>> {
        let mut peaks: Vec<Hash> = Vec::new();
        if !self.layers[0].is_empty() {
            for level in 0..self.max_height {
                if self.layers[level].len() % 2 == 1 {
                    peaks.push(self.layers[level].last().unwrap().clone());
                }
            }
            return Some(peaks);
        }
        None
    }

    // 生成 SVG 图，显示每一层节点及父子连线
    pub fn generate_svg(&self) -> String {
        // 配置常量：节点半径、水平和垂直间距、画布边距
        let node_radius = 10.0;
        let h_spacing = 50.0;
        let v_spacing = 70.0;
        let margin = 20.0;

        // 计算画布宽高：以第 0 层最大节点数为基准
        let max_nodes = self.layers.get(0).map(|lvl| lvl.len()).unwrap_or(0);
        let width = margin * 2.0 + (max_nodes as f32 - 1.0) * h_spacing + node_radius * 2.0;
        let height = margin * 2.0 + (self.max_height as f32 - 1.0) * v_spacing + node_radius * 2.0;

        // SVG 头部
        let mut svg = String::new();
        svg.push_str(&format!(
            r#"<svg width="{:.0}" height="{:.0}" xmlns="http://www.w3.org/2000/svg">"#,
            width, height
        ));

        // 用于存储每个节点的中心坐标，便于后面连线查找
        let mut coords: Vec<Vec<(f32, f32)>> = Vec::with_capacity(self.max_height);

        // 1. 绘制所有节点，并记录坐标
        for (level, layer) in self.layers.iter().enumerate() {
            let y = margin + level as f32 * v_spacing + node_radius;
            let mut row_coords = Vec::with_capacity(layer.len());
            for (i, _hash) in layer.iter().enumerate() {
                // x 坐标：以水平间距均匀分布
                let x = margin + i as f32 * h_spacing + node_radius;
                // 圆形节点
                svg.push_str(&format!(
                    r#"<circle cx="{:.1}" cy="{:.1}" r="{:.1}" fill="lightblue" stroke="black" />"#,
                    x, y, node_radius
                ));
                row_coords.push((x, y));
            }
            coords.push(row_coords);
        }

        // 2. 绘制父子连线
        for (level, layer) in self.layers.iter().enumerate() {
            // 最底层或超出范围则跳过
            if level + 1 >= self.layers.len() {
                break;
            }
            let next = &coords[level + 1];
            for (i, _hash) in layer.iter().enumerate() {
                // 只有偶数索引且下一个兄弟存在时才有父节点
                if i % 2 == 0 && i + 1 < layer.len() {
                    let child_pos = coords[level][i];
                    // 父节点索引 = i / 2
                    let parent_pos = next[i / 2];
                    // 从左子到父
                    svg.push_str(&format!(
                        r#"<line x1="{:.1}" y1="{:.1}" x2="{:.1}" y2="{:.1}" stroke="gray" />"#,
                        child_pos.0, child_pos.1, parent_pos.0, parent_pos.1
                    ));
                    // 从右子到父
                    let right_child = coords[level][i + 1];
                    svg.push_str(&format!(
                        r#"<line x1="{:.1}" y1="{:.1}" x2="{:.1}" y2="{:.1}" stroke="gray" />"#,
                        right_child.0, right_child.1, parent_pos.0, parent_pos.1
                    ));
                }
            }
        }

        // 关闭 SVG
        svg.push_str("</svg>");
        svg
    }

    // 生成 SVG 图，底层第 0 层在最底部，从下往上绘制
    pub fn generate_svg2(&self) -> String {
        // 配置常量：节点半径、水平和垂直间距、画布边距
        let node_radius = 10.0;
        let h_spacing = 50.0;
        let v_spacing = 70.0;
        let margin = 20.0;

        // 总层数
        let total_layers = self.layers.len();
        // 以第 0 层节点数计算画布宽度
        let max_nodes = self.layers.get(0).map(|lvl| lvl.len()).unwrap_or(0);
        let width = margin * 2.0 + (max_nodes as f32 - 1.0) * h_spacing + node_radius * 2.0;
        // 以层数计算画布高度
        let height = margin * 2.0 + ((total_layers as f32 - 1.0) * v_spacing) + node_radius * 2.0;

        // SVG 头部
        let mut svg = String::new();
        svg.push_str(&format!(
            r#"<svg width="{:.0}" height="{:.0}" xmlns="http://www.w3.org/2000/svg">"#,
            width, height
        ));

        // 存储节点坐标
        let mut coords: Vec<Vec<(f32, f32)>> = Vec::with_capacity(total_layers);

        // 绘制节点（从下往上）
        for (level, layer) in self.layers.iter().enumerate() {
            let y = margin + ((total_layers - 1 - level) as f32) * v_spacing + node_radius;
            let mut row = Vec::with_capacity(layer.len());
            for (i, _hash) in layer.iter().enumerate() {
                let x = margin + i as f32 * h_spacing + node_radius;
                svg.push_str(&format!(
                    r#"<circle cx="{:.1}" cy="{:.1}" r="{:.1}" fill="lightblue" stroke="black" />"#,
                    x, y, node_radius
                ));
                row.push((x, y));
            }
            coords.push(row);
        }

        // 绘制父子连线
        for (level, layer) in self.layers.iter().enumerate() {
            if level + 1 >= coords.len() {
                break;
            }
            let next = &coords[level + 1];
            for i in (0..layer.len()).step_by(2) {
                if i + 1 < layer.len() {
                    let left = coords[level][i];
                    let right = coords[level][i + 1];
                    let parent = next[i / 2];
                    svg.push_str(&format!(
                        r#"<line x1="{:.1}" y1="{:.1}" x2="{:.1}" y2="{:.1}" stroke="gray" />"#,
                        left.0, left.1, parent.0, parent.1
                    ));
                    svg.push_str(&format!(
                        r#"<line x1="{:.1}" y1="{:.1}" x2="{:.1}" y2="{:.1}" stroke="gray" />"#,
                        right.0, right.1, parent.0, parent.1
                    ));
                }
            }
        }

        // 关闭 SVG
        svg.push_str("</svg>");
        svg
    }

    // 生成 SVG 图，底层第 0 层在最底部，从下往上绘制，各层节点水平居中
    pub fn generate_svg3(&self) -> String {
        // 配置常量：节点半径、水平和垂直间距、画布边距
        let node_radius = 10.0;
        let h_spacing = 50.0;
        let v_spacing = 70.0;
        let margin = 20.0;

        // 总层数
        let total_layers = self.layers.len();
        // 以第 0 层最大节点数计算画布宽度
        let max_nodes = self.layers.get(0).map(|lvl| lvl.len()).unwrap_or(0);
        let width = margin * 2.0 + (max_nodes as f32 - 1.0) * h_spacing + node_radius * 2.0;
        // 以层数计算画布高度
        let height = margin * 2.0 + ((total_layers as f32 - 1.0) * v_spacing) + node_radius * 2.0;

        // SVG 头部
        let mut svg = String::new();
        svg.push_str(&format!(
            r#"<svg width="{:.0}" height="{:.0}" xmlns="http://www.w3.org/2000/svg">"#,
            width, height
        ));

        // 存储节点坐标
        let mut coords: Vec<Vec<(f32, f32)>> = Vec::with_capacity(total_layers);

        // 绘制节点（从下往上），且每层水平居中
        for (level, layer) in self.layers.iter().enumerate() {
            let y = margin + ((total_layers - 1 - level) as f32) * v_spacing + node_radius;
            let layer_len = layer.len() as f32;
            // 计算当前层起始 x，使节点水平居中
            let x_start = margin + node_radius + ((max_nodes as f32 - layer_len) * h_spacing / 2.0);
            let mut row = Vec::with_capacity(layer.len());
            for (i, _hash) in layer.iter().enumerate() {
                let x = x_start + i as f32 * h_spacing;
                svg.push_str(&format!(
                    r#"<circle cx="{:.1}" cy="{:.1}" r="{:.1}" fill="lightblue" stroke="black" />"#,
                    x, y, node_radius
                ));
                row.push((x, y));
            }
            coords.push(row);
        }

        // 绘制父子连线
        for (level, layer) in self.layers.iter().enumerate() {
            if level + 1 >= coords.len() {
                break;
            }
            let next = &coords[level + 1];
            for i in (0..layer.len()).step_by(2) {
                if i + 1 < layer.len() {
                    let left = coords[level][i];
                    let right = coords[level][i + 1];
                    let parent = next[i / 2];
                    svg.push_str(&format!(
                        r#"<line x1="{:.1}" y1="{:.1}" x2="{:.1}" y2="{:.1}" stroke="gray" />"#,
                        left.0, left.1, parent.0, parent.1
                    ));
                    svg.push_str(&format!(
                        r#"<line x1="{:.1}" y1="{:.1}" x2="{:.1}" y2="{:.1}" stroke="gray" />"#,
                        right.0, right.1, parent.0, parent.1
                    ));
                }
            }
        }

        // 关闭 SVG
        svg.push_str("</svg>");
        svg
    }

    // 生成 SVG 图，底层第 0 层在最底部，从下往上绘制，父节点位于左右子节点连线的正上方
    pub fn generate_svg4(&self) -> String {
        // 常量配置：节点半径、水平与垂直间距、画布边距
        let node_radius = 10.0;
        let h_spacing = 50.0;
        let v_spacing = 70.0;
        let margin = 20.0;

        // 层数与最大节点数（第0层）
        let total_layers = self.layers.len();
        let max_nodes = self.layers.get(0).map(|lvl| lvl.len()).unwrap_or(0);

        // 画布尺寸
        let width = margin * 2.0 + (max_nodes as f32 - 1.0) * h_spacing + node_radius * 2.0;
        let height = margin * 2.0 + ((total_layers as f32 - 1.0) * v_spacing) + node_radius * 2.0;

        // SVG 开始
        let mut svg = String::new();
        svg.push_str(&format!(
            r#"<svg width="{:.0}" height="{:.0}" xmlns="http://www.w3.org/2000/svg">"#,
            width, height
        ));

        // 存储各层坐标
        let mut coords: Vec<Vec<(f32, f32)>> = vec![Vec::new(); total_layers];

        // 第0层节点：水平居中
        let y0 = margin + ((total_layers - 1) as f32) * v_spacing + node_radius;
        let layer0_len = self.layers[0].len() as f32;
        let x_start0 = margin + node_radius + ((max_nodes as f32 - layer0_len) * h_spacing / 2.0);
        for (i, _hash) in self.layers[0].iter().enumerate() {
            let x = x_start0 + i as f32 * h_spacing;
            // 画节点
            svg.push_str(&format!(
                r#"<circle cx="{:.1}" cy="{:.1}" r="{:.1}" fill="lightblue" stroke="black" />"#,
                x, y0, node_radius
            ));
            coords[0].push((x, y0));
        }

        // 高层节点：依据子节点连线中点定位
        for level in 1..total_layers {
            let y = margin + ((total_layers - 1 - level) as f32) * v_spacing + node_radius;
            for j in 0..self.layers[level].len() {
                // 取下方两子节点
                let left = coords[level - 1][2 * j];
                let right = coords[level - 1][2 * j + 1];
                // 计算中点
                let x = (left.0 + right.0) / 2.0;
                svg.push_str(&format!(
                    r#"<circle cx="{:.1}" cy="{:.1}" r="{:.1}" fill="lightblue" stroke="black" />"#,
                    x, y, node_radius
                ));
                coords[level].push((x, y));
            }
        }

        // 父子连线：从每层到上一层
        for level in 1..total_layers {
            for j in 0..self.layers[level].len() {
                let parent = coords[level][j];
                let left = coords[level - 1][2 * j];
                let right = coords[level - 1][2 * j + 1];
                svg.push_str(&format!(
                    r#"<line x1="{:.1}" y1="{:.1}" x2="{:.1}" y2="{:.1}" stroke="gray" />"#,
                    left.0, left.1, parent.0, parent.1
                ));
                svg.push_str(&format!(
                    r#"<line x1="{:.1}" y1="{:.1}" x2="{:.1}" y2="{:.1}" stroke="gray" />"#,
                    right.0, right.1, parent.0, parent.1
                ));
            }
        }

        // 结束 SVG
        svg.push_str("</svg>");
        svg
    }
}
