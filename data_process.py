import pandas as pd
import numpy as np
import ast
from typing import List, Tuple, Dict, Any, Optional

class ProtocolDataProcessor:
    def __init__(self, max_len=64, min_packets=10, min_group_size=5):
        self.max_len = max_len
        self.min_packets = min_packets
        self.min_group_size = min_group_size  # 新增：每组至少需要的原始样本数
    
    def hex_to_bytes(self, hex_str: str) -> bytes:
        """将16进制字符串转换为字节序列"""
        hex_str = hex_str.strip().replace(' ', '').lower()
        if hex_str.startswith('0x'):
            hex_str = hex_str[2:]
        if len(hex_str) % 2 != 0:
            hex_str = '0' + hex_str
        return bytes.fromhex(hex_str)
    
    def parse_segments(self, segment_str: str) -> List[Tuple[int, int]]:
        """解析Segment字符串"""
        try:
            segments = ast.literal_eval(segment_str)
            return [(int(s[0]), int(s[1])) for s in segments]
        except:
            return []
    
    def parse_field_names(self, field_names_str: str) -> List[str]:
        """解析Field Names字符串"""
        try:
            field_names = ast.literal_eval(field_names_str)
            return [str(name) for name in field_names]
        except:
            return []
    
    def truncate_segments(self, segments: List[Tuple[int, int]], max_len: int) -> List[Tuple[int, int]]:
        """将Segment列表截断到max_len"""
        truncated = []
        for start, end in segments:
            if start >= max_len:
                continue
            end = min(end, max_len)
            if start < end:
                truncated.append((start, end))
        return truncated
    
    def segments_and_fields_to_key(self, segments: List[Tuple[int, int]], field_names: List[str]) -> str:
        """将Segment列表和Field Names列表转换为一个唯一的、标准化的字符串key"""
        sorted_segments = sorted(segments)
        # 确保segments和field_names长度一致
        if len(sorted_segments) != len(field_names):
            # 如果长度不一致，取较短的长度
            min_len = min(len(sorted_segments), len(field_names))
            sorted_segments = sorted_segments[:min_len]
            field_names = field_names[:min_len]
        
        # 创建包含segments和field_names的复合key
        key = str((sorted_segments, field_names))
        return key
    
    def load_data(self, csv_file: str) -> pd.DataFrame:
        """加载CSV数据"""
        df = pd.read_csv(csv_file)
        # 添加协议列（从文件名推断）
        protocol_name = csv_file.split('/')[-1].split('_')[0] if '_' in csv_file.split('/')[-1] else 'unknown'
        df['protocol'] = protocol_name.lower()
        print(f"加载数据完成，共 {len(df)} 条记录，协议: {protocol_name}")
        return df
    
    def group_by_segments_and_fields(self, df: pd.DataFrame) -> Dict[str, Dict[str, List]]:
        """
        按截断后的Segment和Field Names严格分组
        只有Segments和Field Names都完全一样才能分到一组
        """
        groups = {}
        
        for _, row in df.iterrows():
            hex_str = str(row['Hex'])
            segment_str = str(row['Segment'])
            field_names_str = str(row['Field Names'])
            
            raw_segments = self.parse_segments(segment_str)
            field_names = self.parse_field_names(field_names_str)
            
            if not raw_segments or not field_names:
                continue
            
            truncated_segments = self.truncate_segments(raw_segments, self.max_len)
            if not truncated_segments:
                continue
            
            # 同步截断field_names，保持与truncated_segments对应
            original_len = len(raw_segments)
            truncated_len = len(truncated_segments)
            if truncated_len < original_len:
                # 找出被截断的segments对应的field_names索引
                truncated_field_names = []
                for i, (start, end) in enumerate(raw_segments):
                    if start < self.max_len and i < len(field_names):
                        truncated_field_names.append(field_names[i])
                field_names = truncated_field_names
            
            # 创建基于segments和field_names的复合key
            composite_key = self.segments_and_fields_to_key(truncated_segments, field_names)
            
            if composite_key not in groups:
                groups[composite_key] = {
                    'packets': [], 
                    'labels': [], 
                    'original_segments': [],
                    'field_names': field_names  # 保存field_names信息
                }
            
            packet_bytes = self.hex_to_bytes(hex_str)
            packet_bytes = packet_bytes[:self.max_len]  # 截断报文
            
            groups[composite_key]['packets'].append(packet_bytes)
            groups[composite_key]['original_segments'].append(raw_segments)
            
            label = self.segments_to_boundary_labels(truncated_segments, self.max_len)
            groups[composite_key]['labels'].append(label)
        
        print(f"\n按Segments和Field Names严格分组完成，共发现 {len(groups)} 种类型:")
        #for composite_key, data in groups.items():
        #    print(f"  类型样本数: {len(data['packets'])}, Key: {composite_key[:100]}...")
        
        return groups
    
    def segments_to_boundary_labels(self, segments: List[Tuple[int, int]], max_len: int) -> np.ndarray:
        """将Segment列表转换为边界标签向量 (B标记)"""
        labels = np.zeros(max_len, dtype=np.float32)
        for start, end in segments:
            if 0 <= start < max_len:
                labels[start] = 1.0
        return labels
    
    def build_matrix(self, sampled_packets: List[bytes]) -> Tuple[np.ndarray, np.ndarray]:
        """
        构建 N×L 字节矩阵
        sampled_packets: 从一个组中随机采样的10条报文
        """
        N = len(sampled_packets)
        L = self.max_len
        X = np.full((N, L), 0, dtype=np.uint8)
        mask = np.zeros((N, L), dtype=bool)
        
        for i, p in enumerate(sampled_packets):
            actual_len = min(len(p), self.max_len)
            X[i, :actual_len] = list(p)[:actual_len]
            mask[i, :actual_len] = True
        
        return X, mask
    
    def compute_position_features(self, X: np.ndarray, mask: np.ndarray) -> np.ndarray:
        """计算每个偏移位置的特征"""
        N, L = X.shape
        features = np.zeros((L, 4))
        
        # 预计算熵
        entropies = np.zeros(L)
        for j in range(L):
            valid_vals = X[:, j][mask[:, j]]
            if len(valid_vals) == 0:
                continue
            counts = np.bincount(valid_vals, minlength=256)
            probs = counts / len(valid_vals)
            probs = probs[probs > 0]
            entropies[j] = -np.sum(probs * np.log2(probs + 1e-10))
        
        for j in range(L):
            valid_vals = X[:, j][mask[:, j]]
            if len(valid_vals) == 0:
                continue
            
            features[j, 0] = entropies[j]  # 熵
            if len(valid_vals) > 1:
                features[j, 1] = np.std(valid_vals) / 255.0  # 标准差
            if j > 0:
                features[j, 2] = abs(entropies[j] - entropies[j-1])  # 突变强度
            features[j, 3] = (valid_vals == 0).mean()  # 零字节比例
        
        return features
    
    def _calculate_adaptive_samples(self, num_original_packets: int, 
                                   base_samples: int = 10,
                                   thresholds: Optional[Dict] = None,
                                   multipliers: Optional[Dict] = None,
                                   max_samples: int = 30) -> int:
        """
        自适应计算训练样本数 - 渐进式增长策略 (配置化版本)
        
        策略: 所有阈值和倍数都从配置文件读取,方便灵活调整
        
        Args:
            num_original_packets: 原始样本数量
            base_samples: 基础样本数(默认10)
            thresholds: 阈值配置字典
            multipliers: 倍数配置字典
            max_samples: 最大样本数
            
        Returns:
            int: 应生成的训练样本数
        """
        # 使用默认值(兼容旧版调用)
        if thresholds is None:
            thresholds = {
                'very_low': 500,
                'low': 1000,
                'medium': 2000,
                'high': 3000
            }
        
        if multipliers is None:
            multipliers = {
                'very_low': 1.0,
                'low': 1.5,
                'medium': 2.0,
                'high': 2.5,
                'very_high': 3.0
            }
        
        # 根据原始样本数选择倍数
        if num_original_packets < thresholds['very_low']:
            multiplier = multipliers['very_low']
        elif num_original_packets < thresholds['low']:
            multiplier = multipliers['low']
        elif num_original_packets < thresholds['medium']:
            multiplier = multipliers['medium']
        elif num_original_packets < thresholds['high']:
            multiplier = multipliers['high']
        else:
            multiplier = multipliers['very_high']
        
        # 计算样本数并应用上限
        num_samples = int(base_samples * multiplier)
        return min(num_samples, max_samples)
    
    def _generate_with_random_sampling(self, packets: List[bytes], labels: List[np.ndarray], 
                                      num_samples: int, X_list: List, mask_list: List, 
                                      labels_list: List) -> None:
        """
        使用随机采样生成训练样本 (快速策略,适用于大样本量)
        
        核心思想: 多次随机抽取,天然保证多样性
        """
        num_packets = len(packets)
        
        for i in range(num_samples):
            # 随机选择 min_packets 个报文 (有放回)
            selected_indices = np.random.choice(
                num_packets, 
                size=self.min_packets, 
                replace=True
            )
            
            sampled_packets = [packets[idx] for idx in selected_indices]
            sampled_labels = [labels[idx] for idx in selected_indices]
            
            # 构建矩阵和标签
            X, mask = self.build_matrix(sampled_packets)
            stacked_labels = np.stack(sampled_labels, axis=0)
            avg_labels = np.mean(stacked_labels, axis=0)
            
            X_list.append(X)
            mask_list.append(mask)
            labels_list.append(avg_labels)
    
    def _generate_with_diversity_sampling(self, packets: List[bytes], labels: List[np.ndarray],
                                         num_samples: int, X_list: List, mask_list: List,
                                         labels_list: List) -> None:
        """
        使用多样性采样生成训练样本 (精确策略,适用于小样本量)
        
        策略: 
        - 第1个样本: 贪心选择多样性最高的组合
        - 后续样本: 从多样性前50%中随机选择
        """
        # 计算每个报文的多样性分数
        diversity_scores = self.compute_packet_diversity(packets)
        
        # 使用现有的 select_diverse_packets 方法
        selected_combinations = self.select_diverse_packets(
            packets, num_samples, diversity_scores
        )
        
        # 生成样本
        for selected_indices in selected_combinations:
            sampled_packets = [packets[idx] for idx in selected_indices]
            sampled_labels = [labels[idx] for idx in selected_indices]
            
            X, mask = self.build_matrix(sampled_packets)
            stacked_labels = np.stack(sampled_labels, axis=0)
            avg_labels = np.mean(stacked_labels, axis=0)
            
            X_list.append(X)
            mask_list.append(mask)
            labels_list.append(avg_labels)
    
    def generate_training_samples(self, groups: Dict[str, Dict[str, List]], 
                                adaptive_sampling: bool = True,
                                base_samples: int = 10,
                                diversity_threshold: int = 1000,
                                adaptive_thresholds: Optional[Dict] = None,
                                adaptive_multipliers: Optional[Dict] = None,
                                max_samples_per_format: int = 30,
                                min_samples_per_format: int = 5,
                                min_samples_per_group: int = 1,
                                max_samples_per_group: int = 50,
                                sampling_factor: float = 2.0) -> Tuple[List[np.ndarray], List[np.ndarray], List[np.ndarray]]:
        """
        从分组数据中生成训练样本 - 支持自适应采样 (配置化版本)
        
        Args:
            groups: 按Segment类型分组的数据
            adaptive_sampling: 是否启用自适应采样
            base_samples: 基础样本数(自适应采样时使用)
            diversity_threshold: 多样性采样阈值(超过此值使用随机采样)
            adaptive_thresholds: 自适应阈值配置字典
            adaptive_multipliers: 自适应倍数配置字典
            max_samples_per_format: 单格式组最大样本数
            min_samples_per_format: 单格式组最小样本数
            min_samples_per_group: 每个组最少生成的样本数(旧版兼容)
            max_samples_per_group: 每个组最多生成的样本数(旧版兼容)
            sampling_factor: 采样因子(旧版兼容)
            
        Returns:
            (X_list, mask_list, labels_list): 训练样本列表
        """
        X_list = []
        mask_list = []
        labels_list = []
        
        total_samples_generated = 0
        format_count = 0
        
        for seg_key, data in groups.items():
            packets = data['packets']
            labels = data['labels']
            num_original_packets = len(packets)
            
            # 跳过样本数太少的组
            if num_original_packets < self.min_group_size:
                continue
            
            format_count += 1
            
            # *** 核心改进: 自适应计算样本数 ***
            if adaptive_sampling:
                num_samples_to_generate = self._calculate_adaptive_samples(
                    num_original_packets, 
                    base_samples=base_samples,
                    thresholds=adaptive_thresholds,
                    multipliers=adaptive_multipliers,
                    max_samples=max_samples_per_format
                )
                # 应用最小值保护
                num_samples_to_generate = max(num_samples_to_generate, min_samples_per_format)
            else:
                # 兼容旧版: 使用原有逻辑
                num_samples_to_generate = int(min_samples_per_group + sampling_factor * num_original_packets)
                num_samples_to_generate = min(num_samples_to_generate, max_samples_per_group)
                num_samples_to_generate = max(num_samples_to_generate, min_samples_per_group)
                
                if num_original_packets < self.min_packets:
                    num_samples_to_generate = 0
            
            # *** 核心改进: 根据样本量选择采样策略 ***
            if num_original_packets < diversity_threshold:
                strategy = "多样性采样"
                self._generate_with_diversity_sampling(
                    packets, labels, num_samples_to_generate,
                    X_list, mask_list, labels_list
                )
            else:
                strategy = "随机采样"
                self._generate_with_random_sampling(
                    packets, labels, num_samples_to_generate,
                    X_list, mask_list, labels_list
                )
            
            total_samples_generated += num_samples_to_generate
            
            print(f"格式 {format_count}: {seg_key[:50]}...")
            print(f"  原始样本: {num_original_packets}, "
                  f"生成样本: {num_samples_to_generate}, "
                  f"策略: {strategy}")
        
        print(f"\n{'='*60}")
        print(f"训练样本生成完成!")
        print(f"  总格式数: {format_count}")
        print(f"  总训练样本: {total_samples_generated}")
        print(f"  平均每格式: {total_samples_generated/max(format_count,1):.1f}个")
        print(f"{'='*60}\n")
        
        return X_list, mask_list, labels_list
    
    def generate_training_samples_old(self, groups: Dict[str, Dict[str, List]], 
                                     min_samples_per_group: int = 1,
                                     max_samples_per_group: int = 50,
                                     sampling_factor: float = 2.0) -> Tuple[List[np.ndarray], List[np.ndarray], List[np.ndarray]]:
        """
        【旧版方法 - 已弃用,保留用于兼容】
        从分组数据中生成训练样本
        
        请使用 generate_training_samples(adaptive_sampling=True) 代替
        """
        X_list = []
        mask_list = []
        labels_list = []
        
        for seg_key, data in groups.items():
            packets = data['packets']
            labels = data['labels']
            num_original_packets = len(packets)
            
            if num_original_packets < self.min_group_size:
                continue
            
            num_samples_to_generate = int(min_samples_per_group + sampling_factor * num_original_packets)
            num_samples_to_generate = min(num_samples_to_generate, max_samples_per_group)
            num_samples_to_generate = max(num_samples_to_generate, min_samples_per_group)
            
            if num_original_packets < self.min_packets:
                num_samples_to_generate = 0
            
            print(f"Segment类型: {seg_key}")
            print(f"  原始报文数: {num_original_packets}, 计划生成样本数: {num_samples_to_generate}")
            
            for _ in range(num_samples_to_generate):
                # 核心修改：当原始样本少于min_packets个时，先包含所有样本，再随机补充
                if num_original_packets < self.min_packets:
                    # 1. 先将所有原始样本都加入采样列表
                    sampled_packets = packets.copy()  # 复制所有原始数据包
                    sampled_labels = labels.copy()   # 复制所有原始标签
                    
                    # 2. 计算还需要随机补充多少个样本
                    num_to_sample = self.min_packets - num_original_packets
                    
                    # 3. 如果还需要补充样本（即原始样本数 < min_packets）
                    if num_to_sample > 0:
                        # 从原始样本中有放回地随机选择 num_to_sample 个样本进行补充
                        additional_indices = np.random.choice(num_original_packets, size=num_to_sample, replace=True)
                        # 将选中的样本追加到列表中
                        for idx in additional_indices:
                            sampled_packets.append(packets[idx])
                            sampled_labels.append(labels[idx])
                    
                    # 现在 sampled_packets 和 sampled_labels 的长度应该正好是 self.min_packets
                    assert len(sampled_packets) == self.min_packets, f"采样后数据包数量错误: {len(sampled_packets)}"
                    assert len(sampled_labels) == self.min_packets, f"采样后标签数量错误: {len(sampled_labels)}"
                
                else:
                    # 对于原始样本数 >= min_packets 的情况，保持原有逻辑：有放回随机采样min_packets条报文
                    indices = np.random.choice(num_original_packets, size=self.min_packets, replace=True)
                    sampled_packets = [packets[i] for i in indices]
                    sampled_labels = [labels[i] for i in indices]
                
                # 构建字节矩阵和掩码
                X, mask = self.build_matrix(sampled_packets)  # X: [min_packets, 64], mask: [min_packets, 64]
                
                # 生成标签 (取采样报文标签的平均值) 还好这里所有的字段边界标签都是分类好的，mean之后也一样
                stacked_labels = np.stack(sampled_labels, axis=0)  # [min_packets, 64]
                avg_labels = np.mean(stacked_labels, axis=0)  # [64]
                
                # 添加到训练集
                X_list.append(X)
                mask_list.append(mask)
                labels_list.append(avg_labels)
        
        return X_list, mask_list, labels_list

    def generate_validation_samples(self, groups: Dict[str, Dict[str, List]], 
                                  balanced_sampling: bool = True,
                                  max_samples_per_group: Optional[int] = None) -> Tuple[List[np.ndarray], List[np.ndarray], List[np.ndarray]]:
        """
        从分组数据中生成验证样本 - 支持平衡采样
        
        Args:
            groups: 按Segment类型分组的数据
            balanced_sampling: 是否使用平衡采样（每个格式生成相同数量的样本）
            max_samples_per_group: 每个格式最多生成的样本数（平衡采样时使用）
            
        Returns:
            (X_list, mask_list, labels_list): 验证样本列表
        """
        X_list = []
        mask_list = []
        labels_list = []
        
        # 计算平衡采样时每个格式应生成的样本数
        if balanced_sampling and max_samples_per_group is None:
            # 找到最小的合格组大小，以此为基准进行平衡
            valid_group_sizes = [len(data['packets']) // self.min_packets 
                               for data in groups.values() 
                               if len(data['packets']) >= self.min_group_size]
            if valid_group_sizes:
                max_samples_per_group = min(max(1, min(valid_group_sizes)), 10)  # 限制在合理范围内
            else:
                max_samples_per_group = 1
        
        for seg_key, data in groups.items():
            packets = data['packets']
            labels = data['labels']
            num_original_packets = len(packets)
            
            # 跳过样本数太少的组（使用配置化的阈值）
            if num_original_packets < self.min_group_size:
                continue
            
            print(f"处理验证样本 - Segment类型: {seg_key}, 原始报文数: {num_original_packets}")
            
            # 计算需要生成多少个验证样本
            if balanced_sampling and max_samples_per_group is not None:
                # 平衡采样：每个格式生成相同数量的样本
                num_samples = max_samples_per_group
                print(f"  平衡采样模式，生成 {num_samples} 个样本")
            else:
                # 原有策略：根据数据量决定样本数
                num_samples = max(1, num_original_packets // self.min_packets)
                print(f"  比例采样模式，生成 {num_samples} 个样本")
            
            # 为每个Segment类型生成指定数量的验证样本
            for i in range(num_samples):
                if balanced_sampling:
                    # 平衡采样：随机选择报文，避免偏向
                    indices = np.random.choice(num_original_packets, size=self.min_packets, replace=True)
                    sampled_packets = [packets[idx] for idx in indices]
                    sampled_labels = [labels[idx] for idx in indices]
                else:
                    # 原有策略：顺序采样
                    start_idx = i * self.min_packets
                    end_idx = min((i + 1) * self.min_packets, num_original_packets)
                    
                    sampled_packets = packets[start_idx:end_idx]
                    sampled_labels = labels[start_idx:end_idx]
                    
                    # 如果当前样本的报文数量不足，则复制补充
                    if len(sampled_packets) < self.min_packets:
                        num_to_sample = self.min_packets - len(sampled_packets)
                        additional_indices = np.random.choice(
                            len(sampled_packets), 
                            size=num_to_sample, 
                            replace=True
                        )
                        for idx in additional_indices:
                            sampled_packets.append(sampled_packets[idx])
                            sampled_labels.append(sampled_labels[idx])
                
                # 构建字节矩阵和掩码
                X, mask = self.build_matrix(sampled_packets)
                
                # 生成标签
                stacked_labels = np.stack(sampled_labels, axis=0)
                avg_labels = np.mean(stacked_labels, axis=0)
                
                # 添加到验证集
                X_list.append(X)
                mask_list.append(mask)
                labels_list.append(avg_labels)
        
        return X_list, mask_list, labels_list
    
    def process_all_data(self, csv_file: str, 
                        samples_per_group: int = 10,
                        adaptive_sampling: bool = True,
                        diversity_threshold: int = 1000,
                        adaptive_thresholds: Optional[Dict] = None,
                        adaptive_multipliers: Optional[Dict] = None,
                        max_samples_per_format: int = 30,
                        min_samples_per_format: int = 5) -> Tuple[List[np.ndarray], List[np.ndarray], List[np.ndarray]]:
        """
        处理所有数据，生成训练集 - 支持自适应采样
        
        Args:
            csv_file: CSV文件路径
            samples_per_group: 基础样本数(自适应采样的基准)
            adaptive_sampling: 是否启用自适应采样
            diversity_threshold: 多样性采样阈值(超过此值使用随机采样)
        
        Returns:
            (X_list, mask_list, labels_list): 训练样本
        """
        # 1. 加载数据
        df = self.load_data(csv_file)
        
        # 2. 按截断后的Segment和Field Names严格分组
        groups = self.group_by_segments_and_fields(df)
        
        # 3. 生成训练样本 (使用自适应策略)
        X_list, mask_list, labels_list = self.generate_training_samples(
            groups,
            adaptive_sampling=adaptive_sampling,
            base_samples=samples_per_group,
            diversity_threshold=diversity_threshold,
            adaptive_thresholds=adaptive_thresholds,
            adaptive_multipliers=adaptive_multipliers,
            max_samples_per_format=max_samples_per_format,
            min_samples_per_format=min_samples_per_format
        )
        
        return X_list, mask_list, labels_list

    def compute_packet_diversity(self, packets: List[bytes]) -> np.ndarray:
        """
        计算报文的多样性分数（基于字节分布的熵）
        
        Args:
            packets: 报文字节序列列表
            
        Returns:
            np.ndarray: 每个报文的多样性分数
        """
        diversity_scores = []
        
        for packet in packets:
            # 计算字节分布熵作为多样性指标
            if len(packet) == 0:
                diversity_scores.append(0.0)
                continue
                
            # 截断到max_len
            packet_bytes = packet[:self.max_len]
            byte_counts = np.bincount(list(packet_bytes), minlength=256)
            byte_probs = byte_counts / len(packet_bytes)
            byte_probs = byte_probs[byte_probs > 0]
            
            # 计算熵
            entropy = -np.sum(byte_probs * np.log2(byte_probs + 1e-10))
            diversity_scores.append(entropy)
        
        return np.array(diversity_scores)
    
    def select_diverse_packets(self, packets: List[bytes], num_samples: int, 
                              diversity_scores: np.ndarray) -> List[List[int]]:
        """
        Select packet combinations with maximum diversity
        
        Args:
            packets: List of packets
            num_samples: Number of samples to generate
            diversity_scores: Diversity score for each packet
            
        Returns:
            List[List[int]]: List of selected packet indices for each sample
        """
        n_packets = len(packets)
        selected_combinations = []
        
        for sample_idx in range(num_samples):
            if sample_idx == 0:
                # First sample: greedily select combination with highest diversity
                selected_indices = []
                remaining_indices = list(range(n_packets))
                
                # First select packet with highest diversity
                first_idx = np.argmax(diversity_scores)
                selected_indices.append(first_idx)
                remaining_indices.remove(int(first_idx))
                
                # Iteratively select packet with maximum difference from already selected
                while len(selected_indices) < min(self.min_packets, n_packets):
                    if not remaining_indices:
                        break
                        
                    max_diversity = -1
                    best_idx = None
                    
                    for candidate_idx in remaining_indices:
                        # Calculate difference with selected packets
                        diversity_sum = 0
                        for selected_idx in selected_indices:
                            # Calculate byte difference between two packets
                            packet1 = packets[candidate_idx][:self.max_len]
                            packet2 = packets[selected_idx][:self.max_len]
                            
                            # Calculate byte-level difference
                            min_len = min(len(packet1), len(packet2))
                            if min_len > 0:
                                diff_ratio = np.sum(np.array(list(packet1[:min_len])) != 
                                                   np.array(list(packet2[:min_len]))) / min_len
                            else:
                                diff_ratio = 0
                            
                            diversity_sum += diff_ratio
                        
                        # Consider both packet's own diversity and difference from selected packets
                        total_diversity = diversity_scores[candidate_idx] + diversity_sum
                        
                        if total_diversity > max_diversity:
                            max_diversity = total_diversity
                            best_idx = candidate_idx
                    
                    if best_idx is not None:
                        selected_indices.append(best_idx)
                        remaining_indices.remove(best_idx)
                    else:
                        break
                
                # If selected packet count is insufficient, supplement with replacement
                if len(selected_indices) < self.min_packets:
                    while len(selected_indices) < self.min_packets:
                        # Prefer selecting high-diversity packets for supplementation
                        available_indices = list(range(n_packets))
                        sorted_by_diversity = sorted(available_indices, 
                                                   key=lambda x: diversity_scores[x], 
                                                   reverse=True)
                        for idx in sorted_by_diversity:
                            if len(selected_indices) < self.min_packets:
                                selected_indices.append(idx)
                            else:
                                break
                        
            else:
                # Subsequent samples: introduce randomness while ensuring some diversity
                # Randomly select from top 50% by diversity
                sorted_indices = np.argsort(diversity_scores)[::-1]
                top_half = sorted_indices[:max(self.min_packets, len(sorted_indices)//2)]
                selected_indices = np.random.choice(top_half, size=min(self.min_packets, len(top_half)), 
                                                   replace=True).tolist()
                
                # Supplement to min_packets
                while len(selected_indices) < self.min_packets:
                    selected_indices.append(np.random.choice(top_half))
            
            selected_combinations.append(selected_indices)
        
        return selected_combinations
    
    def generate_test_samples_with_diversity(self, groups: Dict[str, Dict[str, List]], 
                                           max_samples_per_group: Optional[int] = None) -> Tuple[List[np.ndarray], List[np.ndarray], List[np.ndarray], Dict[str, Dict]]:
        """
        生成测试样本 - 优先选择多样性最大的报文组合
        
        Args:
            groups: 按Segment类型分组的数据
            max_samples_per_group: 每个格式最多生成的样本数
            
        Returns:
            (X_list, mask_list, labels_list, group_metadata): 测试样本和元数据
        """
        X_list = []
        mask_list = []
        labels_list = []
        group_metadata = {}  # 保存每个组的元数据，用于后续集成预测
        
        if max_samples_per_group is None:
            # 确保测试样本数不会过少，同时保持多样性
            max_samples_per_group = max(5, min(20, 100 // max(1, len(groups))))  # 每个格式至少5个样本
        
        for seg_key, data in groups.items():
            packets = data['packets']
            labels = data['labels']
            num_original_packets = len(packets)
            
            # 跳过样本数太少的组
            if num_original_packets < self.min_group_size:
                continue
            
            print(f"处理测试样本 - Segment类型: {seg_key}, 原始报文数: {num_original_packets}")
            
            # 计算报文多样性
            diversity_scores = self.compute_packet_diversity(packets)
            
            # 确定生成样本数 - 保持与训练集合理的比例，同时保证足够的样本数量
            # 基本原则：每个格式至少生成 max_samples_per_group 个样本，但不超过数据允许的最大值
            min_required_samples = max_samples_per_group  # 每个格式的最少样本数
            max_possible_samples = max(1, num_original_packets // self.min_packets)  # 数据允许的最大样本数
            
            # 取两者的最小值，但确保至少有1个样本
            num_samples = max(1, min(min_required_samples, max_possible_samples))
            
            # 如果原始数据充足，允许生成更多样本以提高评估的稳定性
            if num_original_packets >= self.min_packets * min_required_samples:
                num_samples = min_required_samples
            
            print(f"  计划生成 {num_samples} 个多样性样本（最少要求: {min_required_samples}, 数据允许: {max_possible_samples}）")
            
            # 选择多样性最大的报文组合
            selected_combinations = self.select_diverse_packets(packets, num_samples, diversity_scores)
            
            # 记录组元数据
            group_metadata[seg_key] = {
                'diversity_scores': diversity_scores,
                'selected_combinations': selected_combinations,
                'sample_weights': [],  # 将在生成样本时计算
                'num_original_packets': num_original_packets
            }
            
            # 为每个选中的组合生成样本
            for i, selected_indices in enumerate(selected_combinations):
                sampled_packets = [packets[idx] for idx in selected_indices]
                sampled_labels = [labels[idx] for idx in selected_indices]
                
                # 计算当前样本的权重（基于选中报文的平均多样性）
                sample_diversity = np.mean([diversity_scores[idx] for idx in selected_indices])
                group_metadata[seg_key]['sample_weights'].append(sample_diversity)
                
                # 构建字节矩阵和掩码
                X, mask = self.build_matrix(sampled_packets)
                
                # 生成标签
                stacked_labels = np.stack(sampled_labels, axis=0)
                avg_labels = np.mean(stacked_labels, axis=0)
                
                # 添加到测试集
                X_list.append(X)
                mask_list.append(mask)
                labels_list.append(avg_labels)
                
                # print(f"    样本 {i+1}: 选中报文索引 {selected_indices[:3]}..., 多样性权重: {sample_diversity:.3f}")
            
            # 归一化权重
            total_weight = sum(group_metadata[seg_key]['sample_weights'])
            if total_weight > 0:
                group_metadata[seg_key]['sample_weights'] = [
                    w / total_weight for w in group_metadata[seg_key]['sample_weights']
                ]
        
        return X_list, mask_list, labels_list, group_metadata
    
    def process_all_data_validation(self, csv_file: str, samples_per_group: int = 100) -> Tuple[List[np.ndarray], List[np.ndarray], List[np.ndarray]]:
        """
        Process all data and generate training set
        Returns: (features_list, labels_list) 
        Each element is a training sample of [64, 4] and [64]
        """
        # 1. Load data
        df = self.load_data(csv_file)
        
        # 2. Group strictly by truncated segments and field names
        groups = self.group_by_segments_and_fields(df)
        
        # 3. Generate training samples
        X_list, mask_list, labels_list = self.generate_validation_samples(groups)
        
        print(f"\nTraining sample generation complete!")
        print(f"Generated {len(X_list)} training samples")
        print(f"Feature matrix shape for each sample: {X_list[0].shape}")
        print(f"Label vector shape for each sample: {labels_list[0].shape}")
        
        return X_list, mask_list, labels_list
        
    def process_test_data_with_diversity(self, csv_file: str, samples_per_group: int = 5) -> Tuple[List[np.ndarray], List[np.ndarray], List[np.ndarray], Dict]:
        """
        Process test data and generate diversity-first test samples
        
        Args:
            csv_file: Test data file path
            samples_per_group: Maximum samples per group
            
        Returns:
            (X_list, mask_list, labels_list, group_metadata): Test samples and group metadata
        """
        # 1. Load data
        df = self.load_data(csv_file)
        
        # 2. Group strictly by truncated segments and field names
        groups = self.group_by_segments_and_fields(df)
        
        # 3. Generate diversity-first test samples
        X_list, mask_list, labels_list, group_metadata = self.generate_test_samples_with_diversity(
            groups, max_samples_per_group=samples_per_group
        )
        
        print(f"\nDiversity test sample generation complete!")
        print(f"Generated {len(X_list)} test samples")
        print(f"Covering {len(group_metadata)} format types")
        if X_list:
            print(f"Feature matrix shape for each sample: {X_list[0].shape}")
            print(f"Label vector shape for each sample: {labels_list[0].shape}")
        
        return X_list, mask_list, labels_list, group_metadata



