# -*- coding: utf-8 -*-
"""
Protocol Boundary Detection Model with Dual-Stream Architecture

This module implements a dual-stream neural network for protocol boundary detection.
The model combines horizontal and vertical feature streams to capture both
intra-message sequential dependencies and cross-message statistical patterns.

Architecture Overview:
- Embedding + Positional Encoding
- Horizontal Stream: Transformer encoder for sequential dependencies
- Vertical Stream: VerticalAttention for cross-message patterns
- FiLM Modulation: Feature-wise linear modulation based on byte statistics
- Dynamic Fusion: Gate-controlled fusion of dual streams
- CRF Layer: Conditional Random Field for sequence labeling

Key Components:
  * Horizontal Path: h_transformer → film_horiz
  * Vertical Path: vertical_attention → film_vert
  * Both paths are fused via DynamicFusion mechanism

Usage:
  from dual_stream_model import ProtocolBoundaryModel
  model = ProtocolBoundaryModel(vocab_size=256, d_model=128, ...)

Design Philosophy:
- Leverage multi-packet statistical patterns via vertical attention
- Capture sequential context via horizontal transformer
- Adaptive feature modulation using byte-level statistics
- End-to-end trainable with CRF for boundary consistency
"""

import torch
from base_model import ProtocolBoundaryModel as BaseProtocolBoundaryModel


class ProtocolBoundaryModel(BaseProtocolBoundaryModel):
    """
    Dual-stream model for protocol boundary detection.
    Combines horizontal transformer and vertical attention mechanisms.
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Model variant identifier
        self.model_type = "dual_stream"
    
    def _encode(self, X_BNL, mask_BNL):
        """
        Encoding logic for dual-stream architecture:
        1. Embedding + Positional Encoding
        2. Horizontal Transformer (h_transformer)
        3. Vertical Attention (VerticalAttention)
        4. Dual-path FiLM Modulation (vertical + horizontal)
        5. Dynamic Fusion
        6. Return fused features
        
        Args:
            X_BNL: (B, N, L) Input byte sequences
            mask_BNL: (B, N, L) Valid position mask
        
        Returns:
            fused_LBD: (L, B, D) Fused sequence features
            per_msg_LBND: (L, B, N, D) Per-message features
            attn_BLN: (B, L, N) Cross-message attention weights
            (vert_orig, horiz_orig): Original feature tuple
        """
        B, N, L = X_BNL.shape
        
        # 1. Embedding and Positional Encoding
        x = self.embedding(X_BNL.view(-1, L)).permute(1, 0, 2)  # (L, B*N, D)
        x = self.pos(x)  # (L, B*N, D)
        
        # 2. Horizontal Transformer (extract intra-sequence context)
        key_padding = ~mask_BNL.view(B * N, L)
        h_first = self.h_transformer(x, src_key_padding_mask=key_padding)  # (L, B*N, D)
        
        # 3. Vertical Attention (extract cross-message dependencies)
        vert = self.vertical(h_first, N, mask_BNL)  # (L, B, N, D)
        
        # 4. Prepare horizontal stream features
        # Reshape transformer output to (L, B, N, D) for fusion
        L_dim, BN, D = h_first.shape
        horiz = h_first.view(L_dim, B, N, D)  # (L, B, N, D)
        
        # 5. Dual-path FiLM Modulation
        # Vertical path: FiLM modulation on vertical attention output
        # Horizontal path: FiLM modulation on transformer output
        vert_filmed = self.film_vert(vert, mask_BNL, X_BNL)  # (L, B, N, D)
        horiz_filmed = self.film_horiz(horiz, mask_BNL, X_BNL)  # (L, B, N, D)
        
        # 6. Dynamic Fusion of dual streams
        fused_LBD, per_msg_LBND, attn_BLN = self.fusion(vert_filmed, horiz_filmed, mask_BNL)
        
        # Return fused features and intermediate outputs
        return fused_LBD, per_msg_LBND, attn_BLN, (vert, horiz)
