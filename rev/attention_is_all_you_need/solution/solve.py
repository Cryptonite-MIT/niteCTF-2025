#!/usr/bin/env python3
"""
Neural Flag Checker Solver
Implements the forward pass from the binary and uses beam search to recover the flag
"""

import numpy as np
from pathlib import Path
import heapq
from tqdm import tqdm

# Configuration
WEIGHTS_DIR = Path('extracted_weights')
L = 34  # Flag length
EMB_DIM = 32
HIDDEN_DIM = 64

class FlagChecker:
    """
    Reimplementation of the eval() function from the binary
    """
    
    def __init__(self, weights_dir=WEIGHTS_DIR):
        """Load all weights from extracted files"""
        print("Loading weights...")
        
        # Load charset
        with open(weights_dir / 'C.txt', 'r') as f:
            self.charset = f.read()
        self.V = len(self.charset)
        self.char_to_idx = {c: i for i, c in enumerate(self.charset)}
        self.idx_to_char = {i: c for i, c in enumerate(self.charset)}
        
        # Load position head weights
        self.W0 = np.load(weights_dir / 'W0.npy')  # [V, EMB_DIM] - char embeddings
        self.W1 = np.load(weights_dir / 'W1.npy')  # [L, EMB_DIM] - position embeddings
        self.W2 = np.load(weights_dir / 'W2.npy')  # [L, HIDDEN_DIM, EMB_DIM]
        self.W3 = np.load(weights_dir / 'W3.npy')  # [L, HIDDEN_DIM] - bias
        self.W4 = np.load(weights_dir / 'W4.npy')  # [L, 1, HIDDEN_DIM]
        self.W5 = np.load(weights_dir / 'W5.npy')  # [L] - bias
        
        # Load global head weights
        self.G0 = np.load(weights_dir / 'G0.npy')  # [HIDDEN_DIM, EMB_DIM]
        self.G1 = np.load(weights_dir / 'G1.npy')  # [HIDDEN_DIM] - bias
        self.G2 = np.load(weights_dir / 'G2.npy')  # [HIDDEN_DIM] - final projection
        
        print(f"✓ Charset: {self.charset}")
        print(f"✓ Charset size: {self.V}")
        print(f"✓ Flag length: {L}")
        print(f"✓ All weights loaded\n")
    
    def encode(self, flag_str):
        """Convert string to indices"""
        return np.array([self.char_to_idx[c] for c in flag_str], dtype=np.int32)
    
    def decode(self, indices):
        """Convert indices to string"""
        return ''.join([self.idx_to_char[i] for i in indices])
    
    def eval_batch(self, indices_batch):
        """
        Evaluate a batch of candidate flags
        
        Args:
            indices_batch: [batch_size, L] array of character indices
        
        Returns:
            scores: [batch_size] array of scores
        """
        batch_size = indices_batch.shape[0]
        
        # Step 1: Build embeddings (corresponds to first loop in binary)
        # v10[m] = W1[pos][m] + W0[char_idx][m]
        embeddings = np.zeros((batch_size, L, EMB_DIM), dtype=np.float32)
        for pos in range(L):
            char_indices = indices_batch[:, pos]  # [batch_size]
            embeddings[:, pos, :] = self.W0[char_indices] + self.W1[pos]
        
        # Step 2: Position-specific scoring (main loop with W2, W3, W4, W5)
        position_scores = np.zeros(batch_size, dtype=np.float32)
        
        for pos in range(L):
            # Get embeddings for this position: [batch_size, EMB_DIM]
            x = embeddings[:, pos, :]  # [batch_size, EMB_DIM]
            
            # First FC layer: x @ W2[pos].T + W3[pos]
            # W2[pos] is [HIDDEN_DIM, EMB_DIM], so x @ W2[pos].T = [batch_size, HIDDEN_DIM]
            h = x @ self.W2[pos].T + self.W3[pos]  # [batch_size, HIDDEN_DIM]
            
            # ReLU activation
            h = np.maximum(h, 0.0)
            
            # Second FC layer: h @ W4[pos].T + W5[pos]
            # W4[pos] is [1, HIDDEN_DIM], so h @ W4[pos].T = [batch_size, 1]
            score = (h @ self.W4[pos].T).squeeze(-1) + self.W5[pos]  # [batch_size]
            
            position_scores += score
        
        # Step 3: Global context scoring (pooling + G0, G1, G2)
        # Average pooling: mean across positions
        pooled = embeddings.mean(axis=1)  # [batch_size, EMB_DIM]
        
        # First FC layer: pooled @ G0.T + G1
        h_global = pooled @ self.G0.T + self.G1  # [batch_size, HIDDEN_DIM]
        
        # ReLU activation
        h_global = np.maximum(h_global, 0.0)
        
        # Final projection: h_global @ G2
        global_scores = h_global @ self.G2  # [batch_size]
        
        # Step 4: Combine scores (70% position, 30% global)
        total_scores = 0.7 * position_scores + 0.3 * global_scores
        
        return total_scores
    
    def eval(self, flag_str):
        """Evaluate a single flag string"""
        indices = self.encode(flag_str).reshape(1, -1)
        return self.eval_batch(indices)[0]


def greedy_search(checker, verbose=True):
    """
    Greedy search: pick best character for each position independently
    Fast but may not find global optimum
    """
    if verbose:
        print("="*70)
        print("GREEDY SEARCH")
        print("="*70)
    
    best_indices = np.zeros(L, dtype=np.int32)
    
    for pos in tqdm(range(L), desc="Position", disable=not verbose):
        best_score = -float('inf')
        best_char = 0
        
        # Try all characters at this position
        for char_idx in range(checker.V):
            best_indices[pos] = char_idx
            score = checker.eval_batch(best_indices.reshape(1, -1))[0]
            
            if score > best_score:
                best_score = score
                best_char = char_idx
        
        best_indices[pos] = best_char
        
        if verbose and (pos + 1) % 5 == 0:
            current = checker.decode(best_indices[:pos+1])
            tqdm.write(f"  Pos {pos+1:2d}: '{current}' (score: {best_score:.4f})")
    
    final_flag = checker.decode(best_indices)
    final_score = checker.eval(final_flag)
    
    if verbose:
        print(f"\n✓ Greedy result: '{final_flag}'")
        print(f"✓ Final score: {final_score:.4f}")
    
    return final_flag, final_score


def beam_search(checker, beam_width=100, batch_size=1000, verbose=True):
    """
    Beam search: maintain top-k candidates at each position
    Better exploration, higher success rate
    
    Args:
        beam_width: Number of candidates to keep at each step
        batch_size: Batch size for evaluation (for speed)
    """
    if verbose:
        print("="*70)
        print(f"BEAM SEARCH (width={beam_width})")
        print("="*70)
    
    # Initialize beam with all possible first characters
    beam = []
    for char_idx in range(checker.V):
        seq = np.zeros(L, dtype=np.int32)
        seq[0] = char_idx
        beam.append(seq)
    
    # Evaluate initial beam
    beam_array = np.array(beam)
    scores = checker.eval_batch(beam_array)
    
    # Keep top beam_width
    top_indices = np.argsort(scores)[-beam_width:]
    beam = [beam[i] for i in top_indices]
    
    if verbose:
        best_seq = beam[-1]
        best_score = scores[top_indices[-1]]
        print(f"Pos 1: Best = '{checker.decode([best_seq[0]])}___...' (score: {best_score:.4f})")
    
    # Build position by position
    for pos in tqdm(range(1, L), desc="Position", disable=not verbose):
        candidates = []
        
        # Expand each sequence in beam with all possible characters
        for seq in beam:
            for char_idx in range(checker.V):
                new_seq = seq.copy()
                new_seq[pos] = char_idx
                candidates.append(new_seq)
        
        # Evaluate all candidates in batches
        candidates_array = np.array(candidates)
        all_scores = []
        
        for i in range(0, len(candidates), batch_size):
            batch = candidates_array[i:i+batch_size]
            batch_scores = checker.eval_batch(batch)
            all_scores.append(batch_scores)
        
        scores = np.concatenate(all_scores)
        
        # Keep top beam_width candidates
        top_indices = np.argsort(scores)[-beam_width:]
        beam = [candidates[i] for i in top_indices]
        
        if verbose and (pos + 1) % 5 == 0:
            best_seq = beam[-1]
            best_score = scores[top_indices[-1]]
            partial = checker.decode(best_seq[:pos+1])
            tqdm.write(f"  Pos {pos+1:2d}: Best = '{partial}' (score: {best_score:.4f})")
    
    # Final evaluation
    beam_array = np.array(beam)
    final_scores = checker.eval_batch(beam_array)
    best_idx = np.argmax(final_scores)
    
    best_seq = beam[best_idx]
    best_score = final_scores[best_idx]
    final_flag = checker.decode(best_seq)
    
    if verbose:
        print(f"\n✓ Beam search result: '{final_flag}'")
        print(f"✓ Final score: {best_score:.4f}")
    
    return final_flag, best_score


def main():
    print("="*70)
    print("NEURAL FLAG CHECKER SOLVER")
    print("="*70)
    print()
    
    # Initialize checker
    checker = FlagChecker()
    
    # Test with a known string to verify implementation
    print("="*70)
    print("TESTING IMPLEMENTATION")
    print("="*70)
    test_str = "nite{test_string_for_validation__}"
    test_score = checker.eval(test_str)
    print(f"Test string: '{test_str}'")
    print(f"Test score: {test_score:.4f}")
    print("(Score should be non-zero if implementation is correct)\n")
    
    # Method 1: Greedy search
    print("\n" + "="*70)
    print("METHOD 1: GREEDY SEARCH")
    print("="*70)
    greedy_flag, greedy_score = greedy_search(checker, verbose=True)
    
    # Method 2: Beam search
    print("\n" + "="*70)
    print("METHOD 2: BEAM SEARCH")
    print("="*70)
    beam_flag, beam_score = beam_search(checker, beam_width=100, verbose=True)
    
    # Results
    print("\n" + "="*70)
    print("FINAL RESULTS")
    print("="*70)
    print(f"Greedy:      '{greedy_flag}' (score: {greedy_score:.4f})")
    print(f"Beam Search: '{beam_flag}' (score: {beam_score:.4f})")
    
    # Pick best
    if beam_score > greedy_score:
        best_flag = beam_flag
        best_score = beam_score
        method = "Beam Search"
    else:
        best_flag = greedy_flag
        best_score = greedy_score
        method = "Greedy"
    
    print(f"\n{'='*70}")
    print(f"BEST SOLUTION ({method}):")
    print(f"{'='*70}")
    print(f"Flag:  {best_flag}")
    print(f"Score: {best_score:.4f}")
    
    if best_score > 9.9:
        print(f"Status: ✓✓✓ LIKELY CORRECT (score > 9.9) ✓✓✓")
    else:
        print(f"Status: ✗ Score too low (need > 9.9)")
    
    print(f"{'='*70}")
    
    print("\nNext steps:")
    print(f"  1. Test flag against binary: ./challenge '{best_flag}'")
    print(f"  2. If score matches, submit the flag!")
    
    return best_flag, best_score


if __name__ == '__main__':
    flag, score = main()