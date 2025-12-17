# Floating Point Guardian Solution

**Author:** tryhard

**Flag:** `nite{br0_i5_n0t_g0nn4_b3_t4K1n6_any1s_j0bs_34x}`

The binary is a plain feed-forward neural network with fully known weights and activation functions, so the entire system is mathematically invertible layer-by-layer. The goal is to find an input vector that produces exactly the target output probability. The model flow is: XOR-based activation on every 4th input index, then `tanh`, `cos`, or `sinh(x/10)` depending on index mod 4, then an affine W1/B1 layer, then `tanh`, then affine W2/B2, then `tanh`, then affine W3/B3, then final sigmoid. Because every step is deterministic and monotonic/invertible (except the linear mixing), the solution is to walk backwards from the target output through each layer.

* Start from the final probability `p`. Apply inverse sigmoid on it to retrieve the pre-activation value of the output neuron.
* Subtract the output bias and solve the 6×1 linear system defined by W3. Because W3 is not square, use a pseudoinverse (`pinv`) to recover a compatible hidden vector.
* Apply `inverse_tanh` componentwise to undo the hidden2 activation.
* Subtract B2, then apply the pseudoinverse of W2 to recover the hidden1 activations.
* Apply `inverse_tanh` again to undo the hidden1 nonlinearity.
* Subtract the bias B1, then apply the pseudoinverse of W1 to get the vector of "activated inputs" before the per-index activation rules.
* For each index **i**:

| i % 4 | Activation forward | Inverse used      |
| ----- | ------------------ | ----------------- |
| 0     | XOR-activation     | undo XOR          |
| 1     | tanh               | atanh             |
| 2     | cos                | arccos            |
| 3     | sinh(x/10)         | inverse-sinh × 10 |

This yields the final 15-element input vector.
* The recovered vector is a valid solution; forward-passing it through the original code reproduces the target probability.
* No guessing is needed because all weights and activations are deterministic and invertible, and linear mappings are solvable via pseudoinverse.

The full working script used to solve the challenge is here: [`solve.py`](./solve.py)

* It performs the full analytic inversion described above and prints the correct 15-value input vector.

