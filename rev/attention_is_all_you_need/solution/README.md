# Attention Is All You Need

**Flag:** `nite{0ops_i_ov3rf1tt3d_ag4in}`

## Overview

This challenge involves reversing a CUDA-enabled binary that implements a transformer-style forward pass. The goal is to extract encrypted model weights, reconstruct the forward function, and reproduce the inference logic in order to recover the flag.

The solution combines **dynamic debugging**, **static analysis**, and **model reconstruction**, ultimately reimplementing the inference pipeline and decoding the output using standard sequence search techniques.

## Step-by-Step Solution

### 1. Dynamic Debugging with `cuda-gdb`

* The binary was debugged using **`cuda-gdb`** to enable introspection of GPU execution.
* A breakpoint was set on the CUDA kernel responsible for attention head computation:

  ```
  global_head_kernel
  ```
* This kernel is invoked after runtime decryption of the model weights, making it an ideal interception point.

### 2. Weight Extraction via Runtime Memory Dump

* While stopped at the kernel breakpoint, GPU memory was inspected.
* A custom dumping script, [`autodump.py`], was used to:

  * Traverse relevant device memory regions
  * Extract decrypted weight tensors
  * Serialize them in raw format

This step bypasses the binary’s encryption and obfuscation logic by leveraging runtime state.

### 3. Converting Extracted Weights

* The dumped raw buffers were post-processed and reshaped according to inferred tensor dimensions.
* All weights were converted into **NumPy `.npy` files** for convenient downstream use.
* Layer-wise separation was performed to match attention heads, projections, and feed-forward components.

### 4. Static Analysis of the CUDA Binary

#### a. Binary Decompilation

* The host binary was loaded into **IDA Pro**.
* Control flow and kernel launch logic were analyzed to understand:

  * Layer ordering
  * Tensor shapes
  * Invocation patterns

#### b. PTX Kernel Extraction

* **`cudaobjdump`** was used to dump PTX kernels embedded in the binary.
* These kernels were examined to recover:

  * Matrix multiplication logic
  * Attention score computation
  * Softmax and scaling behavior
  * Head concatenation and projection

### 5. Reconstructing the Forward Pass

By combining:

* Decompiled host-side logic (IDA)
* PTX-level kernel semantics
* Extracted decrypted weights

…the **entire forward function** was reconstructed, matching a simplified transformer inference pipeline:

* Embedding
* Multi-head attention
* Linear projections
* Output logits computation

### 6. Inference and Decoding

* The reconstructed forward function was implemented in Python using NumPy.
* Using the recovered weights, token-level inference was performed.
* Output decoding was done using either:

  * **Greedy search**, or
  * **Beam search**

Both methods successfully recovered the target output sequence.

Solve scripts:

* **Solve script**: [`solve.py`](solve.py)
* **Memory dump script**: [`autodump.py`](autodump.py)

