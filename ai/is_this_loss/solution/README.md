# is this loss

**Flag:** `nite{1.0_0.5_0.3_0.05_0.37}`

**Author:** `tryhard`

Solve Script: [solve.py]

This challenge presents a black-box optimization problem where participants must reverse-engineer the hyperparameters of a composite loss function by strategically querying a remote oracle.

Participants receive comprehensive information about the underlying system:

1. **Neural Network Architecture** - A complete specification of the model topology, including layer dimensions and activation functions
2. **Trained Parameters** - Pretrained weights exported in ONNX format, enabling local inference
3. **Loss Function Structure** - Visual documentation describing the compositional form of the objective
4. **Query Interface** - A networked oracle service that evaluates the loss for arbitrary inputs

The fundamental insight is that while the loss coefficients remain hidden, all architectural components and learned parameters are transparent. This asymmetry creates an information-theoretic puzzle that can be solved through strategic experimentation.


The remote service accepts queries via :

```
ncat --ssl loss.chalz.nitectf25.live 1337
```

**Query Format:**
- Eight real-valued features constituting the input vector
- A binary class label (0 or 1)
- Optional `latent` keyword to request intermediate representations

**Example Query:**
```
0.1 -0.3 0.7 0.2 -0.5 0.9 0.4 -0.1 1 latent
```

**Response Format:**
```
Output: <prediction> Loss: <scalar_value>
```

The oracle imposes no rate limits, allowing extensive exploration of the input space under different label configurations. This unrestricted access proves essential for differential analysis techniques.

## Neural Network Architecture

### Forward Propagation

The model implements a standard feedforward architecture with three computational stages:

**Layer 1 - Feature Extraction:**
```
h = tanh(W₁x + b₁)
```
- Input dimension: 8
- Hidden dimension: 16
- Nonlinearity: Hyperbolic tangent

**Layer 2 - Latent Encoding:**
```
z = tanh(W₂h + b₂)
```
- Hidden dimension: 16
- Latent dimension: 6
- Nonlinearity: Hyperbolic tangent

**Layer 3 - Classification:**
```
f(x) = W₃z + b₃
```
- Latent dimension: 6
- Output dimension: 1 (logit)
- Nonlinearity: None (linear)


Since the ONNX weights are provided, any intermediate quantity can be computed locally with arbitrary precision. By executing forward passes offline, we verify that locally computed predictions exactly match oracle outputs, confirming identical model implementations.

This equivalence is crucial: it means the oracle reveals **only** the aggregated loss value, while all internal signals: latent representations, gradients, and individual loss components, remain accessible through local analysis.

## Gradient Computation

\
The gradient of the output logit with respect to input features can be derived using the chain rule:

```
∂f/∂x = W₃ · diag(1 - z²) · W₂ · diag(1 - h²) · W₁
```

This produces a (1 × 8) Jacobian vector. The squared Euclidean norm of this gradient:

```
‖∇ₓf(x)‖₂² = Σᵢ(∂f/∂xᵢ)²
```

appears as a regularization term in the loss function and can be computed entirely offline using NumPy operations on the provided weights.

The gradient penalty does not require autodifferentiation frameworks—manual backpropagation through tanh activations suffices given the shallow architecture.

## Loss Function Structure

### Piecewise Definition

The objective function exhibits conditional behavior based on the magnitude of the latent representation:

**Regime A (Small Latent Norm):**
When ‖z(x)‖₂ ≤ τ, the loss simplifies to a scaled supervised component:
```
L(x, y) = α · Lₛᵤₚ(f(x), y)
```

**Regime B (Large Latent Norm):**
When ‖z(x)‖₂ > τ, the loss incorporates multiple regularization terms:
```
L(x, y) = β · Lₛᵤₚ(f(x), y) + γ · Lcontrastive(z(x)) + δ · ‖∇ₓf(x)‖₂²
```

The threshold τ determines which regime governs each query, creating a discontinuity in the loss landscape.

### Unknown Parameters

The challenge requires recovering:
- **α** - Supervised loss scaling in the simple regime
- **β** - Supervised loss scaling in the composite regime
- **γ** - Contrastive loss coefficient
- **δ** - Gradient penalty coefficient
- **τ** - Latent norm threshold

## Solution Methodology

### Phase 1: Supervised Loss Identification

**Approach:** Exploit label symmetry through differential measurements.

Query the oracle with identical inputs but opposite labels:
```
L(x, 0) and L(x, 1)
```

In Regime B, subtract these values:
```
ΔL = L(x, 0) - L(x, 1)
   = β · [Lₛᵤₚ(f(x), 0) - Lₛᵤₚ(f(x), 1)]
```

All label-independent terms (contrastive loss, gradient penalty) cancel exactly. This isolates the supervised component modulated by β.

**Loss Function Selection:**

Test candidate formulations:
- Mean squared error
- Hinge loss
- Binary cross-entropy with logits

Only binary cross-entropy produces a consistent scaling relationship across diverse inputs. For this loss:
```
Lₛᵤₚ(ŷ, y) = -[y·log(σ(ŷ)) + (1-y)·log(1-σ(ŷ))]
```

where σ denotes the sigmoid function.

**Parameter Estimation:**

Compute the ratio:
```
β = ΔL / ΔLₛᵤₚ(f(x))
```

Averaging across multiple random inputs yields:
```
β ≈ 0.5
```

### Phase 2: Regime Classification

**Approach:** Detect which branch of the piecewise loss is active.

Define the residual after removing the supervised component:
```
r(x, y) = L(x, y) - β · Lₛᵤₚ(f(x), y)
```

**Discriminative Property:**

- **In Regime A:** Residual remains label-dependent (only α·Lₛᵤₚ present)
- **In Regime B:** Residual becomes label-invariant (regularization terms dominate)

By computing r(x, 0) and r(x, 1) from oracle queries, we determine:
```
|r(x, 0) - r(x, 1)| < ε  ⟹  Regime B
|r(x, 0) - r(x, 1)| > ε  ⟹  Regime A
```

This provides an oracle-based classifier for the active loss regime.

### Phase 3: Controlled Regime Entry

**Challenge:** Random inputs overwhelmingly satisfy ‖z(x)‖₂ > τ, landing in Regime B.

**Strategy:** Deliberately construct inputs that minimize latent activation magnitude.

Observe that z = tanh(u) where u = W₂h + b₂. Since tanh(0) = 0, we seek inputs where u ≈ 0.

**Optimization Problem:**
```
minimize ‖u(x)‖₂² = ‖W₂·tanh(W₁x + b₁) + b₂‖₂²
```

Using gradient descent on this objective yields inputs with ‖z(x)‖₂ ≈ 0, guaranteed to activate Regime A.

### Phase 4: Parameter α Recovery

**Approach:** Direct measurement in the simplified regime.

For inputs in Regime A:
```
L(x, y) = α · Lₛᵤₚ(f(x), y)
```

Since both L(x, y) (from oracle) and Lₛᵤₚ(f(x), y) (computed locally) are known:
```
α = L(x, y) / Lₛᵤₚ(f(x), y)
```

Evaluating this ratio across multiple Regime A inputs converges to:
```
α = 1.0
```

### Phase 5: Threshold τ Estimation

**Approach:** Boundary search through gradient ascent.

Starting from a confirmed Regime A input (small ‖z‖), iteratively increase the latent norm:

1. Compute ∇ₓ‖z(x)‖₂²
2. Update x ← x + η·∇ₓ‖z(x)‖₂²
3. Query oracle to check active regime
4. Continue until transition to Regime B detected

**Bisection Refinement:**

Once a bracket is established:
- x_lower: Last Regime A input
- x_upper: First Regime B input

Apply binary search on the line segment connecting these points, querying the oracle at each midpoint to determine regime membership.

This converges to:
```
τ ≈ 0.37
```

### Phase 6: Coefficients γ and δ Recovery

**Approach:** Linear regression over label-averaged losses.

For inputs in Regime B, average over both labels:
```
L̄(x) = [L(x, 0) + L(x, 1)] / 2
      = β·Lₛᵤₚ + γ·Lcontrast(z) + δ·‖∇ₓf‖₂²
```

Since supervised loss averages to a constant across labels, this reduces to:
```
L̄(x) - β·L̄ₛᵤₚ(x) = γ·Lcontrast(z) + δ·‖∇ₓf‖₂²
```

**System Construction:**

Sample N inputs in Regime B, forming the matrix equation:
```
⎡ Lcontrast(z₁)  ‖∇f₁‖² ⎤ ⎡ γ ⎤   ⎡ residual₁ ⎤
⎢ Lcontrast(z₂)  ‖∇f₂‖² ⎥ ⎢ δ ⎥ = ⎢ residual₂ ⎥
⎢       ⋮            ⋮    ⎥ ⎣   ⎦   ⎢     ⋮     ⎥
⎣ Lcontrast(zₙ)  ‖∇fₙ‖² ⎦         ⎣ residualₙ ⎦
```

**Least Squares Solution:**

Apply ordinary least squares regression:
```python
A = np.column_stack([contrastive_losses, gradient_penalties])
b = label_averaged_residuals
[γ, δ] = np.linalg.lstsq(A, b, rcond=None)[0]
```

This yields:
```
γ ≈ 0.3  (sign ambiguity)
δ ≈ 0.05
```

**Sign Ambiguity:** Since the oracle only reveals γ·Lcontrast, the internal definition of the contrastive loss determines the sign. Both solutions are mathematically valid.

## Final Solution

### Recovered Coefficients

| Parameter | Value | Recovery Method |
|-----------|-------|-----------------|
| α | 1.0 | Direct ratio in Regime A |
| β | 0.5 | Label difference analysis |
| γ | ±0.3 | Linear regression |
| δ | 0.05 | Linear regression |
| τ | 0.37 | Bisection search |

### Valid Flag Formats

```
nite{1.0_0.5_0.3_0.05_0.37}
nite{1.0_0.5_-0.3_0.05_0.37}
```

The accepted flag uses the positive sign convention.

## Alternative Solution Approaches

The challenge is mathematical in nature and can be solved in different ways. Here are some other methods used by players that I have decided to briefly share:

### Method 1: Direct Regime Detection

Rather than constructing Regime A inputs through optimization, sample the input space extensively:

1. Generate random inputs xᵢ
2. Compute ‖z(xᵢ)‖₂ locally
3. Query oracle for L(xᵢ, y)
4. Plot loss behavior against latent norm
5. Identify discontinuity visually

The threshold τ appears as a sharp transition in the loss surface. Inputs naturally clustered around this boundary enable parameter estimation without gradient-based search.

### Method 2: Perturbation Analysis

Focus on isolating δ through infinitesimal perturbations:

For input x in Regime B:
1. Record baseline loss L(x)
2. Apply small perturbation: x' = x + ε·û (unit direction)
3. Measure ΔL = L(x') - L(x)
4. Compute predicted changes in supervised and contrastive terms
5. Attribute residual to gradient penalty change

```python
Δgrad = ‖∇f(x')‖² - ‖∇f(x)‖²
δ ≈ [ΔL - β·ΔLₛᵤₚ - γ·ΔLcontrast] / Δgrad
```

This method avoids solving simultaneous equations by isolating individual terms through controlled experiments.

### Method 3: Systematic Grid Search

For problems with bounded parameter spaces:

1. Define plausible ranges: α, β ∈ [0, 2], γ, δ ∈ [0, 1], τ ∈ [0, 1]
2. Sample inputs covering both regimes
3. Evaluate candidate parameters on a dense grid
4. Score each configuration by prediction error:
```
error = Σᵢ [Lpredicted(xᵢ; α,β,γ,δ,τ) - Loracle(xᵢ)]²
```
5. Refine search around minimum error configuration

While computationally intensive, this approach requires minimal mathematical sophistication and guarantees convergence.

