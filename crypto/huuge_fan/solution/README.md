# Huuge FAN

**Flag**: `nite{1m_^_#ug3_f4n_of_8KZ!!_afa5d267f6ae51da6ab8019d1e}`

[Solve script](solve.py)

The challenge is driven by `record()`. Each call generates 5 nonce values, which are used in a standard ECDSA signing algorithm. For each nonce, the
function extracts the 4 most-significant digits (referred to as leaks), which are all passed to the `gen_n()` function.

The `gen_n()` function uses the top 4 digits of each leak as a "block" in a base-1817 number. These "blocks" get flipped and both numbers get multipled. This is the leak $n$.

Labelling the "blocks" in the leaks as $a, b, c, d, e$ and $t = 1817$,

$$
n = (
    a \cdot t^4 +
    b \cdot t^3 +
    c \cdot t^2 +
    d \cdot t^1 +
    e \cdot t^0
) \\ \cdot (
    e \cdot t^4 +
    d \cdot t^3 +
    c \cdot t^2 +
    b \cdot t^1 +
    a \cdot t^0
)
$$
Which can be rewritten as:
$$
n = (t^8 + 1) \cdot          (a \cdot  e)                                   \\
    + (t^7 + t) \cdot        (a\cdot d + b\cdot e)                          \\
    + (t^6 + t^2) \cdot      (a\cdot c + b\cdot d + c\cdot e)               \\
    + (t^5 + t^3) \cdot      (a\cdot b + b\cdot c + c\cdot d + d\cdot e)    \\
    + (t^4) \cdot            (a^2 + b^2 + c^2 + d^2 + e^2)                  \\
$$

Using [TheBlupper's linear inequality solver](https://raw.githubusercontent.com/TheBlupper/linineq/) (for ease of solving), this can be used to recover the top 4 digits of each nonce:

$$
Let \quad X = \begin{pmatrix}
    x_0 \\ x_1 \\ x_2 \\ x_3 \\ x_4
\end{pmatrix}
 = \begin{pmatrix}
    a \cdot e \\
    a \cdot d + b \cdot e \\
    a \cdot c + b \cdot d + c \cdot e \\
    a \cdot b + b \cdot c + c \cdot d + d \cdot e \\
    a^2 + b^2 + c^2 + d^2 + e^2
\end{pmatrix}
$$

$$
\begin{bmatrix}
    t^8 + 1 && t^7 + t && t^6 + t^2 && t^5 + t^3 && t^4
\end{bmatrix}
\cdot
X = \begin{pmatrix}
    n
\end{pmatrix}
$$

$$
Lower \ Bound \ (b_l) = \begin{pmatrix}
    0 \\
    0 \\
    0 \\
    0 \\
    0
\end{pmatrix}
\quad
Upper \ Bound \ (b_u) = \begin{pmatrix}
    1 \cdot t^2\\
    2 \cdot t^2\\
    3 \cdot t^2\\
    4 \cdot t^2\\
    5 \cdot t^2
\end{pmatrix}
$$

Since there are multiple possible solutions, the `solve_bounded_gen()` function comes in handy.
The above is covered by `solve_xi()` in `solve.py`.

To get from $X$ to $a, b, c, d, e$ , the fastest method found was the `groebner_basis()` function in SageMath. Feeding

$$
\begin{pmatrix}
    x_0 \\
    x_1 \\
    x_2 \\
    x_3 \\
    x_4
\end{pmatrix}
\minus
\begin{pmatrix}
    a \cdot e \\
    a \cdot d + b \cdot e \\
    a \cdot c + b \cdot d + c \cdot e \\
    a \cdot b + b \cdot c + c \cdot d + d \cdot e \\
    a^2 + b^2 + c^2 + d^2 + e^2
\end{pmatrix} = 0
$$
solves for $a, b, c, d, e$. This is covered by `solve_ai()` in `solve.py`.

To recover the leaks from each nonce, this process is repeated for each leaked block. This can be computed parallelly using Python's `multiprocessing` module as there is no dependency between the leaks.

After successful recovery of the leak values, the attack becomes a standard known-MSB (biased nonce) ECDSA attack, with a slight twist; the known known leak is in base-10. This can be accounted for with a slight change in the equation for this attack.

Taking $u_i$ as the known upper 4 digits of each $k_i$, $k_i$ can be written as:
$$
k_i = u_i \cdot 10^{\log_{10}(m) - x} + k_i'
$$

Where:
- $u_i$: known upper 4 digits of $k_i$.
- $m$: modulus used to form the ring of integers $R$ in the challenge
- $x$: number of digits in $u_i$ ($= 4$)
- $k_i'$: unknown part of $k_i$.

Now, taking $l = \log_2 m$, LLL is performed (using SageMath) on the Basis:
$$
M = \begin{bmatrix}
    I_{60}  && \frac{r_i}{s_i} && \frac{z_i}{s_i} - u_i \cdot 10^{\log_{10}(m) - l} \\
    O       && \frac{1}{2^l} && 0 \\
    O       && 0 && \frac{m}{2^l}
\end{bmatrix}_{62 \times 62}
$$
Where the last 2 rows are used to identify the correct result, containing sentinel values.
These sentinel values are set carefully to make the resultant vector close to the origin.
This Basis works because:
$$
M \cdot \begin{pmatrix}
    O \\
    d \\
    1
\end{pmatrix}_{62}
 = \begin{pmatrix}
    O \\
    d / 2^l \\
    m / 2^l
\end{pmatrix}_{62}
$$
Where the RHS is close to the origin.

In the resulting matrix (after LLL), take advantage of the sentinel values.
Find the vector which has the last element (`r[-1]`) as $\frac{m}{2^l}$.
This is the correct vector, and the second-last element (`r[-2]`) contains the recovered private key $d$.

Converting the recovered private key $d$ to bytes reveals the flag: `?nite{1m_^_#ug3_f4n_of_8KZ!!_afa5d267f6ae51da6ab8019d1e}`.
The `?` is added to maintain the bit-length of $d$, which can be removed for submission.

