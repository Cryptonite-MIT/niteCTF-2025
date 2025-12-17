# The Last Song - Solution

Kaelen's tome is written in verse, but it forms a **precise technical specification** for building a speech recognition model. Every line maps to a concrete choice in preprocessing, model architecture, vocabulary, normalization, or training procedure.

## 1. Understanding the Tome

Below we walk through the poem, in order, mapping each segment to its technical requirement and solver action.

### **1.1 Time-Frequency Foundations**

#### **Tome:**

> *Where time meets frequency, there lies the first gate. Work in the log-mel realm: eighty slices through the spectrum. The source must flow at sixteen thousand.*

#### **Meaning:**

Kaelen's representations live jointly in time and frequency, using mel-scaled features.

#### **Technical Requirements:**

* Use **log-mel spectrograms**
* Sample rate: **16,000 Hz**
* **80 mel bins**

#### **Solver Must:**

Extract 80-bin log-mel features at 16 kHz from every audio file in both training and decoding.

### **1.2 Exact STFT Geometry**

#### **Tome:**

> *The scrying window: one-zero-two-four spans, stepping two-five-six at a time. Power becomes sound's shadow – the decibel form. Stray from these marks, the vision shatters.*

#### **Meaning:**

Kaelen defines the exact STFT parameters and the requirement to convert **power** mel spectrograms to **dB**.

#### **Technical Requirements:**

* `n_fft = 1024`
* `hop_length = 256`
* `win_length = 1024` (Hann window)
* Compute power spectrogram (`|STFT|²`)
* Convert power mel to dB
* DO NOT alter these parameters

#### **Solver Must:**

Use these values exactly; even slight deviations will produce incompatible features and ruin decoding.

### **1.3 Input Projection**

#### **Tome:**

> *Mel sees only surfaces. Raise each moment to one-two-eight before the work begins.*

#### **Meaning:**

Mel features are insufficient on their own; project each 80-dim vector to 128 dims.

#### **Technical Requirement:**

Add a framewise linear layer:

```python
Linear(80 → 128)
```

#### **Solver Must:**

Implement this projection as the first learned layer of the model.

### **1.4 Architecture Structure - The Three Gates**

#### **Tome:**

> *Three gates guard the path. Each gate follows the divided pattern:*
>
> *A half-measure of transformation stands at the threshold*
> *Four eyes watching in parallel*
> *A depthwise temporal span of thirty-one*
> *A half-measure of transformation guards the exit*
>
> *The two halves complete what one began. The sequence cannot be broken.*

#### **Meaning:**

The encoder consists of **3 identical Conformer-style blocks**, each with a specific internal structure.

#### **Technical Requirements:**

* `num_layers = 3`
* Each block contains (in order):
  1. **Feed-Forward #1 (macaron pre-FF):** Scale by 0.5 when adding residual
  2. **Multi-Head Self-Attention:** `n_heads = 4` ("Four eyes watching in parallel")
  3. **Convolution Module:** Depthwise 1D conv with `kernel_size = 31` ("depthwise temporal span of thirty-one")
  4. **Feed-Forward #2 (macaron post-FF):** Scale by 0.5

#### **Solver Must:**

Implement a standard Conformer block with:

* FF → MHSA → Conv → FF (in this exact order)
* Two FFs scaled by 0.5 (macaron structure)
* 4 attention heads
* 31 kernel depthwise conv

### **1.5 Alignment-Free Loss**

#### **Tome:**

> *Time bends. Symbols float untethered. Let the void hold the spaces between.*

#### **Meaning:**

Use **Connectionist Temporal Classification (CTC)** with a blank token to handle variable-length alignments.

#### **Technical Requirement:**

* Loss: `CTCLoss(blank=0)`

#### **Solver Must:**

Train using CTC; no frame-level alignments are provided.

### **1.6 Vocabulary Definition**

#### **Tome:**

> *Forty-one runes, arranged in sacred order:*
> *The void at origin, then the twenty-six letters of speech, the ten digits of counting, and four marks of structure: the twin braces, the bridge, the break.*

#### **Meaning:**

The entire output space is explicitly defined.

#### **Technical Requirements:**

Token mapping:

```
0:     <blank> (the void)
1–26:  a–z (twenty-six letters)
27–36: 0–9 (ten digits)
37:    { (brace left)
38:    } (brace right)
39:    _ (bridge/underscore)
40:    - (break/hyphen)
```

Total = **41 tokens**.

#### **Solver Must:**

Encode training transcripts using exactly this mapping.

### **1.7 Normalization Rules**

#### **Tome:**

> *Each song breathes differently. Find its centre, divide by its spread, add the smallest whisper (ten raised to the sixth shadow). Otherwise, all becomes formless.*

#### **Meaning:**

Normalize each audio **independently** using its own mean and standard deviation.

#### **Technical Requirement:**

Per-utterance normalization:

```python
mel_norm = (mel_db - mel_db.mean()) / (mel_db.std() + 1e-6)
```

The "smallest whisper" is `1e-6` (epsilon for numerical stability).

#### **Solver Must:**

Apply this normalization separately to every file (train, dev, and final).

### **1.8 Saving the Model Correctly**

#### **Tome:**

> *Keep only the essence – the weights themselves. The vessel means nothing if it doesn't echo the true form.*

#### **Meaning:**

Save ONLY the state dictionary, not the full model object.

#### **Technical Requirement:**

```python
torch.save(model.state_dict(), "best.pt")
```

During inference:

* Rebuild the architecture **exactly**
* Load the state dict

#### **Solver Must:**

Do not use `torch.save(model)`; it will break loading if the model class changes.

### **1.9 Critical Warning**

#### **Tome:**

> *One number misaligned, one rune displaced, and the prophecy remains forever silent.*

#### **Meaning:**

**Every single parameter must match exactly.** Any deviation will cause the model to fail:

* Wrong FFT size → incompatible features
* Wrong vocab mapping → garbled output
* Wrong architecture → weight loading fails
* Wrong normalization → distribution mismatch

## 2. Training the Reconstructed Songweaver

Once all poem instructions are understood, the solver must:

### **2.1 Preprocess training audio**

For every file in `training_harmonies/`:

1. Resample to 16 kHz
2. Compute STFT (`n_fft=1024`, `hop=256`, power = |STFT|²)
3. Convert to **80 mel bins**
4. Convert to **dB**
5. Normalize per recording: `(x - mean) / (std + 1e-6)`
6. Output shape: `(T, 80)`

### **2.2 Encode transcripts**

Convert each transcript into the exact 41-token alphabet following the mapping above.

### **2.3 Build the model**

1. Linear(80 → 128) input projection
2. Add positional encoding (implicit in Conformer)
3. Add 3 Conformer blocks (each with FF → MHSA → Conv → FF)
4. Final linear layer → 41 logits
5. Use log-softmax and CTC loss

### **2.4 Train with CTCLoss**

* Optimizer: AdamW (`lr ≈ 1e-3`)
* Batch size: ~8
* Clip gradients if needed
* Early stop on dev loss

### **2.5 Save the best model**

Only save `state_dict`:

```python
torch.save(model.state_dict(), "checkpoints/best.pt")
```

## 3. Decoding Kaelen's Prophetic Echo

To decode `the_prophetic_echo.wav`, the solver must:

### **3.1 Rebuild the model**

Same architecture, same parameters, same vocabulary.

```python
model = ConformerCTC(input_dim=80, d_model=128, n_classes=41)
model.load_state_dict(torch.load("checkpoints/best.pt"))
model.eval()
```

### **3.2 Preprocess final audio**

Exact same pipeline:

* 16kHz
* 1024 FFT
* 256 hop
* 80 mel bins
* power → dB
* per-utterance normalization

### **3.3 Pass through model**

Obtain logits `(T, 41)`.

### **3.4 Greedy CTC decode**

1. `argmax` per frame
2. Collapse repeats
3. Remove blanks (`0`)
4. Map token IDs → characters

```python
def greedy_ctc(logits):
    seq = logits.argmax(-1).cpu().numpy()[0]
    prev = None
    out = []
    for s in seq:
        if s == prev: continue
        prev = s
        if s == BLANK: continue
        out.append(ALPHABET[s-1])
    return "".join(out)
```

### **3.5 Final decoded string**

The prophecy emerges as plain text - **the flag**:

```
nite{0nly_th3_w0rthy_c4n_h34r}
```

## 4. Summary Table

| Poem Line / Stanza                                         | Meaning                      | Solver Must Implement       |
| ---------------------------------------------------------- | ---------------------------- | --------------------------- |
| *Where time meets frequency*                               | Use time–freq features       | Log-mel spectrograms        |
| *Eighty slices, sixteen thousand*                          | Exact feature dims           | `n_mels=80`, `sr=16000`     |
| *One-zero-two-four spans, two-five-six steps*              | Exact STFT geometry          | `n_fft=1024`, `hop=256`     |
| *Power becomes sound's shadow – decibel form*              | Use power mel in dB          | `power_to_db`               |
| *Raise each moment to one-two-eight*                       | Increase feature dimension   | Linear(80→128)              |
| *Three gates guard the path*                               | Number of encoder blocks     | 3 Conformer blocks          |
| *Four eyes watching in parallel*                           | Multi-head attention         | 4 attention heads           |
| *Depthwise temporal span of thirty-one*                    | Conv kernel size             | depthwise conv k=31         |
| *Half-measure at threshold and exit*                       | Macaron FF structure         | FF (×0.5) before & after    |
| *Time bends, symbols float, void holds spaces*             | CTC loss required            | Use CTCLoss(blank=0)        |
| *Forty-one runes in sacred order*                          | Vocabulary definition        | IDs 0–40 exact mapping      |
| *Each song breathes differently*                           | Per-sample normalization     | `(x-mean)/(std+1e-6)`       |
| *Keep only the essence – the weights*                      | Save state dict only         | `torch.save(state_dict)`    |
| *One number misaligned, one rune displaced → silent*       | Exact precision required     | No deviations allowed       |

## 5. Code

The provided solution files (`model.py`, `train.py`, `decode.py`) correctly implement the technical requirements.

Running `python decode.py the_prophetic_echo.wav` with a properly trained model will output:

Decoded: `nite{0nly_th3_w0rthy_c4n_h34r}`

