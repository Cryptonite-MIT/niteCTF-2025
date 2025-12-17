# lastnleast

[Solve script](solver.py)

This challenge provides two partial datasets and the exact preprocessing models used originally.
By reconstructing the PCA output and interpreting the final component as bits, we recover a Base64 message that decodes to the final flag.

## Files Used
- `Dimension1.csv`
- `Dimension2.csv`
- `scaler.joblib` — StandardScaler used in the original pipeline
- `pca_model.joblib` — PCA model used to generate the original components

## Overview of the Approach

1. **Merge CSVs**
   Load `Dimension1.csv` and `Dimension2.csv`, concatenate them row-wise into a single dataset.

2. **Clean the Data**
   - Remove rows with NULL / NaN values
   - Convert all entries to numeric
   - Drop rows that remain invalid after conversion

3. **Apply Provided Models**
   - Load `scaler.joblib` and apply `scaler.transform()`
   - Load `pca_model.joblib` and compute `pca.transform()`
   - Extract the *last* PCA component for every row

4. **Extract Bits**
   Each value in the last PCA component corresponds to a bit:
   - `> 0` → **1**
   - `≤ 0` → **0**

   Concatenate these into a binary stream.

5. **Decode ASCII**
   - Split the binary stream into 8-bit chunks
   - Convert each byte into an ASCII character
   - Stop at the first non-printable character

   This yields the printable Base64 encoded string:
   **`WFZsT2lqY2dYbGRvYmRaVlBrZUxKRkpyb2lWeEp1blRSbXN3UkN6eHJUZVhTRVpWUXlFcGFKVVRxRW1MSk5NUWdGVlNMY2tCaHpVeGlFWWFYbWRidUJla2RXV2R3eUVzUmNnWWp3VnVjTGRsYUREaUVibnBvYk1DenVLVmdJeFhlaGpBc2JXeVRPTUt0Zk9FSW9YUVl5dEhBaU1DSmJ2ZWd5cFRNU3Z0SkFnT0tZaWJWQ1ZBWXZjUm5mdG9DRmRLbWxyb2xydVB6ZVpMdnZEU05EVnRwQm1Cb01kZXZOYm5XaVFUanZGd3Jncnp5VEt4c05iWktQeExtc0R4UnhVUUNBRlF3bU50bWRYRWRKZ2pmZ29JVnJGVWpGbUVIbUdnT3lBTXJleWRDVHlJVVVUZ1prWkJEdUlYVml4TklLUVdMdURxYnZxZ2Vod0phQllVcktBS1lnQ3ZGUGdxTEJzcUNpSUduRGVtaUZXYmV2bFNQVlpFQmxxeVVhRlhnek1ISEpwUk9keXVaT2x2ZElUVnlOQUJ3aUtqcmRkd1NHcnJzQkNKTlBPdUpMV1RLSmVMS3ZRdGlsbXlFT2NHaUZ0bVlXSkxOek5GTkZPTXpYW... `**
   the encoded string around 5000 letters long.

6. **Base64 Decode**
   Decoding the above produces the final challenge flag in between the random string letters :
   **`nite{PrInc3!eS_of_D!me$ions_G0__D33p}`**

### `solve.py` process

- Reads both CSVs and concatenates them
- Cleans and converts numeric values
- Loads the StandardScaler + PCA models
- Extracts the last PCA component and converts signs → bits
- Converts bits → ASCII → Base64
- Decodes Base64 to reveal the final flag

