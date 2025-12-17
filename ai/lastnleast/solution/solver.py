import numpy as np
import pandas as pd
import joblib

def binary_to_text(binary_str):
    chars = []
    for i in range(0, len(binary_str), 8):
        byte = binary_str[i:i+8]
        if len(byte) < 8:
            break
        c = chr(int(byte, 2))
        if not (32 <= ord(c) <= 126):
            break
        chars.append(c)
    return ''.join(chars)

def solve():
    df1 = pd.read_csv("Dimension1.csv")
    df2 = pd.read_csv("Dimension2.csv")
    df = pd.concat([df1, df2], ignore_index=True)

    numeric_cols = [c for c in df.columns if c.startswith("col_")]
    numeric_df = df[numeric_cols].apply(pd.to_numeric, errors="coerce")
    numeric_df = numeric_df.dropna(axis=0, how="any")

    X = numeric_df.values

    scaler = joblib.load("scaler.joblib")
    pca = joblib.load("pca_model.joblib")

    X_scaled = scaler.transform(X)
    X_pca = pca.transform(X_scaled)

    
    pca_no = X_pca.shape[1]
    print("No of PCA's :" , pca_no , "\n")

    for i in range(pca_no):
        last_comp = X_pca[:, i]
        N = (len(last_comp))
        bits = ''.join('1' if v > 0 else '0' for v in last_comp[:N])
    
        message = binary_to_text(bits)
        print("PCA",i,"\nRecovered message:", message , "\n\n\n")

    print("The PC9 has the base64 encoded flag with 5000 random string in each side/nAfter decoding the message find for nite{}.")

if __name__ == "__main__":
    solve()
