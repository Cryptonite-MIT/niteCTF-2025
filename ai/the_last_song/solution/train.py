import os, csv, math, random, time
import numpy as np, soundfile as sf
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
import torchaudio.transforms as T
from model import ConformerCTC, ConformerEncoder

SAMPLE_RATE=16000
N_FFT=1024; HOP=256; N_MELS=80
ALPHABET="abcdefghijklmnopqrstuvwxyz0123456789{}_-" 
BLANK = 0
IDX_MAP = {c:i+1 for i,c in enumerate(ALPHABET)}
NUM_CLASSES = len(ALPHABET)+1

class ToneDataset(Dataset):
    def __init__(self, folder, labels_csv):
        self.folder=folder
        self.samples=[]
        with open(labels_csv,'r',encoding='utf-8') as f:
            r=csv.DictReader(f)
            for row in r:
                self.samples.append((row['file'], row['transcript']))
    def __len__(self): return len(self.samples)
    def __getitem__(self,idx):
        name, txt = self.samples[idx]
        wav, sr = sf.read(os.path.join(self.folder, name))
        if wav.ndim>1: wav = wav.mean(axis=1)
        if sr != SAMPLE_RATE:
            wav = torchaudio.functional.resample(torch.from_numpy(wav).unsqueeze(0), sr, SAMPLE_RATE).squeeze(0).numpy()
        # compute mel
        spec = T.MelSpectrogram(sample_rate=SAMPLE_RATE, n_fft=N_FFT, hop_length=HOP, n_mels=N_MELS)(torch.from_numpy(wav).float())
        spec = T.AmplitudeToDB(stype='power')(spec).transpose(0,1).numpy()  # (T, F)
        # normalize per sample
        spec = (spec - spec.mean()) / (spec.std()+1e-6)
        # convert transcript to ids
        ids = [IDX_MAP[c] for c in txt]
        return spec.astype(np.float32), np.array(ids, dtype=np.int32)

def collate(batch):
    specs, ids = zip(*batch)
    lens_x = [s.shape[0] for s in specs]
    maxT = max(lens_x)
    F = specs[0].shape[1]
    X = np.zeros((len(batch), maxT, F), dtype=np.float32)
    for i,s in enumerate(specs): X[i,:s.shape[0],:] = s
    # targets
    targets = np.concatenate(ids)
    target_lens = [len(t) for t in ids]
    return torch.from_numpy(X), torch.from_numpy(targets), torch.tensor(lens_x), torch.tensor(target_lens)

def ctc_decode_greedy(logits):
    ids = logits.argmax(-1)
    out=[]
    prev=None
    for a in ids:
        if a==prev: continue
        prev=a
        if a==BLANK: continue
        out.append(ALPHABET[a-1])
    return "".join(out)

def train_one_epoch(model, opt, loader, device):
    model.train()
    total=0; acc_loss=0.0
    ctc = nn.CTCLoss(blank=BLANK, zero_infinity=True)
    for X, targets, x_lens, t_lens in loader:
        X = X.to(device); targets = targets.to(device)
        logits = model(X)  # (B, T, C)
        logp = logits.log_softmax(-1).transpose(0,1)  # (T, B, C)
        # compute input_lengths (frames per sample)
        input_lengths = x_lens.to(device)
        loss = ctc(logp, targets, input_lengths, t_lens.to(device))
        opt.zero_grad(); loss.backward(); opt.step()
        acc_loss += float(loss.item()); total+=1
    return acc_loss/total

def evaluate(model, dev_loader, device):
    model.eval()
    with torch.no_grad():
        for X, targets, x_lens, t_lens in dev_loader:
            X=X.to(device)
            logits = model(X)
            pred = logits.argmax(-1).cpu().numpy()[0]
            print("example pred:", "".join([ALPHABET[i-1] for i in pred if i>0])[:60])
            break

if __name__=="__main__":
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    os.makedirs("checkpoints", exist_ok=True)
    train_ds = ToneDataset("data/training_harmonies", "data/train_labels.csv") # change path if required
    dev_ds = ToneDataset("data/validation_harmonies", "data/validation_labels.csv")  # change path if required
    loader = DataLoader(train_ds, batch_size=8, shuffle=True, collate_fn=collate, num_workers=0)
    dev_loader = DataLoader(dev_ds, batch_size=1, shuffle=False, collate_fn=collate)
    model = ConformerCTC(input_dim=N_MELS, d_model=128, n_classes=NUM_CLASSES).to(device)
    opt = torch.optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-6)
    best_loss=1e9
    for epoch in range(1,21):
        t0=time.time()
        loss = train_one_epoch(model,opt,loader,device)
        print(f"Epoch {epoch} loss {loss:.4f} time {time.time()-t0:.1f}s")
        evaluate(model, dev_loader, device)
        # save
        torch.save(model.state_dict(), f"checkpoints/epoch{epoch}.pt")
        if loss < best_loss:
            best_loss = loss
            torch.save(model.state_dict(), "checkpoints/best.pt")
            print("Saved best.pt")
