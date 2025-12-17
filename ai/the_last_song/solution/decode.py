# Usage: python decode.py the_prophetic_echo.wav
import sys, torch, soundfile as sf, numpy as np
from model import ConformerCTC
import torchaudio.transforms as T

ALPHABET="abcdefghijklmnopqrstuvwxyz0123456789{}_-" 
BLANK=0
def greedy_ctc(logits):
    seq = logits.argmax(-1).cpu().numpy()[0]
    prev=None; out=[]
    for s in seq:
        if s==prev: continue
        prev=s
        if s==BLANK: continue
        out.append(ALPHABET[s-1])
    return "".join(out)

def load_mel(wav_path):
    wav, sr = sf.read(wav_path)
    if wav.ndim>1: wav=wav.mean(axis=1)
    if sr!=16000:
        wav = torchaudio.functional.resample(torch.from_numpy(wav).unsqueeze(0), sr, 16000).squeeze(0).numpy()
    mel = T.MelSpectrogram(sample_rate=16000, n_fft=1024, hop_length=256, n_mels=80)(torch.from_numpy(wav).float())
    mel_db = T.AmplitudeToDB(stype='power')(mel).transpose(0,1).unsqueeze(0)
    mel_db = (mel_db - mel_db.mean()) / (mel_db.std()+1e-6)
    return mel_db

if __name__=="__main__":
    if len(sys.argv)<2:
        print("Usage: python decode.py challenge.wav"); sys.exit(1)
    model = ConformerCTC(input_dim=80, d_model=128, n_classes=len(ALPHABET)+1)
    model.load_state_dict(torch.load("checkpoints/best.pt", map_location="cpu"))
    model.eval()
    mel = load_mel(sys.argv[1])
    with torch.no_grad():
        logits = model(mel)
    print("Decoded:", greedy_ctc(logits))
