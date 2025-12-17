import torch, torch.nn as nn, torch.nn.functional as F

class Swish(nn.Module):
    def forward(self,x): return x * torch.sigmoid(x)

class FeedForward(nn.Module):
    def __init__(self,d,h,drop=0.1):
        super().__init__()
        self.net = nn.Sequential(nn.Linear(d,h), Swish(), nn.Dropout(drop), nn.Linear(h,d), nn.Dropout(drop))
    def forward(self,x): return self.net(x)

class DepthwiseConv1d(nn.Module):
    def __init__(self,channels,k=31):
        super().__init__()
        pad=(k-1)//2
        self.conv = nn.Conv1d(channels,channels,k,groups=channels,padding=pad)
    def forward(self,x): return self.conv(x)

class ConformerConv(nn.Module):
    def __init__(self,d,k=31,drop=0.1):
        super().__init__()
        self.ln = nn.LayerNorm(d)
        self.pw1 = nn.Conv1d(d,2*d,1)
        self.dw = DepthwiseConv1d(d,k)
        self.pw2 = nn.Conv1d(d,d,1)
        self.bn = nn.BatchNorm1d(d)
        self.drop = nn.Dropout(drop)
    def forward(self,x):
        res=x
        x=self.ln(x).transpose(1,2)
        x=self.pw1(x); a,b = x.chunk(2,1); x = a * torch.sigmoid(b)
        x = self.dw(x); x = self.bn(x); x = F.relu(x)
        x = self.pw2(x); x = self.drop(x)
        x = x.transpose(1,2)
        return x+res

class ConformerBlock(nn.Module):
    def __init__(self,d,heads,ff_mult=4,k=31,drop=0.1):
        super().__init__()
        dff=d*ff_mult
        self.ff1=FeedForward(d,dff,drop); self.ln1=nn.LayerNorm(d)
        self.attn_ln=nn.LayerNorm(d); self.mha=nn.MultiheadAttention(d,heads,batch_first=True,dropout=drop)
        self.conv = ConformerConv(d,k,drop)
        self.ff2=FeedForward(d,dff,drop); self.ln2=nn.LayerNorm(d)
        self.outln = nn.LayerNorm(d); self.scale=0.5; self.drop=nn.Dropout(drop)
    def forward(self,x,mask=None):
        x = x + self.scale * self.drop(self.ff1(self.ln1(x)))
        y = self.mha(self.attn_ln(x), self.attn_ln(x), self.attn_ln(x), key_padding_mask=mask)[0]
        x = x + self.drop(y)
        x = x + self.drop(self.conv(x))
        x = x + self.scale * self.drop(self.ff2(self.ln2(x)))
        return self.outln(x)

class ConformerEncoder(nn.Module):
    def __init__(self, input_dim=80, d_model=128, heads=4, layers=3):
        super().__init__()
        self.proj = nn.Linear(input_dim, d_model)
        self.layers = nn.ModuleList([ConformerBlock(d_model, heads) for _ in range(layers)])
    def forward(self,x,mask=None):
        x=self.proj(x)
        for l in self.layers: x = l(x,mask)
        return x

class ConformerCTC(nn.Module):
    def __init__(self, input_dim=80, d_model=128, n_classes=41):
        super().__init__()
        self.enc = ConformerEncoder(input_dim, d_model, heads=4, layers=3)
        self.head = nn.Linear(d_model, n_classes)
    def forward(self, x):
        # x: (B, T, F)
        h = self.enc(x)
        return self.head(h)  # logits (B, T, C)
