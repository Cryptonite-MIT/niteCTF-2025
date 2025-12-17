import torch
import torch.nn as nn

class Model(nn.Module):
    def __init__(self):
        super().__init__()
        self.fc1 = nn.Linear(8, 16)
        self.fc2 = nn.Linear(16, 6)   # latent z
        self.fc3 = nn.Linear(6, 1)

    def forward(self, x):
        h = torch.tanh(self.fc1(x))
        z = torch.tanh(self.fc2(h))
        y = self.fc3(z)
        return y, z

