import torch
import torch.nn.functional as F

def supervised_loss(y, target):
    return F.binary_cross_entropy_with_logits(y, target)

def contrastive_loss(z):
    z = F.normalize(z, dim=1)
    sim = z @ z.T
    return -sim.mean()

def loss_fn(model, x, y, alpha, beta, gamma, delta, tau):
    y_hat, z = model(x)
    latent_norm = torch.norm(z, dim=1)

    grad_penalty = 0.0

    if latent_norm.mean() <= tau:
        return alpha * supervised_loss(y_hat, y)
    else:
        grad = torch.autograd.grad(
            y_hat.sum(), x, create_graph=True
        )[0]
        grad_penalty = grad.pow(2).sum(dim=1).mean()

        return (
            beta * supervised_loss(y_hat, y)
            + gamma * contrastive_loss(z)
            + delta * grad_penalty
        )
