import sys
import numpy as np
import torch
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from model import Model
from loss import loss_fn

console = Console()

# ---- HIDDEN LOSS PARAMETERS (SERVER ONLY) ----
ALPHA = 1.0
BETA  = 0.5
GAMMA = 0.3
DELTA = 0.05
TAU   = 0.37
# ---------------------------------------------

def print_banner():
    banner = """[bold cyan]╔════════════════════════════════════╗[/bold cyan]
[bold cyan]║[/bold cyan]   [bold magenta]🔮 LOSS WHISPERER ORACLE[/bold magenta]    [bold cyan]║[/bold cyan]
[bold cyan]║[/bold cyan]      [dim]stdin → stdout only[/dim]        [bold cyan]║[/bold cyan]
[bold cyan]╚════════════════════════════════════╝[/bold cyan]"""

    console.print(banner)
    console.print()

    instructions = Panel(
        "[yellow]Enter 8 floats followed by a label (0 or 1).[/yellow]\n"
        "[green]Add 'latent' to reveal the latent vector z.[/green]\n\n"
        "[bold]Example:[/bold]\n"
        "  [cyan]0.1 -0.3 0.7 0.2 -0.5 0.9 0.4 -0.1 1[/cyan]\n"
        "  [cyan]0.1 -0.3 0.7 0.2 -0.5 0.9 0.4 -0.1 1 latent[/cyan]",
        title="[bold]Instructions[/bold]",
        border_style="blue",
        box=box.ROUNDED
    )
    console.print(instructions)
    console.print()

def format_output(loss, y, z=None):
    if z is None:
        console.print(
            f"[bold green]Output:[/bold green] {y:.6f}   "
            f"[bold yellow]Loss:[/bold yellow] {loss:.6f}"
        )
    else:
        table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
        table.add_column("Output y", justify="center")
        table.add_column("Loss L", justify="center")
        table.add_column("Latent z", justify="left")

        z_str = " ".join(f"{v:.4f}" for v in z)
        table.add_row(f"{y:.6f}", f"{loss:.6f}", z_str)
        console.print(table)

def main():
    device = torch.device("cpu")

    model = Model().to(device)
    model.load_state_dict(torch.load("weights.pt", map_location=device))
    model.eval()

    print_banner()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        want_latent = "latent" in line
        parts = line.replace("latent", "").strip().split()

        if len(parts) != 9:
            console.print("[bold red]ERR:[/bold red] Expected 8 floats + label", style="red")
            continue

        try:
            x_vals = [float(p) for p in parts[:8]]
            y_val  = float(parts[8])
        except ValueError:
            console.print("[bold red]ERR:[/bold red] Invalid numeric input", style="red")
            continue

        x = torch.tensor(x_vals, dtype=torch.float32, requires_grad=True).unsqueeze(0)
        y_true = torch.tensor([[y_val]], dtype=torch.float32)

        try:
            loss = loss_fn(
                model,
                x,
                y_true,
                ALPHA,
                BETA,
                GAMMA,
                DELTA,
                TAU
            )

            with torch.no_grad():
                y_hat, z = model(x)

            if want_latent:
                format_output(loss.item(), y_hat.item(), z.squeeze(0).numpy())
            else:
                format_output(loss.item(), y_hat.item())

        except Exception as e:
            console.print(f"[bold red]ERR:[/bold red] {e}", style="red")

if __name__ == "__main__":
    main()
