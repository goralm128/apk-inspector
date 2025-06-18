import matplotlib.pyplot as plt
import matplotlib as mpl

def apply_default_theme():
    plt.style.use("seaborn-v0_8-whitegrid")  # or "ggplot", "fivethirtyeight", etc.

    mpl.rcParams.update({
        "font.family": "DejaVu Sans",
        "font.size": 10,
        "axes.titlesize": 12,
        "axes.labelsize": 10,
        "xtick.labelsize": 9,
        "ytick.labelsize": 9,
        "figure.dpi": 120,
        "savefig.dpi": 120,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "grid.alpha": 0.3,
        "legend.frameon": False
    })