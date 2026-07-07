#!/usr/bin/env python3
"""
Generate publication‑quality (600 dpi) contingency heatmaps with high‑precision p‑values
computed using Sympy, rounded to three significant figures in scientific notation.
Modern sans‑serif font, horizontal labels, and “Count” label anchored to the right above
the colorbar (shifted further right).
"""

import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from scipy.stats import chi2_contingency
import sympy as sp
import matplotlib as mpl

from config import AGGREGATED_REPORT_CSV, FIGURE_DIR

# —— GLOBAL FONT & STYLE —— #
mpl.rcParams['font.family']     = 'sans-serif'
mpl.rcParams['font.sans-serif'] = ['DejaVu Sans', 'Arial', 'Liberation Sans']
mpl.rcParams['axes.titlesize']  = 16
mpl.rcParams['axes.titleweight']= 'bold'
mpl.rcParams['axes.labelsize']  = 14
mpl.rcParams['axes.labelweight']= 'bold'
mpl.rcParams['xtick.labelsize'] = 12
mpl.rcParams['ytick.labelsize'] = 12
mpl.rcParams['figure.titlesize']= 16

# —— CONFIGURATION —— #
REPORT_FILE_PATH = AGGREGATED_REPORT_CSV
OUTPUT_DIR       = FIGURE_DIR
DPI              = 600
FIGSIZE          = (8, 6)

ROW_ORDER = {
    'quark_verdict': ['low', 'moderate', 'high'],
    'vt_verdict'   : ['benign', 'borderline', 'malicious']
}

PAIRS = [
    ('quark_verdict', 'vt_verdict',
     'Quark‑Engine Threat Level', 'VirusTotal Verdict'),
    ('vt_verdict',    'paper_verdict',
     'VirusTotal Verdict', 'Paper Removal Verdict'),
    ('quark_verdict', 'paper_verdict',
     'Quark‑Engine Threat Level', 'Paper Removal Verdict'),
]

ANNOTATION_FS = 10
AXIS_LABEL_FS  = 14  # for colorbar title


def high_precision_pvalue_sympy(chi2_stat, dof, prec=50):
    """Compute chi-square p-value with high precision via Sympy."""
    v = sp.Rational(dof, 1) / 2
    x = sp.Rational(chi2_stat, 1) / 2
    ratio = sp.uppergamma(v, x) / sp.gamma(v)
    return sp.N(ratio, prec)


def save_heatmap(df, col1, col2, label1, label2, out_path):
    # Build & reorder contingency table
    table = pd.crosstab(df[col1], df[col2])
    order = ROW_ORDER.get(col1, table.index.tolist())
    table = table.reindex(order, fill_value=0).fillna(0)
    table = table.loc[table.sum(axis=1) > 0, table.sum(axis=0) > 0]

    # Chi‑square test statistic
    chi2_stat, _, _, _ = chi2_contingency(table)
    dof = (table.shape[0] - 1) * (table.shape[1] - 1)

    # High‑precision p-value, rounded to three significant figures
    p_mp = high_precision_pvalue_sympy(chi2_stat, dof)
    p_str = sp.N(p_mp, 3).__format__('.3e')

    # Plot setup
    sns.set_theme(style='whitegrid')
    fig, ax = plt.subplots(figsize=FIGSIZE, dpi=DPI)
    # extra right margin for colorbar and label
    fig.subplots_adjust(right=0.70, top=0.90)

    # Draw heatmap
    heat = sns.heatmap(
        table,
        cmap='Blues',
        annot=False,
        linewidths=0.5,
        linecolor='lightgray',
        cbar_kws={'pad': 0.02, 'shrink': 0.8},
        ax=ax
    )

    # Anchor “Count” left‑aligned above colorbar
    cbar = heat.collections[0].colorbar
    cbar.ax.set_title('Count',
                      pad=12,
                      loc='left',
                      fontsize=AXIS_LABEL_FS)

    # Annotate cell counts
    maxc = table.values.max()
    for (i, j), v in np.ndenumerate(table.values):
        color = 'white' if v > maxc / 2 else 'black'
        ax.text(
            j + 0.5, i + 0.5, f'{int(v)}',
            ha='center', va='center',
            color=color, fontsize=ANNOTATION_FS
        )

    # Titles and labels
    ax.set_title(f'{label1} vs {label2} Contingency Table', pad=18)
    ax.set_xlabel(label2, labelpad=12)
    ax.set_ylabel(label1, labelpad=12)

    # Horizontal x‑axis labels
    ax.tick_params(axis='x', rotation=0)
    ax.tick_params(axis='y', rotation=0)

    # Save
    plt.tight_layout(pad=2.0)
    fig.savefig(out_path, dpi=DPI, bbox_inches='tight')
    plt.close(fig)

    print(f'Saved {out_path}  (χ²={chi2_stat:.2f}, p={p_str})')


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    df = pd.read_csv(REPORT_FILE_PATH)
    for col1, col2, lbl1, lbl2 in PAIRS:
        fname = f'contingency_{col1}_vs_{col2}.png'
        save_heatmap(df, col1, col2, lbl1, lbl2, OUTPUT_DIR / fname)


if __name__ == '__main__':
    main()
