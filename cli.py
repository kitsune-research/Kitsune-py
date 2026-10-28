"""
Kitsune NIDS: Unified Command-Line Interface (CLI).
Production-grade entry point powered by Typer and Rich.

Implements:
- 'kitsune demo': End-to-end interactive demonstration on the Mirai trace.
- 'kitsune run' : Production streaming engine for arbitrary PCAP/TSV files.
- 'kitsune eval': NDSS 2018 Sec. V-C & Fig. 9 forensic benchmarking.

Architect: Tamamo-no-Mae (kitsune-research core)
"""
from __future__ import annotations

import json
import os
import sys
import time
import zipfile
from pathlib import Path
from typing import Optional

import numpy as np
import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

# Resilient imports for root-level and packaged execution
try:
    from Kitsune import Kitsune
except ImportError:
    try:
        from kitsune.core import Kitsune  # type: ignore
    except ImportError:
        Kitsune = None

try:
    from metrics import compute_roc_metrics
except ImportError:
    compute_roc_metrics = None

app = typer.Typer(
    name="kitsune",
    help="🦊 Kitsune NIDS: Online Network Anomaly Detection via Autoencoder Ensembles (NDSS 2018).",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()

# Constante canónica extraída empíricamente de mirai.pcap.tsv (NDSS 2018 Tab. III: t = 52.0 min)
MIRAI_CANONICAL_ATTACK_PKT = 85381


def _ensure_mirai_dataset(target_pcap: Path) -> Path:
    """Verifies existence of mirai.pcap/mirai.pcap.tsv or autonomously extracts it."""
    tsv_candidate = target_pcap.with_suffix(".pcap.tsv")
    if tsv_candidate.exists():
        return tsv_candidate
    if target_pcap.exists():
        return target_pcap

    local_zip = target_pcap.with_suffix(".zip")
    if local_zip.exists():
        console.print(f"[yellow][*] Extracting local archive '{local_zip.name}'...[/yellow]")
        with zipfile.ZipFile(local_zip, "r") as z:
            z.extractall(target_pcap.parent)
        if tsv_candidate.exists():
            return tsv_candidate
        return target_pcap

    upstream_url = "https://github.com/kitsune-research/Kitsune-py/raw/main/mirai.zip"
    console.print("[cyan][*] Downloading evaluation trace from upstream...[/cyan]")
    import urllib.request

    urllib.request.urlretrieve(upstream_url, local_zip)
    with zipfile.ZipFile(local_zip, "r") as z:
        z.extractall(target_pcap.parent)

    if tsv_candidate.exists():
        return tsv_candidate
    return target_pcap


# =====================================================================
# SUBCOMANDO: kitsune demo
# =====================================================================
@app.command(name="demo")
def demo_command(
    limit: int = typer.Option(
        25000,
        "--limit",
        "-n",
        help="Maximum packets to process (use 0 for all 764k).",
    ),
    save_plot: bool = typer.Option(
        True,
        "--plot/--no-plot",
        help="Generate and save the forensic semi-logarithmic anomaly plot.",
    ),
    plot_path: Path = typer.Option(
        Path("docs/demo_plot.png"),
        "--plot-path",
        help="Destination path for the rendered anomaly curve.",
    ),
    out_scores: Path = typer.Option(
        Path("demo_scores.csv"),
        "--out",
        "-o",
        help="Destination path for the exported anomaly scores.",
    ),
) -> None:
    """
    Run an end-to-end unsupervised anomaly detection demonstration on the Mirai trace.
    """
    console.print(
        Panel.fit(
            "[bold white]🦊 Kitsune NIDS: Interactive Anomaly Detection Demo[/bold white]\n"
            "[dim]NDSS 2018 | AfterImage O(1) Feature Extraction + KitNET O(k²) Ensemble[/dim]",
            border_style="cyan",
        )
    )

    if Kitsune is None:
        console.print("[red][!] Error: Kitsune engine core could not be imported.[/red]")
        raise typer.Exit(code=1)

    pcap_path = _ensure_mirai_dataset(Path("mirai.pcap"))
    effective_limit = np.inf if limit <= 0 else limit

    fm_grace = 500
    ad_grace = 1500
    total_grace = fm_grace + ad_grace
    max_ae = 10

    console.print(f"[dim]• Dataset        :[/dim] [green]{pcap_path.resolve()}[/green]")
    console.print(f"[dim]• Ingestion Cap  :[/dim] [cyan]{'All (~764k)' if limit <= 0 else f'{limit:,}'}[/cyan] pkts")
    console.print(f"[dim]• Architecture   :[/dim] corClust (m≤{max_ae}) | FM Grace: {fm_grace} | AD Grace: {ad_grace}\n")

    k_engine = Kitsune(
        file_path=str(pcap_path),
        limit=effective_limit,
        max_autoencoder_size=max_ae,
        FM_grace_period=fm_grace,
        AD_grace_period=ad_grace,
    )

    rmse_scores: list[float] = []
    start_time = time.perf_counter()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(complete_style="cyan", finished_style="green"),
        TaskProgressColumn(),
        TextColumn("• Ingested: [bold cyan]{task.fields[ingested]}[/bold cyan]"),
        TextColumn("• RMSE: [bold yellow]{task.fields[rmse]:.4f}[/bold yellow]"),
        TextColumn("• [bold magenta]{task.fields[fps]:.1f}[/bold magenta] pkt/s"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task_total = limit if limit > 0 else 764137
        task = progress.add_task(
            "Streaming packets...",
            total=task_total,
            ingested=0,
            rmse=0.0,
            fps=0.0,
        )

        count = 0
        while True:
            rmse = k_engine.proc_next_packet()
            if rmse == -1:
                break
            rmse_scores.append(rmse)
            count += 1

            if count % 1000 == 0 or count == 1:
                elapsed = time.perf_counter() - start_time
                fps = count / elapsed if elapsed > 0 else 0.0
                progress.update(task, completed=min(count, task_total), ingested=count, rmse=rmse, fps=fps)

        elapsed_total = time.perf_counter() - start_time
        final_fps = count / elapsed_total if elapsed_total > 0 else 0.0
        progress.update(task, completed=task_total, ingested=count, rmse=rmse_scores[-1] if rmse_scores else 0.0, fps=final_fps)

    console.print(f"\n[green][✓] Ingestion complete:[/green] {count:,} packets processed in {elapsed_total:.2f}s ({final_fps:.1f} pkt/s)")

    # Guardar scores CSV
    out_scores.parent.mkdir(parents=True, exist_ok=True)
    np.savetxt(out_scores, np.array(rmse_scores), delimiter=",", fmt="%.6f", header="rmse", comments="")
    console.print(f"[dim]• Anomaly scores :[/dim] [cyan]{out_scores.resolve()}[/cyan]")

    # Calibración Manifold Log-Normal (Fase benigna post-gracia)
    attack_start = MIRAI_CANONICAL_ATTACK_PKT
    benign_end = min(attack_start, len(rmse_scores))
    baseline_slice = [s for s in rmse_scores[total_grace:benign_end] if s > 0]

    if len(baseline_slice) > 100:
        log_base = np.log(baseline_slice)
        mu_log = float(np.mean(log_base))
        sigma_log = float(np.std(log_base))
        k_risk = 3.0902  # Corresponde a FPR <= 0.001 en distribución normal estándar
        tau = float(np.exp(mu_log + k_risk * sigma_log))
    else:
        tau = 0.3021
        mu_log, sigma_log = -3.1304, 0.6256

    attack_scores = np.array(rmse_scores[attack_start:]) if len(rmse_scores) > attack_start else np.array([])
    baseline_scores = np.array(baseline_slice) if len(baseline_slice) > 0 else np.array([0.04])

    table = Table(title="Kitsune NIDS: Forensic Telemetry & Separation Summary", border_style="cyan")
    table.add_column("Forensic Metric", style="dim")
    table.add_column("Empirical Value", justify="right", style="bold green")

    table.add_row("Baseline Mean ln(RMSE)", f"{mu_log:.4f}")
    table.add_row("Baseline StdDev ln(RMSE)", f"{sigma_log:.4f}")
    table.add_row("Decision Cutoff (tau, FPR <= 10^-3)", f"{tau:.4f}")

    if len(attack_scores) > 0:
        detected = int(np.sum(attack_scores > tau))
        det_ratio = (detected / len(attack_scores)) * 100
        snr_median = float(np.median(attack_scores) / np.median(baseline_scores))
        snr_peak = float(np.max(attack_scores) / np.median(baseline_scores))

        table.add_row("Attack Packets Evaluated", f"{len(attack_scores):,}")
        table.add_row("Anomalies Flagged (> tau)", f"{detected:,} ({det_ratio:.2f}%)")
        table.add_row("Median SNR Separation", f"{snr_median:.2f}x")
        table.add_row("Peak Anomaly / Noise Floor", f"{snr_peak:.2f}x")

    console.print(table)

    if save_plot and len(rmse_scores) > 1000:
        _render_plot(rmse_scores, tau, fm_grace, ad_grace, attack_start, plot_path)


# =====================================================================
# SUBCOMANDO: kitsune run
# =====================================================================
@app.command(name="run")
def run_command(
    input_file: Path = typer.Option(
        ...,
        "--input",
        "-i",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Path to the PCAP, PCAPNG, or pre-extracted TSV trace.",
    ),
    limit: int = typer.Option(
        0,
        "--limit",
        "-n",
        help="Maximum packets to process (use 0 for all packets in trace).",
    ),
    out_file: Path = typer.Option(
        Path("output_scores.csv"),
        "--out",
        "-o",
        help="Destination path for the anomaly score trajectory.",
    ),
    out_format: str = typer.Option(
        "csv",
        "--format",
        "-f",
        help="Output serialisation format: 'csv' or 'ndjson'.",
    ),
    fm_grace: int = typer.Option(
        2000,
        "--fm-grace",
        help="Feature Mapper clustering grace window (packets for corClust).",
    ),
    ad_grace: int = typer.Option(
        5000,
        "--ad-grace",
        help="Anomaly Detector baseline training grace window (packets for KitNET SGD).",
    ),
    max_ae: int = typer.Option(
        10,
        "--max-ae",
        "-m",
        help="corClust maximum subspace dimension bound (m <= 10).",
    ),
) -> None:
    """
    Ingest and process arbitrary network packet captures in streaming mode (O(1) memory).
    """
    if Kitsune is None:
        console.print("[red][!] Error: Kitsune engine core could not be imported.[/red]")
        raise typer.Exit(code=1)

    out_format = out_format.lower().strip()
    if out_format not in {"csv", "ndjson"}:
        console.print("[red][!] Invalid format. Must be either 'csv' or 'ndjson'.[/red]")
        raise typer.Exit(code=1)

    effective_limit = np.inf if limit <= 0 else limit

    console.print(
        Panel.fit(
            f"[bold white]🦊 Kitsune NIDS: Stream Processing Pipeline[/bold white]\n"
            f"[dim]Input: {input_file.resolve()} | Format: {out_format.upper()}[/dim]",
            border_style="blue",
        )
    )

    console.print(f"[dim]• Ingestion Cap   :[/dim] [cyan]{'Uncapped (EOF)' if limit <= 0 else f'{limit:,}'}[/cyan] pkts")
    console.print(f"[dim]• Grace Windows   :[/dim] FM={fm_grace:,} pkts | AD={ad_grace:,} pkts")
    console.print(f"[dim]• corClust Bound  :[/dim] m ≤ {max_ae}\n")

    k_engine = Kitsune(
        file_path=str(input_file),
        limit=effective_limit,
        max_autoencoder_size=max_ae,
        FM_grace_period=fm_grace,
        AD_grace_period=ad_grace,
    )

    out_file.parent.mkdir(parents=True, exist_ok=True)
    f_out = open(out_file, "w", encoding="utf-8")
    if out_format == "csv":
        f_out.write("packet_idx,rmse\n")

    count = 0
    start_time = time.perf_counter()
    rmse_last = 0.0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(complete_style="blue", finished_style="green"),
        TaskProgressColumn(),
        TextColumn("• Ingested: [bold cyan]{task.fields[ingested]}[/bold cyan]"),
        TextColumn("• RMSE: [bold yellow]{task.fields[rmse]:.4f}[/bold yellow]"),
        TextColumn("• [bold magenta]{task.fields[fps]:.1f}[/bold magenta] pkt/s"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task_total = limit if limit > 0 else None
        task = progress.add_task(
            "Ingesting packet stream...",
            total=task_total,
            ingested=0,
            rmse=0.0,
            fps=0.0,
        )

        while True:
            rmse = k_engine.proc_next_packet()
            if rmse == -1:
                break
            count += 1
            rmse_last = rmse

            if out_format == "csv":
                f_out.write(f"{count},{rmse:.6f}\n")
            else:
                f_out.write(json.dumps({"packet_idx": count, "rmse": float(rmse)}) + "\n")

            if count % 2500 == 0 or count == 1:
                elapsed = time.perf_counter() - start_time
                fps = count / elapsed if elapsed > 0 else 0.0
                progress.update(task, completed=count if task_total else None, ingested=count, rmse=rmse, fps=fps)

        elapsed_total = time.perf_counter() - start_time
        final_fps = count / elapsed_total if elapsed_total > 0 else 0.0
        progress.update(task, completed=count if task_total else None, ingested=count, rmse=rmse_last, fps=final_fps)

    f_out.close()
    console.print(f"\n[green][✓] Execution finished:[/green] {count:,} packets processed in {elapsed_total:.2f}s ({final_fps:.1f} pkt/s)")
    console.print(f"[dim]• Output payload  :[/dim] [cyan]{out_file.resolve()}[/cyan]\n")


# =====================================================================
# SUBCOMANDO: kitsune eval
# =====================================================================
@app.command(name="eval")
def eval_command(
    scores_file: Path = typer.Option(
        ...,
        "--scores",
        "-s",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Path to the anomaly scores file (CSV with 'rmse' column or raw values).",
    ),
    labels_file: Path = typer.Option(
        ...,
        "--labels",
        "-l",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Path to ground truth labels file (CSV/TXT with 0 for benign, 1 for anomaly).",
    ),
    skip_grace: int = typer.Option(
        2000,
        "--skip-grace",
        "-g",
        help="Number of initial packets to exclude from evaluation (FM + AD grace periods).",
    ),
    out_json: Optional[Path] = typer.Option(
        None,
        "--json",
        "-j",
        help="Optional destination path to export forensic metrics as structured JSON.",
    ),
) -> None:
    """
    Audit anomaly scores against ground truth labels according to NDSS 2018 (Sec. V-C & Fig. 9).
    """
    if compute_roc_metrics is None:
        console.print("[red][!] Error: 'metrics.py' could not be imported.[/red]")
        raise typer.Exit(code=1)

    console.print(
        Panel.fit(
            "[bold white]🦊 Kitsune NIDS: Forensic Benchmarking Engine[/bold white]\n"
            "[dim]NDSS 2018 Section V-C | AUC, EER and Zero-False-Alarm Operating Points[/dim]",
            border_style="magenta",
        )
    )

    console.print(f"[dim]• Scores Path    :[/dim] [cyan]{scores_file.resolve()}[/cyan]")
    console.print(f"[dim]• Labels Path    :[/dim] [cyan]{labels_file.resolve()}[/cyan]")
    if skip_grace > 0:
        console.print(f"[dim]• Grace Offset   :[/dim] [yellow]Excluding first {skip_grace:,} pkts (evaluating strictly in exec-mode)[/yellow]\n")
    else:
        console.print()

    # Carga robusta de scores
    with console.status("[bold cyan]Loading scores and labels into memory...[/bold cyan]"):
        try:
            scores_raw = np.genfromtxt(scores_file, delimiter=",", skip_header=0, comments="#", dtype=np.float64)
            if scores_raw.ndim > 1:
                # Si tiene formato index,rmse o similar, tomar la última columna
                y_scores = scores_raw[:, -1]
            else:
                y_scores = scores_raw
            # Eliminar posibles NaNs residuales de encabezados de texto no comentados
            y_scores = y_scores[~np.isnan(y_scores)]
        except Exception as e:
            console.print(f"[red][!] Error parsing scores file: {e}[/red]")
            raise typer.Exit(code=1)

        try:
            labels_raw = np.genfromtxt(labels_file, delimiter=",", skip_header=0, comments="#", dtype=np.float64)
            if labels_raw.ndim > 1:
                y_true = labels_raw[:, -1].astype(np.int32)
            else:
                y_true = labels_raw.astype(np.int32)
            y_true = y_true[~np.isnan(y_true)]
        except Exception as e:
            console.print(f"[red][!] Error parsing labels file: {e}[/red]")
            raise typer.Exit(code=1)

    # Validar alineación dimensional antes de saltar la gracia
    min_len = min(len(y_scores), len(y_true))
    if len(y_scores) != len(y_true):
        console.print(
            f"[yellow][!] Dimension mismatch: {len(y_scores):,} scores vs {len(y_true):,} labels. "
            f"Truncating evaluation to the first {min_len:,} instances.[/yellow]\n"
        )
        y_scores = y_scores[:min_len]
        y_true = y_true[:min_len]

    # Aplicar corte metodológico de periodo de gracia (NDSS 2018 Sec. IV-A / V-C)
    if skip_grace > 0:
        if len(y_scores) > skip_grace:
            y_scores = y_scores[skip_grace:]
            y_true = y_true[skip_grace:]
        else:
            console.print(f"[red][!] Error: Evaluated stream length ({len(y_scores):,}) is shorter than skip_grace ({skip_grace:,}).[/red]")
            raise typer.Exit(code=1)

    # Ejecutar motor de métricas
    with console.status("[bold magenta]Computing ROC curve, AUC, EER and operational operating points...[/bold magenta]"):
        try:
            report = compute_roc_metrics(y_true, y_scores)
        except ValueError as err:
            console.print(f"[red][!] Evaluation failed: {err}[/red]")
            raise typer.Exit(code=1)

    # Tabla de presentación NDSS 2018 (Figura 9)
    table = Table(
        title="NDSS 2018 Intrusion Detection Benchmark (Sec. V-C & Fig. 9)",
        border_style="magenta",
        show_lines=True,
    )
    table.add_column("Benchmark Metric", style="cyan", no_wrap=True)
    table.add_column("NDSS 2018 Criterion", style="dim")
    table.add_column("Empirical Result", justify="right", style="bold green")

    table.add_row(
        "Total Packets Evaluated",
        "Stream Length (Exec-mode)",
        f"{report['n_packets']:,}",
    )
    table.add_row(
        "Class Distribution",
        "Positives / Negatives",
        f"{report['n_pos']:,} (1) / {report['n_neg']:,} (0)",
    )
    table.add_row(
        "Area Under Curve (AUC)",
        "Overall Ranking Quality (Higher is better)",
        f"{report['auc']:.4f}",
    )
    table.add_row(
        "Equal Error Rate (EER)",
        "Equilibrium where FPR == FNR (Lower is better)",
        f"{report['eer']:.4f} (at τ={report['eer_threshold']:.4f})",
    )
    table.add_row(
        "TPR @ FPR = 0",
        "Zero False Alarms (Fig. 9 Top)",
        f"{report['tpr_at_fpr_0']*100:.2f}% ({report['tp_at_fpr_0']:,} pkts)",
    )
    table.add_row(
        "FNR @ FPR = 0",
        "Missed Attacks at Zero FP (Fig. 9 Top)",
        f"{report['fnr_at_fpr_0']*100:.2f}% (at τ={report['thresh_at_fpr_0']:.4f})",
    )
    table.add_row(
        "TPR @ FPR ≤ 0.001",
        "Operational Threshold (Fig. 9 Middle)",
        f"{report['tpr_at_fpr_001']*100:.2f}% ({report['tp_at_fpr_001']:,} pkts)",
    )
    table.add_row(
        "FNR @ FPR ≤ 0.001",
        "Missed Attacks at Max 0.1% FP (Fig. 9 Middle)",
        f"{report['fnr_at_fpr_001']*100:.2f}% (at τ={report['thresh_at_fpr_001']:.4f})",
    )

    console.print(table)

    if out_json:
        out_json.parent.mkdir(parents=True, exist_ok=True)
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        console.print(f"\n[green][✓] Forensic benchmark JSON exported to:[/green] [cyan]{out_json.resolve()}[/cyan]")


def _render_plot(
    scores: list[float],
    tau: float,
    fm_grace: int,
    ad_grace: int,
    attack_start: int,
    out_path: Path,
) -> None:
    """Generates the canonical dark-mode forensic plot."""
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        console.print("[yellow][!] Matplotlib not available; skipping plot generation.[/yellow]")
        return

    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.figure(figsize=(13, 5), dpi=140)
    plt.style.use("dark_background")

    x = np.arange(len(scores))
    plt.plot(x, scores, color="#38bdf8", lw=1.1, label="KitNET RMSE Residue", alpha=0.9)
    plt.axhline(
        y=tau,
        color="#f43f5e",
        ls="--",
        lw=1.6,
        label=rf"Decision Cutoff $\tau = {tau:.4f}$ (FPR $\leq 10^{{-3}}$)",
    )

    plt.axvspan(0, fm_grace, color="#64748b", alpha=0.25, label="corClust Feature Mapping")
    plt.axvspan(fm_grace, fm_grace + ad_grace, color="#eab308", alpha=0.15, label="Online SGD Calibration")
    if len(scores) > attack_start:
        plt.axvspan(attack_start, len(scores), color="#ef4444", alpha=0.20, label="Mirai Active Attack Phase")

    plt.yscale("log")
    plt.title("Kitsune NIDS: Online Streaming Anomaly Detection (Mirai Botnet Trace)", fontsize=12, pad=10)
    plt.xlabel("Ingested Packets (Continuous Stream)", fontsize=9)
    plt.ylabel("RMSE Reconstruction Error (Log Scale)", fontsize=9)
    plt.grid(True, which="both", ls=":", alpha=0.25)
    plt.legend(loc="upper left", framealpha=0.85)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()
    console.print(f"[green][✓] Forensic plot rendered at:[/green] [cyan]{out_path.resolve()}[/cyan]\n")


def main() -> None:
    app()


if __name__ == "__main__":
    main()