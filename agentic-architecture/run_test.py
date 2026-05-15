#!/usr/bin/env python3
"""
Test runner du pipeline forensique.

Lance les 4 étapes une par une, capture stdout/stderr de chaque sous-processus,
affiche les logs en temps réel sur la console ET les écrit dans un fichier de log.

Usage (depuis le dossier agentic-architecture/) :
    python run_test.py
    python run_test.py --collector ../test_input.json
    python run_test.py --use-llm          # si OPENROUTER_API_KEY est définie
    python run_test.py --no-llm           # force le mode règles (debug)
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Chemins par défaut
# ---------------------------------------------------------------------------
_HERE       = Path(__file__).parent.resolve()
_SCRIPTS    = _HERE / "scripts"
_OUTPUT     = _HERE / "output"
_LOGS       = _HERE / "logs"
_COLLECTOR  = _HERE.parent / "test_input.json"
_ARTIFACTS  = _HERE.parent
_LLM_CONFIG = _HERE / "llm_config.json"


# ---------------------------------------------------------------------------
# Setup logging : console + fichier
# ---------------------------------------------------------------------------

class _ColorFormatter(logging.Formatter):
    """Formatter avec couleurs ANSI pour la console."""
    COLORS = {
        logging.DEBUG:    "\033[90m",   # gris
        logging.INFO:     "\033[0m",    # blanc normal
        logging.WARNING:  "\033[33m",   # jaune
        logging.ERROR:    "\033[31m",   # rouge
        logging.CRITICAL: "\033[1;31m", # rouge gras
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelno, self.RESET)
        msg = super().format(record)
        return f"{color}{msg}{self.RESET}"


def setup_logging(log_dir: Path, run_id: str) -> Path:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"run_{run_id}.log"

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    # Handler fichier : tout (DEBUG+), sans couleurs
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    root.addHandler(fh)

    # Handler console : INFO+, avec couleurs
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(_ColorFormatter(
        "%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S"
    ))
    root.addHandler(ch)

    return log_file


# ---------------------------------------------------------------------------
# Exécution d'un sous-processus avec capture ligne par ligne
# ---------------------------------------------------------------------------

def run_step(label: str, cmd: list, step_num: int, total_steps: int) -> bool:
    """
    Lance un sous-processus, streame sa sortie ligne par ligne vers les logs.
    Retourne True si succès, False si erreur.
    """
    log = logging.getLogger()
    separator = "─" * 60

    log.info("")
    log.info(separator)
    log.info(f"ÉTAPE {step_num}/{total_steps} : {label}")
    log.info(f"Commande : {' '.join(str(c) for c in cmd)}")
    log.info(separator)

    start = time.time()
    all_output_lines = []

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,   # fusionne stderr dans stdout
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        for line in proc.stdout:
            line = line.rstrip("\n")
            if line:
                all_output_lines.append(line)
                # Les lignes de DEBUG vont dans le fichier uniquement
                log.debug(f"  [{label}] {line}")
                # Les lignes importantes (warnings/erreurs) aussi sur console
                low = line.lower()
                if any(w in low for w in ("error", "failed", "traceback", "exception", "warning")):
                    log.warning(f"  >> {line}")
                elif any(w in low for w in ("complete", "success", "done", "running")):
                    log.info(f"  >> {line}")

        proc.wait()
        elapsed = time.time() - start

        if proc.returncode == 0:
            log.info(f"  [OK] '{label}' terminé en {elapsed:.1f}s (exit 0)")
            return True
        else:
            log.error(f"  [FAIL] '{label}' a échoué en {elapsed:.1f}s (exit {proc.returncode})")
            # Réaffiche les dernières lignes pour diagnostiquer
            log.error("  --- Dernières lignes de sortie ---")
            for line in all_output_lines[-15:]:
                log.error(f"  {line}")
            return False

    except FileNotFoundError as exc:
        log.error(f"  [FAIL] Impossible de lancer '{label}': {exc}")
        return False


# ---------------------------------------------------------------------------
# Vérification et affichage d'un fichier de sortie JSON
# ---------------------------------------------------------------------------

def inspect_output_json(path: Path, label: str) -> None:
    log = logging.getLogger()
    if not path.exists():
        log.warning(f"  [?] {label} : fichier non trouvé ({path})")
        return

    size = path.stat().st_size
    log.info(f"  [fichier] {label} : {path.name} ({size} octets)")

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        # Affiche un résumé adapté selon le type de fichier
        if "suspicious_processes" in data:
            procs = data.get("suspicious_processes", [])
            paths = data.get("suspicious_paths", [])
            log.info(f"    -> {len(procs)} processus suspects, {len(paths)} chemins suspects")
            for p in procs[:5]:
                score = p.get("score", "?")
                img   = p.get("image", "?")
                pid   = p.get("pid", "?")
                phase = p.get("attack_phase", "")
                reasons = "; ".join(p.get("reasons", []))[:120]
                log.info(f"    PID {pid:>6} | score={score:>2} | {img:<25} | {phase}")
                log.debug(f"             reasons: {reasons}")

        elif "by_pid" in data:
            by_pid  = data.get("by_pid", {})
            by_path = data.get("by_path", {})
            total_pid_hits  = sum(sum(len(v) for v in f.values()) for f in by_pid.values())
            total_path_hits = sum(sum(len(v) for v in f.values()) for f in by_path.values())
            log.info(f"    -> {len(by_pid)} PIDs ciblés ({total_pid_hits} lignes matchées)")
            log.info(f"    -> {len(by_path)} chemins ciblés ({total_path_hits} lignes matchées)")
            for pid, files in by_pid.items():
                hits = sum(len(v) for v in files.values())
                log.debug(f"       PID {pid}: {hits} hits dans {list(files.keys())}")

        elif "validated_findings" in data:
            confirmed    = data.get("validated_findings", [])
            rejected     = data.get("rejected_findings", [])
            inconclusive = data.get("inconclusive_findings", [])
            summary      = data.get("analyst_summary", "")
            log.info(f"    -> Confirmés: {len(confirmed)} | Rejetés: {len(rejected)} | Inconclusifs: {len(inconclusive)}")
            if summary:
                log.info(f"    -> Résumé analyste: {summary[:200]}")
            for f in confirmed:
                log.info(f"    [CONFIRMED] {f.get('target')} | conf={f.get('confidence')} | {f.get('attack_phase')}")
                log.debug(f"       justif: {f.get('justification', '')[:200]}")
            for f in inconclusive:
                log.debug(f"    [INCONCLUSIVE] {f.get('target')}: {f.get('justification', '')[:120]}")

    except json.JSONDecodeError as exc:
        log.error(f"    [ERREUR] JSON invalide : {exc}")
    except Exception as exc:
        log.error(f"    [ERREUR] Lecture impossible : {exc}")


def inspect_report(path: Path) -> None:
    log = logging.getLogger()
    if not path.exists():
        log.warning(f"  [?] Rapport non trouvé : {path}")
        return
    size = path.stat().st_size
    log.info(f"  [fichier] Rapport final : {path.name} ({size} octets)")
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
        log.info(f"  [rapport] {len(lines)} lignes — aperçu :")
        # Affiche les 30 premières lignes en INFO (visibles en console)
        for line in lines[:30]:
            log.info(f"    {line.rstrip()}")
        if len(lines) > 30:
            log.info(f"    ... ({len(lines) - 30} lignes supplémentaires dans {path.name})")
    except Exception as exc:
        log.error(f"    [ERREUR] {exc}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Test runner du pipeline forensique")
    parser.add_argument("--collector",     default=str(_COLLECTOR),    help="Chemin vers le JSON collecteur")
    parser.add_argument("--artifact-root", default=str(_ARTIFACTS),   help="Dossier contenant les *.txt Volatility")
    parser.add_argument("--out",           default=str(_OUTPUT),       help="Dossier de sortie des artefacts")
    parser.add_argument("--llm-config",    default=str(_LLM_CONFIG),   help="Config LLM")
    parser.add_argument("--use-llm",       action="store_true",        help="Active le LLM sur toutes les étapes")
    parser.add_argument("--no-llm",        action="store_true",        help="Force le mode règles partout (debug)")
    args = parser.parse_args()

    run_id  = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    log_file = setup_logging(_LOGS, run_id)
    log = logging.getLogger()

    out_dir      = Path(args.out)
    triage_path  = out_dir / "triage.json"
    pivot_path   = out_dir / "pivot.json"
    analyst_path = out_dir / "analyst.json"
    report_path  = out_dir / "report.md"
    out_dir.mkdir(parents=True, exist_ok=True)

    log.info("=" * 60)
    log.info("  PIPELINE FORENSIQUE — TEST COMPLET")
    log.info("=" * 60)
    log.info(f"  Run ID       : {run_id}")
    log.info(f"  Log file     : {log_file}")
    log.info(f"  Collector    : {args.collector}")
    log.info(f"  Artifacts    : {args.artifact_root}")
    log.info(f"  Output dir   : {out_dir}")
    log.info(f"  Mode LLM     : {'ACTIVÉ' if args.use_llm else 'DÉSACTIVÉ (règles)' if args.no_llm else 'AUTO (LLM si clé dispo)'}")
    log.info("=" * 60)

    # Vérifications préalables
    if not Path(args.collector).exists():
        log.error(f"Collector introuvable : {args.collector}")
        sys.exit(1)
    if not Path(args.artifact_root).exists():
        log.error(f"Artifact root introuvable : {args.artifact_root}")
        sys.exit(1)

    python = sys.executable
    results = {}
    total_start = time.time()

    # ------------------------------------------------------------------
    # ÉTAPE 1 : Triage (Agent 1)
    # ------------------------------------------------------------------
    cmd1 = [python, str(_SCRIPTS / "triage_agent.py"),
            "--collector", args.collector,
            "--out", str(triage_path),
            "--llm-config", args.llm_config]
    if args.no_llm:
        cmd1.append("--no-llm")
    results["1_triage"] = run_step("Agent 1 — Triage", cmd1, 1, 4)
    if results["1_triage"]:
        inspect_output_json(triage_path, "triage.json")

    # ------------------------------------------------------------------
    # ÉTAPE 2 : Grep pivot (déterministe)
    # ------------------------------------------------------------------
    cmd2 = [python, str(_SCRIPTS / "pivot_grep.py"),
            "--triage", str(triage_path),
            "--artifact-root", args.artifact_root,
            "--out", str(pivot_path)]
    results["2_pivot"] = run_step("Script — Grep Pivot", cmd2, 2, 4)
    if results["2_pivot"]:
        inspect_output_json(pivot_path, "pivot.json")

    # ------------------------------------------------------------------
    # ÉTAPE 3 : Pivot Analyst (Agent 2)
    # ------------------------------------------------------------------
    cmd3 = [python, str(_SCRIPTS / "pivot_analyst.py"),
            "--triage", str(triage_path),
            "--pivot", str(pivot_path),
            "--out", str(analyst_path),
            "--llm-config", args.llm_config]
    results["3_analyst"] = run_step("Agent 2 — Pivot Analyst", cmd3, 3, 4)
    if results["3_analyst"]:
        inspect_output_json(analyst_path, "analyst.json")

    # ------------------------------------------------------------------
    # ÉTAPE 4 : Report Writer (Agent 3)
    # ------------------------------------------------------------------
    cmd4 = [python, str(_SCRIPTS / "report_agent.py"),
            "--analyst", str(analyst_path),
            "--pivot", str(pivot_path),
            "--out", str(report_path),
            "--llm-config", args.llm_config]
    if args.use_llm:
        cmd4.append("--use-llm")
    results["4_report"] = run_step("Agent 3 — Report Writer", cmd4, 4, 4)
    if results["4_report"]:
        inspect_report(report_path)

    # ------------------------------------------------------------------
    # Résumé final
    # ------------------------------------------------------------------
    total_elapsed = time.time() - total_start
    log.info("")
    log.info("=" * 60)
    log.info("  RÉSUMÉ DU RUN")
    log.info("=" * 60)
    status_map = {True: "✓  OK", False: "✗  FAIL"}
    step_labels = {
        "1_triage":   "Agent 1 — Triage",
        "2_pivot":    "Script — Grep Pivot",
        "3_analyst":  "Agent 2 — Pivot Analyst",
        "4_report":   "Agent 3 — Report Writer",
    }
    all_ok = True
    for key, label in step_labels.items():
        ok = results.get(key, False)
        all_ok = all_ok and ok
        log.info(f"  {status_map[ok]}  {label}")

    log.info("")
    log.info(f"  Durée totale : {total_elapsed:.1f}s")
    log.info(f"  Logs         : {log_file}")
    log.info(f"  Outputs      : {out_dir}")
    log.info("=" * 60)

    if all_ok:
        log.info("  PIPELINE TERMINÉ AVEC SUCCÈS")
    else:
        log.error("  PIPELINE TERMINÉ AVEC DES ERREURS — voir logs ci-dessus")
    log.info("=" * 60)

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
