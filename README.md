# Procmon Residue Analyzer

A PySide6 desktop application that analyzes Procmon CSV traces to detect residual
artifacts left behind by software installations/uninstallations on Windows.

## Project Structure

```
leftovers/
├── main.py                         # Application entry point
├── requirements.txt                # Python dependencies
└── leftovers/                      # Main package
    ├── app.py                      # QApplication setup
    ├── constants/                  # Configuration & constants
    │   ├── operations.py           # Process & operation constants
    │   ├── paths.py                # Path & registry prefix constants
    │   ├── scoring.py              # Scoring config & persistence bonus
    │   └── trust.py                # Trusted signers & stop words
    ├── models/                     # Data models
    │   ├── event.py                # ProcmonEvent dataclass
    │   ├── process.py              # ProcessInfo dataclass
    │   └── residue.py              # ResidueCandidate dataclass
    ├── core/                       # Core analysis logic
    │   ├── loader.py               # Procmon CSV file loader
    │   └── analyzer.py             # Main analysis engine
    ├── utils/                      # Utility functions
    │   ├── text.py                 # Text processing utilities
    │   ├── path.py                 # Path normalization & classification
    │   ├── pattern.py              # Pattern compilation & token matching
    │   └── trust.py                # Authenticode & signature verification
    ├── workers/                    # Background workers
    │   └── analysis.py             # Analysis worker thread
    └── ui/                         # User interface
        ├── table_model.py          # Qt table model for residue display
        └── main_window.py          # Main application window
```

## Setup

```bash
pip install -r requirements.txt
```

## Usage

```bash
python main.py
```

## Analysis Algorithm – 3-Step Root Finding

The core of the analysis engine is the **flood-fill expansion** algorithm
implemented in `ProcmonAnalyzer._flood_fill_from_confirmed_roots()`.  After
the initial scoring pass produces a list of candidate residues, this function
iteratively expands the set by discovering related artifacts that were missed.

The algorithm runs up to **3 iterations** (`max_iterations=3`).  Each
iteration consists of **5 ordered sub-steps**:

| # | Azərbaycanca | English | What it does |
|---|---|---|---|
| 1 | Kök klaster genişlənməsi | Root cluster expansion | Seeds from high-confidence roots (score ≥ 80) propagate a +20 score boost to candidates sharing a family ID (vendor, service, rename, or installer cluster). Uses a transitive BFS — DuckDB recursive CTE when available, Python BFS otherwise. |
| 2 | Fayl sistemi və registr qonşuluğu | FS & registry neighbourhood | For each confirmed residue (score ≥ 55) that still exists on disk, walks the parent directory (up to depth 4) and discovers neighbouring registry keys via binary-search. New items inherit ~50% of the parent score. |
| 3 | Registr budaq taraması | Registry branch sweep | Enumerates the full branch (sub-keys and values) of every registry-type residue with score ≥ 50. |
| 4 | Qardaş fayllar | Sibling files | Adds files sharing the same base name (different extension) and registry keys sharing the same parent. |
| 5 | Ana qovluqlar | Parent directories | If a residue's parent directory was originally created during the traced session, adds it as a directory candidate. |

The loop **terminates early** when an iteration produces no new candidates,
meaning the expansion has converged.  Progress is reported between 86% and
90% of the overall analysis.
