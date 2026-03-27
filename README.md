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
