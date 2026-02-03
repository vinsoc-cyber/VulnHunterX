"""CodeQL static analysis operations."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional


class CodeQLAnalyzer:
    """
    Runs CodeQL analysis on databases.
    
    Supports security-extended and code-scanning query suites.
    """
    
    # Default query suites per language
    DEFAULT_SUITES: dict[str, str] = {
        "cpp": "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls",
        "c": "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls",
        "python": "codeql/python-queries:codeql-suites/python-security-extended.qls",
        "javascript": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
    }
    
    def __init__(
        self,
        codeql_path: str = "codeql",
        output_dir: Path | None = None,
    ):
        self.codeql_path = codeql_path
        self.output_dir = output_dir or Path("output")
    
    def run_analysis(
        self,
        db_path: Path,
        lang: str,
        output_name: Optional[str] = None,
        suite: Optional[str] = None,
    ) -> tuple[bool, Path | None, str]:
        """
        Run CodeQL analysis on a database.
        
        Args:
            db_path: Path to the CodeQL database
            lang: Language (c, cpp, python, javascript)
            output_name: Name for output file (default: database name)
            suite: Query suite (default: language-specific security suite)
            
        Returns:
            Tuple of (success, sarif_path, message)
        """
        codeql_lang = "cpp" if lang in ("c", "cpp") else lang
        suite = suite or self.DEFAULT_SUITES.get(codeql_lang, self.DEFAULT_SUITES["cpp"])
        output_name = output_name or db_path.name
        
        sarif_dir = self.output_dir / "sarif" / lang
        sarif_dir.mkdir(parents=True, exist_ok=True)
        sarif_path = sarif_dir / f"{output_name}.sarif"
        
        # First, finalize if needed
        if not self._is_finalized(db_path):
            success, msg = self._finalize(db_path)
            if not success:
                return False, None, f"Finalization failed: {msg}"
        
        # Run analysis
        cmd = [
            self.codeql_path,
            "database",
            "analyze",
            str(db_path),
            suite,
            "--format=sarifv2.1.0",
            f"--output={sarif_path}",
            "--sarif-add-snippets",
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600,  # 1 hour
            )
            
            if result.returncode == 0:
                return True, sarif_path, "Analysis completed"
            else:
                return False, None, result.stderr or result.stdout
                
        except subprocess.TimeoutExpired:
            return False, None, "Analysis timed out"
        except Exception as e:
            return False, None, str(e)
    
    def run_tool_query(
        self,
        db_path: Path,
        query_path: Path,
        output_path: Path,
    ) -> tuple[bool, str]:
        """
        Run a tool query and output to CSV.
        
        Args:
            db_path: Path to the CodeQL database
            query_path: Path to the .ql file
            output_path: Path for CSV output
            
        Returns:
            Tuple of (success, message)
        """
        bqrs_path = output_path.with_suffix(".bqrs")
        
        # Run query
        cmd_run = [
            self.codeql_path,
            "query",
            "run",
            str(query_path),
            f"--database={db_path}",
            f"--output={bqrs_path}",
        ]
        
        try:
            result = subprocess.run(
                cmd_run,
                capture_output=True,
                text=True,
                timeout=600,
            )
            
            if result.returncode != 0:
                return False, result.stderr or result.stdout
            
            # Decode to CSV
            cmd_decode = [
                self.codeql_path,
                "bqrs",
                "decode",
                "--format=csv",
                f"--output={output_path}",
                str(bqrs_path),
            ]
            
            result = subprocess.run(
                cmd_decode,
                capture_output=True,
                text=True,
                timeout=120,
            )
            
            # Clean up bqrs
            if bqrs_path.exists():
                bqrs_path.unlink()
            
            if result.returncode == 0:
                return True, f"Query output: {output_path}"
            else:
                return False, result.stderr or result.stdout
                
        except Exception as e:
            return False, str(e)
    
    def _is_finalized(self, db_path: Path) -> bool:
        """Check if database is finalized."""
        return (db_path / "db-cpp" / "trap" / "completion-stamp").exists() or \
               (db_path / "db-python" / "trap" / "completion-stamp").exists() or \
               (db_path / "db-javascript" / "trap" / "completion-stamp").exists()
    
    def _finalize(self, db_path: Path) -> tuple[bool, str]:
        """Finalize the database."""
        cmd = [self.codeql_path, "database", "finalize", str(db_path)]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )
            
            if result.returncode == 0:
                return True, "Finalized"
            else:
                return False, result.stderr or result.stdout
                
        except Exception as e:
            return False, str(e)
    
    def download_packs(self) -> tuple[bool, str]:
        """Download required CodeQL packs."""
        packs = [
            "codeql/cpp-queries",
            "codeql/python-queries",
            "codeql/javascript-queries",
        ]
        
        for pack in packs:
            cmd = [self.codeql_path, "pack", "download", pack]
            
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
                
                if result.returncode != 0:
                    return False, f"Failed to download {pack}: {result.stderr}"
                    
            except Exception as e:
                return False, f"Error downloading {pack}: {e}"
        
        return True, "All packs downloaded"
