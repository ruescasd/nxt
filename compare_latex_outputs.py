#!/usr/bin/env python3
"""
Compare LaTeX outputs from legacy and new threat model generators.

This script:
1. Generates LaTeX files using the legacy script (SQLite database)
2. Generates LaTeX files using the new script (Python model + compat layer)
3. Compares both sets of files and reports differences
"""

import subprocess
import sys
import tempfile
from pathlib import Path


def run_command(cmd: list[str], cwd: Path) -> tuple[int, str, str]:
    """Run a command and return exit code, stdout, stderr."""
    result = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout, result.stderr


def generate_legacy_latex(output_dir: Path, project_root: Path) -> bool:
    """Generate LaTeX files using the legacy script."""
    print("Generating legacy LaTeX files...")
    
    legacy_script = project_root / "legacy" / "generate_latex_inputs.py"
    
    # Run from legacy folder so it can find the database
    code, stdout, stderr = run_command(
        [sys.executable, str(legacy_script), "-o", str(output_dir)],
        cwd=project_root / "legacy",
    )
    
    if code != 0:
        print(f"  ERROR: Legacy generation failed")
        print(f"  stdout: {stdout}")
        print(f"  stderr: {stderr}")
        return False
    
    print(f"  Generated {len(list(output_dir.glob('*.tex')))} files")
    return True


def generate_new_latex(output_dir: Path, project_root: Path) -> bool:
    """Generate LaTeX files using the new script."""
    print("Generating new LaTeX files...")
    
    # Run as module from project root
    code, stdout, stderr = run_command(
        [sys.executable, "-m", "nxt.model.generate_latex_inputs", "-o", str(output_dir)],
        cwd=project_root,
    )
    
    if code != 0:
        print(f"  ERROR: New generation failed")
        print(f"  stdout: {stdout}")
        print(f"  stderr: {stderr}")
        return False
    
    print(f"  Generated {len(list(output_dir.glob('*.tex')))} files")
    return True


def compare_files(legacy_dir: Path, new_dir: Path) -> tuple[int, int, list[str]]:
    """Compare files between two directories.
    
    Returns: (identical_count, different_count, list of different filenames)
    """
    legacy_files = {f.name for f in legacy_dir.glob("*.tex")}
    new_files = {f.name for f in new_dir.glob("*.tex")}
    
    # Check for missing files
    only_in_legacy = legacy_files - new_files
    only_in_new = new_files - legacy_files
    
    if only_in_legacy:
        print(f"  WARNING: Files only in legacy: {only_in_legacy}")
    if only_in_new:
        print(f"  WARNING: Files only in new: {only_in_new}")
    
    common_files = legacy_files & new_files
    identical = 0
    different = 0
    different_files = []
    
    for filename in sorted(common_files):
        legacy_content = (legacy_dir / filename).read_text(encoding="utf-8")
        new_content = (new_dir / filename).read_text(encoding="utf-8")
        
        # Normalize line endings for comparison
        legacy_normalized = legacy_content.replace("\r\n", "\n")
        new_normalized = new_content.replace("\r\n", "\n")
        
        if legacy_normalized == new_normalized:
            identical += 1
        else:
            different += 1
            different_files.append(filename)
    
    return identical, different, different_files


def show_diff(legacy_dir: Path, new_dir: Path, filename: str) -> None:
    """Show a simple diff between two files."""
    legacy_lines = (legacy_dir / filename).read_text(encoding="utf-8").replace("\r\n", "\n").splitlines()
    new_lines = (new_dir / filename).read_text(encoding="utf-8").replace("\r\n", "\n").splitlines()
    
    print(f"\n  Diff for {filename}:")
    
    # Simple line-by-line comparison
    max_lines = max(len(legacy_lines), len(new_lines))
    diff_count = 0
    
    for i in range(max_lines):
        legacy_line = legacy_lines[i] if i < len(legacy_lines) else "<missing>"
        new_line = new_lines[i] if i < len(new_lines) else "<missing>"
        
        if legacy_line != new_line:
            diff_count += 1
            if diff_count <= 5:  # Show first 5 differences
                print(f"    Line {i + 1}:")
                print(f"      Legacy: {legacy_line[:80]}{'...' if len(legacy_line) > 80 else ''}")
                print(f"      New:    {new_line[:80]}{'...' if len(new_line) > 80 else ''}")
    
    if diff_count > 5:
        print(f"    ... and {diff_count - 5} more differences")


def main() -> int:
    project_root = Path(__file__).parent.resolve()
    
    print("=" * 60)
    print("LaTeX Output Comparison: Legacy vs New")
    print("=" * 60)
    
    # Create temporary directories for output
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        legacy_output = temp_path / "legacy"
        new_output = temp_path / "new"
        legacy_output.mkdir()
        new_output.mkdir()
        
        # Step 1: Generate legacy LaTeX
        print("\n[Step 1] Legacy Generation")
        if not generate_legacy_latex(legacy_output, project_root):
            return 1
        
        # Step 2: Generate new LaTeX
        print("\n[Step 2] New Generation")
        if not generate_new_latex(new_output, project_root):
            return 1
        
        # Step 3: Compare outputs
        print("\n[Step 3] Comparing Outputs")
        identical, different, different_files = compare_files(legacy_output, new_output)
        
        print(f"\n{'=' * 60}")
        print("Results:")
        print(f"  Identical files: {identical}")
        print(f"  Different files: {different}")
        
        if different_files:
            print(f"\n  Files with differences:")
            for filename in different_files:
                print(f"    - {filename}")
                show_diff(legacy_output, new_output, filename)
            print(f"\n{'=' * 60}")
            print("FAILED: Some files differ")
            return 1
        else:
            print(f"\n{'=' * 60}")
            print("SUCCESS: All files are identical!")
            return 0


if __name__ == "__main__":
    sys.exit(main())
