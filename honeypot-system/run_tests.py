import argparse
import ast
from pathlib import Path

SRC_ROOT = Path("src")
TEST_ROOT = Path("test/unit/src")


def compute_function_coverage(data_file: Path, source_root: Path) -> tuple[int, int]:
    try:
        from coverage import Coverage
    except ImportError:
        return 0, 0

    cov = Coverage(data_file=str(data_file))
    cov.load()
    coverage_data = cov.get_data()

    total_functions = 0
    covered_functions = 0

    for measured_file in sorted(coverage_data.measured_files()):
        file_path = Path(measured_file)
        if not file_path.exists() or source_root not in file_path.resolve().parents:
            continue
        if file_path.suffix != ".py":
            continue

        executed_lines = set(coverage_data.lines(str(file_path)) or [])
        with file_path.open("r", encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=str(file_path))

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                total_functions += 1
                function_lines = {
                    child.lineno
                    for child in ast.walk(node)
                    if hasattr(child, "lineno")
                }
                if function_lines & executed_lines:
                    covered_functions += 1

    return total_functions, covered_functions


def main() -> int:
    parser = argparse.ArgumentParser(description="Run parser and enricher unit tests with pytest")
    parser.add_argument(
        "--no-coverage",
        action="store_true",
        help="Run tests without pytest-cov coverage measurement",
    )
    parser.add_argument(
        "--tests",
        nargs="*",
        default=[str(TEST_ROOT)],
        help="Directories or files to run",
    )
    args = parser.parse_args()

    try:
        import pytest
    except ImportError:
        print("pytest is required to run this script. Install it with: pip install pytest pytest-cov")
        return 1

    pytest_args = [*args.tests]
    if not args.no_coverage:
        pytest_args += [
            "--cov=src",
            "--cov-branch",
            "--cov-report=term-missing",
            "--cov-report=html:coverage_html",
            "--cov-report=xml:coverage.xml",
        ]

    exit_code = pytest.main(pytest_args)

    if exit_code == 0 and not args.no_coverage:
        total_functions, covered_functions = compute_function_coverage(Path(".coverage"), SRC_ROOT)
        if total_functions:
            rate = covered_functions / total_functions * 100.0
            print(f"\nFunction coverage: {covered_functions}/{total_functions} functions covered ({rate:.1f}%)")
        else:
            print("\nFunction coverage: no Python functions found in source files.")

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
