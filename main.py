import argparse
import logging
import subprocess
import sys
import os
import astroid
from pylint import lint
import pycodestyle

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="cvsa-Dependency-Checker: Lightweight static analysis tool.")
    parser.add_argument("project_path", help="Path to the project directory.")
    parser.add_argument("--report_file", help="Path to save the report. If not provided, it prints to stdout.", default=None)
    parser.add_argument("--ignore", help="Comma-separated list of vulnerabilities to ignore (e.g., CVE-2023-123,PYLINT:W0613)", default=None)
    return parser

def check_dependencies(project_path):
    """
    Lists project dependencies using pip freeze and checks them against known vulnerabilities databases using safety.
    Args:
        project_path (str): The path to the project directory.
    Returns:
        tuple: Dependencies list, report string, and a flag telling
        whether the safety check actually ran. The flag matters because
        safety exits non-zero when it finds vulnerabilities, so its
        exit code alone cannot separate "found problems" from "never
        ran"; a run that produced a report counts as ran either way.
    """
    project_path = os.path.abspath(project_path)
    try:
        # Use the virtual environment executables directly by path when a
        # .venv is present. No shell is involved, so the project path is
        # never parsed as shell syntax, and the freeze and the safety check
        # describe the same environment.
        venv_path = os.path.join(project_path, ".venv")
        bin_dir = os.path.join(venv_path, "bin")
        if not os.path.isdir(bin_dir):
            bin_dir = os.path.join(venv_path, "Scripts")
        safety_exe = os.path.join(bin_dir, "safety")
        pip_exe = os.path.join(bin_dir, "pip")
        python_exe = os.path.join(bin_dir, "python")
        has_venv = os.path.isdir(venv_path) and os.path.isdir(bin_dir)
        if not has_venv:
            logging.warning("Virtual environment not found. Checking global dependencies.")
            dependencies = subprocess.check_output(["pip", "freeze"], text=True)
            proc = subprocess.run(["safety", "check", "--full-report"], capture_output=True, text=True)
            if not proc.stdout:
                raise subprocess.CalledProcessError(proc.returncode, proc.args, output=proc.stdout, stderr=proc.stderr)
            report = proc.stdout
        else:
            logging.info("Virtual environment found. Checking dependencies with its own executables.")
            if os.path.exists(safety_exe):
                proc = subprocess.run([safety_exe, "check", "--full-report"], capture_output=True, text=True, cwd=project_path)
            elif os.path.exists(python_exe):
                proc = subprocess.run([python_exe, "-m", "safety", "check", "--full-report"], capture_output=True, text=True, cwd=project_path)
            else:
                raise FileNotFoundError(f"No safety executable found in {bin_dir}")
            if proc.returncode != 0 and not proc.stdout:
                logging.error(f"Safety check failed: {proc.stderr}")
                raise subprocess.CalledProcessError(proc.returncode, proc.args, output=proc.stdout, stderr=proc.stderr)
            report = proc.stdout
            # The freeze comes from the same venv. A freeze failure must not
            # throw away a safety report that already finished.
            try:
                if os.path.exists(pip_exe):
                    dependencies = subprocess.check_output([pip_exe, "freeze"], text=True, cwd=project_path)
                elif os.path.exists(python_exe):
                    dependencies = subprocess.check_output([python_exe, "-m", "pip", "freeze"], text=True, cwd=project_path)
                else:
                    dependencies = ""
            except Exception as freeze_error:
                logging.error(f"Error running pip freeze in virtual environment: {freeze_error}")
                dependencies = f"Error running pip freeze: {freeze_error}"
        return dependencies, report, True

    except subprocess.CalledProcessError as e:
        logging.error(f"Error running dependency check: {e.stderr}")
        return "", f"Error running dependency check: {e.stderr}", False
    except FileNotFoundError as e:
        logging.error(f"Error: pip or safety not found: {e}")
        return "", f"Error: pip or safety not found: {e}", False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return "", f"An unexpected error occurred: {e}", False

def static_analysis(project_path):
    """
    Performs static analysis using pylint and pycodestyle.
    Args:
        project_path (str): The path to the project directory.
    Returns:
        tuple: Pylint output string and pycodestyle output string.
    """
    # Each tool gets its own try block. Sharing one meant a pylint failure
    # also wiped out the pycodestyle result, and the report showed the same
    # pylint error in both sections.
    pylint_output = ""
    pycodestyle_output = ""
    try:
        logging.info("Running Pylint analysis...")
        # Current pylint takes exit=False, and output only reaches a string
        # buffer when a reporter writing to one is passed in.
        from io import StringIO
        from pylint.reporters.text import TextReporter
        buffer = StringIO()
        lint.Run([project_path], reporter=TextReporter(buffer), exit=False)
        pylint_output = buffer.getvalue()
    except Exception as e:
        logging.error(f"Error during pylint: {e}")
        pylint_output = f"Error during pylint: {e}"

    try:
        logging.info("Running Pycodestyle analysis...")
        style_guide = pycodestyle.StyleGuide()
        report = style_guide.check_files([project_path])
        pycodestyle_output = f"Pycodestyle violations: {report.total_errors}"
    except Exception as e:
        logging.error(f"Error during pycodestyle: {e}")
        pycodestyle_output = f"Error during pycodestyle: {e}"

    return pylint_output, pycodestyle_output

def filter_ignored(text, ignored):
    """Remove lines that mention any ignored id, so an ignored finding is
    not presented as a found vulnerability."""
    if not ignored or not text:
        return text
    lowered = [item.strip().lower() for item in ignored if item.strip()]
    if not lowered:
        return text
    kept = []
    for line in text.splitlines():
        if any(item in line.lower() for item in lowered):
            continue
        kept.append(line)
    return "\n".join(kept) + ("\n" if kept else "")

def main():
    """
    Main function to orchestrate the dependency check and static analysis.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Validate project path and resolve it to an absolute path before any
    # command is built from it, so relative and absolute spellings behave
    # the same.
    if not os.path.isdir(args.project_path):
        logging.error("Invalid project path. Please provide a valid directory.")
        print("Error: Invalid project path. Please provide a valid directory.")
        sys.exit(1)
    args.project_path = os.path.abspath(args.project_path)

    logging.info(f"Starting analysis for project: {args.project_path}")

    # Dependency Check
    dependency_check_ran = True
    try:
        dependencies, safety_report, dependency_check_ran = check_dependencies(args.project_path)
        logging.info("Dependency check completed.")
    except Exception as e:
         logging.error(f"Dependency check failed: {e}")
         safety_report = str(e)
         dependencies = ""
         dependency_check_ran = False

    # Static Analysis
    try:
        pylint_report, pycodestyle_report = static_analysis(args.project_path)
        logging.info("Static analysis completed.")
    except Exception as e:
        logging.error(f"Static analysis failed: {e}")
        pylint_report = str(e)
        pycodestyle_report = str(e)


    ignored_vulns = [item.strip() for item in args.ignore.split(',')] if args.ignore else []
    if ignored_vulns:
        safety_report = filter_ignored(safety_report, ignored_vulns)
        pylint_report = filter_ignored(pylint_report, ignored_vulns)

    # Prepare and output report
    report = f"## cvsa-Dependency-Checker Report\n\n"
    report += f"**Project Path:** {args.project_path}\n\n"

    report += "### Dependencies:\n"
    report += (dependencies if isinstance(dependencies, str) else str(dependencies)) + "\n\n"

    report += "### Dependency Vulnerability Check (Safety):\n"
    report += safety_report + "\n\n"

    report += "### Pylint Report:\n"
    report += pylint_report + "\n\n"

    report += "### Pycodestyle Report:\n"
    report += pycodestyle_report + "\n\n"

    # The footer names the ids whose lines were removed above.
    if ignored_vulns:
        report += f"**Ignored Vulnerabilities:** {', '.join(ignored_vulns)}\n"


    # Output the report
    if args.report_file:
        try:
            with open(args.report_file, "w") as f:
                f.write(report)
            logging.info(f"Report saved to {args.report_file}")
        except Exception as e:
            logging.error(f"Error writing report to file: {e}")
            print(report)  # Fallback to stdout
    else:
        print(report)
    
    logging.info("Analysis complete.")

    # The report is still printed when the safety check never ran (its
    # section carries the error), but the run itself failed: a missing
    # safety executable used to end in "Analysis complete" and exit 0.
    if not dependency_check_ran:
        sys.exit(1)

if __name__ == "__main__":
    main()