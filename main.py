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
        tuple: A tuple containing the dependencies list and a report string.
    """
    try:
        # Activate the virtual environment if it exists
        venv_path = os.path.join(project_path, ".venv")
        activate_script = os.path.join(venv_path, "bin", "activate")  # Linux/macOS
        if not os.path.exists(activate_script):
            activate_script = os.path.join(venv_path, "Scripts", "activate") # Windows
            if not os.path.exists(activate_script):
                logging.warning("Virtual environment not found. Checking global dependencies.")
                dependencies = subprocess.check_output(["pip", "freeze"], text=True)
                report = subprocess.check_output(["safety", "check", "--full-report"], text=True)
                
        else: #if venv exists
            logging.info("Virtual environment found. Activating and checking dependencies.")
            # Use subprocess to activate the virtual environment and run safety check
            activate_cmd = ". " + activate_script + " && safety check --full-report"
            
            process = subprocess.Popen(activate_cmd, shell=True, executable='/bin/bash', cwd=project_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)  
            stdout, stderr = process.communicate()

            if process.returncode != 0:
                logging.error(f"Safety check failed: {stderr}")
                raise subprocess.CalledProcessError(process.returncode, activate_cmd, output=stdout, stderr=stderr)

            report = stdout
            dependencies = subprocess.check_output(["pip", "freeze"], shell=True, executable='/bin/bash', text=True, cwd=project_path)
       
        return dependencies, report

    except subprocess.CalledProcessError as e:
        logging.error(f"Error running dependency check: {e.stderr}")
        return "", f"Error running dependency check: {e.stderr}"
    except FileNotFoundError as e:
        logging.error(f"Error: pip or safety not found: {e}")
        return "", f"Error: pip or safety not found: {e}"
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return "", f"An unexpected error occurred: {e}"

def static_analysis(project_path):
    """
    Performs static analysis using pylint and pycodestyle.
    Args:
        project_path (str): The path to the project directory.
    Returns:
        tuple: Pylint output string and pycodestyle output string.
    """
    pylint_output = ""
    pycodestyle_output = ""
    try:
        # Pylint analysis
        logging.info("Running Pylint analysis...")
        pylint_args = [project_path]
        pylint_results = lint.Run(pylint_args, do_exit=False)
        pylint_output = pylint_results.linter.output.getvalue()

        # Pycodestyle analysis
        logging.info("Running Pycodestyle analysis...")
        style_guide = pycodestyle.StyleGuide()
        report = style_guide.check_files([project_path])  # Recursively checks files in the project
        pycodestyle_output = f"Pycodestyle violations: {report.total_errors}"

    except Exception as e:
        logging.error(f"Error during static analysis: {e}")
        pylint_output = f"Error during pylint: {e}"
        pycodestyle_output = f"Error during pycodestyle: {e}"

    return pylint_output, pycodestyle_output

def main():
    """
    Main function to orchestrate the dependency check and static analysis.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Validate project path
    if not os.path.isdir(args.project_path):
        logging.error("Invalid project path. Please provide a valid directory.")
        print("Error: Invalid project path. Please provide a valid directory.")
        sys.exit(1)

    logging.info(f"Starting analysis for project: {args.project_path}")

    # Dependency Check
    try:
        dependencies, safety_report = check_dependencies(args.project_path)
        logging.info("Dependency check completed.")
    except Exception as e:
         logging.error(f"Dependency check failed: {e}")
         safety_report = str(e)
         dependencies = ""

    # Static Analysis
    try:
        pylint_report, pycodestyle_report = static_analysis(args.project_path)
        logging.info("Static analysis completed.")
    except Exception as e:
        logging.error(f"Static analysis failed: {e}")
        pylint_report = str(e)
        pycodestyle_report = str(e)


    # Prepare and output report
    report = f"## cvsa-Dependency-Checker Report\n\n"
    report += f"**Project Path:** {args.project_path}\n\n"

    report += "### Dependency Vulnerability Check (Safety):\n"
    report += safety_report + "\n\n"

    report += "### Pylint Report:\n"
    report += pylint_report + "\n\n"

    report += "### Pycodestyle Report:\n"
    report += pycodestyle_report + "\n\n"

    # Handle ignored vulnerabilities
    if args.ignore:
        ignored_vulns = args.ignore.split(',')
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

if __name__ == "__main__":
    main()