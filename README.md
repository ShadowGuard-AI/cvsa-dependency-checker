![Banner](banner.png)

# cvsa-Dependency-Checker
Lists all project dependencies and checks them against the known vulnerabilities databases (e.g., using libraries like `safety`).  Outputs a summary of vulnerabilities, if any, and suggests possible upgrade paths. - Focused on Performs static analysis of source code to identify common security vulnerabilities (e.g., injection flaws, weak cryptography usage) based on pre-defined rules and patterns. Intended for quick, preliminary security assessments during development.

## Install
`git clone https://github.com/ShadowStrikeHQ/cvsa-dependency-checker`

## Usage
`./cvsa-dependency-checker [params]`

## Parameters
- `-h`: Show help message and exit
- `--report_file`: Path to save the report. If not provided, it prints to stdout.
- `--ignore`: Comma-separated list of ids to ignore, for example CVE-2023-123,PYLINT:W0613. Report lines in the Safety and Pylint sections that mention an ignored id are removed from the report.

## Notes

The report includes a Dependencies section holding the pip freeze output. When the project has a .venv, the freeze and the safety check both run with that venv's own executables, called directly by path with no shell, and they describe the venv environment. The project path is resolved to an absolute path before any command runs, so relative and absolute paths behave the same. An invalid project path exits 1, and a run where the dependency check never ran also exits 1.

## License
Copyright (c) ShadowStrikeHQ
