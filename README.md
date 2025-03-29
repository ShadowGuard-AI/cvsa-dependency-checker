# cvsa-Dependency-Checker
Lists all project dependencies and checks them against the known vulnerabilities databases (e.g., using libraries like `safety`).  Outputs a summary of vulnerabilities, if any, and suggests possible upgrade paths. - Focused on Performs static analysis of source code to identify common security vulnerabilities (e.g., injection flaws, weak cryptography usage) based on pre-defined rules and patterns. Intended for quick, preliminary security assessments during development.

## Install
`git clone https://github.com/ShadowStrikeHQ/cvsa-dependency-checker`

## Usage
`./cvsa-dependency-checker [params]`

## Parameters
- `-h`: Show help message and exit
- `--report_file`: Path to save the report. If not provided, it prints to stdout.
- `--ignore`: No description provided

## License
Copyright (c) ShadowStrikeHQ
