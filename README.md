# Semgrep SAST Scan Report Generator

## Overview

This script automates the process of generating Security Static Analysis (SAST) reports for projects managed under a specified organization in Semgrep. It fetches project data, analyzes security findings, and compiles detailed reports in various formats including JSON, CSV, XLSX, HTML, and PDF. The script supports filtering findings based on severity and allows for comprehensive reporting by combining individual project findings into a single overview.

[Example PDF Report](https://github.com/r2c-CSE/semgrep_findings_to_csv_html_pdf_all_repos_filter_tag/blob/FR-security_grades_bar_graphs/reports/1709112459/combined_output_portfolio-B.pdf)

[Example HTML Report](https://github.com/r2c-CSE/semgrep_findings_to_csv_html_pdf_all_repos_filter_tag/blob/FR-security_grades_bar_graphs/reports/1709112459/combined_output_portfolio-B.html)

## Features

- Fetch projects and findings from Semgrep based on organizational slug and specific tags.
- Generate detailed findings reports in JSON, CSV, XLSX, HTML, and PDF formats.
- Combine reports from multiple projects into a single comprehensive report.
- Filter findings based on severity to focus on the most critical issues.
- Automated report generation with timestamping for historical tracking.
- [NEW] Provides a security grade to each repository based on number of High, Medium and Low `Open` vulnerabilities found
- [NEW] Create a bar graph showing the top 15 repos by number of High, Medium and Low `Open` vulnerabilities 
- [NEW] Create a bar graph showing the top 15 repos by number of High, Medium and Low `Fixed` vulnerabilities

## Prerequisites

- Python 3.x
- `requests`, `pandas`, `fpdf`, `html`, `pdfkit`, `PyPDF2`, `plotly` Python packages
- A valid Semgrep API web token set as an environment variable `SEMGREP_API_WEB_TOKEN`
- Access to Semgrep projects and deployments

## Installation

1. Ensure Python 3 and pip are installed.
2. Install the required Python packages:

`pip install pandas requests fpdf pdfkit PyPDF2 plotly`


## Configuration
Before running the script, you must set up the `SEMGREP_API_WEB_TOKEN` environment variable with your Semgrep API token:

`export SEMGREP_API_WEB_TOKEN='your_api_token_here'`

Generate your `SEMGREP_API_WEB_TOKEN` from https://semgrep.dev/orgs/-/settings/tokens 

Optionally, you can modify the script to change the default behavior, such as filtering findings based on severity by setting `FILTER_IMPORTANT_FINDINGS` to `True` or `False`.

## Usage
[Add a tag](https://semgrep.dev/docs/semgrep-appsec-platform/tags) to the projects you want to generate reports for, if they don't already have a tag in common. One quick way to do this is to select them in the [Projects view](https://semgrep.dev/orgs/-/projects) and click Edit.

Run the script from the command line, specifying the tag of the projects you want to generate reports for:

`python semgrep_findings_to_csv_html_pdf_all_repos_filter_tag.py --tag <your_project_tag>`

## The script will perform the following actions:

* Fetch all projects associated with the specified tag.
* Generate findings reports for each project in multiple formats.
* Combine individual project reports into comprehensive reports.
* Save all reports to the specified output directory.

## Output
The script saves generated reports in a dynamically created directory under reports/ based on the current epoch time. You will find the following files for each project and combined reports:
* Individual project findings in JSON, CSV, XLSX, HTML, and PDF formats.
* Combined reports for all projects in JSON, HTML, and PDF formats.
* A summary HTML report providing an overview of findings across all projects.
