# Steps:
# 1. Read findings from SEMGREP using API and write to JSON
# 2. Convert the json file to pandas dataframe
# 3. Get the list of all column names from headers  
# 4. list of columns of interest to include in the report
# 5. Create a new dataframe with the columns of interest
# 6. Write the dataframe to excel file
# 7. Create a HTML report from the dataframe

import getopt
import requests
import sys
import json
import re
import os
import pandas as pd
from pandas import json_normalize
from datetime import datetime
import logging
import json
from fpdf import FPDF
import html
import pdfkit
import time
from PyPDF2 import PdfMerger
import plotly.express as px
import pandas as pd
import plotly.graph_objects as go
from plotly.offline import plot
import base64
from io import BytesIO

import file_handling_helpers



try:
    SEMGREP_API_WEB_TOKEN = os.environ["SEMGREP_API_WEB_TOKEN"]
except KeyError:
    SEMGREP_API_WEB_TOKEN = "Token not available!"

FILTER_IMPORTANT_FINDINGS = False

EPOCH_TIME = str(int(time.time()))

severity_and_state_counts_all_repos = []
vulnerability_counts_all_repos = []
owasp_top10_counts_all_repos = []


def get_deployments():
    headers = {"Accept": "application/json", "Authorization": "Bearer " + SEMGREP_API_WEB_TOKEN}

    r = requests.get('https://semgrep.dev/api/v1/deployments',headers=headers)
    if r.status_code != 200:
        sys.exit(f'Getting org details failed: {r.text}')
    data = json.loads(r.text)
    slug_name = data['deployments'][0].get('slug')
    logging.info("Accessing org: " + slug_name)
    return slug_name

def get_projects(slug_name, interesting_tag):
    logging.info("Getting list of projects in org: " + slug_name)

    headers = {"Accept": "application/json", "Authorization": "Bearer " + SEMGREP_API_WEB_TOKEN}
    params =  {"page_size": 3000}

    r = requests.get('https://semgrep.dev/api/v1/deployments/' + slug_name + '/projects?page=0',params=params,headers=headers)
    if r.status_code != 200:
        sys.exit(f'Getting list of projects failed: {r.text}')

    data = json.loads(r.text)
    for project in data['projects']:
        project_name = project['name']
        logging.debug(f"Currently processing project/repo: {project_name}  with the following tags {project['tags']}")
        if interesting_tag in project.get("tags", []):
            logging.debug(f"Currently processing project/repo: {project_name} and has the tag {interesting_tag} ")
            get_findings_per_repo(slug_name, project_name)

    print(f"vulnerability_counts_all_repos: {vulnerability_counts_all_repos}")

    output_file = "combined" + "-" + EPOCH_TIME +  ".json"
    logging.info (f"starting process to combine JSON files")
    file_handling_helpers.combine_json_files(output_file)
    logging.info (f"finished process to combine JSON files")
    logging.info (f"starting process to combine PDF files")
    output_pdf_filename = f'combined_output_{interesting_tag}.pdf'
    file_handling_helpers.combine_pdf_files(output_pdf_filename)
    logging.info (f"finished process to combine PDF files")

    folder_path = os.path.join(os.getcwd(), "reports", EPOCH_TIME)  # Define the output path
    summary_file = "summary-" + EPOCH_TIME +  ".html"
    summary_file_path = os.path.join(folder_path, summary_file)

    logging.info (f"starting process to combine HTML files")
    output_filename = f'combined_output_{interesting_tag}.html'  # The name of the output file
    file_handling_helpers.combine_html_files(severity_and_state_counts_all_repos, vulnerability_counts_all_repos, owasp_top10_counts_all_repos, output_filename, output_pdf_filename, interesting_tag)
    logging.info (f"finished process to combine HTML files")

def get_findings_per_repo(slug_name, repo):
      
    headers = {"Accept": "application/json", "Authorization": "Bearer " + SEMGREP_API_WEB_TOKEN}
    params =  {"page_size": 3000, "repos": repo}
    # r = requests.get('https://semgrep.dev/api/v1/deployments/' + slug_name + '/findings?repos='+repo,params=params, headers=headers)
    r = requests.get('https://semgrep.dev/api/v1/deployments/' + slug_name + '/findings',params=params, headers=headers)
    if r.status_code != 200:
        sys.exit(f'Getting findings for project failed: {r.text}')
    data = json.loads(r.text)

    # create folder reports/EPOCH_TIME
    output_folder = os.path.join(os.getcwd(), "reports", EPOCH_TIME)  # Define the output path
    os.makedirs(output_folder, exist_ok=True)

    # Construct the full path for the output file
    output_filename = re.sub(r"[^\w\s]", "_", repo) + "-" + EPOCH_TIME + ".json"
    file_path = os.path.join(output_folder, output_filename)

    if FILTER_IMPORTANT_FINDINGS == True:
        logging.info("Filtering Important findings for requested project/repo: " + project_name)
        data = [obj for obj in data['findings'] if obj["severity"] == "high" and obj["confidence"] == "high" or obj["confidence"] == "medium"]
    else:
        logging.info("All findings for requested project/repo: " + repo)
        data = [obj for obj in data['findings'] ]

    if len(data) == 0:
        logging.info(f"No SAST findings in repo - {repo}")
    else:
        # calculate severity data
        severity_and_state_counts = count_severity_and_state(data)
        severity_and_state_counts_all_repos.append({repo : severity_and_state_counts})

        # Call the function with the example JSON object
        (vulnerability_counts, owasp_top10_counts) = count_vulnerability_classes_and_owasp_top_10(data)
        vulnerability_counts_all_repos.append({repo : vulnerability_counts})
        owasp_top10_counts_all_repos.append({repo : owasp_top10_counts})

        # Print the results
        logging.debug(f"severity_and_state_counts in repo: {repo} - {severity_and_state_counts}")
        logging.debug(f" {severity_and_state_counts_all_repos} ")
 
        with open(file_path, "w") as file:
            json.dump(data, file)
            logging.info("Findings for requested project/repo: " + repo + "written to: " + file_path)
    
        logging.info (f"starting process to convert JSON file to csv & xlsx for repo {repo}")
        
        output_name = re.sub(r"[^\w\s]", "_", repo)
        logging.debug ("output_name: " + output_name)
        json_file = output_name + "-" + EPOCH_TIME +  ".json"
        json_file_path = os.path.join(output_folder, json_file)        
        csv_file = output_name + "-" + EPOCH_TIME + ".csv"
        csv_file_path = os.path.join(output_folder, csv_file)        
        xlsx_file = output_name + "-" + EPOCH_TIME + ".xlsx"
        xlsx_file_path = os.path.join(output_folder, xlsx_file)        
        html_file = output_name + "-" + EPOCH_TIME +  ".html"
        html_file_path = os.path.join(output_folder, html_file)        
        pdf_file = output_name + "-" + EPOCH_TIME +  ".pdf"
        pdf_file_path = os.path.join(output_folder, pdf_file)

        logging.info(f"file names: {output_name}, {json_file_path},{csv_file_path}, {xlsx_file_path},{html_file_path}, {pdf_file_path}")
        json_to_csv_pandas(json_file_path, csv_file_path)
        # json_to_xlsx_pandas(json_file, xlsx_file)
        # convert_json_to_pdf(json_file)
        json_to_html_pandas(json_file_path, html_file_path, pdf_file_path, repo)

        logging.info (f"completed conversion process for repo: {repo}")

def count_severity_and_state(data):
    # Initialize counters for each severity level and each state within that level
    counts = {
        'high': {'muted': 0, 'fixed': 0, 'removed': 0, 'unresolved': 0},
        'medium': {'muted': 0, 'fixed': 0, 'removed': 0, 'unresolved': 0},
        'low': {'muted': 0, 'fixed': 0, 'removed': 0, 'unresolved': 0}
    }

    # Iterate through each item in the data
    for item in data:
        severity = item.get('severity')  # Get the severity of the current item
        state = item.get('state')  # Get the state of the current item

        # Check if the severity and state are recognized, then increment the appropriate counter
        if severity in counts and state in counts[severity]:
            counts[severity][state] += 1

    return counts

def count_vulnerability_classes_and_owasp_top_10(data):
    # Initialize a dictionary to keep count of each vulnerability class
    vulnerability_counts = {}
    owasp_top10_counts = {}
    
    # Iterate over each finding in the JSON object
    for finding in data:
        # Extract the vulnerability classes for the current finding
        vulnerability_classes = finding['rule']['vulnerability_classes']
        owasp_top10_categories = finding['rule']['owasp_names']
        severity = finding['severity']
        state = finding['state']
        
        # Iterate over each vulnerability class in the current finding
        #  we are only interested in open findings with high severity
        if (severity=="high" and state=="unresolved"):
            for v_class in vulnerability_classes:
                # If the class is already in the dictionary, increment its count
                if v_class in vulnerability_counts:
                    vulnerability_counts[v_class] += 1
                # Otherwise, add the class to the dictionary with a count of 1
                else:
                    vulnerability_counts[v_class] = 1

            for owasp_cat in owasp_top10_categories:
                # If the class is already in the dictionary, increment its count
                if owasp_cat in owasp_top10_counts:
                    owasp_top10_counts[owasp_cat] += 1
                # Otherwise, add the class to the dictionary with a count of 1
                else:
                    owasp_top10_counts[owasp_cat] = 1

    # Return the dictionary containing counts of each vulnerability class
    return (vulnerability_counts, owasp_top10_counts)

def json_to_df(json_file):
    # Read the JSON file into a DataFrame
    df = pd.read_json(json_file)

    df = df.rename(columns={'rule_name' : 'Finding Title' , 'rule_message'  : 'Finding Description & Remediation', 'relevant_since' : 'First Seen'})


    # filter out only specific columns
    df = df.loc[:, [ 'Finding Title', 'Finding Description & Remediation', 'state', 'First Seen', 'severity', 'confidence',  'triage_state', 'triaged_at', 'triage_comment', 'state_updated_at', 'repository',  'location' ]] 
    logging.info("Findings converted to DF from JSON file : " + json_file)

    return df

def json_to_df_html(json_file):
    with open(json_file) as json_file_data:
        data = json.load(json_file_data)
        logging.debug(data)

    df = json_normalize(data)
    return df

def json_to_csv_pandas(json_file, csv_file):

    df = json_to_df(json_file)
    
    df = df.rename(columns={'rule_name' : 'Finding Title' , 'rule_message'  : 'Finding Description & Remediation', 'relevant_since' : 'First Seen'})

    # Write the DataFrame to CSV
    df.to_csv(csv_file, index=False)

    logging.info("Findings converted from JSON file : " + json_file + " to CSV File: " + csv_file)

def escape_html_description(row):
    s = row['Finding Description & Remediation']
    return (s.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))

def add_short_ref(row):
    match = re.search(r'\b\w+$', row['ref'])
    # Return the found word or None if no match
    return match.group(0) if match else None

def add_short_rule_name(row):
    # Split the string by period
    items = row['Finding Title'].split('.')
    last_item = items[-1]
    link_to_rule = f"https://semgrep.dev/r?q={row['Finding Title']}"

    # return the last item
    return (html.unescape("<a href='" + link_to_rule + "'>" + last_item + "</a>"))

def add_hyperlink_to_code(row):
    return row['repository.url'] + '/blob/' + row['short_ref'] + '/' + row['location.file_path'] + '#L' + str(row['location.line'])

def add_repo_details(row):
    return (html.unescape("<a href='" + row['repository.url'] + "'>" + row['repository.name'] + "</a>"))

def add_location_details_hyperlink(row):
    return (html.unescape("<a href='" + row['link_to_code'] + "'>" + row['location.file_path'] + '#L' + str(row['location.line']) + "</a>"))

def process_sast_findings(df: pd.DataFrame, html_filename, pdf_filename, repo_name):
    # Create new DF with SAST findings only
    # df_sast = df.loc[(df['check_id'].str.contains('ssc')==False)]

    # Get the list of all column names from headers
    column_headers = list(df.columns.values)
    # logging.debug("The Column Header :", column_headers)

    # # list of columns of interest to include in the report
    # 'state', 'first_seen_scan_id', 'triage_state', 'severity', 'confidence', 'First Seen', 'Finding Title', 
    # 'Finding Description & Remediation', 'triaged_at', 'triage_comment', 'state_updated_at', 'categories', 
    # 'repository.name', 'repository.url', 'location.file_path', 'location.line', 'location.column', 'location.end_line', 'location.end_column', 'sourcing_policy.id', 'sourcing_policy.name', 'sourcing_policy.slug'],
    interesting_columns_sast = [
        # 'First Seen', 
        'Finding Title', 
        'Finding Description & Remediation',
        'severity',
        'state',
        'repository.name', 
        'repository.url', 
        'location.file_path', 
        'location.line',
        'ref',
        # 'finding_hyperlink',
        # 'extra.severity',
        # 'extra.metadata.confidence', 
        # 'extra.metadata.semgrep.url',
        # 'extra.metadata.likelihood',
        # 'extra.metadata.impact',
        # 'extra.metadata.owasp',
        # 'extra.metadata.cwe', 
        # 'extra.metadata.cwe2021-top25', 
        # 'extra.metadata.cwe2022-top25', 
    ]

    START_ROW = 0
    df_red = df[interesting_columns_sast]

    # Apply the function and create a new column
    df_red['Finding Description & Remediation'] = df_red.apply(escape_html_description, axis=1)
    df_red['Finding Title'] = df_red.apply(add_short_rule_name, axis=1)
    df_red['short_ref'] = df_red.apply(add_short_ref, axis=1)
    df_red['link_to_code'] = df_red.apply(add_hyperlink_to_code, axis=1)
    # df_red['repository'] = df_red.apply(add_repo_details, axis=1)
    df_red['location'] = df_red.apply(add_location_details_hyperlink, axis=1)

    df_red.drop(['repository.name', 'repository.url', 'location.file_path', 'location.line', 'link_to_code', 'short_ref'], axis=1, inplace=True)

    # create filename for XLSX report
    dir_name = os.path.basename(os.getcwd())
    logging.debug(dir_name)
    current_time = datetime.now().strftime("%Y%m%d-%H%M")
    reportname = f"semgrep_sast_findings_{dir_name}_{current_time}"
    xlsx_filename = f"{reportname}.xlsx"

    # Create a Pandas Excel writer using XlsxWriter as the engine.
    writer = pd.ExcelWriter(xlsx_filename, engine="xlsxwriter")

    # Write the dataframe data to XlsxWriter. Turn off the default header and
    # index and skip one row to allow us to insert a user defined header.
    df_red.to_excel(writer, sheet_name="findings", startrow=START_ROW, header=True, index=False)

    # Get the xlsxwriter workbook and worksheet objects.
    workbook = writer.book
    worksheet = writer.sheets["findings"]

    # Get the dimensions of the dataframe.
    (max_row, max_col) = df_red.shape

    # Create a list of column headers, to use in add_table().
    column_settings = [{"header": column.split(".")[-1]} for column in df_red.columns]

    # Add the Excel table structure. Pandas will add the data.
    # we start from row = 4 to allow us to insert a title and summary of findings
    worksheet.add_table(START_ROW, 0, max_row+START_ROW, max_col - 1, {"columns": column_settings})

    # Add a format.
    text_format = workbook.add_format({'text_wrap' : True})

    # Make the text columns width = 48 & add text wrap for clarity
    worksheet.set_column(0, max_col - 1, 48, text_format) 

    # Make the message columns width = 96 & add text wrap for clarity
    worksheet.set_column(1, 1, 96, text_format) 

    # Make the severity, confidence, likelyhood & impact columns width = 12 
    worksheet.set_column(4, 7, 12)

    # #  create new df_high by filtering df_red for HIGH severity
    df_high = df_red.loc[(df_red['severity'] == 'high')]
    # Create a list of column headers, to use in add_table().
    column_settings = [{"header": column.split(".")[-1]} for column in df_high.columns]

    # #  create new df_med by filtering df_red for MED severity
    df_med = df_red.loc[(df_red['severity'] == 'medium')]
    # Create a list of column headers, to use in add_table().
    column_settings = [{"header": column.split(".")[-1]} for column in df_med.columns]

    # #  create new df_low by filtering df_red for LOW severity
    df_low = df_red.loc[(df_red['severity'] == 'low')]
    # Create a list of column headers, to use in add_table().
    column_settings = [{"header": column.split(".")[-1]} for column in df_low.columns]

    # Close the Pandas Excel writer and output the Excel file.
    writer.close()

    # generate the HTML from the dataframe
    html = file_handling_helpers.generate_html_sast(df_high, df_med, df_low, repo_name)
    
    # write the HTML content to an HTML file
    open(html_filename, "w").write(html)

    # convert from HTML to PDF
    options = {
        'orientation': 'Landscape',
        'enable-local-file-access': None
    }
    try:
        pdfkit.from_string(html, pdf_filename, options=options)
    except OSError:
        logging.info("Skipping PDF because wkhtmltopdf not found. You can get it here: https://wkhtmltopdf.org/")

def json_to_html_pandas(json_file, html_file, pdf_file, repo_name):

    df = json_to_df_html(json_file)
    # logging.debug("data in JSON file is: ")
    # logging.debug(data)

    df = df.rename(columns={'rule_name' : 'Finding Title' , 'rule_message'  : 'Finding Description & Remediation', 'relevant_since' : 'First Seen'})

    # Write the DataFrame to HTML
    process_sast_findings(df, html_file, pdf_file, repo_name)

    logging.info("Findings converted from JSON file : " + json_file + " to HTML File: " + html_file)

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    user_inputs = sys.argv[1:]
    logging.debug(user_inputs)

    # get option and value pair from getopt
    try:
        opts, args = getopt.getopt(user_inputs, "t:h", ["tag=", "help"])
        #lets's check out how getopt parse the arguments
        logging.debug(opts)
        logging.debug(args)
    except getopt.GetoptError:
        logging.debug('pass the arguments like -t <tag> -h <help> or --tag <tag> and --help <help>')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            logging.info('pass the arguments like -t <tag> -h <help> or --tag <tag> and --help <help>')
            sys.exit()
        elif opt in ("-t", "--tag"):
            logging.debug(opt)
            logging.debug(arg)
            interesting_tag = arg

    slug_name = get_deployments()
    get_projects(slug_name, interesting_tag)
    logging.info ("completed conversion process")
