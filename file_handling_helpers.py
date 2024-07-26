
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

EPOCH_TIME = str(int(time.time()))

def assign_security_grade(high, medium, low):
    """
    Assigns a security grade based on the number of high, medium, and low vulnerabilities.

    :param high: Number of high vulnerabilities.
    :param medium: Number of medium vulnerabilities.
    :param low: Number of low vulnerabilities (currently not used in grading logic).
    :return: Security grade as a string (A, B, C, or D).
    """
    # Criteria for grade A
    if high == 0 and medium < 10:
        return 'A'
    # Criteria for grade B
    elif high < 5 and medium < 25:
        return 'B'
    # Criteria for grade C
    elif high < 10 and medium < 50:
        return 'C'
    # Criteria for grade D
    elif high < 25 and medium < 100:
        return 'D'
    # If none of the above criteria are met, the security grade is considered to be below D.
    else:
        return 'F'

def generate_table_rows(df):
    """
    Generates HTML table rows (<tr>) for a DataFrame, including a header row.
    Each 'Security Grade' cell gets colored based on its value, and certain columns are centered.
    
    :param df: DataFrame with columns including 'Project Name', 'Security Grade', etc.
    :return: String with HTML content for table rows.
    """
    # Define headers
    headers = [
        "Project", " ", "Security Grade", "  ", 
        "Open-HIGH", "Open-MEDIUM", "Open-LOW", "   ", 
        "Fixed-HIGH", "Fixed-MEDIUM", "Fixed-LOW"
    ]
    
    # Columns to center
    center_columns = ["Security Grade", "Open-HIGH", "Open-MEDIUM", "Open-LOW", "Fixed-HIGH", "Fixed-MEDIUM", "Fixed-LOW"]

    # Generate HTML for the header row with center-text class for specific headers
    header_html = "<tr>" + "".join([f'<th class="{"center-text" if header in center_columns else ""}">{header}</th>' for header in headers]) + "</tr>"
    
    # Initialize HTML rows string with the header
    html_rows = header_html
    
    for index, row in df.iterrows():
        security_grade = row['Security Grade']
        
        # Determine class based on 'Security Grade'
        class_name = ""
        if security_grade == "A":
            class_name = "grade-A"
        elif security_grade == "B":
            class_name = "grade-B"
        elif security_grade == "C":
            class_name = "grade-C"
        elif security_grade == "D":
            class_name = "grade-D"
        elif security_grade == "F":
            class_name = "grade-F"
        
        # Generate HTML for one row
        row_html = "<tr>"
        for col, header in zip(df.columns, headers):
            cell_class = "center-text" if header in center_columns else ""
            if header == "Security Grade":
                cell_class += f" {class_name}"  # Add security grade class if applicable
            row_html += f'<td class="{cell_class.strip()}">{row[col]}</td>'
        row_html += "</tr>"
        
        html_rows += row_html
    return html_rows

def create_heatmap_vulnerability_classes(vulnerability_counts_all_repos, image_folder):
    
    # Convert the list of dictionaries to a DataFrame
    df = pd.DataFrame({list(d.keys())[0]: list(d.values())[0] for d in vulnerability_counts_all_repos}).T.fillna(0)

    # Calculate the total number of vulnerabilities for each repository
    df['Total'] = df.sum(axis=1)

    # Sort repositories by total vulnerabilities in decreasing order and select the top 15
    df_sorted = df.sort_values(by='Total', ascending=False).head(15)

    # Drop the 'Total' column as it's no longer needed in the heatmap
    df_sorted = df_sorted.drop(columns=['Total'])

    # Custom Red-Amber-Green color scale
    rag_colorscale = [
        [0.0, "green"],  
        [0.10, "green"],
        [0.10, "yellow"],
        [0.33, "yellow"],
        [0.33, "red"],  
        [1.0, "red"]
    ]

    # Generate the heatmap
    fig = go.Figure(data=go.Heatmap(
        z=df_sorted.values,
        x=df_sorted.columns,
        y=df_sorted.index,
        colorscale=rag_colorscale,
        text=df_sorted.values.astype(int).astype(str),  # Convert the values to strings for display
        texttemplate="%{text}",
        hoverinfo="text"
    ))

    # Set the title and axis labels, and adjust the size of the heatmap image
    fig.update_layout(
        xaxis_title='Vulnerability Class',
        yaxis_title='Repository',
        xaxis=dict(side='top'),
        width=1200,  # Adjust the width as needed
        height=800   # Adjust the height based on the number of repos to display
    )


    # Save the figure as an image file
    fig.write_image(f"{image_folder}/heatmap_vulnerability_classes.png")

def create_heatmap_owasp_top10_categories(owasp_top10_counts_all_repos, image_folder):
    
    # Convert the list of dictionaries to a DataFrame
    df = pd.DataFrame({list(d.keys())[0]: list(d.values())[0] for d in owasp_top10_counts_all_repos}).T.fillna(0)

    # Calculate the total number of vulnerabilities for each repository
    df['Total'] = df.sum(axis=1)

    # Sort repositories by total vulnerabilities in decreasing order and select the top 15
    df_sorted = df.sort_values(by='Total', ascending=False).head(15)

    # Drop the 'Total' column as it's no longer needed in the heatmap
    df_sorted = df_sorted.drop(columns=['Total'])

    # Custom Red-Amber-Green color scale
    rag_colorscale = [
        [0.0, "green"],  
        [0.10, "green"],
        [0.10, "yellow"],
        [0.33, "yellow"],
        [0.33, "red"],  
        [1.0, "red"]
    ]

    # Generate the heatmap
    fig = go.Figure(data=go.Heatmap(
        z=df_sorted.values,
        x=df_sorted.columns,
        y=df_sorted.index,
        colorscale=rag_colorscale,
        text=df_sorted.values.astype(int).astype(str),  # Convert the values to strings for display
        texttemplate="%{text}",
        hoverinfo="text"
    ))

    # Set the title and axis labels, and adjust the size of the heatmap image
    fig.update_layout(
        xaxis_title='OWASP Top 10',
        yaxis_title='Repository',
        xaxis=dict(side='top'),
        width=1200,  # Adjust the width as needed
        height=800   # Adjust the height based on the number of repos to display
    )


    # Save the figure as an image file
    fig.write_image(f"{image_folder}/heatmap_owasp_top10_categories.png")



def create_bar_graph_open_vulns(data, image_folder):
    rows = []
    for entry in data:
        for project_name, severities in entry.items():
            row = {}
            row ['Project'] = project_name
            for severity, states in severities.items():
                if (severity== 'high'):
                    row ['high'] = states['unresolved']
                if (severity== 'medium'):
                    row ['medium'] = states['unresolved']
                if (severity== 'low'):
                    row ['low'] = states['unresolved']
            print(row)
            rows.append(row)

    transformed_json = {
        'Project': [],
        'high': [],
        'medium': [],
        'low': [],
    }

    logging.debug(f"rows is {rows}")
    # Populate the new structure
    for item in rows:
        for key in transformed_json:
            logging.debug(f"item is {item}")
            logging.debug(f"key is {key}")
            logging.debug(f"item[key] is {item[key]}")
            transformed_json[key].append(item[key])

    logging.debug(transformed_json)
    
    # Create a DataFrame from the rows
    df = pd.DataFrame(rows)

    logging.debug(df)

    # Sorting the DataFrame by 'Subcolumn1' in descending order and selecting the top 10
    df = df.sort_values(by='high', ascending=False).head(15)

    # Melting the DataFrame to long format, which Plotly can use to differentiate subcolumns
    df_long = pd.melt(df, id_vars='Project', value_vars=['high', 'medium', 'low'], 
                    var_name='Severity', value_name='Value')

    # Adding a column for text to display the value on all bars
    df_long['Text'] = df_long['Value'].apply(lambda x: f'{x}')

    color_map = {
        'high': 'darkred',          # Dark Red
        'medium': 'darkorange',     # Dark Orange
        'low': 'darkgoldenrod'      # Dark Yellow
    }

    # Create a bar graph with subcolumns for the top 10 objects
    fig = px.bar(df_long, x='Project', y='Value', color='Severity', barmode='group',
                color_discrete_map=color_map, text='Text', 
                title='Top 15 Repos by High Severity Open Vulnerabilities count')

    fig.update_traces(texttemplate='%{text}', textposition='outside')

    # Update the layout for axis titles
    fig.update_layout(
        xaxis_title='Project Name',
        yaxis_title='Number of Vulnerabilities'
    )
    
    graph_div = plot(fig, output_type='div', include_plotlyjs=False)

    # Show the plot
    # fig.show()
    fig.write_image(f"{image_folder}/open.png")
    return(graph_div)

def create_bar_graph_fixed_vulns(data, image_folder):
    rows = []
    for entry in data:
        for project_name, severities in entry.items():
            row = {}
            row ['Project'] = project_name
            for severity, states in severities.items():
                if (severity== 'high'):
                    row ['high'] = states['fixed']
                if (severity== 'medium'):
                    row ['medium'] = states['fixed']
                if (severity== 'low'):
                    row ['low'] = states['fixed']
            print(row)
            rows.append(row)

    transformed_json = {
        'Project': [],
        'high': [],
        'medium': [],
        'low': [],
    }

    logging.debug(f"rows is {rows}")
    # Populate the new structure
    for item in rows:
        for key in transformed_json:
            logging.debug(f"item is {item}")
            logging.debug(f"key is {key}")
            logging.debug(f"item[key] is {item[key]}")
            transformed_json[key].append(item[key])

    logging.debug(transformed_json)
    
    # Create a DataFrame from the rows
    df = pd.DataFrame(rows)

    logging.debug(df)

    # Sorting the DataFrame by 'high' in descending order and selecting the top 10
    df = df.sort_values(by='high', ascending=False).head(15)

    # Melting the DataFrame to long format, which Plotly can use to differentiate subcolumns
    df_long = pd.melt(df, id_vars='Project', value_vars=['high', 'medium', 'low'], 
                    var_name='Severity', value_name='Value')

    # Adding a column for text to display the value on all bars
    df_long['Text'] = df_long['Value'].apply(lambda x: f'{x}')

    color_map = {
        'high': 'darkred',          # Dark Red
        'medium': 'darkorange',     # Dark Orange
        'low': 'darkgoldenrod'      # Dark Yellow
    }

    # Create a bar graph with subcolumns for the top 10 objects
    fig = px.bar(df_long, x='Project', y='Value', color='Severity', barmode='group',
                color_discrete_map=color_map, text='Text', 
                title='Top 15 Repos by High Severity Fixed Vulnerabilities count')

    fig.update_traces(texttemplate='%{text}', textposition='outside')

    # Update the layout for axis titles
    fig.update_layout(
        xaxis_title='Project Name',
        yaxis_title='Number of Vulnerabilities'
    )

    graph_div = plot(fig, output_type='div', include_plotlyjs=False)

    # Show the plot
    # fig.show()
    fig.write_image(f"{image_folder}/fixed.png")

    return(graph_div)

def combine_json_files(output_file):
    combined_data = []
    # create folder reports/EPOCH_TIME
    output_folder = os.path.join(os.getcwd(), "reports", EPOCH_TIME)  # Define the output path
    logging.debug(f"output_folder when combining JSON files: {output_folder}")
    
    # Loop through each file in the folder
    for filename in os.listdir(output_folder):
        if filename.endswith("-" + EPOCH_TIME + ".json"):
            print("Opening " + filename)
            with open(os.path.join(output_folder, filename), 'r') as file:
                data = json.load(file)
                
                # Append data from current file to combined data
                if isinstance(data, list):
                    combined_data.extend(data)
                else:
                    combined_data.append(data)

    # Write combined data to output file
    with open(output_file, 'w') as outfile:
        json.dump(combined_data, outfile, indent=4)

def combine_pdf_files(output_filename):
    # Create a PDF merger object
    merger = PdfMerger()

    # create folder reports/EPOCH_TIME
    output_folder = os.path.join(os.getcwd(), "reports", EPOCH_TIME)  # Define the output path
    logging.debug(f"output_folder when combining PDF files: {output_folder}")

    # Loop through all the files in the folder
    for item in os.listdir(output_folder):
        # Construct the full path of the file
        file_path = os.path.join(output_folder, item)
        
        # Check if the file is a PDF to be combined
        if item.endswith(EPOCH_TIME +".pdf"):
            # Append the PDF to the merger
            logging.debug(f"appending PDF file: {item}")
            with open(os.path.join(output_folder, file_path), 'rb') as f:
                merger.append(f)

    # Write out the combined PDF to the output file
    with open(output_filename, 'wb') as f_out:
        merger.write(f_out)
    merger.close()

def add_summary_table_and_save_as_html(data, output_filename):
    # Transform the JSON data into a list of dictionaries, each representing a row in the DataFrame
    rows = []
    for entry in data:
        for project_name, severities in entry.items():
            for severity, states in severities.items():
                row = {
                    'Project Name': project_name,
                    'Severity': severity,
                    'Muted': states['muted'],
                    'Fixed': states['fixed'],
                    'Removed': states['removed'],
                    'Unresolved': states['unresolved']
                }
                rows.append(row)

    # Create a DataFrame from the rows
    df = pd.DataFrame(rows)

    # Convert the DataFrame to an HTML table string
    html_table = df.to_html(index=False)

    # Save the HTML table to a file
    with open(output_filename, 'w') as file:
        file.write(html_table)
    logging.debug(f"HTML table saved to {output_filename}")

def combine_html_files(severity_and_state_counts_all_repos, vulnerability_counts_all_repos, owasp_top10_counts_all_repos, output_filename, output_pdf_filename, interesting_tag):

    # Transform the JSON data into a list of dictionaries, each representing a row in the DataFrame
    rows = []
    for entry in severity_and_state_counts_all_repos:
        for project_name, severities in entry.items():
            row = {
                    'Project Name': project_name,
                    ' ': '   ',
                    'Security Grade': '',
                    '  ': '    ',
                    'Open/High': 0,
                    'Open/Medium': 0,
                    'Open/Low': 0,
                    '   ': '   ',
                    'Fixed/High': 0,
                    'Fixed/Medium': 0,
                    'Fixed/Low': 0,
            }
            for severity, states in severities.items():
                if severity == 'high':
                    row['Fixed/High'] = states['fixed']
                    row['Open/High'] = states['unresolved']               
                if severity == 'medium':
                    row['Fixed/Medium'] = states['fixed']
                    row['Open/Medium'] = states['unresolved']
                if severity == 'low':
                    row['Fixed/Low'] = states['fixed']
                    row['Open/Low'] = states['unresolved']
            row['Security Grade'] = assign_security_grade(row['Open/High'], row['Open/Medium'], row['Open/Low'])
            rows.append(row)

    # Create a DataFrame from the rows
    df = pd.DataFrame(rows)

    # Sorting the DataFrame by 'Open/High' in descending order and selecting the top 10
    df = df.sort_values(by='Open/High', ascending=False)

    html_summary_table_content = generate_table_rows(df)
    html_summary_table = f"<table id='myDataTable' class='my_table'>{html_summary_table_content}</table>"

    # create folder reports/EPOCH_TIME
    folder_path = os.path.join(os.getcwd(), "reports", EPOCH_TIME)  # Define the output path
    logging.debug(f"output_folder when combining PDF files: {folder_path}")

    # Get the current date and time
    now = datetime.now()

    # Format the date and time
    formatted_now = now.strftime("%Y-%m-%d %H:%M")

    graph_div_open_vulns = create_bar_graph_open_vulns(severity_and_state_counts_all_repos, folder_path)

    graph_div_fixed_vulns = create_bar_graph_fixed_vulns(severity_and_state_counts_all_repos, folder_path)

    create_heatmap_vulnerability_classes(vulnerability_counts_all_repos, folder_path)

    create_heatmap_owasp_top10_categories(owasp_top10_counts_all_repos, folder_path)

    relative_path_open = 'open.png'  # This is your relative path
    absolute_path_open = os.path.join(os.getcwd(), "reports", EPOCH_TIME, relative_path_open) 

    relative_path_fixed = 'fixed.png'  # This is your relative path
    absolute_path_fixed = os.path.join(os.getcwd(), "reports", EPOCH_TIME, relative_path_fixed) 

    relative_path_heatmap_vuln_classes = 'heatmap_vulnerability_classes.png'  # This is your relative path
    absolute_path_heatmap_vuln_classes = os.path.join(os.getcwd(), "reports", EPOCH_TIME, relative_path_heatmap_vuln_classes) 

    relative_path_heatmap_owasp_top10_categories = 'heatmap_owasp_top10_categories.png'  # This is your relative path
    absolute_path_heatmap_owasp_top10_categories = os.path.join(os.getcwd(), "reports", EPOCH_TIME, relative_path_heatmap_owasp_top10_categories) 

    logging.debug(f"absolute_path_open= {absolute_path_open}")
    logging.debug(f"absolute_path_fixed= {absolute_path_fixed}")
    logging.debug(f"absolute_path_heatmap_vuln_classes= {absolute_path_heatmap_vuln_classes}")
    logging.debug(f"absolute_path_heatmap_owasp_top10_categories= {absolute_path_heatmap_owasp_top10_categories}")

    combined_html = f"""
    <html>
    <head>
    <title> Semgrep SAST Scan Report for All Repository with tag {interesting_tag} </title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
    .container-table {{
        display: grid; /* Use CSS Grid */
        place-items: center; /* Center both horizontally and vertically */
    }}
    </style>
    <style>
    .center-text {{
        text-align: center; 
    }}
    </style>
    <style>
    .my_table {{
        width: 100%;
        border-collapse: collapse;
    }}
    .my_table th, .my_table td {{
        border: 1px solid black;
        text-align: left;
        padding: 8px;
    }}
    .my_table th {{
        background-color: #f2f2f2;
    }}
    </style>
    <style>
        #myImage {{
            display: block;
            margin-left: auto;
            margin-right: auto;
            width: 75%; /* or any desired width */
            height: auto; /* to maintain the aspect ratio */
        }}
    </style>
    <style>
        .centered-table {{
            margin-left: auto;
            margin-right: auto;
        }}
    </style>
    <style>
        table {{
            border-collapse: collapse;
            width: 50%;
        }}
        th, td {{
            border: 1px solid black;
            text-align: left;
            padding: 8px;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        tr:nth-child(even) {{
            background-color: #f2f2f2;
        }}
    </style>
    <style>
        .grade-A {{
            background-color: green;
            color: white; /* For better readability */
        }}
        .grade-B {{
            background-color: yellow;
            color: black; /* Adjust color for readability */
        }}
        .grade-C {{
            background-color: orange;
            color: white;
        }}
        .grade-D {{
            background-color: red;
            color: white;
        }}
        .grade-F {{
            background-color: darkred;
            color: white;
        }}
        /* Add more classes if needed */
    </style>


    </head>
    <header>
        <link href="https://cdn.datatables.net/1.11.5/css/jquery.dataTables.min.css" rel="stylesheet">
        <script type="text/javascript" src="https://code.jquery.com/jquery-3.5.1.js"></script>
        <script type="text/javascript" src="https://cdn.datatables.net/1.11.5/js/jquery.dataTables.min.js"></script>
    </header>
    <body>
    <div style="height: 75px;"></div> <!-- Creates 75px of vertical space -->
    <div class="container">
    <img src="https://i.ibb.co/8xyV6WJ/Semgrep-logo.png" alt="logo" id="myImage">
    </div>
    <div class="container">
    <h1> <p style="text-align: center;" id="sast"> Semgrep SAST Scan Report for All Repositories with tag {interesting_tag} </p> </h1>
    <h2> <p style="text-align: center;" id="reporttime"> Report Generated at {formatted_now}</p> </h2>
    </div>
    <div style="page-break-after: always;"></div>

    <div class="heading">
    <h2> <p style="text-align: center;" id="html_summary_table"> SAST Findings Summary </p> </h2>
    </div>
    <div class="container-table centered-table">
        <table id="myTable" class="my_table">
            {html_summary_table}
        </table>
    </div>

    <script>
    $(document).ready(function () {{
        $('#myTable').DataTable({{
        }});
    }});
    </script>

    <div style="page-break-after: always;"></div>

    <div class="heading">
    <h2> <p id="bar_graph_open_vulns"> Top 15 Projects with High Severity Open Vulnerability Count  </p> </h2>
    <div style="height: 75px;"></div> <!-- Creates 75px of vertical space -->
    <div class="container">
        <img src="{absolute_path_open}" alt="open_vulns" id="myImage">
    </div>
    <div style="page-break-after: always;"></div>

    <div class="heading">
    <h2> <p id="bar_graph_fixed_vulns"> Top 15 Projects with High Severity Fixed Vulnerability Count  </p> </h2>
    </div>

    <div style="height: 75px;"></div> <!-- Creates 75px of vertical space -->
    <div class="container">
        <img src="{absolute_path_fixed}" alt="fixed_vulns" id="myImage">
    </div>

    <div style="page-break-after: always;"></div>

    <div class="heading">
    <h2> <p id="heatmap_vuln_classes"> Vulnerability Classes for Top 15 Projects with High Severity Open Vulnerability Count  </p> </h2>
    <div style="height: 75px;"></div> <!-- Creates 75px of vertical space -->
    <div class="container">
        <img src="{absolute_path_heatmap_vuln_classes}" alt="heatmap_vuln_classes" id="myImage">
    </div>
    <div style="page-break-after: always;"></div>

    <div class="heading">
    <h2> <p id="heatmap_owasp_top10_categories"> OWASP Top 10 mapping for Top 15 Projects with High Severity Open Vulnerability Count  </p> </h2>
    <div style="height: 75px;"></div> <!-- Creates 75px of vertical space -->
    <div class="container">
        <img src="{absolute_path_heatmap_owasp_top10_categories}" alt="heatmap_owasp_top10_categories" id="myImage">
    </div>
    <div style="page-break-after: always;"></div>

    <div style="page-break-after: always;"></div>"""

    # Loop through all the files in the folder
    for item in sorted(os.listdir(folder_path)):
        # Check if the file is an HTML file to be combined
        if item.endswith(".html"):
            # Construct the full path of the file
            file_path = os.path.join(folder_path, item)
            # Open and read the HTML file
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                # Extract body content (simple approach, could be improved with an HTML parser for robustness)
                body_content = content.split('<body>', 1)[-1].rsplit('</body>', 1)[0]
                combined_html += body_content + """\n <div style="page-break-after: always;"></div>"""

    # End of the HTML document
    combined_html += "</body>\n</html>"

    # Write the combined HTML to the output file
    with open(os.path.join(folder_path, output_filename), 'w', encoding='utf-8') as f_out:
        f_out.write(combined_html)

    # convert from HTML to PDF
    options = {
        'orientation': 'Landscape',
        'enable-local-file-access': None
    }
    try:
        pdfkit.from_string(combined_html, os.path.join(folder_path, output_pdf_filename), options=options)
    except OSError:
        logging.info("Skipping PDF because wkhtmltopdf not found. You can get it here: https://wkhtmltopdf.org/")

def generate_html_sast(df_high: pd.DataFrame, df_med: pd.DataFrame, df_low: pd.DataFrame, repo_name):
    # get the Overview table HTML from the dataframe
    # overview_table_html = df_overview.to_html(table_id="table")
    # get the Findings table HTML from the dataframe
    high_findings_table_html = df_high.to_html(index=False, table_id="tableHigh", render_links=True, escape=False, classes='my_table')
    med_findings_table_html = df_med.to_html(index=False, table_id="tableMedium", render_links=True, escape=False, classes='my_table')
    low_findings_table_html = df_low.to_html(index=False, table_id="tableLow", render_links=True, escape=False, classes='my_table')

    # Get the current date and time
    now = datetime.now()

    # Format the date and time
    formatted_now = now.strftime("%Y-%m-%d %H:%M")

    # Print the formatted date and time
    # logging.debug("Current date and time:", str(formatted_now))

    html = f"""
    <html>
    <head>
    <title> Semgrep SAST Scan Report for Repository: {repo_name} </title>
    <style>
    .my_table {{
        width: 100%;
        border-collapse: collapse;
    }}
    .my_table th, .my_table td {{
        border: 1px solid black;
        text-align: left;
        padding: 8px;
    }}
    .my_table th {{
        background-color: #f2f2f2;
    }}
    /* Example of setting specific column widths */
    .my_table td:nth-of-type(1) {{ /* Targeting first column */
        width: 20% !important;
    }}
    .my_table td:nth-of-type(2) {{ /* Targeting second column */
        width: 30% !important;
    }}
    .my_table td:nth-of-type(3) {{ /* Targeting third column */
        width: 10% !important;
    }}
    .my_table td:nth-of-type(4) {{ /* Targeting fourth column */
        width: 10% !important;
    }}
    .my_table td:nth-of-type(5) {{ /* Targeting fifth column */
        width: 15% !important;
    }}
    .my_table td:nth-of-type(6) {{ /* Targeting sixth column */
        width: 15% !important;
    }}
    </style>
    <style>
        #myImage {{
            display: block;
            margin-left: auto;
            margin-right: auto;
            width: 75%; /* or any desired width */
            height: auto; /* to maintain the aspect ratio */
        }}
    </style>
    <style>
        .centered-table {{
            margin-left: auto;
            margin-right: auto;
        }}
    </style>
    <style>
        table {{
            border-collapse: collapse;
            width: 50%;
        }}
        th, td {{
            border: 1px solid black;
            text-align: left;
            padding: 8px;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        tr:nth-child(even) {{
            background-color: #f2f2f2;
        }}
    </style>

    </head>
    <header>
        <link href="https://cdn.datatables.net/1.11.5/css/jquery.dataTables.min.css" rel="stylesheet">
    </header>
    <body>
    <div style="height: 75px;"></div> <!-- Creates 75px of vertical space -->
    <div class="container">
    <img src="https://i.ibb.co/8xyV6WJ/Semgrep-logo.png" alt="logo" id="myImage">
    </div>
    <div class="container">
    <h1> <p style="text-align: center;" id="sast"> Semgrep SAST Scan Report for Repository: {repo_name} </p> </h1>
    <h2> <p style="text-align: center;" id="reporttime"> Report Generated at {formatted_now} </p> </h2>
    </div>
    <div style="height: 40px;"></div> <!-- Creates 50px of vertical space -->
    <div class="topnav">
    <h2> <p style="text-align: center;" id="sast-summary"> SAST Scan Summary </p> </h2>

    <table border="1" class="centered-table"> <!-- Added border for visibility -->
        <!-- Table Header -->
        <tr>
            <th>Vulnerability Severity</th>
            <th>Vulnerability Count</th>
        </tr>

        <!-- Table Rows and Data Cells -->
        <tr>
            <td><a href="#sast-high"> Findings- SAST High Severity </a> </td>
            <td> {len(df_high)} </td>
        </tr>
        <tr>
            <td> <a href="#sast-med"> Findings- SAST Medium Severity </a> </td>
            <td> {len(df_med)} </td>
        </tr>
        <tr>
            <td> <a href="#sast-low"> Findings- SAST Low Severity </a> </td>
            <td> {len(df_low)} </td>
        </tr>
    </table>

    </div>

    <div style="page-break-after: always;"></div>

    <div class="heading">
    <h2> <p id="sast-high"> Findings Summary- HIGH Severity </p> </h2>
    </div>
    <div class="container">
        {high_findings_table_html}
    </div>

    <div style="page-break-after: always;"></div>

    <div class="heading">
    <h2> <p id="sast-med"> Findings Summary- MEDIUM Severity </p> </h2>
    </div>
    <div class="container">
    <table style="width: 100%;">
    {med_findings_table_html}
    </table>
    </div>

    <div style="page-break-after: always;"></div>

    <div class="heading">
    <h2> <p id="sast-low"> Findings Summary- LOW Severity </p> </h2>
    </div>
    <div class="container">
    <table style="width: 100%;">
    {low_findings_table_html}
    </table>
    </div>

    </body>
    </html>
    """
    # return the html
    return html
