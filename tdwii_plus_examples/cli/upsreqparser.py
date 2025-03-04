#!/usr/bin/env python
"""
A DICOM UPS Attributes Requirements parser application.

This application parses UPS Attributes requirements from DICOM Part 4 Section
CC.2.5 and IHE-RO TDW-II Profile Supplement Tables.
It reads the PS3.4 DICOM standard chunked HTML file and the IHE-RO PDF file
from the project's `ref` directory or downloads them from NEMA.org and IHE.net
and converts the tables into tree structures.

The DICOM UPS Attributes requirements tree can be:
- Filtered to extract requirements for a specific DICOM primitive and role.
- Enriched with IHE-RO TDW-II requirements tree.
- Rendered as a flat ASCII table or an ASCII tree.
- Exported to a JSON file.

Usage:
    upsreqparser.py [options]

Arguments:
    None

Options:
    -h, --help               Show this help message and exit
    -v, --verbose            Enable verbose output (info level)
    -d, --debug              Enable debug output (debug level)
    -q, --quiet              Suppress all output (quiet mode)

    -f, --file               Path to the PS3.4 CC.2.5 XHTML file
    -id, --table-id          Identifier of the table to extract
    -i, --include-depth      Recursion depth for including referenced tables

    -p, --primitive          Filter requirements per DIMSE primitive
    -r, --role               Filter primitive requirements per DICOM Role
    -m, --mandatory          Filter requirements per DICOM Type
    -x, --exclude-titles     Exclude rows that are only titles
 
    --tdw-ii                 Add IHE-RO TDW-II requirements
    --tdw-ii-file            Path to the IHE-RO TDW-II PDF file

    -ta, --table             Print requirements as a flat ASCII table
    -tr, --tree              Print attributes as an ASCII tree
    -c, --colorize           Colorize the ASCII output by level of nesting

    -j, --json               Export the requirements to a JSON file

For more details on usage, run:
    upsreqparser.py --help
"""
import argparse
import logging
import os
import re
import sys
from pathlib import Path

import pdfplumber
import requests
from anytree import Node, PreOrderIter, RenderTree, findall
from anytree.exporter import JsonExporter
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table, box
from rich.text import Text

# Configure the logger at the module level
logger = logging.getLogger(os.path.basename(sys.argv[0]))

# Define lists of attributes corresponding to DIMSE primitives CC.2.5 Tables columns
primitive_columns = {
    "N-CREATE": ["name", "tag", "ncreate", "remark"],
    "N-SET": ["name", "tag", "nset", "remark"],
    "N-GET": ["name", "tag", "nget", "remark"],
    "C-FIND": ["name", "tag", "matching", "return", "remark"],
    "FINAL": ["name", "tag", "finalstate", "remark"],
    "ALL": ["name", "tag", "ncreate", "nset", "finalstate", "nget", "matching", "return", "remark"],
    "COMMON": ["name", "tag", "remark"],
}

# Define lists of attributes corresponding to DIMSE primitives CC.2.5 Tables columns
tdw_ii_primitive_columns = {
    "N-CREATE": ["name", "tag", "tdw_ii_ncreate", "tdw_ii_note"],
    "N-SET": ["name", "tag", "tdw_ii_progress", "tdw_ii_note"],
    "FINAL": ["name", "tag", "tdw_ii_final", "tdw_ii_note"],
    "C-FIND": [
        "name",
        "tag",
        "tdw_ii_matching_scu",
        "tdw_ii_matching_scp",
        "tdw_ii_return_scu",
        "tdw_ii_return_scp",
        "tdw_ii_matching_scu_note",
        "tdw_ii_matching_scp_note",
        "tdw_ii_return_scu_note",
        "tdw_ii_return_scp_note",
    ],
    "ALL": [
        "name",
        "tag",
        "tdw_ii_ncreate",
        "tdw_ii_progress",
        "tdw_ii_final",
        "tdw_ii_matching_scu",
        "tdw_ii_matching_scp",
        "tdw_ii_return_scu",
        "tdw_ii_return_scp",
        "tdw_ii_note",
    ],
    "COMMON": ["name", "tag", "tdw_ii_note"],
}

level_colors = [
    "rgb(255,255,255)",  # Node depth 0, Root: White
    "rgb(173,216,230)",  # Node depth 1, Table Level 0: Light Blue
    "rgb(135,206,250)",  # Node depth 2, Table Level 1: Sky Blue
    "rgb(0,191,255)",  # Node depth 3, Table Level 2: Deep Sky Blue
    "rgb(30,144,255)",  # Node depth 4, Table Level 3: Dodger Blue
    "rgb(0,0,255)",  # Node depth 5, Table Level 4: Blue
]

fdir = os.path.abspath(os.path.dirname(__file__))
REF_DIR = os.path.join(fdir, "../../ref")
UPS_PS3_4_CC_2_5_FILE = os.path.join(REF_DIR, "PS3_4_CC.2.5.html")
TDW_II_FILE = os.path.join(REF_DIR, "IHE_RO_Suppl_TDW_II.pdf")


def find_project_root(current_path, marker_file="pyproject.toml"):
    """
    Finds the project root directory by looking for the presence of a marker
    file (default is 'pyproject.toml') in the directory tree.

    Parameters:
    ----------
        current_path (str): The current path to start searching from.
        marker_file (str, optional): The file name to look for in each directory.
            Defaults to 'pyproject.toml'.
    Returns:
    -------
        str: The path to the project root directory if found, otherwise None.
    """
    while current_path != os.path.dirname(current_path):
        if marker_file in os.listdir(current_path):
            return current_path
        current_path = os.path.dirname(current_path)
    return None


def setup_logging(log_level=logging.DEBUG):
    # Set the logs directory at the top level of the project
    current_script_dir = os.path.dirname(__file__)
    project_root = find_project_root(current_script_dir)
    if project_root is None:
        raise RuntimeError("Project root not found. Make sure 'pyproject.toml' exists at the top level of your project.")
    logs_path = os.path.join(project_root, "logs")
    if not os.path.exists(logs_path):
        os.makedirs(logs_path)

    # Configure log level
    logger.setLevel(log_level)

    # Create a console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)

    # Create a file handler with UTF-8 encoding
    logfile_name = os.path.join(logs_path, "extract_ups_attr_req.log")
    file_handler = logging.FileHandler(logfile_name, encoding="utf-8")
    file_handler.setLevel(log_level)

    # Create formatters and add them to handlers
    formatter = logging.Formatter("%(levelname)s - %(message)s")
    console_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)

    # Add handlers to the logger
    if not logger.handlers:
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)


def download_ups_cc_2_5():
    """Download DICOM PS3.4 Section CC.2.5 XHTML file from NEMA.org"""
    url = "https://dicom.nema.org/medical/dicom/current/output/chtml/part04/sect_CC.2.5.html"
    os.makedirs(REF_DIR, exist_ok=True)
    print(f"downloading DICOM Part 4 Section CC.2.5 XHTML file from NEMA.org to {os.path.abspath(UPS_PS3_4_CC_2_5_FILE)}")
    response = requests.get(url)
    with open(UPS_PS3_4_CC_2_5_FILE, "w", encoding="utf-8") as file:
        file.write(response.text)
    return UPS_PS3_4_CC_2_5_FILE


def download_tdw_ii():
    """Download IHE-RO TDW-II Profile PDF file from IHE.net"""
    url = "https://www.ihe.net/uploadedFiles/Documents/Radiation_Oncology/IHE_RO_Suppl_TDW_II.pdf"
    os.makedirs(REF_DIR, exist_ok=True)
    print(f"downloading IHE-RO TDW-II Profile PDF file from IHE.net to {os.path.abspath(TDW_II_FILE)}")
    response = requests.get(url)
    with open(TDW_II_FILE, "wb") as file:
        file.write(response.content)
    return TDW_II_FILE


def sanitize_string(s):
    """
    Sanitize a given string by replacing non-ASCII characters with a space.
    """
    return re.sub(r"[^\x00-\x7F]+", " ", s)


def map_header_to_attributes(header):
    """
    Map headers to XML attributes based on pattern matching
    """
    attributes = ["name", "tag", "ncreate", "nset", "finalstate", "nget", "matching", "return", "remark"]
    stripped_header = header.replace("-", "").replace("/Matching", "").lower()
    for attr in attributes:
        if attr[:5] in stripped_header:
            return attr
    return None


def get_type(role, value):
    """
    Return the Type of the UPS Attribute for the specified role.
    """
    if role == "SCU":
        return value.split("/")[0]
    elif role == "SCP":
        return value.split("/")[-1]


def extract_table_from_file(file, table_id, include_depth):
    logger.debug(f"Extracting Table {table_id} from: {file}")
    file_path = file
    if not Path(file_path).exists():
        if file == UPS_PS3_4_CC_2_5_FILE:
            file_path = download_ups_cc_2_5()
        else:
            print(f"{file_path} not found")
            sys.exit(1)

    with open(file_path, "r", encoding="utf-8") as file:
        content = file.read()

    dom = BeautifulSoup(content, "lxml-xml")

    return extract_table_from_chtml(dom, table_id, include_depth=include_depth)


def extract_table_from_chtml(dom, table_id, table_nesting_level=0, include_depth=0):
    """
    Extract the rows of the specified table and return them as a tree
    of nodes, organized according to their level of nesting under a root node.

    When a row contains an Include Table statement, this function recursively
    calls itself to extract the included table. The resulting tree root node
    is then added under the parent element at the appropriate level of nesting
    corresponding to the Include row.

    Parameters:
    ----------
        dom (bs4.BeautifulSoup): The BeautifulSoup object representing the XHTML DOM.
        table_id (str): The ID of the table to extract.
        nesting_level (int, optional): The nesting level of the table to extract.
        include_level (int, optional): The depth include level of the table.

    Returns:
    -------
        str: The extracted headers of the table as a string.
        ET.Element: The root element of the extracted table.
    """
    logger.debug(f"Nesting Level: {table_nesting_level}, Searching for table: {table_id}")
    anchor = dom.find("a", {"id": table_id})
    if anchor is None:
        logger.error(f"Nesting Level: {table_nesting_level}, Table Id {table_id} not found.")
        sys.exit(1)

    table = anchor.find_next("table")
    if table is None:
        logger.error(f"Nesting Level: {table_nesting_level}, Table {table_id} not found.")
        sys.exit(1)

    logger.debug(f"Nesting Level: {table_nesting_level}, Table {table_id} found.")
    table_headers = [header.text.strip() for header in table.find_all("th")]
    logger.debug(f"Nesting Level: {table_nesting_level}, Table headers: {table_headers}")

    # Create a single root node
    root = Node("Root")

    # Dictionary to keep track of the most recent nodes at each level
    level_nodes = {0: root}

    # Define the node attributes names
    node_attributes = primitive_columns["ALL"]

    previous_row_name = ""
    # Read each row in the table
    for row in table.find_all("tr")[1:]:  # Skip the header row
        cells = []
        colspans = []

        for cell in row.find_all("td"):
            paragraphs = cell.find_all("p")
            if len(paragraphs) > 1:
                cell_text = "\n".join(p.text.strip() for p in paragraphs)
            else:
                cell_text = paragraphs[0].text.strip() if paragraphs else ""
            cells.append(sanitize_string(cell_text))
            colspans.append(int(cell.get("colspan", 1)))  # Get colspan, default to 1 if not present

        # Create a dictionary for the row data
        row_data = {}
        attr_index = 0
        for cell, colspan in zip(cells, colspans):
            if attr_index < len(node_attributes):
                row_data[node_attributes[attr_index]] = cell
                attr_index += colspan  # Skip the attributes spanned by colspan

        # Patch the include level error for Output Information Sequence items attributes
        if previous_row_name.startswith(">Output Information Sequence") and row_data["name"].startswith(">Include"):
            row_data["name"] = ">" + row_data["name"]
            logger.debug("Patched include level error for Output Information Sequence items attributes")
        previous_row_name = row_data["name"]

        # Determine the row nesting level
        row_nesting_level = table_nesting_level + row_data["name"].count(">")

        # Add nesting level symbols to attribute names from included table
        if table_nesting_level > 0:
            row_data["name"] = ">" * table_nesting_level + row_data["name"]

        # Check if this row contains an Include Table statement
        if "Include" in row_data["name"] and include_depth > 0:
            # Search the reference to the included table in the XHTML row element
            include_anchor = row.find("a", {"class": "xref"})
            if include_anchor:
                include_table_id = include_anchor["href"].split("#", 1)[-1]
                logger.debug(
                    f"Nesting Level: {row_nesting_level}, Name: {row_data['name']}, Include Table Id: {include_table_id}"
                )
                table_headers, included_table_tree = extract_table_from_chtml(
                    dom, include_table_id, table_nesting_level=row_nesting_level, include_depth=include_depth - 1
                )
                # Add the included table nodes under the most recent node at the upper level
                parent_node = level_nodes.get(row_nesting_level - 1, root)
                parent_name = parent_node.name if parent_node else "None"
                logger.debug(
                    f"Nesting Level: {row_nesting_level}, Table Id: {include_table_id}, Parent Node Name: {parent_name}"
                )
                for child in included_table_tree.children:
                    child.parent = parent_node

            else:
                logger.warning(f"Nesting Level: {row_nesting_level}, Name: {row_data['name']}, Include Table Id not found")

        else:
            # Create a new node under the most recent node at the upper level
            node_name = row_data.pop("name")
            parent_node = level_nodes.get(row_nesting_level - 1, root)
            parent_name = parent_node.name if parent_node else "None"
            logger.debug(f"Nesting Level: {row_nesting_level}, Name: {node_name}, Parent Node Name: {parent_name}")
            node = Node(node_name, parent=parent_node, **row_data)

            # Update the most recent node at this level
            level_nodes[row_nesting_level] = node

    return table_headers, root


def cleanup_table(tables):
    if tables:
        header = tables[0][0]  # Assume the first row of the first table is the header
        header_found = False
        for table in tables:
            cleaned_table = []
            for row in table:
                if row == header and not header_found:
                    header_found = True
                elif row != header:
                    cleaned_table.append(row)
            table[:] = cleaned_table
    return tables


def create_node(row_data, parent_nodes):
    node_name = row_data.pop("name")
    level = node_name.count(">") + 1  # Calculate the level based on the number of '>' symbols
    parent = parent_nodes[level - 1]
    child = Node(node_name, parent=parent, **row_data)  # Create the child node
    parent_nodes[level] = child  # Update the current node at this level
    logger.debug(f"Nesting Level: {level}, Name: {node_name}, Parent Node Name: {parent.name}")


def extract_tables_from_pdf(pdf, page_numbers, relevant_table_indexes):
    """
    Extract tables from specified pages of a PDF and return the relevant ones.

    Parameters:
    ----------
    pdf : pdfplumber.PDF
        The PDF object from which to extract tables.
    page_numbers : list of int
        A list of page numbers from which to extract tables (1-indexed).
    relevant_table_indexes : list of int
        A list of indexes specifying which extracted tables to return

    Returns:
    -------
    list of list of list of str
        A list of tables, where each table is represented as a list of rows,
        and each row is a list of cell strings.
    """

    all_tables = []
    for page_num in page_numbers:
        page = pdf.pages[page_num - 1]  # Page numbers are 0-indexed in pdfplumber
        tables = page.extract_tables()
        if tables:
            for table in tables:
                cleaned_table = [[cell for cell in row if cell not in ("", None)] for row in table]
                all_tables.append(cleaned_table)

    relevant_tables = [all_tables[i] for i in relevant_table_indexes if i < len(all_tables)]
    relevant_tables = cleanup_table(relevant_tables)

    return relevant_tables


def extract_notes_from_pdf(pdf, page_numbers):
    notes = {}
    note_pattern = re.compile(r"^\d*\s*Note\s\d+:")
    header_footer_pattern = re.compile(r"^\s*(IHE|_{3,}|Rev\.|Copyright|Template|Page\s\d+|\(TDW-II\))")
    line_number_pattern = re.compile(r"^\d+\s")
    end_note_pattern = re.compile(r".*7\.5\.1\.1\.2")
    current_note = None
    for page_num in page_numbers:
        page = pdf.pages[page_num - 1]  # Page numbers are 0-indexed in pdfplumber
        text = page.extract_text()
        if text:
            lines = text.split("\n")
            for line in lines:
                if header_footer_pattern.search(line):
                    continue  # Skip header or footer lines
                if end_note_pattern.search(line):
                    current_note = None  # Stop adding to the current note
                    break  # Stop processing further lines
                match = note_pattern.search(line)
                if match:
                    note_number = match.group().strip()
                    # Remove any text before "Note note_number:"
                    note_number = re.sub(r"^\d*\s*", "", note_number)
                    note_text = line[match.end() :].strip()
                    notes[note_number] = note_text
                    current_note = note_number
                elif current_note:
                    # Continuation of the current note
                    line = line_number_pattern.sub("", line).strip()  # Remove line numbers
                    notes[current_note] += " " + line
    for note in notes:
        logger.debug(f"{note} {notes[note]}")
    return notes


def extract_ncreate_scu_tables(pdf, primitive):
    """
    Extract UPS Scheduled Procedure Information Base table
    from TDW-II Profile Supplement pages 57 and 58 and
    returns the table as a tree.
    """
    relevant_tables = extract_tables_from_pdf(pdf, [57, 58, 60], [1, 2, 4])

    # Convert tables to tree
    root = Node("Root")
    parent_nodes = {0: root}  # Dictionary to keep track of parent node at each level
    node_attributes = tdw_ii_primitive_columns[primitive]
    for table in relevant_tables:
        for row_index, row in enumerate(table):
            row_data = {}
            for cell_index in range(len(row)):
                cell = row[cell_index]
                # Replace \n with space unless preceded by a period AND followed by an uppercase letter,
                # OR followed by the string "CID"
                row[cell_index] = re.sub(r"[\n](?![A-Z]|CID)|(?<!\.|\:)[\n](?!CID)", " ", cell)
                # Pad rows to 4 columns
                if row[0] == "All other attributes":
                    row = [row[0]] + [""] * (4 - len(row)) + row[1:]
                else:
                    row = row + [""] * (4 - len(row))
                # Add UPS Scheduled Procedure Information for ‘Treatment Delivery’ requirements
                if cell == "Scheduled Workitem Code Sequence":
                    table[row_index + 1].append('shall be equal to "121726"')
                    table[row_index + 2].append('shall be equal to "DCM"')
                    table[row_index + 3].append('shall be equal to "RT Treatment with Internal Verification"')
                if cell == "Input Information Sequence":
                    row[cell_index + 3] += (
                        "\nShall contain at least 2 Referenced DICOM Instances:"
                        "\nRT Plan Storage or RT Ion Plan Storage in OST."
                        "\nRT Beams Delivery Instruction Storage in TMS."
                        "\nShall contain more Referenced DICOM Instances if Treatment Delivery Type is equal to CONTINUATION:"
                        "\nRT Beams Treatment Record Storage or RT Ion Beams Treatment Record Storage in OST."
                    )
                if cell == "Scheduled Processing Parameters\nSequence":
                    row[cell_index + 3] += (
                        "\nShall include 4 Content Items per Template:"
                        '\nEV (121740, DCM, "Treatment Delivery Type"), VT:TEXT (TREAMENT or CONTINUATION).'
                        '\nEV (2018001, 99IHERO2018, "Plan Label"), VT:TEXT (RT Plan Label (300A,0002) value).'
                        '\nEV (2018002, 99IHERO2018, "Current Fraction Number"), VT:NUMERIC '
                        "(Current Fraction Number (3008,0022) value)."
                        '\nEV (2018003, 99IHERO2018, "Number of Fractions Planned"), VT:NUMERIC '
                        "(Number of Fractions Planned (300A,0078) value)."
                    )
                row_data[node_attributes[cell_index]] = row[cell_index]

            if row[0] != "All other attributes":
                create_node(row_data, parent_nodes)

    return root


def extract_finalupdate_scu_tables(pdf, primitive):
    """
    Extract UPS Performed Procedure Information Base table
    from TDW-II Profile Supplement pages 61 and 62 and
    returns the table as a tree.
    """
    relevant_tables = extract_tables_from_pdf(pdf, [61, 62], [0, 1])

    # Convert tables to tree
    root = Node("Root")
    parent_nodes = {0: root}  # Dictionary to keep track of parent node at each level
    node_attributes = tdw_ii_primitive_columns[primitive]
    for table in relevant_tables:
        for row_index, row in enumerate(table):
            row_data = {}
            for cell_index in range(len(row)):
                cell = row[cell_index]
                # Replace \n with space unless preceded by a period AND followed by an uppercase letter,
                # OR followed by the string "CID"
                row[cell_index] = re.sub(r"[\n](?![A-Z]|CID)|(?<!\.)[\n](?!CID)", " ", cell)
                # Pad rows to 4 columns
                if row[0] == "All other attributes":
                    row = [row[0]] + [""] * (4 - len(row)) + row[1:]
                else:
                    row = row + [""] * (4 - len(row))
                # Add UPS Scheduled Procedure Information for ‘Treatment Delivery’ requirements
                if cell == ">Performed Workitem Code Sequence":
                    table[row_index + 1].append('shall be equal to "121726"')
                    table[row_index + 2].append('shall be equal to "DCM"')
                    table[row_index + 3].append('shall be equal to "RT Treatment with Internal Verification"')
                if cell == ">Output Information Sequence":
                    row[cell_index + 3] += (
                        "\nShall contain at least 1 items if any therapeutic treatment was delivered to the patient:"
                        "\nRT Beams Treatment Record Storage (1.2.840.10008.5.1.4.1.1.481.4) or "
                        "RT Ion Beams Treatment Record Storage (1.2.840.10008.5.1.4.1.1.481.9) stored to OST"
                        "\nMay be present otherwise"
                    )
                row_data[node_attributes[cell_index]] = row[cell_index]

            if row[0] != "All other attributes":
                create_node(row_data, parent_nodes)

    return root


def extract_progressupdate_scu_tables(pdf, primitive):
    """
    Extract UPS N-SET Progress Update Requirements table
    from TDW-II Profile Supplement pages 64 and 65 and
    returns the table as a tree.
    """
    relevant_tables = extract_tables_from_pdf(pdf, [64, 65], [0, 1])

    # Convert tables to tree
    root = Node("Root")
    parent_nodes = {0: root}  # Dictionary to keep track of parent node at each level
    node_attributes = tdw_ii_primitive_columns[primitive]
    for table in relevant_tables:
        for row_index, row in enumerate(table):
            row_data = {}
            # Process each cell in the row
            for cell_index in range(len(row)):
                cell = row[cell_index]
                # Replace \n with space unless preceded by a period AND followed by an uppercase letter
                row[cell_index] = re.sub(r"\n|(?<!\.)[\n]", " ", cell)

                # Add N-SET Progress Update Requirements for ‘Treatment Delivery’ requirements
                if cell == ">Procedure Step Progress Parameters\nSequence":
                    row[cell_index + 3] += (
                        "\nShall include 1 Content Item per Template:"
                        '\nEV (2018004, 99IHERO2018, "Referenced Beam Number"), VT:NUMERIC'
                    )
                row_data[node_attributes[cell_index]] = row[cell_index]

            # create node if row has more than 2 elements
            if len(row) > 2:
                create_node(row_data, parent_nodes)
    return root


def extract_cfind_tables(pdf, primitive):
    """
    Extract UPS C-FIND Requirements table
    from TDW-II Profile Supplement pages 63 and
    returns the table as a tree.
    """
    relevant_tables = extract_tables_from_pdf(pdf, [63], [0])
    notes = extract_notes_from_pdf(pdf, [63, 64])

    # Convert tables to tree
    root = Node("Root")
    parent_nodes = {0: root}  # Dictionary to keep track of parent node at each level
    node_attributes = tdw_ii_primitive_columns[primitive]
    for table in relevant_tables:
        for row in table:
            row_data = {}
            # Process each cell in the row
            for cell_index in range(len(row)):
                cell = row[cell_index]
                # Replace \n with space unless preceded by a period AND followed by an uppercase letter
                row[cell_index] = re.sub(r"\n|(?<!\.)[\n]", " ", cell)

                # Replace (Note #) placeholder by the note text
                note_match = re.search(r".*\(Note (\d+)\).*", cell)
                if note_match:
                    note_key = "Note " + note_match.group(1) + ":"
                    if note_key in notes:
                        note_text = notes[note_key]
                        row_data[node_attributes[cell_index] + "_note"] = note_text
                    # Remove the reference from the cell value
                    cell = re.sub(r"\(Note " + note_match.group(1) + r"\)", "", cell).strip()
                row_data[node_attributes[cell_index]] = cell

            # create node if row has more than 2 elements
            if len(row) > 5:
                create_node(row_data, parent_nodes)
    return root


def merge_trees(table_tree, root_tree, primitive):
    """
    Merge the TDW-II attributes from root_tree into table_tree.
    """
    logger.debug(f"Nodes to merge:\n{RenderTree(root_tree).by_attr()}")

    for node in root_tree.descendants:
        # Get the path for the current node using ancestors, matching on tags
        logger.debug(f"Node: {node.name} ({getattr(node, 'tag', None)})")

        node_path = [getattr(ancestor, "tag", None) for ancestor in node.ancestors] + [getattr(node, "tag", None)]
        logger.debug(f"Node Path: {node_path}")

        # Find matching nodes in table_tree based on the full node path
        matching_nodes = findall(
            table_tree,
            filter_=lambda n: (
                [getattr(ancestor, "tag", None) for ancestor in n.ancestors] + [getattr(n, "tag", None)] == node_path
            ),
        )

        for match in matching_nodes:
            logger.debug(f"Match found: {match.name} with path {node_path}")
            # Merge TDW-II attributes
            for key, value in node.__dict__.items():
                if key in tdw_ii_primitive_columns[primitive] and key not in ["name", "tag"]:
                    setattr(match, key, value)


def remove_nodes_attributes(root, attributes_to_remove):
    for node in PreOrderIter(root):
        for attr in attributes_to_remove:
            if hasattr(node, attr):
                delattr(node, attr)


def split_nodes_attributes(root, primitive_attribute, role):
    attr_to_split = primitive_attribute[0]
    for node in PreOrderIter(root):
        if hasattr(node, attr_to_split):
            value = getattr(node, attr_to_split)
            if "/" in value:
                if "\n" in value:
                    type, comment = value.split("\n", 1)
                    node.comment = comment
                else:
                    type = value.split("\n", 1)[0]
                role_type = get_type(role, type)
                setattr(node, attr_to_split, role_type)


def remove_optional_nodes(root, primitive_attribute, tdw_ii_attribute=None):
    # Define the types to keep and remove
    # TODO: Check what to do with "" in FINAL
    # TODO: Check what to do with "Not allowed" types
    logger.debug(f"Removing nodes based on value of {primitive_attribute[0]} attribute")
    types_to_keep = ["1", "1C", "2", "2C", "U", "R", "RC", "P", "X"]
    types_to_remove = ["3", "-", "O"]
    if tdw_ii_attribute:
        tdw_ii_types_to_keep = ["R", "R*", "RC", "RC*", "R+", "RC+", "R+*", "RC+*", "D", "X", "X+"]
        tdw_ii_types_to_remove = ["O", "O+", "O+*", "-"]
    # Iterate on a static list of nodes to safely modify the tree structure
    for node in list(PreOrderIter(root)):
        type = None
        # Remove nodes based on primitive_attribute
        if hasattr(node, primitive_attribute[0]):
            type = getattr(node, primitive_attribute[0])
            if type in types_to_remove and type not in types_to_keep:
                # Check if we need to keep the node based on TDW-II
                if tdw_ii_attribute:
                    if hasattr(node, tdw_ii_attribute[0]):
                        tdw_ii_type = getattr(node, tdw_ii_attribute[0])
                        if tdw_ii_type in tdw_ii_types_to_keep and tdw_ii_type not in tdw_ii_types_to_remove:
                            logger.debug(f"[{tdw_ii_type.rjust(3)}] : Keeping {node.name} element")
                            continue
                logger.debug(f"[{type.rjust(3)}] : Removing {node.name} element")
                node.parent = None
                continue

        if type is not None:
            logger.debug(f"[{type.rjust(3)}] : Keeping {node.name} element")
        else:
            logger.debug(f"[{''.rjust(3)}] : Keeping {node.name} element")

        # Remove nodes under "Sequence" nodes with specific primitive_attributes
        if "Sequence" in node.name and hasattr(node, primitive_attribute[0]) and not hasattr(node, "tdw_ii"):
            type = getattr(node, primitive_attribute[0])
            if type in ["3", "2", "2C", "-", "O", "Not allowed"]:
                logger.debug(f"[{type.rjust(3)}] : Removing {node.name} subelements")
                for descendant in node.descendants:
                    descendant.parent = None


def remove_titles_nodes(root):
    # Iterate on a static list of nodes to safely modify the tree structure
    for node in list(PreOrderIter(root)):
        attribute_values = [getattr(node, attr, "") for attr in primitive_columns["ALL"] if attr != "name"]
        all_empty_except_first = all(item == "" for item in attribute_values[1:])
        if all_empty_except_first and "Include" not in node.name and node.name != "Root":
            logger.debug(f"Removing {node.name} node")
            node.parent = None


def render_tree_as_table(headers, table_tree, primitive=None, role=None, tdw_ii=False, colorize=False):
    console = Console()
    table = Table(show_header=True, header_style="bold magenta", show_lines=True, box=box.ASCII_DOUBLE_HEAD)
    # Add columns to the table
    for header in headers:
        table.add_column(header, overflow="fold", max_width=30)
    if tdw_ii:
        if primitive == "C-FIND":
            column_title = "TDW-II " + primitive
            scu_columns_suffixes = [" Matching Keys SCU", " Return Keys SCU"]
            scp_columns_suffixes = [" Matching Keys SCP", " Return Keys SCP"]
            if role == "SCU" or role is None:
                for suffix in scu_columns_suffixes:
                    table.add_column(column_title + suffix, overflow="fold", max_width=30)
            if role == "SCP" or role is None:
                for suffix in scp_columns_suffixes:
                    table.add_column(column_title + suffix, overflow="fold", max_width=30)
            # Add column for notes
            if role == "SCU" or role is None:
                for suffix in scu_columns_suffixes:
                    table.add_column(column_title + suffix + " Note", overflow="fold", max_width=30)
            if role == "SCP" or role is None:
                for suffix in scp_columns_suffixes:
                    table.add_column(column_title + suffix + " Note", overflow="fold", max_width=30)

        elif primitive in ["N-CREATE", "N-SET", "FINAL"] and role == "SCU":
            column_title = "TDW-II " + primitive
            table.add_column(column_title, overflow="fold", max_width=30)
            table.add_column(column_title + " Note", overflow="fold", max_width=30)

        else:
            print(f"IHE-RO TDW-II does not define any additional UPS requirements for {primitive} {role}.")
    column_names = [column.header for column in table.columns]
    logger.debug(f"Columns: {column_names}")

    # Define the node attributes names
    node_attributes = primitive_columns["ALL"] if primitive is None else primitive_columns[primitive]
    if role is not None and primitive == "C-FIND":
        if role == "SCU":
            node_attributes.remove("return")
        else:
            node_attributes.remove("matching")
    elif role is not None and primitive not in ("C-FIND", "FINAL"):
        node_attributes.append("comment")
    if tdw_ii:
        for attr in tdw_ii_primitive_columns[primitive]:
            if attr not in ("name", "tag"):
                if primitive == "C-FIND" and role == "SCU" and "scu" in attr:
                    node_attributes.append(attr)
                elif primitive == "C-FIND" and role == "SCP" and "scp" in attr:
                    node_attributes.append(attr)
                elif primitive == "C-FIND" and role is None:
                    node_attributes.append(attr)
                elif primitive in ["N-CREATE", "N-SET", "FINAL"] and role == "SCU":
                    node_attributes.append(attr)

    logger.debug(f"Attributes: {node_attributes}")

    # Traverse the tree and add rows to the table
    for pre, fill, node in RenderTree(table_tree):
        if node.name == "Root":
            continue
        row = []
        is_include = "Include Table" in node.name
        if is_include:
            pass
        all_empty_except_name = True
        for attr in node_attributes:
            row.append(str(getattr(node, attr, "")))
            if attr != "name" and getattr(node, attr, "") != "":
                all_empty_except_name = False
        if colorize:
            if all_empty_except_name:
                row_style = "bold magenta" if not is_include else "yellow"
            else:
                row_style = level_colors[node.depth] if not is_include else "yellow"
        else:
            row_style = "default"

        table.add_row(*row, style=row_style)
    if any("Comment" in header for header in headers):
        # swap the 4th and 5th columns
        table.columns[3], table.columns[4] = table.columns[4], table.columns[3]
    # Print the table
    console.print(table)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description=(
            "A DICOM UPS Attributes Requirements parser application.\n\n"
            "This application parses UPS Attributes requirements from DICOM Part 4 Section "
            "CC.2.5 and IHE-RO TDW-II Profile Supplement Tables.\n"
            "It reads the PS3.4 DICOM standard chunked HTML file and the IHE-RO PDF file "
            "from the project's `ref` directory or downloads them from NEMA.org and IHE.net "
            "and converts the tables into tree structures.\n\n"
            "The DICOM UPS Attributes requirements tree can be:\n"
            "- Filtered to extract requirements for a specific DICOM primitive and role.\n"
            "- Enriched with IHE-RO TDW-II requirements tree.\n"
            "- Rendered as a flat ASCII table or an ASCII tree.\n"
            "- Exported to a JSON file."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
    )
    # General options
    general_group = parser.add_argument_group("General Options")
    general_group.add_argument("-h", "--help", action="help", help="Show this help message and exit")
    general_group.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (info level)")
    general_group.add_argument("-d", "--debug", action="store_true", help="Enable debug output (debug level)")
    general_group.add_argument("-q", "--quiet", action="store_true", help="Suppress all output (quiet mode)")

    # Parsing options
    parse_group = parser.add_argument_group("Parsing Options")
    parse_group.add_argument(
        "-f", "--file", type=str, default=UPS_PS3_4_CC_2_5_FILE, help="Path to the PS3.4 CC.2.5 XHTML file"
    )
    parse_group.add_argument(
        "-id", "--table-id", type=str, default="table_CC.2.5-3", help="Identifier of the table to extract"
    )
    parse_group.add_argument(
        "-i", "--include-depth", type=int, default=0, help="Recursion depth for including referenced tables"
    )

    # Filtering options
    filter_group = parser.add_argument_group("Filtering Options")
    filter_group.add_argument(
        "-p",
        "--primitive",
        type=str,
        choices=["N-CREATE", "N-SET", "N-GET", "C-FIND", "FINAL"],
        default=None,
        help="Filter requirements per DIMSE primitive",
    )
    filter_group.add_argument(
        "-r",
        "--role",
        type=str,
        choices=["SCU", "SCP"],
        default=None,
        help="Filter primitive requirements per DICOM Role (requires --primitive to be set)",
    )
    filter_group.add_argument(
        "-m",
        "--mandatory",
        action="store_true",
        help="Filter requirements per DICOM Type (requires --role and --primitive to be set)",
    )
    filter_group.add_argument("-x", "--exclude-titles", action="store_true", help="Exclude rows that are only titles")

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument("-ta", "--table", action="store_true", help="Print requirements as a flat ASCII table")
    output_group.add_argument("-tr", "--tree", action="store_true", help="Print attributes as an ASCII tree")
    output_group.add_argument("-c", "--colorize", action="store_true", help="Colorize the ASCII output by level of nesting")
    output_group.add_argument("-j", "--json", action="store_true", help="Export the requirements to a JSON file")

    # Enrichment options
    enrich_group = parser.add_argument_group("Enrichment Options")
    enrich_group.add_argument("--tdw-ii", action="store_true", help="Add IHE-RO TDW-II requirements")
    parse_group.add_argument("--tdw-ii-file", type=str, default=TDW_II_FILE, help="Path to the IHE-RO TDW-II PDF file")

    args = parser.parse_args()

    if args.role is not None and not args.primitive:
        parser.error("--role requires --primitive to be set")
    if args.mandatory and not (args.role and args.primitive):
        parser.error("--mandatory requires --role and --primitive to be set")
    if args.colorize and not (args.table or args.tree):
        parser.error("--colorize requires --table or --tree to be set")

    # Set up logging
    log_level = logging.WARNING  # Default log level is WARNING
    if args.verbose:
        log_level = logging.INFO
    elif args.debug:
        log_level = logging.DEBUG
    elif args.quiet:
        log_level = logging.ERROR

    return args, log_level


def main():
    args, log_level = parse_arguments()
    setup_logging(log_level)

    table_headers, table_tree = extract_table_from_file(args.file, args.table_id, args.include_depth)
    if table_tree is not None:
        print(
            f"Successfully extracted UPS {args.primitive} DIMSE attributes requirements "
            f"from DICOM Part 4 Table {args.table_id[6:]}"
        )

    # Filter columns based on DIMSE primitive and role
    if args.primitive is not None:
        table_headers = [
            header.replace("\n", "")
            for header in table_headers
            if map_header_to_attributes(header) in primitive_columns[args.primitive]
        ]
        attributes_to_remove = list(set(primitive_columns["ALL"]) - set(primitive_columns[args.primitive]))
        if args.primitive == "C-FIND" and args.role is not None:
            if args.role == "SCU":
                table_headers.pop(-2)
            elif args.role == "SCP":
                table_headers.pop(-3)
            attributes_to_remove.append("return" if args.role == "SCU" else "matching")

        remove_nodes_attributes(table_tree, attributes_to_remove)

        primitive_attribute = list(set(primitive_columns[args.primitive]) - set(primitive_columns["COMMON"]))
        if args.primitive == "C-FIND" and args.role is not None:
            if args.role == "SCU":
                primitive_attribute = ["matching"]
            elif args.role == "SCP":
                primitive_attribute = ["return"]

    # Split column by role
    if args.role is not None and not (args.primitive == "C-FIND" or args.primitive == "FINAL"):
        split_nodes_attributes(table_tree, primitive_attribute, args.role)

        # Modify primitive column header to include only the specified role and
        # add a column for the comments removed from the primitive requirement
        for i, header in enumerate(table_headers):
            if "SCU/SCP" in header:
                table_headers[i] = header.replace("SCU/SCP", args.role)
                if not (args.primitive == "C-FIND" or args.primitive == "FINAL"):
                    table_headers.append("Usage " + args.primitive + " Comments")

    # Add IHE-RO TDW-II requirements
    if args.tdw_ii:
        file_path = args.tdw_ii_file
        if not Path(file_path).exists():
            if args.tdw_ii_file == TDW_II_FILE:
                file_path = download_tdw_ii()
            else:
                print(f"{file_path} not found")
                sys.exit(1)

        logger.debug(f"Extracting TDW-II UPS Requirements from: {file_path}")
        with pdfplumber.open(file_path) as pdf:
            if args.primitive == "N-CREATE" and args.role == "SCU":
                tdw_ii_tree = extract_ncreate_scu_tables(pdf, args.primitive)
                logger.debug("Merging TDW-II N-CREATE SCU requirements")
                merge_trees(table_tree, tdw_ii_tree, args.primitive)
            elif args.primitive == "FINAL" and args.role == "SCU":
                tdw_ii_tree = extract_finalupdate_scu_tables(pdf, args.primitive)
                logger.debug("Merging TDW-II N-SET Final Update SCU requirements")
                merge_trees(table_tree, tdw_ii_tree, args.primitive)
            elif args.primitive == "N-SET" and args.role == "SCU":
                tdw_ii_tree = extract_progressupdate_scu_tables(pdf, args.primitive)
                logger.debug("Merging TDW-II N-SET Progress Update SCU requirements")
                merge_trees(table_tree, tdw_ii_tree, args.primitive)
            elif args.primitive == "C-FIND":
                tdw_ii_tree = extract_cfind_tables(pdf, args.primitive)
                logger.debug("Merging TDW-II C-FIND SCU requirements")
                merge_trees(table_tree, tdw_ii_tree, args.primitive)
                if args.role is not None:
                    if args.role == "SCU":
                        scp_attributes = [
                            "tdw_ii_matching_scp",
                            "tdw_ii_return_scp",
                            "tdw_ii_matching_scp_note",
                            "tdw_ii_return_scp_note",
                        ]
                        attributes_to_remove.extend(scp_attributes)
                    elif args.role == "SCP":
                        scu_attributes = [
                            "tdw_ii_matching_scu",
                            "tdw_ii_return_scu",
                            "tdw_ii_matching_scu_note",
                            "tdw_ii_return_scu_note",
                        ]
                        attributes_to_remove.extend(scu_attributes)
                    remove_nodes_attributes(table_tree, attributes_to_remove)
        tdw_ii_attribute = list(set(tdw_ii_primitive_columns[args.primitive]) - set(tdw_ii_primitive_columns["COMMON"]))
        if args.primitive == "C-FIND" and args.role is not None:
            if args.role == "SCU":
                tdw_ii_attribute = ["tdw_ii_matching_scp"]
            elif args.role == "SCP":
                tdw_ii_attribute = ["tdw_ii_return_scp"]

    # Filter out optional rows by Type
    if args.mandatory:
        remove_optional_nodes(table_tree, primitive_attribute, tdw_ii_attribute if args.tdw_ii else None)

    # Filter out rows that are just titles
    if args.exclude_titles:
        remove_titles_nodes(table_tree)

    # Display the table a a flat ASCII table
    if args.table:
        render_tree_as_table(
            table_headers, table_tree, primitive=args.primitive, role=args.role, tdw_ii=args.tdw_ii, colorize=args.colorize
        )

    # Display the table as an ASCII tree
    if args.tree:
        console = Console(highlight=False)
        for pre, fill, node in RenderTree(table_tree):
            style = level_colors[node.depth] if args.colorize else "default"
            # print tree prefix in white and label in color based on depth
            pre_text = Text(pre)
            label_text = Text(f"{node.name} {getattr(node, 'tag', '')}", style=style)
            console.print(pre_text + label_text)  # not using formatting as it resets the style

    # Export the table tree to a JSON file
    if args.json:
        # Create the output file name based on the extract scope
        scope = [
            args.table_id,
            args.primitive or "",
            args.role or "",
            "tdw-ii" if args.tdw_ii else "",
            "mandatory" if args.mandatory else "",
        ]

        file_stem = "_".join(filter(None, scope))
        if args.file:
            file_path = args.file
        else:
            file_path = UPS_PS3_4_CC_2_5_FILE
        input_file_path = Path(file_path)
        output_file_path = input_file_path.with_stem(f"{file_stem}").with_suffix(".json")

        # Write the table tree to pretty-printed JSON file
        exporter = JsonExporter(indent=4, ensure_ascii=False)
        with open(output_file_path, "w", encoding="utf-8") as json_file:
            exporter.write(table_tree, json_file)


if __name__ == "__main__":
    main()
