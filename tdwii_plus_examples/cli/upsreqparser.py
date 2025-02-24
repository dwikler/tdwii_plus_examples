import argparse
import logging
import os
import re
import sys
from pathlib import Path

import requests
from anytree import Node, PreOrderIter, RenderTree
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


def extract_table(dom, table_id, table_nesting_level=0, include_depth=0):
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
    node_attributes = ["name", "tag", "ncreate", "nset", "finalstate", "nget", "matching", "return", "remark"]

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
                table_headers, included_table_tree = extract_table(
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


def remove_optional_nodes(root, primitive_attribute):
    # Define the types to keep and remove
    types_to_keep = ["1", "1C", "2", "2C", "U", "R", "RC", "P", "X"]
    types_to_remove = ["3", "-", "O"]
    # Iterate on a static list of nodes to safely modify the tree structure
    for node in list(PreOrderIter(root)):
        type = None
        # Remove nodes based on primitive_attribute
        if hasattr(node, primitive_attribute[0]):
            type = getattr(node, primitive_attribute[0])
            if type in types_to_remove and type not in types_to_keep:
                logger.debug(f"[{type.rjust(3)}] : Removing {node.name} element")
                node.parent = None
                continue

        if type is not None:
            logger.debug(f"[{type.rjust(3)}] : Keeping {node.name} element")
        else:
            logger.debug(f"[{''.rjust(3)}] : Keeping {node.name} element")

        # Remove nodes under "Sequence" nodes with specific primitive_attributes
        if "Sequence" in node.name and hasattr(node, primitive_attribute[0]):
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


def render_tree_as_table(headers, table_tree, primitive=None, role=None, colorize=False):
    console = Console()
    table = Table(show_header=True, header_style="bold magenta", show_lines=True, box=box.ASCII_DOUBLE_HEAD)
    # Add columns to the table
    for header in headers:
        table.add_column(header, overflow="fold", max_width=30)

    # Define the node attributes names
    node_attributes = primitive_columns["ALL"] if primitive is None else primitive_columns[primitive]
    if role is not None:
        node_attributes.append("comment")

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
        # swap the 2 latest columns
        table.columns[-2], table.columns[-1] = table.columns[-1], table.columns[-2]
    # Print the table
    console.print(table)


def main():
    parser = argparse.ArgumentParser(
        description="Parse UPS Attributes Requirements from DICOM Part 4 Section CC.2.5 Tables.\n"
        "This script downloads the chunked HTML file from NEMA.org, \n"
        "converts it to a tree data structure, which is filtered, rendered, and \n"
        "exported to a JSON file according to the specified options.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (info level)")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output (debug level)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress all output (quiet mode)")
    parser.add_argument("-j", "--json", action="store_true", help="Export the requirements to a JSON file")
    parser.add_argument("-ta", "--table", action="store_true", help="Print requirements as a flat ASCII table")
    parser.add_argument("-tr", "--tree", action="store_true", help="Print attributes as an ASCII tree")
    parser.add_argument("-c", "--colorize", action="store_true", help="Colorize the ASCII output by level of nesting")
    parser.add_argument("-i", "--include-depth", type=int, default=0, help="Recursion depth for including referenced tables")
    parser.add_argument(
        "-p",
        "--primitive",
        type=str,
        choices=["N-CREATE", "N-SET", "N-GET", "C-FIND", "FINAL"],
        default=None,
        help='filter requirements per DIMSE primitive"',
    )
    parser.add_argument(
        "-r",
        "--role",
        type=str,
        choices=["SCU", "SCP"],
        default=None,
        help="filter primitive requirements per DICOM Role (requires --primitive to be set)",
    )
    parser.add_argument(
        "-m",
        "--mandatory",
        action="store_true",
        help="filter requirements per DICOM Type (requires --role and --primitive to be set)",
    )
    parser.add_argument("-x", "--exclude-titles", action="store_true", help="Exclude rows that are only titles")
    parser.add_argument("-f", "--file", type=str, default=UPS_PS3_4_CC_2_5_FILE, help="Path to the PS3.4 CC.2.5 XHTML file")
    parser.add_argument("-id", "--table-id", type=str, default="table_CC.2.5-3", help="Identifier of the table to extract")

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

    setup_logging(log_level)

    file_path = args.file
    logger.debug(f"Extracting Table {args.table_id} from: {file_path}")
    if not Path(file_path).exists():
        if args.file == UPS_PS3_4_CC_2_5_FILE:
            file_path = download_ups_cc_2_5()
        else:
            print(f"{file_path} not found")
            sys.exit(1)

    with open(file_path, "r", encoding="utf-8") as file:
        content = file.read()

    dom = BeautifulSoup(content, "lxml-xml")  # Use the lxml XML parser

    table_headers, table_tree = extract_table(dom, args.table_id, include_depth=args.include_depth)

    if table_tree is not None:
        print(f"Successfully extracted UPS {args.primitive} DIMSE attributes requirements " f"from Table {args.table_id[6:]}")

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

        primitive_attribute = list(
            set(primitive_columns[args.primitive]) - set(primitive_columns["COMMON"])
        )  # note that order is lost

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

    # Filter out optional rows by Type
    if args.mandatory:
        remove_optional_nodes(table_tree, primitive_attribute)

    # Filter out rows that are just titles
    if args.exclude_titles:
        remove_titles_nodes(table_tree)

    # Display the table a a flat ASCII table
    if args.table:
        render_tree_as_table(table_headers, table_tree, primitive=args.primitive, role=args.role, colorize=args.colorize)

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
        scope = [args.table_id, args.primitive or "", args.role or "", "mandatory" if args.mandatory else ""]

        file_stem = "_".join(filter(None, scope))

        input_file_path = Path(file_path)
        output_file_path = input_file_path.with_stem(f"{file_stem}").with_suffix(".json")

        # Write the table tree to pretty-printed JSON file
        exporter = JsonExporter(indent=4, ensure_ascii=False)
        with open(output_file_path, "w", encoding="utf-8") as json_file:
            exporter.write(table_tree, json_file)


if __name__ == "__main__":
    main()
