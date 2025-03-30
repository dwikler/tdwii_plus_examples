import logging
import os
from datetime import datetime

import requests
from anytree import Node, PreOrderIter, RenderTree
from anytree.exporter import JsonExporter
from anytree.importer import JsonImporter
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table, box
from rich.text import Text

LEVEL_COLORS = [
    "rgb(255,255,255)",  # Node depth 0, Root: White
    "rgb(173,216,230)",  # Node depth 1, Table Level 0: Light Blue
    "rgb(135,206,250)",  # Node depth 2, Table Level 1: Sky Blue
    "rgb(0,191,255)",  # Node depth 3, Table Level 2: Deep Sky Blue
    "rgb(30,144,255)",  # Node depth 4, Table Level 3: Dodger Blue
    "rgb(0,0,255)",  # Node depth 5, Table Level 4: Blue
]


class DICOMAttributeModel:
    """Parses DICOM attribute information from an XHTML document.

    This class downloads, reads, and parses an XHTML document containing
    DICOM attribute information, constructing a tree-like representation
    of the attributes.
    """

    def __init__(self, include_depth=0, logger=None):
        """Initializes the DICOMAttributeModel.

        Sets up the logger and initializes the attribute model.

        Args:
            logger: A pre-configured logger instance to use.
                    If None, a default logger will be created.
        """
        self.attribute_model = None
        self.include_depth = include_depth
        self.logger = logger or self._create_default_logger()
        # Maps column indices in the DICOM standard table to corresponding node attribute names
        # for constructing a tree-like representation of the table's data.
        self.column_to_attr = {0: "name", 1: "tag"}
        # Initialize an empty list to store the column headers extracted from the table
        self.header = []

    def download_xhtml(self, url, file_path):
        """Downloads the XHTML document from the specified URL.

        The URL from a Part of the DICOM standard in HTML or a Part section
        in CHTML format containing Attributes tables is expected.

        Retrieves the XHTML content and saves it to the given file path,
        creating any necessary directories.

        Args:
            url: The URL of the XHTML document to download.
            file_path: The local path where the document should be saved.

        Returns:
            The file path where the document was saved.
        """
        self.logger.info(f"Downloading XHTML document from {url} to {file_path}")

        # Create the folder if it doesn't exist
        folder = os.path.dirname(file_path)
        if not os.path.exists(folder):
            os.makedirs(folder)
            self.logger.info(f"Created folder: {folder}")

        # Download the document
        response = requests.get(url)

        # Decode the response content using UTF-8, ignoring any decoding errors
        html_content = response.content.decode("utf-8", errors="ignore")

        # Write the HTML content to a file with UTF-8 encoding
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(html_content)

        self.logger.info(f"Document downloaded to {file_path}")
        return file_path

    def read_xhtml_dom(self, file_path):
        """Reads and parses the XHTML document from the specified file path.

        Opens the file, reads its content, and parses it using BeautifulSoup.

        Args:
            file_path: The path to the XHTML file.

        Returns:
            A BeautifulSoup DOM object representing the parsed XHTML.
        """
        self.logger.info(f"Reading XHTML DOM from {file_path}")
        with open(file_path, "r") as file:
            content = file.read()
        dom = BeautifulSoup(content, "html.parser")
        self.logger.info("XHTML DOM read successfully")
        return dom

    def get_table(self, dom, table_id):
        """Retrieves the table element with the specified ID from the DOM.

        DocBook XML to XHTML conversion stylesheets enclose tables in a
        <div class="table"> with the table identifier in <a id="table_ID"></a>

        Searches for an anchor tag with the given ID and then finds the next
        table element.

        Args:
            dom: The BeautifulSoup DOM object.
            table_id: The ID of the table to retrieve.

        Returns:
            The table element if found, otherwise None.
        """
        anchor = dom.find("a", {"id": table_id})
        if anchor is None:
            self.logger.warning(f"Table Id {table_id} not found.")
            return None
        table = anchor.find_next("table")
        if not table:
            self.logger.warning(f"Table {table_id} not found.")
            return None
        return table

    def parse_table(self, dom, table_id, table_nesting_level=0, include_depth=0):
        """Parses the specified table from the DOM and constructs a tree.

        This method extracts data from each row of the table, handles nested
        tables indicated by "Include" links, and builds a tree-like structure
        of the DICOM attributes which root node is assigned to the attribute
        model.

        Args:
            dom: The BeautifulSoup DOM object.
            table_id: The ID of the table to parse.
            table_nesting_level: The nesting level of the table (used for recursion).
            include_depth: The depth to which included tables should be parsed.

        Returns:
            The root node of the parsed tree.
        """
        self.logger.info(f"Nesting Level: {table_nesting_level}, Parsing table with id {table_id}")
        table = self.get_table(dom, table_id)
        if not table:
            return None

        root = Node("Body")
        level_nodes = {0: root}

        for row in table.find_all("tr")[1:]:
            row_data = self._extract_row_data(row, table_nesting_level)
            row_nesting_level = table_nesting_level + row_data["name"].count(">")

            if table_nesting_level > 0:
                row_data["name"] = ">" * table_nesting_level + row_data["name"]

            if "Include" in row_data["name"] and include_depth > 0:
                self._parse_included_table(dom, row, row_nesting_level, include_depth, level_nodes, root)
            else:
                self._create_node(row_data, row_nesting_level, level_nodes, root)

        if table_nesting_level == 0:
            self._extract_header(table)
            self.attribute_model = root

        self.logger.info(f"Nesting Level: {table_nesting_level}, Table parsed successfully")
        return root

    def print_tree(self, colorize=None):
        """Prints the attribute model tree to the console.

        Traverses the tree structure and prints each node's name,
        tag (if available), along with its hierarchical representation.
        """
        # for pre, fill, node in RenderTree(self.attribute_model):
        #     node_display = f"{node.name}"
        #     if hasattr(node, "tag") and node.tag:
        #         node_display += f" {node.tag}"
        #     print(f"{pre}{node_display}")

        console = Console(highlight=False)
        for pre, fill, node in RenderTree(self.attribute_model):
            style = LEVEL_COLORS[node.depth] if colorize else "default"
            # print tree prefix in white and label in color based on depth
            pre_text = Text(pre)
            node_text = Text(f"{node.name} {getattr(node, 'tag', '')}", style=style)
            console.print(pre_text + node_text)  # avoid f-string as it resets the style

    def print_table(self, colorize=False):
        """Prints the attribute model tree as a flat table using rich."""
        console = Console()
        row_style = None
        table = Table(show_header=True, header_style="bold magenta", show_lines=True, box=box.ASCII_DOUBLE_HEAD)

        # Define the columns using the extracted headers
        for header in self.header:
            table.add_column(header, style="dim", width=20)

        # Traverse the tree and add rows to the table
        for node in PreOrderIter(self.attribute_model):
            # skip the root node
            if node.name == "Body":
                continue
            # identify Include nodes
            is_include = "Include Table" in node.name
            is_module_title = node.name.endswith("Module") and not node.name.startswith("All")
            row = [getattr(node, attr, "") for attr in self.column_to_attr.values()]
            if colorize:
                row_style = "yellow" if is_include else "magenta" if is_module_title else LEVEL_COLORS[node.depth - 1]
            table.add_row(*row, style=row_style)

        console.print(table)

    def save_as_json(self, file_path):
        """Saves the attribute model as a JSON file.

        Args:
            file_path: The path to the JSON file where the model should be saved.
        """
        exporter = JsonExporter(indent=4, sort_keys=False)

        # Create a new top node "Table"
        table_node = Node("Table")

        # Add info as a child of the table node
        Node("Info", parent=table_node, date=datetime.now().isoformat(), include_depth=self.include_depth)

        # Add headers as a child of the table node
        Node("Header", parent=table_node, cells=self.header)

        # Add the attribute model as a child of the table node
        self.attribute_model.parent = table_node

        with open(file_path, "w", encoding="utf-8") as json_file:
            exporter.write(table_node, json_file)

        # Remove the attribute model from the table node after exporting
        self.attribute_model.parent = None

        self.logger.info(f"Attribute model saved as JSON to {file_path}")

    def load_from_json(self, file_path):
        """Loads the attribute model from a JSON file.

        Args:
            file_path: The path to the JSON file from which to load the model.
        """
        importer = JsonImporter()
        with open(file_path, "r", encoding="utf-8") as json_file:
            table_node = importer.read(json_file)

            info_node = next((node for node in PreOrderIter(table_node) if node.name == "Info"), None)

            if info_node:
                json_include_depth = info_node.include_depth
                self.logger.info(f"JSON File depth: {json_include_depth}, Requested depth: {self.include_depth}")
                depth_mismatch = json_include_depth != self.include_depth
                if depth_mismatch:
                    self.logger.debug(
                        f"JSON File depth ({json_include_depth}) does not match requested depth ({self.include_depth})"
                    )
                    return False

            header_node = next((node for node in PreOrderIter(table_node) if node.name == "Header"), None)
            if header_node:
                self.header = header_node.cells

            self.attribute_model = next((node for node in PreOrderIter(table_node) if node.name == "Body"), None)

        self.logger.info(f"Attribute model loaded from JSON file {file_path}")
        return True

    def _create_default_logger(self):
        """Creates a default logger for the class.

        Configures a logger with a console handler and a specific format.
        """
        logger = logging.getLogger("DICOMAttributeModel")
        logger.setLevel(logging.DEBUG)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        return logger

    def _extract_header(self, table):
        """Extracts headers from the table and saves them in the headers attribute.

        Only extracts headers of the columns corresponding to the keys in column_to_attr.

        Args:
            table: The table element from which to extract headers.
        """
        cells = table.find_all("th")
        self.header = [header.get_text(strip=True) for i, header in enumerate(cells) if i in self.column_to_attr]
        self.logger.info(f"Extracted Header: {self.header}")

    def _extract_row_data(self, row, table_nesting_level):
        """Extracts data from a table row.

        Processes each cell in the row, handling colspans and extracting text
        content from paragraphs within the cells. Constructs a dictionary
        containing the extracted data.

        Args:
            row: The table row element (BeautifulSoup Tag).
            table_nesting_level: The nesting level of the table.

        Returns:
            A dictionary containing the extracted data from the row.
        """
        cells = []
        colspans = []

        for cell in row.find_all("td"):
            paragraphs = cell.find_all("p")
            cell_text = "\n".join(p.text.strip() for p in paragraphs) if paragraphs else ""
            cells.append(cell_text)
            colspans.append(int(cell.get("colspan", 1)))

        row_data = {}
        attr_index = 0
        for cell, colspan in zip(cells, colspans):
            if attr_index in self.column_to_attr:
                row_data[self.column_to_attr[attr_index]] = cell
            attr_index += colspan

        return row_data

    def _parse_included_table(self, dom, row, table_nesting_level, include_depth, level_nodes, root):
        include_anchor = row.find("a", {"class": "xref"})
        if not include_anchor:
            self.logger.warning(f"Nesting Level: {table_nesting_level}, Include Table Id not found")
            return

        include_table_id = include_anchor["href"].split("#", 1)[-1]
        self.logger.debug(f"Nesting Level: {table_nesting_level}, Include Table Id: {include_table_id}")

        included_table_tree = self.parse_table(
            dom, include_table_id, table_nesting_level=table_nesting_level, include_depth=include_depth - 1
        )
        if not included_table_tree:
            return

        self._nest_included_table(included_table_tree, level_nodes, table_nesting_level, root)

    def _nest_included_table(self, included_table_tree, level_nodes, row_nesting_level, root):
        parent_node = level_nodes.get(row_nesting_level - 1, root)
        for child in included_table_tree.children:
            child.parent = parent_node

    def _create_node(self, row_data, row_nesting_level, level_nodes, root):
        node_name = row_data.pop("name")
        parent_node = level_nodes.get(row_nesting_level - 1, root)
        self.logger.debug(
            f"Nesting Level: {row_nesting_level}, Name: {node_name}, Parent: {parent_node.name if parent_node else 'None'}"
        )
        node = Node(node_name, parent=parent_node, **row_data)
        level_nodes[row_nesting_level] = node
