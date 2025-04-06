import os

from anytree import PreOrderIter

from tdwii_plus_examples.standard.dicom_attribute_model import DICOMAttributeModel

current_file_directory = os.path.abspath(os.path.dirname(__file__))
reference_directory = os.path.abspath(os.path.join(current_file_directory, "../../ref"))


class UPSAttributeModel(DICOMAttributeModel):
    """Builds an information model from DICOM UPS SOP Classes Attributes tables.

    This class provides services to download, parse, filter, and represent
    XHTML format DICOM UPS SOP Classes attribute tables in a hierarchical structure.
    It supports saving and loading the model as JSON for persistence.
    """

    URL = "https://dicom.nema.org/medical/dicom/current/output/chtml/part04/sect_CC.2.5.html"
    XHTML_FILENAME = "PS3_4_CC.2.5.html"
    TABLE_ID = "table_CC.2.5-3"
    MODEL_FILENAME = "PS3_4_UPS.json"

    DIMSE_MAPPING = {
        "ALL_DIMSE": {2: "ncreate", 3: "nset", 4: "final", 5: "nget", 6: "matching", 7: "return", 8: "remark"},
        "N-CREATE": {2: "ncreate", 8: "remark"},
        "N-SET": {3: "nset", 8: "remark"},
        "N-GET": {5: "nget", 8: "remark"},
        "C-FIND": {6: "matching", 7: "return", 8: "remark"},
        "FINAL": {4: "final", 8: "remark"},
    }

    def __init__(self, include_depth=0, logger=None):
        super().__init__(
            url=self.URL,
            xhtml_filename=self.XHTML_FILENAME,
            table_id=self.TABLE_ID,
            model_filename=self.MODEL_FILENAME,
            column_to_attr=self.DIMSE_MAPPING["ALL_DIMSE"],
            include_depth=include_depth,
            logger=logger,
        )
        self.dimse = None

    def select_dimse(self, dimse):
        """Selects the attribute model for the specified DIMSE SOP Class.

        Args:
            dimse: The key of DIMSE_MAPPING to select.
        """

        if dimse not in self.DIMSE_MAPPING:
            self.logger.warning(f"DIMSE '{dimse}' not found in DIMSE_MAPPING")
            return
        else:
            self.dimse = dimse
        dimse_attributes = set(self.DIMSE_MAPPING[dimse].values())
        all_attributes = set(self.DIMSE_MAPPING["ALL_DIMSE"].values())

        # Remove node attributes that are not belonging to the DIMSE
        body_node = next((node for node in PreOrderIter(self.attribute_model) if node.name == "Body"), None)
        if body_node:
            for node in PreOrderIter(body_node):
                for attr in list(node.__dict__.keys()):
                    if attr in all_attributes and attr not in dimse_attributes:
                        delattr(node, attr)

        # Determine the columns indices corresponding to the selected DIMSE
        dimse_indices = {key for key, value in self.DIMSE_MAPPING[dimse].items()}

        # Remove header items that are not belonging to the DIMSE
        self.header = [
            cell for i, cell in enumerate(self.header) if i in dimse_indices or i not in self.DIMSE_MAPPING["ALL_DIMSE"]
        ]

        # Update the column_to_attr to only include attributes belonging to the selected DIMSE
        self.column_to_attr = {
            key: value
            for key, value in self.column_to_attr.items()
            if value in dimse_attributes or key not in self.DIMSE_MAPPING["ALL_DIMSE"]
        }

    def select_role(self, role):
        """Selects the attribute model for the specified Role of the selected DIMSE Service User"""
        if role is None:
            return
        if self.dimse in ("C-FIND", "FINAL", None):
            self.logger.info(f"No role-specific requirements for {self.dimse}")
            return

        body_node = next((node for node in PreOrderIter(self.attribute_model) if node.name == "Body"), None)
        if not body_node:
            return

        dimse_attr_key = next(iter(self.DIMSE_MAPPING[self.dimse]))
        attribute_name = self.DIMSE_MAPPING[self.dimse][dimse_attr_key]

        for node in PreOrderIter(body_node):
            if hasattr(node, attribute_name):
                value = getattr(node, attribute_name)
                if not isinstance(value, str):
                    continue
                # Split SCU/SCP optionality requirements and any additional comment
                parts = value.split("\n", 1)
                optionality = parts[0]
                if len(parts) > 1:
                    setattr(node, attribute_name, optionality)
                    setattr(node, "comment", parts[1])
                    self.column_to_attr[9] = "comment"
                    if "Comment" not in self.header:
                        self.header.append("Comment")
                # Split SCU/SCP optionality requirements
                sub_parts = optionality.split("/", 1)
                if len(sub_parts) > 1:
                    setattr(node, attribute_name, sub_parts[0] if role == "SCU" else sub_parts[1])

        for i, header in enumerate(self.header):
            if "SCU/SCP" in header:
                self.header[i] = header.replace("SCU/SCP", role)

    def _patch_table(self, dom, table_id):
        """Patches the XHTML table to fix an error in the standard where the 'Include' row
        under the '>Output Information Sequence' row is missing a '>' netsing symbol.

        Args:
            dom: The BeautifulSoup DOM object representing the XHTML document.
            table_id: The ID of the table to patch.
        """
        target_element_id = self._search_element_id(dom, table_id)
        if not target_element_id:
            self.logger.warning("Output Information Sequence Include Row element ID not found")
            return

        element = dom.find(id=target_element_id).find_parent()
        span_element = element.find("span", class_="italic")
        if span_element:
            for child in span_element.children:
                if isinstance(child, str) and ">Include" in child:
                    new_text = child.replace(">Include", ">>Include")
                    child.replace_with(new_text)

    def _search_element_id(self, dom, table_id):
        table = self.get_table(dom, table_id)
        if not table:
            return None

        self.logger.debug(f"Table with id {table_id} found")
        tr_elements = table.find_all("tr")
        include_id = self._search_sequence_include_id(tr_elements)

        if include_id is None:
            self.logger.debug("No <tr> matching criteria found")

        return include_id

    def _search_sequence_include_id(self, tr_elements):
        target_found = False
        for tr in tr_elements:
            first_td = tr.find("td")
            if first_td and first_td.get_text(strip=True) == ">Output Information Sequence":
                self.logger.debug("Output Information Sequence <tr> found")
                target_found = True
                break

        if target_found:
            tr = tr.find_next("tr")
            first_td = tr.find("td")
            if first_td and first_td.get_text(strip=True).startswith(">Include"):
                self.logger.debug("Include <tr> found")
                return first_td.find("a")["id"]

        return None
