import os

from anytree import PreOrderIter

from tdwii_plus_examples.standard.dicom_attribute_model import DICOMAttributeModel

current_file_directory = os.path.abspath(os.path.dirname(__file__))
reference_directory = os.path.abspath(os.path.join(current_file_directory, "../../ref"))


class UPSAttributeModel(DICOMAttributeModel):
    URL = "https://dicom.nema.org/medical/dicom/current/output/chtml/part04/sect_CC.2.5.html"
    XHTML_FILENAME = "PS3_4_CC.2.5.html"
    TABLE_ID = "table_CC.2.5-3"
    MODEL_FILENAME = "PS3_4_UPS.json"

    PRIMITIVE_MAPPING = {
        "ALL_PRIMITIVES": {2: "ncreate", 3: "nset", 4: "final", 5: "nget", 6: "matching", 7: "return", 8: "remark"},
        "N-CREATE": {2: "ncreate", 8: "remark"},
        "N-SET": {3: "nset", 8: "remark"},
        "N-GET": {5: "nget", 8: "remark"},
        "C-FIND": {6: "matching", 7: "return", 8: "remark"},
        "FINAL": {4: "final", 8: "remark"},
    }

    def __init__(self, include_depth=0, logger=None):
        super().__init__(logger)
        self.attributes_mapping.update(self.PRIMITIVE_MAPPING["ALL_PRIMITIVES"])

        model_filepath = os.path.join(reference_directory, self.MODEL_FILENAME)
        xhtml_filepath = os.path.join(reference_directory, self.XHTML_FILENAME)

        # TODO: fix discrepancy between include_depth of json file and arg
        if not os.path.exists(model_filepath):
            if not os.path.exists(xhtml_filepath):
                file_path = self.download_xhtml(self.URL, xhtml_filepath)
            else:
                file_path = xhtml_filepath
            dom = self.read_xhtml_dom(file_path)
            self._patch_outputinfoseq_include(dom, self.TABLE_ID)
            self.parse_table(dom, self.TABLE_ID, include_depth=include_depth)
            self.save_as_json(model_filepath)
        else:
            self.load_from_json(model_filepath)

    def filter_attributes_by_primitive(self, primitive):
        """Filters the attribute model by the specified primitive.

        Args:
            primitive: The key of PRIMITIVE_MAPPING to filter by.
        """
        if primitive not in self.PRIMITIVE_MAPPING:
            self.logger.warning(f"Primitive '{primitive}' not found in PRIMITIVE_MAPPING")
            return

        allowed_attributes = set(self.PRIMITIVE_MAPPING[primitive].values())
        all_attributes = set(self.PRIMITIVE_MAPPING["ALL_PRIMITIVES"].values())

        # Find the Body node
        body_node = next((node for node in PreOrderIter(self.attribute_model) if node.name == "Body"), None)
        if body_node:
            # Traverse the Body node and remove attributes that are not allowed
            for node in PreOrderIter(body_node):
                for attr in list(node.__dict__.keys()):
                    if attr in all_attributes and attr not in allowed_attributes:
                        delattr(node, attr)

        # Process headers and attributes_mapping together
        allowed_indices = {key for key, value in self.PRIMITIVE_MAPPING[primitive].items()}
        self.header = [
            cell
            for i, cell in enumerate(self.header)
            if i in allowed_indices or i not in self.PRIMITIVE_MAPPING["ALL_PRIMITIVES"]
        ]
        self.attributes_mapping = {
            key: value
            for key, value in self.attributes_mapping.items()
            if value in allowed_attributes or key not in self.PRIMITIVE_MAPPING["ALL_PRIMITIVES"]
        }

    def _patch_outputinfoseq_include(self, dom, table_id):
        outputinfoseq_include_id = self._find_outputinfoseq_include(dom, table_id)
        if not outputinfoseq_include_id:
            self.logger.warning("Include ID not found")
            return

        element = dom.find(id=outputinfoseq_include_id).find_parent()
        span_element = element.find("span", class_="italic")
        if span_element:
            for child in span_element.children:
                if isinstance(child, str) and ">Include" in child:
                    new_text = child.replace(">Include", ">>Include")
                    child.replace_with(new_text)

    def _find_outputinfoseq_include(self, dom, table_id):
        table = self.get_table(dom, table_id)
        if not table:
            return None

        self.logger.debug(f"Table with id {table_id} found")
        tr_elements = table.find_all("tr")
        include_id = self._find_outputinfoseq_include_id(tr_elements)

        if include_id is None:
            self.logger.debug("No matching <tr> found")

        return include_id

    def _find_outputinfoseq_include_id(self, tr_elements):
        target_found = False
        for tr in tr_elements:
            first_td = tr.find("td")
            if first_td and first_td.get_text(strip=True) == ">Output Information Sequence":
                self.logger.debug("Target <tr> found")
                target_found = True
                break

        if target_found:
            tr = tr.find_next("tr")
            first_td = tr.find("td")
            if first_td and first_td.get_text(strip=True).startswith(">Include"):
                self.logger.debug("Next <tr> with required starting value found")
                return first_td.find("a")["id"]

        return None
