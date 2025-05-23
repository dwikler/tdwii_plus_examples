import logging
import unittest
from unittest import mock

from pydicom import Dataset
from pydicom.uid import ExplicitVRLittleEndian, generate_uid
from pynetdicom.presentation import build_context
from pynetdicom.sop_class import (
    CTImageStorage,
    MRImageStorage,
    SecondaryCaptureImageStorage,
    StudyRootQueryRetrieveInformationModelFind,
)

from tdwii_plus_examples.cstorescu import CStoreSCU

LOGGER = logging.getLogger(__name__)


class TestCStoreSCU(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Setup before all tests."""
        # Create CStoreSCU instance
        cls.cstore_scu = CStoreSCU(
            calling_ae_title="CALLING_AE_TITLE",
            called_ae_title="CALLED_AE_TITLE",
            called_ip="127.0.0.1",
            called_port=11112,
            logger=LOGGER,
        )

    @mock.patch("tdwii_plus_examples.cstorescu.CStoreSCU._handle_response")
    @mock.patch("tdwii_plus_examples.cstorescu.CStoreSCU._associate")
    def test_store_instances(self, mock_associate, mock_handle_response):
        """Test storing multiple DICOM instances."""
        # Create 2 empty instances
        ds_1 = Dataset()
        ds_1.SOPClassUID = CTImageStorage
        ds_2 = Dataset()
        ds_2.SOPClassUID = CTImageStorage
        instances = [ds_1, ds_2]

        # Mock the association instance
        mock_assoc_instance = mock.Mock()
        # Mock the release method
        mock_assoc_instance.release = mock.Mock()
        # Mock the send_c_store method to return a success status
        mock_assoc_instance.send_c_store.return_value = Dataset()
        # Mock _associate to return the mock association instance
        mock_associate.return_value = True, mock_assoc_instance
        # Assign the mock association instance to the SCU's assoc attribute
        self.cstore_scu.assoc = mock_assoc_instance
        # Mock the _handle_response method to return a success status
        mock_handle_response.return_value = mock.Mock(status_category="Success")

        # Call the method
        success_count = self.cstore_scu.store_instances(instances)

        # Assert 2 C-STORE messages were sent and succeeded
        self.assertEqual(success_count, 2)
        mock_assoc_instance.send_c_store.assert_called()
        self.assertEqual(mock_assoc_instance.send_c_store.call_count, 2)

    @mock.patch("tdwii_plus_examples.cstorescu.CStoreSCU._handle_response")
    @mock.patch("tdwii_plus_examples.cstorescu.CStoreSCU._associate")
    def test_store_instances_partial(self, mock_associate, mock_handle_response):
        """Test storing multiple DICOM instances with partial success."""
        # Create 2 minimal DICOM instances
        ds_1 = Dataset()
        ds_1.SOPClassUID = CTImageStorage
        ds_1.SOPInstanceUID = generate_uid()
        ds_2 = Dataset()
        ds_2.SOPClassUID = CTImageStorage
        ds_2.SOPInstanceUID = generate_uid()
        instances = [ds_1, ds_2]

        # Mock the association instance
        mock_assoc_instance = mock.Mock()
        # Mock the release method
        mock_assoc_instance.release = mock.Mock()
        # Mock the send_c_store method to return a success status
        mock_assoc_instance.send_c_store.return_value = Dataset()
        # Mock _associate to return the mock association instance
        mock_associate.return_value = True, mock_assoc_instance
        # Assign the mock association instance to the SCU's assoc attribute
        self.cstore_scu.assoc = mock_assoc_instance
        # Set up side_effect for mock_handle_response to return different statuses
        return_values = [
            mock.Mock(status_category="Success"),
            mock.Mock(status_category="Failure"),  # Different status for the second call
        ]
        mock_handle_response.side_effect = return_values

        # Call the method
        success_count = self.cstore_scu.store_instances(instances)

        # Assert 2 C-STORE message were sent and 1 succeeded
        self.assertEqual(success_count, 1)
        mock_assoc_instance.send_c_store.assert_called()
        self.assertEqual(mock_assoc_instance.send_c_store.call_count, 2)

    @mock.patch("tdwii_plus_examples.cstorescu.CStoreSCU._associate")
    def test_store_instances_association_failure(self, mock_associate):
        """Test storing instances with association failure."""
        # Create 1 'valid' DICOM instance
        ds = Dataset()
        ds.SOPClassUID = CTImageStorage
        ds.SOPInstanceUID = generate_uid()
        instances = [ds]

        # Mock the association directly on the CStoreSCU instance
        self.cstore_scu.assoc = mock.Mock()
        # Mock the release method
        self.cstore_scu.assoc.release = mock.Mock()

        # Mock the association result to simulate an association failure
        mock_assoc_result = mock.Mock()
        mock_assoc_result = False
        mock_associate.return_value = False, mock_assoc_result

        # Call the method
        success_count = self.cstore_scu.store_instances(instances)

        # Assert storage failed
        self.assertEqual(success_count, 0)

    @mock.patch("tdwii_plus_examples.cstorescu.CStoreSCU._associate")
    def test_store_instances_required_sop_classes(self, mock_associate):
        """Test that required SOP classes are correctly extracted from instances."""
        # Create instances with different SOP Class UIDs
        ds1 = Dataset()
        ds1.SOPClassUID = CTImageStorage
        ds2 = Dataset()
        ds2.SOPClassUID = MRImageStorage
        instances = [ds1, ds2]

        # Mock the association result
        mock_assoc_result = mock.Mock()
        mock_assoc_result.status = True  # Assume successful association for this test
        mock_assoc_result.accepted_sop_classes = [ds1.SOPClassUID, ds2.SOPClassUID]  # Mock accepted SOP classes
        mock_associate.return_value = (True, mock_assoc_result)

        # Mock the association and release method
        self.cstore_scu.assoc = mock.Mock()
        self.cstore_scu.assoc.release = mock.Mock()

        # Mock the association, release, and send_c_store methods
        self.cstore_scu.assoc = mock.Mock()
        self.cstore_scu.assoc.release = mock.Mock()
        status_dataset = Dataset()
        status_dataset.Status = 0x0000  # Success status
        self.cstore_scu.assoc.send_c_store.return_value = status_dataset

        # Call the method
        self.cstore_scu.store_instances(instances)

        # Assert that _associate was called with the correct required_sop_classes
        expected_required_sop_classes = [ds1.SOPClassUID, ds2.SOPClassUID]
        mock_associate.assert_called_once_with(required_sop_classes=expected_required_sop_classes)

    def test_set_contexts_valid(self):
        """Test set_contexts."""
        # Valid contexts
        storage_contexts = [
            build_context(MRImageStorage),
            build_context(MRImageStorage),
        ]
        self.cstore_scu.set_contexts(storage_contexts)
        self.assertEqual(len(self.cstore_scu.contexts), 2)
        self.assertIn(storage_contexts[0], self.cstore_scu.contexts)
        self.assertIn(storage_contexts[1], self.cstore_scu.contexts)
        self.assertEqual(len(self.cstore_scu.ae.requested_contexts), 3)  # Includes Verification

    def test_set_contexts_invalid(self):
        """Test set_contexts with an invalid context."""
        qr_abstract_syntax = StudyRootQueryRetrieveInformationModelFind  # not a storage context
        invalid_context = build_context(qr_abstract_syntax)

        with self.assertRaisesRegex(
            ValueError, f"Only Storage Presentation Contexts are allowed. Invalid contexts: \\['{qr_abstract_syntax}'\\]"
        ):
            self.cstore_scu.set_contexts([invalid_context])

    def test_set_contexts_from_files(self):
        """Test set_contexts_from_files."""
        # Create some dummy datasets
        ds1 = Dataset()
        ds1.SOPClassUID = CTImageStorage
        ds2 = Dataset()
        ds2.SOPClassUID = MRImageStorage
        instances = [ds1, ds2]

        self.cstore_scu.set_contexts_from_files(instances)

        self.assertEqual(len(self.cstore_scu.contexts), 2)
        self.assertIn(build_context(ds1.SOPClassUID, ExplicitVRLittleEndian), self.cstore_scu.contexts)
        self.assertIn(build_context(ds2.SOPClassUID, ExplicitVRLittleEndian), self.cstore_scu.contexts)
        # Check if requested contexts were updated (including verification)
        self.assertEqual(len(self.cstore_scu.ae.requested_contexts), 3)

    def test_validate_contexts_empty(self):
        """Test _validate_contexts with an empty list."""
        self.assertEqual(self.cstore_scu._validate_contexts([]), [])

    def test_validate_contexts_valid(self):
        """Test _validate_contexts with valid contexts."""
        storage_contexts = [build_context(uid) for uid in [CTImageStorage, SecondaryCaptureImageStorage]]
        self.assertEqual(self.cstore_scu._validate_contexts(storage_contexts), storage_contexts)

    def test_validate_contexts_invalid(self):
        """Test _validate_contexts with invalid contexts."""
        qr_abstract__syntax = StudyRootQueryRetrieveInformationModelFind  # not a storage context
        contexts = [build_context(qr_abstract__syntax)]
        with self.assertRaisesRegex(
            ValueError, f"Only Storage Presentation Contexts are allowed. Invalid contexts: \\['{qr_abstract__syntax}'\\]"
        ):
            self.cstore_scu._validate_contexts(contexts)
