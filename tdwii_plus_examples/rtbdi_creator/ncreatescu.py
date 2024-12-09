# StoreSCU.py
import logging

from pydicom import Dataset

# from pydicom.errors import InvalidDicomError
# from pydicom.uid import UID
from pynetdicom import AE  # , Association, UnifiedProcedurePresentationContexts
from pynetdicom.presentation import build_context

from tdwii_plus_examples import tdwii_config

from tdwii_plus_examples.security import SecurityProfile

# from typing import Optional, Tuple


# from pynetdicom.sop_class import UnifiedProcedureStepPush, UPSGlobalSubscriptionInstance
# from pynetdicom import ALL_TRANSFER_SYNTAXES, AllStoragePresentationContexts, evt


class NCreateSCU:
    def __init__(
        self,
        sending_ae_title: str,
        receiving_ae_title: str,
        mtls: bool = False,
        cert: str = None,
        key: str = None
    ):
        self.calling_ae_title = sending_ae_title
        self.receiving_ae_title = receiving_ae_title
        tdwii_config.load_ae_config()
        if mtls:
            self.cert = cert
            self.key = key

    def create_ups(self, iods: list[Dataset], receiving_ae_title: str = None) -> bool:
        ae = AE(ae_title=self.calling_ae_title)
        dest_ae_title = self.receiving_ae_title
        if receiving_ae_title is not None:
            dest_ae_title = receiving_ae_title
        mtls = tdwii_config.known_ae_mtls[dest_ae_title]
        if mtls:
            print(f"{dest_ae_title} Worklist Manager is Using MTLS")
            ca_cert = tdwii_config.known_ae_ca_certificate[dest_ae_title]

        # Configure mTLS secure communication
        ssl_cx = None
        if mtls:
            key, cert = self.key, self.cert
            print(f"ca_cert: {ca_cert} key: {key} cert: {cert}")
            try:
                security_profile = SecurityProfile(ca_cert, key, cert, logger=None)
                ssl_cx = security_profile.get_profile(SecurityProfile.SCU_ROLE)
                print("mTLS security profile successfully configured.")

            except Exception as e:
                print(f"Failed to create security profile")
                exit(1)

            tls_args = (ssl_cx, tdwii_config.known_ae_ipaddr[dest_ae_title])
        else:
            tls_args = None

        contexts_in_iods = [build_context(x.SOPClassUID) for x in iods]
        assoc = ae.associate(
            tdwii_config.known_ae_ipaddr[dest_ae_title],
            tdwii_config.known_ae_port[dest_ae_title],
            contexts=contexts_in_iods,
            ae_title=dest_ae_title,
            tls_args=tls_args
        )
        success = False
        if assoc.is_established:
            msg_id = 0
            success = True
            for iod in iods:
                msg_id += 1
                response, _ = assoc.send_n_create(
                    iod, iod.SOPClassUID, iod.SOPInstanceUID, msg_id=msg_id, meta_uid=iod.SOPClassUID
                )

                if response is None or response.Status != 0x0000:
                    success = False
                    error_msg = "No response at all from {dest_ae_title} to N-CREATE-RQ"
                    if response is not None:
                        error_msg = f"Failed with status {response.Status} \
                                when trying to issue n-create for {iod.SOPInstanceUID} \
                                    to {dest_ae_title}"
                    logging.error(error_msg)
                    break
            assoc.release()
        return success
