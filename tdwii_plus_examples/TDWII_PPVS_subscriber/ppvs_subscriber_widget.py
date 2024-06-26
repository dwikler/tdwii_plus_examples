# This Python file uses the following encoding: utf-8
import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication, QWidget, QFileDialog
from PySide6.QtCore import Qt, Slot, QDateTime # pylint: disable=no-name-in-module


from ppvsscp import PPVS_SCP
from watchscu import WatchSCU

# Important:
# You need to run the following command to generate the ui_form.py file
#     pyside6-uic form.ui -o ui_form.py, or
#     pyside2-uic form.ui -o ui_form.py
from ui_tdwii_ppvs_subscriber import Ui_MainPPVSSubscriberWidget

class PPVS_SubscriberWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ui = Ui_MainPPVSSubscriberWidget()
        self.ui.setupUi(self)
        self.ui.import_staging_directory_push_button.clicked.connect(self._import_staging_dir_clicked)
        self.ui.ppvs_restart_push_button.clicked.connect(self._restart_scp)
        self.ppvs_scp = None
        self.ui.soonest_date_time_edit.setDateTime(QDateTime.currentDateTime().addSecs(-3600))
        self.ui.latest_date_time_edit.setDateTime(QDateTime.currentDateTime().addSecs(3600))
        self.ui.step_status_combo_box.addItems(["SCHEDULED", "IN PROGRESS", "CANCELED", "COMPLETED", "ANY"])
        self.ui.subscribe_ups_checkbox.toggled.connect(self._toggle_subscription)
        self.watch_scu = None

    @Slot()
    def _import_staging_dir_clicked(self):
        dialog = QFileDialog(self,"Import Staging Dir")
        dialog.setAcceptMode(QFileDialog.AcceptMode.AcceptOpen)
        dialog.setFileMode(QFileDialog.Directory)
        dialog.setOption(QFileDialog.ShowDirsOnly, True)
        dialog.setLabelText(QFileDialog.Accept, "Select")
        if dialog.exec_() == QFileDialog.Accepted:
            file_name = dialog.selectedFiles()[0]
        if file_name:
            path = Path(file_name)
        self.ui.import_staging_dir_line_edit.insert(str(path))

    @Slot()
    def _toggle_subscription(self):
        if self.ui.subscribe_ups_checkbox.checkState() == Qt.Checked:
            self._subscribe_to_ups()
        else:
            self._unsubscribe_from_ups()


    @Slot()
    def _restart_scp(self):
        ppvs_scp_ae_title = self.ui.ppvs_ae_line_edit.text()
        staging_dir = self.ui.import_staging_dir_line_edit.text()
        print(f"PPVS AE Title: {ppvs_scp_ae_title} using {staging_dir} for caching data")
        # PPVS_SCP combines the NEVENT SCP and C-STORE SCP
        self.ppvs_scp = PPVS_SCP(nevent_callback= self._nevent_callback,
                                     ae_title = ppvs_scp_ae_title,
                                     )
        self.ppvs_scp.run()
        self.watch_scu = WatchSCU(self.ui.ppvs_ae_line_edit.text())
        ip_addr = "127.0.0.1"
        port = 11114
        self.watch_scu.set_subscription_ae(self.ui.ups_ae_line_edit.text(), ip_addr=ip_addr,port=port)


    @Slot()
    def _get_ups(self):
        # do C-FIND-RQ
        
        pass

    def _subscribe_to_ups(self, match_on_step_state=False, match_on_beam_number=False)->bool:
        if self.watch_scu is None:
            my_ae_title = self.ui.ppvs_ae_line_edit.text()
            watch_scu = WatchSCU(my_ae_title)
        # hard code for the moment, deal with configuration of AE's soon
            ip_addr = "127.0.0.1"
            port = 11114
            upsscp_ae_title = self.ui.ups_ae_line_edit.text()
            watch_scu.set_subscription_ae(upsscp_ae_title, ip_addr=ip_addr,port=port)
        else:
            watch_scu = self.watch_scu
        
        matching_keys = None
        if (match_on_beam_number or match_on_step_state):
            matching_keys = watch_scu.create_data_set(match_on_beam_number=match_on_beam_number,
                                                    match_on_step_state=match_on_step_state)
        success = watch_scu.subscribe(matching_keys=matching_keys)
        if success and self.watch_scu is None:
            self.watch_scu = watch_scu
        return success



    def _unsubscribe_from_ups(self):
        if self.watch_scu is None:
            my_ae_title = self.ui.ppvs_ae_line_edit.text()
            watch_scu = WatchSCU(my_ae_title)
        # hard code for the moment, deal with configuration of AE's soon
            ip_addr = "127.0.0.1"
            port = 11114
            upsscp_ae_title = self.ui.ups_ae_line_edit.text()
            watch_scu.set_subscription_ae(upsscp_ae_title, ip_addr=ip_addr,port=port)
        else:
            watch_scu = self.watch_scu
        
        matching_keys = None
        success = watch_scu.unsubscribe(matching_keys=matching_keys)
        if success and self.watch_scu is None:
            self.watch_scu = watch_scu
        return success

    def _nevent_callback(self, **kwargs):
        logger = None
        if "logger" in kwargs.keys():
            logger = kwargs["logger"]
        if logger:
            logger.info("nevent_cb invoked")
        event_type_id = 0  # not a valid type ID
        if logger:
            logger.info(
                "TODO: Invoke application response appropriate to content of N-EVENT-REPORT-RQ"
            )
        if "type_id" in kwargs.keys():
            event_type_id = kwargs["type_id"]
            if logger:
                logger.info(f"Event Type ID is: {event_type_id}")
        if "information_ds" in kwargs.keys():
            information_ds = kwargs["information_ds"]
            if logger:
                logger.info("Dataset in N-EVENT-REPORT-RQ: ")
                logger.info(f"{information_ds}")
        # TODO: replace if/elif with dict of {event_type_id,application_response_functions}
        if event_type_id == 1:
            if logger:
                logger.info("UPS State Report")
                logger.info("Probably time to do a C-FIND-RQ")
                self._get_ups()
        elif event_type_id == 2:
            if logger:
                logger.info("UPS Cancel Request")
                self.ui.ups_response_tree_widget.clear()
        elif event_type_id == 3:
            if logger:
                logger.info("UPS Progress Report")
                logger.info(
                    "Probably time to see if the Beam (number) changed, or if adaptation is taking or took place"
                )
                self._get_ups()
        elif event_type_id == 4:
            if logger:
                logger.info("SCP Status Change")
                logger.info(
                    "Probably a good time to check if this is a Cold Start and then re-subscribe \
                        for specific UPS instances if this application has/had instance specific subscriptions"
                )
        elif event_type_id == 5:
            if logger:
                logger.info("UPS Assigned")
                logger.info(
                    "Not too interesting for TDW-II, UPS are typically assigned at the time of scheduling, \
                        but a matching class of machines might make for a different approach"
                )
        else:
            if logger:
                logger.warning(f"Unknown Event Type ID: {event_type_id}")


def restart_ppvs_scp(ae_title:str, output_dir:Path=None) -> str:
    """_summary_

    Args:
        ae_title (str): _description_
        output_dir (Path, optional): _description_. Defaults to None.
                                    If None, the output path will be set
                                    to the current working directory

    Returns:
        str: error string, empty if startup was successful
    """

        


if __name__ == "__main__":
    app = QApplication(sys.argv)
    widget = PPVS_SubscriberWidget()
    widget.show()
    sys.exit(app.exec())
