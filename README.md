# tdwii_plus_examples
Working Python sample code (Not For Clinical Use) for performing various transactions within the IHE-RO TDW-II profile, as well as extensions based on UPS Watch and UPS Event.

No claims are being made that any of the sample code is adherent to the profile,
but the examples that are not UPS Watch/UPS Event should interact successfully within limits with valid TDW-II actors.

While the command lines shown below are run via python as the command, they are now all executable scripts (`chmod +x`) so they can be run directly on *nix platforms (you still need to have Python in your environment).
The samples are in the `tdwii_plus_examples` subdirectory.

> [!NOTE]
> The version of Python used for development is 3.10

# Basic Process Flow in TDW-II Profile
> This diagram is based on: https://www.ihe.net/uploadedFiles/Documents/Radiation_Oncology/IHE_RO_Suppl_TDW_II.pdf <br>
> IHE Radiation Oncology Technical Framework Supplement<br>
> Treatment Delivery Workflow-II (TDW-II)<br>
> Rev. 1.1 – Trial Implementation

```mermaid
sequenceDiagram
    participant TDD as Treatment Delivery Device<br>(TDD)
    participant TMS as Treatment Management System<br>(TMS)
    participant OST as Object Storage<br>(OST)

    TDD->>TMS: Worklist Query for Treatment Delivery [RO-58]
    activate TDD
    deactivate TDD

    activate TMS
    deactivate TMS
    TDD->>OST: Retrieve Static Treatment Delivery Input Instances from OST [RO-59]
    activate OST
    deactivate OST

    activate TDD
    activate TMS
    alt either
        TDD->>TMS: Treatment Delivery in Progress [RO-60]
        TDD->>TMS: Retrieve Dynamic Treatment Delivery Input Instances from TMS [RO-61]
    else or
        TDD->>TMS: Retrieve Dynamic Treatment Delivery Input Instances from TMS [RO-61]
        TDD->>TMS: Treatment Delivery in Progress [RO-60]
    end
    loop one or more times
        TDD->>TDD: Deliver treatment
        TDD->>TMS: Treatment Delivery Progress Update [RO-62]
    end
    deactivate TMS

    TDD->>OST: Store Treatment Delivery Results to OST [RO-63]
    activate OST
    deactivate OST

    TDD->>TMS: Treatment Delivery Final Update [RO-64]
    activate TMS
    deactivate TMS

    TDD->>TMS: Treatment Delivery Completed/Canceled [RO-65]
    activate TMS
    deactivate TMS
    deactivate TDD
```


# Installation
Poetry (https://python-poetry.org/) is used for package management.

Assuming you have already cloned the repository (or downloaded a compressed archive of it) and are in the top level directory for the project
```shell
poetry install
```
To confirm the required packages are installed
```shell
python -m pip list
```
> [!TIP]
> If the required packages are not shown (e.g. pydicom, pynetdicom), you may have an interaction issue between poetry and pyenv.
> Try:
> ```shell
> export VIRTUAL_ENV=$(pyenv virtualenv-prefix)/envs/$(pyenv version | cut -f1 -d ' ')
> poetry install
> ```


# Usage & Sample Workflow

The sample queries and responses are not necessarily coordinated with an OST (yet), i.e. using an appropriate AE Title

Application entity information now in a configuration file

Text files in dcmdump format for various queries.

## dcmdump and dump2dcm
`dcmdump` and `dump2dcm` are in DCMTK, typically available on:

Linux using:
```shell
sudo apt install dcmtk
```
or MacOS using:
```shell
brew install dcmtk
```
To generate `.dcm` files needed by UPS enabled findscu
```shell
dump2dcm queryfile.dcmdump.txt queryfile.dcm
```


## [RO-58] A sample C-FIND SCU is available from pynetdicom (it has been enhanced with support for UPS)

```mermaid
sequenceDiagram
    participant TDD as Treatment Delivery Device (TDD)
    participant TMS as Treatment Management System (TMS)

    TDD->>TMS: Query Scheduled UPS Worklist (C-FIND)
    activate TDD
    activate TMS
    TMS-)TDD: Receive Scheduled UPS Worklist
    deactivate TDD
    deactivate TMS
```

clone latest **pynetdicom** (it supports argument `--ups`) from https://github.com/pydicom/pynetdicom ,

then use `findscu` to query the TMS (Treatment Management System):

in `pynetdicom/apps/`

```shell
python findscu.py -w --ups -f UPSCFind_TDWII_SCHEDULED_FX1.dcm 10.211.55.8 10401
```
Arguments:
* `-w`: use modality worklist information model
* `--ups`: use unified procedure step pull information model
* `-f UPSCFind_TDWII_SCHEDULED_FX1.dcm`: use a DICOM file as the query dataset
* `10.211.55.8 10401`: DICOM peer and port number of the SCP (e.g. TMS)

Assuming the TMS has a session scheduled for machine **FX1**, this should result in a response file
`rsp000001.dcm`

use that response to drive a C-MOVE-RQ in the following section:


## [RO-59] A script that will issue a C-MOVE-RQ for the referenced inputs in the previous response

```mermaid
sequenceDiagram
    participant OST as Object Storage (OST)
    participant TDD as Treatment Delivery Device (TDD)

    TDD->>OST: Retrieve Objects (C-MOVE)
    activate TDD
    activate OST
    OST->>TDD: Store Objects (C-STORE)
    deactivate TDD
    deactivate OST
```

The following will send the C-MOVE-RQ to the AE Title listed (in the C-FIND-RSP e.g. in the rsp000001.dcm file above) for a given input information sequence item and specify PPVS_SCP as the destination for the move
```shell
python cmove_inputs.py PPVS_SCP ../../pynetdicom/pynetdicom/apps/findscu/rsp000001.dcm
```

Note that the IP Address and Port information for a given Application Entity (e.g. **PPVS_SCP** as shown above) must be configured in the `ApplicationEntities.json` file (in the current working directory, so you will need to copy it from the top level and modify to have your AEs).


## A sample N-CREATE SCU that will read in a UPS Push SOP and transmit that to a UPS SCP (e.g. TMS Simulator)
A previous response to findscu can be used for simulation purposes but the Procedure Step State must be **SCHEDULED**
```shell
python ncreatescu.py addr port path
```
Arguments:
* `addr port`: DICOM peer and port number of the SCP (e.g. TMS)
* `path`: use a DICOM file or folder to be transmitted to SCP


## A TMS Simulator (of limited capability) is provided in upsscp.py:
in `tdwii_plus_examples/`
```shell
python upsscp.py --debug
```
The default configuration (`upsscp_default.ini`) will specify a ups_instances directory that upsscp will use to store UPS Push SOP instance it received from the ncreatescu and it will provide those in response to queries that match them.

The default configuration listens on port `11114`

Matching/filtering is currently based only on:
* Scheduled Station Name (machine name)
* Procedure Step State
* Scheduled Procedure Step Start DateTime
* Scheduled Workitem Code Sequence (the Code Value)

```python
ds.ScheduledStationNameCodeSequence[0].CodeValue
ds.ProcedureStepState
ds.ScheduledProcedureStepStartDateTime
ds.ScheduledWorkitemCodeSequence[0].CodeValue
```

A sample response is in `tdwii_plus_examples/responses/dcm/` and it can be renamed and then transmitted to upsscp via ncreatescu

Alternative/additional sample responses can be constructed by using dcmdump on the provided sample response, editing the text, and using dump2dcm.


So one could test without having a real TMS:
```shell
python findscu.py -w --ups -f UPSCFind_TDWII_SCHEDULED_FX1.dcm 127.0.0.1 11114
```


## A sample UPS Watch SCU (for subscribing for UPS Event/notification) is provided in watchscu.py
```shell
python watchscu.py 127.0.0.1 11114
```
the above will attempt to perform a Global Subscription to upsscp (e.g. TMS)


## A sample UPS NACTION SCU (for changing Procedure Step Status for UPS) is provided in nactionscu.py

```mermaid
sequenceDiagram
    participant TDD as Treatment Delivery Device (TDD)
    participant TMS as Treatment Management System (TMS)

    TDD->>TMS: UPS in Progress (N-ACTION)
    activate TDD
    activate TMS

    deactivate TDD
    deactivate TMS
```

```shell
python nactionscu.py -T "1.2.826.0.1.3680043.8.498.23133079088775253446636289730969872574" -R "IN PROGRESS" 127.0.0.1 11114 1.2.840.113854.19.4.2017747596206021632.638223481578481915
```
the above will request that upsscp (listening at 11114) change the state using the **Transaction UID** (-T) of the UPS with the shown UID to "IN PROGRESS"

While the Transaction UID argument is optional here (one will be generated internally), if you don't know the Transaction UID, you can't perform further changes.

```shell
python nactionscu.py -T "1.2.826.0.1.3680043.8.498.23133079088775253446636289730969872574" -R "COMPLETED" 127.0.0.1 11114 1.2.840.113854.19.4.2017747596206021632.638223481578481915
```
the above will request that upsscp (listening at 11114) change the state using the **Transaction UID** (-T) of the UPS with the shown UID to "COMPLETED".  The Transaction UID here is **not** optional.

## A sample application for receiving notifications (N-EVENT-REPORT-RQ) is provided in nevent_receiver.py
```shell
python nevent_receiver.py --debug
```
which listens on port `11115` by default (`nevent_receiver_default.ini`),

The application does not take specific actions when receiving an N-EVENT-REPORT (but it will log in response)


## A sample application for sending notifications is provided in nevent_sender.py (which can be run against nevent_receiver.py mentioned above)
```shell
python nevent_sender.py 127.0.0.1 11115
```


## A Qt/PySide6 based utility for generating RT Beams Delivery Instructions and Unified Procedure Step content
```shell
python tdwii_plus_examples/rtbdi_creator/mainbdiwidget.py
```

## A Qt/PySide6 based example of a Patient Position Verification System that subscribes to UPS Events and responds by querying for the UPS information, requesting (C-MOVE) the referenced information objects, etc.
```shell
python tdwii_plus_examples/TDWII_PPVS_Subscriber/ppvs_subscriber_widget.py
```


## A Qt/PySide6 based example of a Treatment Delivery System that also subscribes to UPS Events and responds by querying for the UPS information, requesting (C-MOVE) the referenced information objects, etc. and allows the user to drive through the entire workflow (but treatment record generation is not supported yet... you'll need to provide your own)
```shell
python tdwii_plus_examples/tdd/tdd_widget.py
```


## The OST can be simulated using the pynetdicom qrscp application.

The remaining intent (now that a PPVS Simulator is included) is to eventually integrate the various functionality as appropriate in to a TMS Simulator (and perhaps eventually a TDS Simulator).

But the purpose of the examples is to provide working sample code for individual TDW-II Transactions and for UPW Watch/UPS Event capabilities that can be used to extend a TDW-II environment so that it is event aware/event driven.

# Cookbook for PPVS: Creating a sample TDW-II environment with the tools described or mentioned above
The following assumes you have at least one RT Ion Plan or RT Plan (that is accessible via the file system),
and you are in the top level directory of this project (directory specifications are *nix switch from / to \ for MS Windows and pushd and popd are available in PowerShell or just change directories explicitly)
The example below assumes you are doing everything in one terminal/shell window, but it can certainly be done in separate windows for easier tracking of console logging from the various programs.


Start the TMS simulator (assuming you are already in the tdwii_plus_example subdirectory):
```shell
python tdwii_plus_examples/upsscp.py --debug &
```
Start the OST simulator (assuming you have cloned pynetdicom parallel to tdwii_plus_examples)
```shell
pushd ../../pynetdicom/pynetdicom/apps/qrscp
python qrscp.py --debug &
```
Start the RTBDI creator
```shell
popd
python tdwii_plus_examples/rtbdi_creator/mainbdiwidget.py &
```
Enter the Move/Retrieve AE Title if you are using something other than the default.

Using the RTBDI creator, find the plan you want to use as the basis for the UPS and RTBDI
send the plan to the OST (the Move/Retrieve AE)

Specify 1 as the fraction number

Select a directory for where the RTBDI and UPS will be placed.  (you might want to create a separate directory for this ahead of time... or right now)

click on the 'Export BDI' button (the RTBDI will get sent to the OST)

Unless you want to specify a date other than today, you don't need to adjust the scheduled DateTime

click on the 'Export UPS' button (the UPS will get scheduled on the TMS)

change back to the tdwii_plus_examples subdirectory of this project

start the PPVS Emulator:
```shell
python tdwii_plus_examples/TDWII_PPVS_subscriber/ppvs_subscriber_widget.py &
```
In the PPVS Emulator:

Enter the UPS AE for the TMS if you are using something other than the default

Enter the QRSCP AE for the OST if you are using something other than the default

Set the Machine Name to... the name of the machine in the RT (Ion) Plan you provided (typical values can be TR1 or G1, but it's whatever is in the plan)

Enter the Event and Store SCP AE Title for the PPVS if you want to use something other than the default (you are using the PPVS emulator, so the default is appropriate for it)

Choose a staging directory (where you want the the retrieved plan and RTBDI to go... mostly as proof that the C-MOVE worked)

check the Subscribe to UPS checkbox, check the Auto Download checkbox, and click the 'Restart SCP' button.

The PPVS Emulator is now ready to be notified of any newly scheduled UPS (after checking those checkboxes, there isn't a need to manually query the TMS ("Get UPS") or manually retrieve from the OST ("Get Listed Inputs" and "Get RTSS and CT"))

Scheduling the UPS:

```python
python tdwii_plus_examples/ncreatescu.py 127.0.0.1 11114 "full path to the UPS you exported"
```
or use the RTBDI creator to create another RTBDI and UPS

This will schedule the UPS in the TMS, and that will trigger the TMS Emulator to notify the PPVS Emulator that a UPS is ready, and the PPVS Emulator will query for the UPS content from the TMS Emulator and then retrieve the plan and the RTBDI that are referenced in the UPS from the OST Emulator (the QRSCP from pynetdicom).

start the TDD Emulator:
```shell
python tdwii_plus_examples/tdd/tdd_widget.py &
```
In the TDD Emulator:

Follow the instructions for the PPVS Emulator, but specify a different import staging directory.

If you don't use the defaults for the TDD Event And Store SCP AE title, make sure not to use the same value being used by any of the other actors.

The TDD has additional UI for Starting the Procedure RO-60 (NACTION-RQ to IN PROGRESS)

Spinners for changing the Beam Number and Percent Complete RO-62 (N-SET-RQ),

A button for sending the treatment record (pops a dialog for you to select your previously generated treatment records for the plan with the current fraction number) RO-63,

A Finish button for RO-64 Final Update, and

Either Cancel or Complete for RO-65.



# Abbreviations
| Abbr. | Description |
|-------| ------------|
| TDW   | Treatment Delivery Workflow |
| UPS   | Unified Procedure Step |
| TMS   | Treatment Management System |
| TDS   | Treatment Delivery System |
| TDD   | Treatment Delivery Device |
| IPDW  | Integrated Positioning and Delivery Workflow |
| PPVS  | Patient Position Verification System |
| OST   | Object Storage |
| RTBDI | RT Beams Delivery Instruction |
| QRSCP | Query Retrieve Service Class Provider |

## Developers
```shell
poetry install -E all
poetry run pre-commit install
```

## Acknowledgments
In addition to being the main package used by this project, some of the code has been inspired, adapted or reused from:
- **pynetdicom** by Patrice Munger and pynetdicom contributors
- URL: https://github.com/pydicom/pynetdicom
- License: MIT
