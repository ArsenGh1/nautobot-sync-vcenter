# nautobot-sync-vcenter
A synchronization tool to import and maintain up-to-date VMware vCenter inventory data into Nautobot.

## Features

* Multi-vCenter Support: Gathers VM details concurrently from multiple vCenter servers.

* Automated Sync: Automatically compares and updates Nautobot without manual intervention.

* Safety Modes: Includes safe (--safe) and dry-run (--dry-run) modes for controlled execution.

* Debugging: Optional debug mode (--debug) saves intermediate data as CSV/YAML files.

## Prerequisites

* VMware vCenter version 6.0 or higher

* Nautobot version 2.0 or higher

* Python 3.6+ installed on your system
* Access credentials for vCenter and Nautobot
* Configurations stored in settings.yaml

## Limitations

* Not tested with Nautobot versions 2.4 or higher.
* Does not sync virtual machine CPU, memory, or disk space information.

## Common Options:

* --dry-run, -d: Preview changes without syncing.

* --safe, -s: Prompt for confirmation before syncing.

* --debug: Enable debug mode, saving additional files.

* --help, -h: Show all available options.

## Usage

Run the script with the following options:
```
python main.py [OPTIONS]
```

  
## Setup and Installation (Ubuntu/Debian)

1. Install the required packages for Python 3 and virtual environments:
```
sudo apt update
sudo apt install python3 python3-pip python3-venv
```
2. Clone the repository and set up the environment:
```
cd /etc
git clone https://github.com/ArsenGh1/nautobot-sync-vcenter.git
cd nautobot-sync-vcenter
```
3. Create and activate a Python virtual environment:
```
python3 -m venv .venv
source .venv/bin/activate
```
4. Install dependencies:
```
python3 -m pip install --upgrade pip
pip3 install -r requirements.txt
```
5. Run the main script:
```
python3 main.py
```
## Configuration
Update the settings.yaml file with your vCenter and Nautobot credentials. Example format:
```
NAUTOBOT_URL: "https://nautobot.example.com"

vCenters:
  - name: "vcenter1"
    url: "vcenter1.example.com"
  - name: "vcenter2"
    url: "vcenter2.example.com"

```