# VulTek-Alert v3.1 (Vulnerabilities Tekium - Alert)

Author: Erick Rodríguez 

Email: erodriguez@tekium.mx, erickrr.tbd93@gmail.com

License: GPLv3

VulTek-Alert was born from the need to have a tool that notifies in a timely manner of the latest published vulnerabilities found in Red Hat systems.

To do this, VulTek-Alert makes use of the Red Hat Security Data API, where it performs a query to obtain said CVE's for later sending to a Telegram channel.

This with the purpose of being able to take timely actions to mitigate said vulnerabilities that could affect the infrastructure of an organization that occupies Red Hat systems.

For more information:

https://access.redhat.com/documentation/en-us/red_hat_security_data_api/1.0/html-single/red_hat_security_data_api/index

# Applications
## VulTek-Alert
Application that obtains the CVE's published in the Red Hat Security Data API in a range of days, and sends alerts via Telegram about them.

![VulTek-Alert](https://github.com/erickrr-bd/VulTek-Alert/blob/master/screens/screen2.jpg)

Characteristics:
- Obtaining the CVE's is done at one hour of the day. This is configurable.
- Obtain CVE's in a range of days (starting from the current day). This is configurable.
- Obtains the CVE's of certain levels of criticality (low, moderate, important and critical). This is configurable.
- Send the CVE's found to a certain Telegram channel as an alert. This is configurable.
- If it does not find CVE's during the established range of days, it sends an alert to the Telegram channel mentioning that it did not find CVE's.
- It can be run as a service or daemon.
- When running as a service or daemon, it is run using the "vultek_alert" user. This for security purposes.
- Creation of application logs (in the path /var/log/VulTek-Alert).

## VulTek-Alert-Tool
Auxiliary graphical application for managing the configuration of the application as well as it's service or daemon.

![VulTek-Alert-Tool](https://github.com/erickrr-bd/VulTek-Alert/blob/master/screens/screen1.jpg)

Characteristics:
- Use of "dialog" for the use of graphical interfaces in the application.
- Manages the VulTek-Alert configuration (creation and modification).
- Manages the operations on the VulTek-Alert daemon or service (start, restart, stop and current status).
- Sensitive information is stored encrypted in YAML files.
- Creation of application logs (in the path /var/log/VulTek-Alert).

# Requirements
- CentOS 8 or RedHat 8 (So far it has only been tested in this version)
- Python 3.6
- Internet connection (specifically to the Telegram and Red Hat API).
- Python Libraries
  - requests
  - pycurl
  - pythondialog
  - pycryptodome
  - pyyaml

# Installation
To install or update VulTek-Alert you must run the script "installer_vultek_alert.sh" for this you can use any of the following commands:

`./installer_vultek_alert.sh` or `sh installer_vultek_alert.sh`

The installer performs the following actions on the computer:

- Copy and creation of directories and files necessary for the operation of VulTek-Alert.
- Creation of the user and group "vultek_alert", which is used only for the operation of the application.
- Assignment of owner to the user "vultek_alert" of the application components for their correct operation.
- Random creation of the passphrase for the encryption/decryption process of sensitive information. Therefore, this is unique to each VulTek-Alert implementation.
- Creation of the VulTek-Alert service or daemon.

# Running
## VulTek-Alert

- Run as service:

`systemctl start vultek-alert.service`

- To execute manually, first you must go to the path /etc/VulTek-Alert-Suite/VulTek-Alert and execute using the following commands:

`python3 VulTek_Alert.py` or `./VulTek_Alert.py`

## VulTek-Alert-Tool

- The first way to run VulTek-Alert-Tool, you must go to the path /etc/VulTek-Alert-Suite/VulTek-Alert-Tool and execute using the following commands:

`python3 VulTek_Alert_Tool.py` or `./VulTek_Alert_Tool.py`

- The second way to run VulTek-Alert-Tool is upon installation of VulTek-Alert an alias for VulTek-Alert-Tool is created. To use it, you must first execute the following command once the installation is complete:

`source ~/.bashrc`

Later, VulTek-Alert-Tool can be executed only by using the following command:

`VulTek-Alert-Tool`

# Commercial Support
![Tekium](https://github.com/unmanarc/uAuditAnalyzer2/blob/master/art/tekium_slogo.jpeg)

Tekium is a cybersecurity company specialized in red team and blue team activities based in Mexico, it has clients in the financial, telecom and retail sectors.

Tekium is an active sponsor of the project, and provides commercial support in the case you need it.

For integration with other platforms such as the Elastic stack, SIEMs, managed security providers in-house solutions, or for any other requests for extending current functionality that you wish to see included in future versions, please contact us: info at tekium.mx

For more information, go to: https://www.tekium.mx/
