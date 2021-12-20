# VulTek-Alert v1.0

Author: Erick Rodríguez 

Email: erodriguez@tekium.mx, erickrr.tbd93@gmail.com

License: GPLv3

VulTek-Alert is an application that obtains the CVE's of a certain level or levels (configurable) of the Red Hat Security Data API and sends the results obtained to a Telegram channel. In order to be aware of the vulnerabilities that affect Red Hat systems and thus take action in a timely manner.

For more information:

https://access.redhat.com/documentation/en-us/red_hat_security_data_api/1.0/html-single/red_hat_security_data_api/index

# Applications
## VulTek-Alert
Application that obtains the CVE's from a previous day using the Red Hat Security Data API and sending the result to a Telegram channel.

Characteristics:
- It runs at a time of day (configurable).
- It obtains the CVE's for 24 hours from the moment it is executed.
- It obtains the CVE's only of a certain level or levels of criticality (configurable).
- Send the results to a certain Telegram channel (configurable).
- It has the option to run as a service or daemon.
- It runs with a user created during the installation process for that purpose.
- Generation of application logs.

## VulTek-Alert-Tool
VulTek-Alert auxiliary tool that allows actions on the VulTek-Alert configuration and service using a graphical interface.

Characteristics:
- Allows you to create and modify the VulTek-Alert configuration.
- Allows you to start, restart, stop and get the current status of the VulTek-Alert service.
- Encrypts sensitive data such as passwords so that they are not stored in plain text.
- Generation of application logs.

# Requirements
- CentOS 8 or RedHat 8 (So far it has only been tested in this version)
- Python 3.6
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
- Creation of user and specific group for the operation of VulTek-Alert.
- It changes the owner of the files and directories necessary for the operation of VulTek-Alert, assigning them to the user created for this purpose.
- Creation of passphrase for the encryption and decryption of sensitive information, which is generated randomly, so it is unique for each installed VulTek-Alert installation.
- Creation of VulTek-Alert service.

# Running



# Commercial Support
![Tekium](https://github.com/unmanarc/uAuditAnalyzer2/blob/master/art/tekium_slogo.jpeg)

Tekium is a cybersecurity company specialized in red team and blue team activities based in Mexico, it has clients in the financial, telecom and retail sectors.

Tekium is an active sponsor of the project, and provides commercial support in the case you need it.

For integration with other platforms such as the Elastic stack, SIEMs, managed security providers in-house solutions, or for any other requests for extending current functionality that you wish to see included in future versions, please contact us: info at tekium.mx

For more information, go to: https://www.tekium.mx/
