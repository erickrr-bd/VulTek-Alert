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
Telk-Alert graphical tool that allows the user to define the configuration and alert rules that will be used for the operation of the application. These data are saved in files with the extension yaml.

Characteristics:
- Allows you to create and modify the Telk-Alert connection settings.
- Allows you to create, modify and delete alert rules.
- Encrypts sensitive data such as passwords so that they are not stored in plain text.
- Allows you to start, restart, stop and get the status of the Telk-Alert service.
- Allows you to create and modify the Telk-Alert-Agent configuration.
- Allows you to start, restart, stop and get the status of the Telk-Alert-Agent service.

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
To install or update Telk-Alert, you must run the installer_telk_alert.sh executable with administrator rights. The installer will perform the following actions:
- Copy and creation of directories and files necessary for the operation of Telk-Alert.
- Creation of user and specific group for the operation of Telk-Alert.
- It changes the owner of the files and directories necessary for the operation of Telk-Alert, assigning them to the user created for this purpose.
- Creation of passphrase for the encryption and decryption of sensitive information, which is generated randomly, so it is unique for each installed Telk-Alert installation.
- Creation of Telk-Alert and Telk-Alert-Agent services.

# Running



# Commercial Support
![Tekium](https://github.com/unmanarc/uAuditAnalyzer2/blob/master/art/tekium_slogo.jpeg)

Tekium is a cybersecurity company specialized in red team and blue team activities based in Mexico, it has clients in the financial, telecom and retail sectors.

Tekium is an active sponsor of the project, and provides commercial support in the case you need it.

For integration with other platforms such as the Elastic stack, SIEMs, managed security providers in-house solutions, or for any other requests for extending current functionality that you wish to see included in future versions, please contact us: info at tekium.mx

For more information, go to: https://www.tekium.mx/
