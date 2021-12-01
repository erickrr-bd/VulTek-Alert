from sys import exit
from time import sleep
from requests import get
from datetime import datetime
from modules.UtilsClass import Utils
from modules.TelegramClass import Telegram

"""
Class that manages everything related to the operation of VulTek-Alert.
"""
class VulTek:
	"""
	Property that stores an object of the Utils class.
	"""
	utils = None

	"""
	Property that stores an object of the Telegram class.
	"""
	telegram = None

	"""
	Constructor for the VulTek class.

	Parameters:
	self -- An instantiated object of the VulTek class.
	"""
	def __init__(self):
		self.utils = Utils()
		self.telegram = Telegram()

	"""
	Method that initiates VulTek-Alert.

	Parameters:
	self -- An instantiated object of the VulTek class.

	Exceptions:
	KeyError -- A Python KeyError exception is what is raised when you try to access a key that isn’t in a dictionary (dict). 
	"""
	def startApplication(self):
		try:
			print("VulTek-Alert v3.0")
			print("@2021 Tekium. All rights reserved.")
			print("Author: Erick Rodriguez")
			print("Email: erodriguez@tekium.mx, erickrr.tbd93@gmail.com")
			print("License: GPLv3")
			print("\nVulTek-Alert started...\n\n")
			data_configuration_vultek = self.utils.readYamlFile(self.utils.getPathVulTekAlert('conf') + '/vultek_alert_conf.yaml', 'r')
			time_to_execute = data_configuration_vultek['time_to_execute'].split(':')
			while True:
				now = datetime.now()
				if (now.hour == int(time_to_execute[0]) and now.minute == int(time_to_execute[1])):
					for severity in data_configuration_vultek['options_level_vulnerabilities']:
						response_http = get("https://access.redhat.com/hydra/rest/securitydata/cve.json?created_days_ago=1&severity=" + severity)
						if response_http.status_code == 200:
							cve_data_json = response_http.json()
							if len(cve_data_json) == 0:
								self.utils.createVulTekAlertLog("No CVE's were found with the following severity: " + severity, 1)
								print("No CVE's were found with the following severity: " + severity)
								message_telegram = self.telegram.getNotVulnerabilityFoundMessage(severity)
								self.telegram.sendTelegramAlert(self.utils.decryptAES(data_configuration_vultek['telegram_chat_id']).decode('utf-8'), self.utils.decryptAES(data_configuration_vultek['telegram_bot_token']).decode('utf-8'), message_telegram)
							else:
								for data_json in cve_data_json:
									cve = data_json['CVE']
									public_date = data_json['public_date']
									severity = data_json['severity']
									bugzilla_description = data_json['bugzilla_description']
									cwe = data_json['CWE']
									cvss3_scoring_vector = data_json['cvss3_scoring_vector']
									cvss3_score = data_json['cvss3_score']
									self.utils.createVulTekAlertLog("CVE Found: " + cve + ", severity: " + severity, 1)
									print("CVE Found: " + cve + ", severity: " + severity)
									message_telegram = self.telegram.getVulnerabilityMessage(cve, public_date, severity, bugzilla_description, cwe, cvss3_scoring_vector, cvss3_score)
									self.telegram.sendTelegramAlert(self.utils.decryptAES(data_configuration_vultek['telegram_chat_id']).decode('utf-8'), self.utils.decryptAES(data_configuration_vultek['telegram_bot_token']).decode('utf-8'), message_telegram)
						else:
							print("Invalid response. Error getting the CVE's.")
							exit(1)
				sleep(60)
		except KeyError as exception:
			print("Key Error: " + str(exception))
			exit(1)