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
			self.utils.createVulTekAlertLog("VulTek-Alert v3.0", 1)
			self.utils.createVulTekAlertLog("@2022 Tekium. All rights reserved.", 1)
			self.utils.createVulTekAlertLog("Author: Erick Rodriguez", 1)
			self.utils.createVulTekAlertLog("Email: erodriguez@tekium.mx, erickrr.tbd93@gmail.com", 1)
			self.utils.createVulTekAlertLog("License: GPLv3", 1)
			self.utils.createVulTekAlertLog("VulTek-Alert started...", 1)
			data_configuration_vultek = self.utils.readYamlFile(self.utils.getPathVulTekAlert('conf') + '/vultek_alert_conf.yaml', 'r')
			time_to_execute = data_configuration_vultek['time_to_execute'].split(':')
			while True:
				now = datetime.now()
				if (now.hour == int(time_to_execute[0]) and now.minute == int(time_to_execute[1])):
					for severity in data_configuration_vultek['options_level_vulnerabilities']:
						response_http = get("https://access.redhat.com/hydra/rest/securitydata/cve.json?created_days_ago=3&severity=" + severity)
						if response_http.status_code == 200:
							cve_data_json = response_http.json()
							if len(cve_data_json) == 0:
								self.utils.createVulTekAlertLog("No CVE's were found with the following severity: " + severity, 1)
								message_telegram = self.telegram.getNotVulnerabilityFoundMessage(severity)
								self.telegram.sendTelegramAlert(self.utils.decryptAES(data_configuration_vultek['telegram_chat_id']).decode('utf-8'), self.utils.decryptAES(data_configuration_vultek['telegram_bot_token']).decode('utf-8'), message_telegram)
							else:
								for data_json in cve_data_json:
									cve = data_json['CVE']
									public_date = data_json['public_date']
									severity = data_json['severity']
									bugzilla_description = data_json['bugzilla_description']
									if "CWE" in data_json:
										cwe = data_json['CWE']
									else:
										cwe = "None"
									if "cvss3_scoring_vector" in data_json:
										cvss3_scoring_vector = data_json['cvss3_scoring_vector']
									else:
										cvss3_scoring_vector = "None"
									if "cvss3_score" in data_json:
										cvss3_score = data_json['cvss3_score']
									else:
										cvss3_score = "None"
									self.utils.createVulTekAlertLog("CVE Found: " + cve + ", severity: " + severity, 1)
									message_telegram = self.telegram.getVulnerabilityMessage(cve, public_date, severity, bugzilla_description, cwe, cvss3_scoring_vector, cvss3_score)
									self.telegram.sendTelegramAlert(self.utils.decryptAES(data_configuration_vultek['telegram_chat_id']).decode('utf-8'), self.utils.decryptAES(data_configuration_vultek['telegram_bot_token']).decode('utf-8'), message_telegram)
						else:
							self.utils.createVulTekAlertLog("Invalid response. Error getting the CVE's.", 3)
							exit(1)
				sleep(60)
		except KeyError as exception:
			self.utils.createVulTekAlertLog("Error starting the application. For more information, see the logs.", 3)
			self.utils.createVulTekAlertLog("Key Error: " + str(exception), 3)
			exit(1)