from os import path
from sys import exit
from requests import get
from libPyLog import libPyLog
from time import sleep, strftime
from libPyUtils import libPyUtils
from .Constants_Class import Constants
from libPyTelegram import libPyTelegram

"""
Class that manages everything related to VulTek-Alert.
"""
class VulTekAlert:
	"""
	Attribute that stores an object of the libPyUtils class.
	"""
	__utils = None

	"""
	Attribute that stores an object of the libPyLog class.
	"""
	__logger = None

	"""
	Attribute that stores an object of the libPyTelegram class.
	"""
	__telegram = None

	"""
	Attribute that stores an object of the Constants class.
	"""
	__constants = None


	def __init__(self):
		"""
		Method that corresponds to the constructor of the class.
		"""
		self.__utils = libPyUtils()
		self.__constants = Constants()
		self.__telegram = libPyTelegram()
		self.__logger = libPyLog(self.__constants.NAME_FILE_LOG, self.__constants.NAME_LOG, self.__constants.USER, self.__constants.GROUP)

	
	def startVulTekAlert(self):
		"""
		Method that starts the operation of VulTek-Alert.
		"""
		self.__logger.createApplicationLog("VulTek-Alert v3.1", 1, use_stream_handler = True)
		self.__logger.createApplicationLog("@2022 Tekium. All rights reserved.", 1, use_stream_handler = True)
		self.__logger.createApplicationLog("Author: Erick Rodriguez", 1, use_stream_handler = True)
		self.__logger.createApplicationLog("Email: erodriguez@tekium.mx, erickrr.tbd93@gmail.com", 1, use_stream_handler = True)
		self.__logger.createApplicationLog("License: GPLv3", 1, use_stream_handler = True)
		self.__logger.createApplicationLog("VulTek-Alert started...", 1, use_stream_handler = True)
		try:
			data_configuration = self.__utils.readYamlFile(self.__constants.PATH_FILE_CONFIGURATION)
			while True:
				for severity in data_configuration['options_level_vulnerabilities']:
					http_response = get("https://access.redhat.com/hydra/rest/securitydata/cve.json?created_days_ago=1&severity=" + severity)
					if http_response.status_code == 200:
						all_cve_data_json = http_response.json()
						passphrase = self.__utils.getPassphraseKeyFile(self.__constants.PATH_KEY_FILE)
						telegram_bot_token = self.__utils.decryptDataWithAES(data_configuration['telegram_bot_token'], passphrase).decode('utf-8')
						telegram_chat_id = self.__utils.decryptDataWithAES(data_configuration['telegram_chat_id'], passphrase).decode('utf-8')
						if not all_cve_data_json:
							self.__logger.createApplicationLog("CVE's not found of the level of criticality: " + severity, 1, use_stream_handler = True)
							message_to_send = self.__generateNoVulnerabilitiesMessageTelegram(severity)
							response_http_code = self.__telegram.sendMessageTelegram(telegram_bot_token, telegram_chat_id, message_to_send)
							self.__createLogByTelegramCode(response_http_code)
						else:
							for data in all_cve_data_json:
								self.__validateExistsCVEinDatabaseFile(data['CVE'], telegram_bot_token, telegram_chat_id)
					else:
						self.__logger.createApplicationLog("Invalid response. Error getting the CVE's.", 3, use_stream_handler = True)
						exit(1)
				sleep(60)
		except (FileNotFoundError, IOError, OSError) as exception:
			self.__logger.createApplicationLog(exception, 3)
			self.__logger.createApplicationLog("Error creating, opening or reading the file. For more information, see the logs.", 3, use_stream_handler = True)
			exit(1)
		except KeyError as exception:
			self.__logger.createApplicationLog("Key Error: " + str(exception), 3, use_stream_handler = True)
			exit(1)


	def __validateExistsCVEinDatabaseFile(self, cve_id, telegram_bot_token, telegram_chat_id):
		"""
		Method that validates if a CVE exists in the database file.

		:arg cve_id: CVE identifier.
		"""
		if path.exists(self.__constants.PATH_DATABASE_FILE):
			database_cves = self.__utils.readYamlFile(self.__constants.PATH_DATABASE_FILE)
			if not cve_id in database_cves['list_all_cves_found']:
				self.__getCVEInformationbyID(cve_id, telegram_bot_token, telegram_chat_id)
				database_cves['list_all_cves_found'].append(cve_id)
				self.__createDatabaseYamlFile(database_cves['list_all_cves_found'])
		else:
			list_all_cves = []
			list_all_cves.append(cve_id)
			self.__getCVEInformationbyID(cve_id, telegram_bot_token, telegram_chat_id)
			self.__createDatabaseYamlFile(list_all_cves)


	def __getCVEInformationbyID(self, cve_id, telegram_bot_token, telegram_chat_id):
		"""
		Method that obtains the information of a specific CVE.

		:arg cve_id: CVE identifier.
		"""
		http_response = get("https://access.redhat.com/hydra/rest/securitydata/cve.json?ids=" + cve_id)
		if http_response.status_code == 200:
			cve_data_json = http_response.json()
			for data in cve_data_json:
				if 'CVE' in data:
					cve = data['CVE']
				else:
					cve = "None"
				if 'public_date' in data:
					public_date = data['public_date']
				else:
					public_date = "None"
				if 'severity' in data:
					severity = data['severity']
				else:
					severity = "None"
				if 'bugzilla_description' in data:
					bugzilla_description = data['bugzilla_description']
				else:
					bugzilla_description = "None"
				if 'CWE' in data:
					cwe = data['CWE']
				else:
					cwe = "None"
				if 'cvss3_scoring_vector' in data:
					cvss3_scoring_vector = data['cvss3_scoring_vector']
				else:
					cvss3_scoring_vector = "None"
				if 'cvss3_score' in data:
					cvss3_score = data['cvss3_score']
				else:
					cvss3_score = "None"
				self.__logger.createApplicationLog("CVE:  " + cve + ", Level: " + severity, 1, use_stream_handler = True)
				message_to_send = self.__generateMessageTelegram(cve, public_date, severity, bugzilla_description, cwe, cvss3_scoring_vector, cvss3_score)
				response_http_code = self.__telegram.sendMessageTelegram(telegram_bot_token, telegram_chat_id, message_to_send)
				self.__createLogByTelegramCode(response_http_code)
		else:
			self.__logger.createApplicationLog("Invalid response. Error getting the CVE information.", 3, use_stream_handler = True)


	def __createDatabaseYamlFile(self, list_all_cves):
		"""
		Method that creates the YAML file where the list of cves obtained will be stored.

		:arg list_all_cves: List containing the name of all obtained cves.
		"""
		database_cves_json = {'last_scan_time' : strftime("%c"),
							  'list_all_cves_found' : list_all_cves,
						      'total_cves_found' : len(list_all_cves)}

		self.__utils.createYamlFile(database_cves_json, self.__constants.PATH_DATABASE_FILE)
		self.__utils.changeOwnerToPath(self.__constants.PATH_DATABASE_FILE, self.__constants.USER, self.__constants.GROUP)


	def __generateNoVulnerabilitiesMessageTelegram(self, severity):
		"""
		Method that generates the message to send via Telegram when no CVEs were found.

		Returns the message that was sent via Telegram.

		:arg severity: Severity level of vulnerability.
		"""
		message_telegram = u'\u26A0\uFE0F' + " VulTek-Alert " + u'\u26A0\uFE0F' + "\n\n" + u'\u23F0' + " Alert sent: " + strftime("%c") + "\n\n\n"
		message_telegram += u'\u2611\uFE0F' + " Severity: " + severity + '\n'
		message_telegram += u'\u2611\uFE0F' + " Description: CVEs not found" + '\n'
		return message_telegram


	def __generateMessageTelegram(self, cve, public_date, severity, bugzilla_description, cwe, cvss3_scoring_vector, cvss3_score):
		"""
		Method that generates the message to be sent via Telegram.

		Returns the message that was sent via Telegram.

		:arg cve: Common Vulnerabilities and Exposures ID.
		:arg public_date: Date of publication of the vulnerability.
		:arg severity: Severity level of vulnerability.
		:arg bugzilla_description: Description of the vulnerability. 
		:arg cwe: Common Weakness Enumeration ID.
		:arg cvss3_scoring_vector: Scoring vector of Common Vulnerability Scoring System.
		:arg cvss3_score: Score of Common Vulnerability Scoring System.
		"""
		message_telegram = u'\u26A0\uFE0F' + " VulTek-Alert " + u'\u26A0\uFE0F' + "\n\n" + u'\u23F0' + " Alert sent: " + strftime("%c") + "\n\n\n"
		message_telegram += u'\u2611\uFE0F' + " CVE: " + cve + '\n'
		message_telegram += u'\u2611\uFE0F' + " Public Date: " + public_date + '\n'
		message_telegram += u'\u2611\uFE0F' + " Severity: " + severity + '\n'
		message_telegram += u'\u2611\uFE0F' + " Description: " + bugzilla_description + '\n'
		message_telegram += u'\u2611\uFE0F' + " CWE: " + str(cwe) + '\n'
		message_telegram += u'\u2611\uFE0F' + " CVSS3 Scoring Vector: " + str(cvss3_scoring_vector) + '\n'
		message_telegram += u'\u2611\uFE0F' + " CVSS3 Score: " + str(cvss3_score) + '\n'
		return message_telegram


	def __createLogByTelegramCode(self, response_http_code):
		"""
		Method that creates a log based on the HTTP code received as a response.

		:arg response_http_code: HTTP code received in the response when sending the alert to Telegram.
		"""
		if response_http_code == 200:
			self.__logger.createApplicationLog("Telegram message sent.", 1, use_stream_handler = True)
		elif response_http_code == 400:
			self.__logger.createApplicationLog("Telegram message not sent. Status: Bad request.", 3, use_stream_handler = True)
		elif response_http_code == 401:
			self.__logger.createApplicationLog("Telegram message not sent. Status: Unauthorized.", 3, use_stream_handler = True)
		elif response_http_code == 404:
			self.__logger.createApplicationLog("Telegram message not sent. Status: Not found.", 3, use_stream_handler = True)