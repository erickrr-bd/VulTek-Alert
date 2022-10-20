from os import path
from sys import exit
from requests import get
from datetime import datetime
from libPyElk import libPyElk
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

	"""
	Attribute that stores an object of the libPyElk class.
	"""
	__elasticsearch = None


	def __init__(self):
		"""
		Method that corresponds to the constructor of the class.
		"""
		self.__logger = libPyLog()
		self.__utils = libPyUtils()
		self.__constants = Constants()
		self.__telegram = libPyTelegram()
		self.__elasticsearch = libPyElk()


	def startVulTekAlert(self):
		"""
		Method that starts the application.
		"""
		self.__logger.generateApplicationLog("VulTek-Alert v3.2.1", 1, "__start", use_stream_handler = True)
		self.__logger.generateApplicationLog("@2022 Tekium. All rights reserved.", 1, "__start", use_stream_handler = True)
		self.__logger.generateApplicationLog("Author: Erick Rodriguez", 1, "__start", use_stream_handler = True)
		self.__logger.generateApplicationLog("Email: erodriguez@tekium.mx, erickrr.tbd93@gmail.com", 1, "__start", use_stream_handler = True)
		self.__logger.generateApplicationLog("License: GPLv3", 1, "__start", use_stream_handler = True)
		self.__logger.generateApplicationLog("VulTek-Alert started", 1, "__start", use_stream_handler = True)
		try:
			flag_integration_elastic = 0
			flag_exists_database_file = 0
			data_configuration = self.__utils.readYamlFile(self.__constants.PATH_FILE_CONFIGURATION)
			self.__logger.generateApplicationLog("Configuration file found in: " + self.__constants.PATH_FILE_CONFIGURATION, 1, "__readConfigurationFile", use_stream_handler = True)
			if data_configuration["integration_with_elastic"] == True:
				flag_integration_elastic = 1
				if data_configuration["use_authentication_method"] == True:
					if data_configuration["authentication_method"] == "API Key":
						conn_es = self.__elasticsearch.createConnectionToElasticSearchAPIKey(data_configuration, self.__constants.PATH_KEY_FILE)
					elif data_configuration["authentication_method"] == "HTTP authentication":
						conn_es = self.__elasticsearch.createConnectionToElasticSearchHTTPAuthentication(data_configuration, self.__constants.PATH_KEY_FILE)
				else:
					conn_es = self.__elasticsearch.createConnectionToElasticSearchWithoutAuthentication(data_configuration)
				self.__logger.generateApplicationLog("Established connection with: " + ",".join(data_configuration['es_host']) + ':' + str(data_configuration['es_port']), 1, "__connection" , use_stream_handler = True)
				self.__logger.generateApplicationLog("Elasticsearch Cluster Name: " + conn_es.info()["cluster_name"], 1, "__connection", use_stream_handler = True)
				self.__logger.generateApplicationLog("Elasticsearch Version: " + conn_es.info()["version"]["number"], 1, "__connection", use_stream_handler = True)
			passphrase = self.__utils.getPassphraseKeyFile(self.__constants.PATH_KEY_FILE)
			telegram_bot_token = self.__utils.decryptDataWithAES(data_configuration["telegram_bot_token"], passphrase).decode("utf-8")
			telegram_chat_id = self.__utils.decryptDataWithAES(data_configuration["telegram_chat_id"], passphrase).decode("utf-8")
			for unit_time in data_configuration["time_search"]:
				time_search_in_seconds = self.__utils.convertTimeToSeconds(unit_time, data_configuration["time_search"][unit_time])
			if path.exists(self.__constants.PATH_DATABASE_FILE):
				database_data = self.__utils.readYamlFile(self.__constants.PATH_DATABASE_FILE)
				self.__logger.generateApplicationLog("Database file found in: " + self.__constants.PATH_DATABASE_FILE, 1, "__readDatabaseFile", use_stream_handler = True)
			while True:
				for criticality_level in data_configuration['options_level_vulnerabilities']:
					http_response = get("https://access.redhat.com/hydra/rest/securitydata/cve.json?created_days_ago=" + str(data_configuration["created_days_ago"]) + "&severity=" + criticality_level)
					if http_response.status_code == 200:
						all_cves_data_json = http_response.json()
						if not all_cves_data_json:
							self.__logger.generateApplicationLog("No CVEs found, Level: " + criticality_level, 1, "__cveFound", use_stream_handler = True)
						else:
							for cve_data_json in all_cves_data_json:
								if self.__validateIfExistCveIdinDatabase(cve_data_json["CVE"], database_data) == False:
									self.__sendTelegramByCve(cve_data_json, telegram_bot_token, telegram_chat_id)
									database_data["list_all_cves_found"].append(cve_data_json["CVE"])
									self.__createDatabaseYamlFile(database_data["list_all_cves_found"])
									if flag_integration_elastic == 1:
										now = datetime.now()
										index_name = "vultek-alert-" + str(now.date())
										body_data = self.__generateBodyWithCVEData(cve_data_json)
										self.__elasticsearch.createDocumentInIndex(conn_es, index_name, body_data)
										self.__logger.generateApplicationLog("A document was created in ElasticSearch, Index: " + index_name + ", CVE: " + cve_data_json["CVE"], 1, "__addDocumentinElasticSearch", use_stream_handler = True, use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
				sleep(time_search_in_seconds)
		except KeyError as exception:
			self.__logger.generateApplicationLog("Key Error: " + str(exception), 3, "__start", use_stream_handler = True, use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
			exit(1)
		except ValueError as exception:
			self.__logger.generateApplicationLog("Error to encrypt or decrypt the data. For more information, see the logs.", 3, "__start", use_stream_handler = True)
			self.__logger.generateApplicationLog(exception, 3, "__start", use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
			exit(1)
		except (FileNotFoundError, OSError, IOError) as exception:
			self.__logger.generateApplicationLog("Error to open, write or read a file or directory. For more information, see the logs.", 3, "__start", use_stream_handler = True)
			self.__logger.generateApplicationLog(exception, 3, "__start", use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		except (self.__elasticsearch.exceptions.AuthenticationException, self.__elasticsearch.exceptions.ConnectionError, self.__elasticsearch.exceptions.AuthorizationException, self.__elasticsearch.exceptions.RequestError, self.__elasticsearch.exceptions.ConnectionTimeout, self.__elasticsearch.exceptions.TransportError) as exception:
			self.__logger.generateApplicationLog("Error connecting with ElasticSearch. For more information, see the logs.", 3, "__connection", use_stream_handler = True)
			self.__logger.generateApplicationLog(exception, 3, "__connection", use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
			exit(1)


	def __validateIfExistCveIdinDatabase(self, cve_id, database_data):
		"""
		Method that validates if a CVE is already in the database file.

		:arg cve_id (string): CVE identifier.
		:arg database_data (dict): Data read from the database file.
		"""
		if cve_id in database_data["list_all_cves_found"]:
			return True
		return False


	def __sendTelegramByCve(self, cve_data_json, telegram_bot_token, telegram_chat_id):
		"""
		Method that sends the CVE found as an alert to a Telegram channel.

		:arg cve_data_json (dict or JSON): JSON object that contains all the data of the CVE found.
		:arg telegram_bot_token (string): Telegram bot token that will be used to send the messages.
		:arg telegram_chat_id (string): Identifier of the Telegram channel where the messages will be sent.
		"""
		if "CVE" in cve_data_json:
			cve = cve_data_json["CVE"]
		else:
			cve = "None"
		if "public_date" in cve_data_json:
			public_date = cve_data_json["public_date"]
		else:
			public_date = "None"
		if "severity" in cve_data_json:
			severity = cve_data_json["severity"]
		else:
			severity = "None"
		if "bugzilla_description" in cve_data_json:
			bugzilla_description = cve_data_json["bugzilla_description"]
		else:
			bugzilla_description = "None"
		if "CWE" in cve_data_json:
			cwe = cve_data_json["CWE"]
		else:
			cwe = "None"
		if "cvss3_scoring_vector" in cve_data_json:
			cvss3_scoring_vector = cve_data_json["cvss3_scoring_vector"]
		else:
			cvss3_scoring_vector = "None"
		if "cvss3_score" in cve_data_json:
			cvss3_score = cve_data_json["cvss3_score"]
		else:
			cvss3_score = "None"
		self.__logger.generateApplicationLog("CVE ID: " + cve + ", Level: " + severity, 1, "__CveFound", use_stream_handler = True, use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		message_to_send = self.__generateMessageTelegram(cve, public_date, severity, bugzilla_description, cwe, cvss3_scoring_vector, cvss3_score)
		response_http_code = self.__telegram.sendMessageTelegram(telegram_bot_token, telegram_chat_id, message_to_send)
		self.__createLogByTelegramCode(response_http_code)


	def __generateBodyWithCVEData(self, cve_data_json):
		"""
		Method that generates the body of the document that will be inserted in ElasticSearch.

		Returns a JSON object that will be the one inserted in ElasticSearch.

		:arg cve_data_json (dict or JSON): JSON object that contains all the data of the CVE found.
		"""
		if "CVE" in cve_data_json:
			cve = cve_data_json["CVE"]
		else:
			cve = "None"
		if "public_date" in cve_data_json:
			public_date = cve_data_json["public_date"]
		else:
			public_date = "None"
		if "severity" in cve_data_json:
			severity = cve_data_json["severity"]
		else:
			severity = "None"
		if "bugzilla_description" in cve_data_json:
			bugzilla_description = cve_data_json["bugzilla_description"]
		else:
			bugzilla_description = "None"
		if "CWE" in cve_data_json:
			cwe = cve_data_json["CWE"]
		else:
			cwe = "None"
		if "cvss3_scoring_vector" in cve_data_json:
			cvss3_scoring_vector = cve_data_json["cvss3_scoring_vector"]
		else:
			cvss3_scoring_vector = "None"
		if "cvss3_score" in cve_data_json:
			cvss3_score = cve_data_json["cvss3_score"]
		else:
			cvss3_score = "None"
		if "affected_packages" in cve_data_json:
			affected_packages = cve_data_json["affected_packages"]
		else:
			affected_packages = None

		body_data ={
			"@timestamp" : datetime.utcnow(),
			"cve_id" : cve,
			"public_date" : public_date,
			"severity" : severity,
			"bugzilla_description" : bugzilla_description,
			"cwe" : cwe,
			"cvss3_scoring_vector" : cvss3_scoring_vector,
			"cvss3_score" : cvss3_score,
			"affected_packages" : affected_packages
		}

		return body_data
		

	def __generateMessageTelegram(self, cve, public_date, severity, bugzilla_description, cwe, cvss3_scoring_vector, cvss3_score):
		"""
		Method that generates the message to be sent via Telegram.

		Returns the message that was sent via Telegram.

		:arg cve (string): Common Vulnerabilities and Exposures ID.
		:arg public_date (string): Date of publication of the vulnerability.
		:arg severity (string): Severity level of vulnerability.
		:arg bugzilla_description (string): Description of the vulnerability. 
		:arg cwe (string): Common Weakness Enumeration ID.
		:arg cvss3_scoring_vector (string): Scoring vector of Common Vulnerability Scoring System.
		:arg cvss3_score (string): Score of Common Vulnerability Scoring System.
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


	def __createDatabaseYamlFile(self, list_all_cves):
		"""
		Method that creates the YAML file where the list of cves obtained will be stored.

		:arg list_all_cves (list): List containing the name of all obtained cves.
		"""
		database_cves_json = {
			"last_scan_time" : strftime("%c"),
			"list_all_cves_found" : list_all_cves,
			"total_cves_found" : len(list_all_cves)}

		self.__utils.createYamlFile(database_cves_json, self.__constants.PATH_DATABASE_FILE)
		self.__utils.changeOwnerToPath(self.__constants.PATH_DATABASE_FILE, self.__constants.USER, self.__constants.GROUP)


	def __createLogByTelegramCode(self, response_http_code):
		"""
		Method that creates a log based on the HTTP code received as a response.

		:arg response_http_code (integer): HTTP code received in the response when sending the alert to Telegram.
		"""
		if response_http_code == 200:
			self.__logger.generateApplicationLog("Telegram message sent.", 1, "__sendTelegramMessage", use_stream_handler = True, use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		elif response_http_code == 400:
			self.__logger.generateApplicationLog("Telegram message not sent. Status: Bad request.", 3, "__sendTelegramMessage", use_stream_handler = True, use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		elif response_http_code == 401:
			self.__logger.generateApplicationLog("Telegram message not sent. Status: Unauthorized.", 3, "__sendTelegramMessage", use_stream_handler = True, use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		elif response_http_code == 404:
			self.__logger.generateApplicationLog("Telegram message not sent. Status: Not found.", 3, "__sendTelegramMessage", use_stream_handler = True, use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)