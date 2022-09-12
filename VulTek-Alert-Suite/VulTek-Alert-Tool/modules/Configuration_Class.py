from os import path
from libPyLog import libPyLog
from libPyUtils import libPyUtils
from libPyDialog import libPyDialog
from .Constants_Class import Constants

"""
Class that manages what is related to the configuration of VulTek-Alert.
"""
class Configuration:
	"""
	Attribute that stores an object of the libPyUtils class.
	"""
	__utils = None

	"""
	Attribute that stores an object of the libPyLog class.
	"""
	__logger = None

	"""
	Attribute that stores an object of the libPyDialog class.
	"""
	__dialog = None

	"""
	Attribute that stores an object of the Constants class.
	"""
	__constants = None

	"""
	Attribute that stores the method to be called when the user chooses the cancel option.
	"""
	__action_to_cancel = None


	def __init__(self, action_to_cancel):
		"""
		Method that corresponds to the constructor of the class.

		:arg action_to_cancel: Method to be called when the user chooses the cancel option.
		"""
		self.__logger = libPyLog()
		self.__utils = libPyUtils()
		self.__constants = Constants()
		self.__action_to_cancel = action_to_cancel
		self.__dialog = libPyDialog(self.__constants.BACKTITLE, action_to_cancel)


	def createConfiguration(self):
		"""
		Method that collects the information for the creation of the VulTek-Alert configuration file.
		"""
		data_vultek_alert_configuration = []
		try:
			passphrase = self.__utils.getPassphraseKeyFile(self.__constants.PATH_KEY_FILE)
			options_level_vulnerabilities = self.__dialog.createCheckListDialog("Select one or more options:", 12, 50, self.__constants.OPTIONS_LEVEL_VULNERABILITIES, "Criticality Levels")
			data_vultek_alert_configuration.append(options_level_vulnerabilities)
			created_days_ago = self.__dialog.createInputBoxToNumberDialog("Enter how many days ago the CVEs will be obtained:", 10, 50, "1")
			data_vultek_alert_configuration.append(created_days_ago)
			option_unit_time_search = self.__dialog.createRadioListDialog("Select a option:", 10, 50, self.__constants.OPTIONS_UNIT_TIME, "Unit Time")
			data_vultek_alert_configuration.append(option_unit_time_search)
			total_unit_time_search = self.__dialog.createInputBoxToNumberDialog("Enter the total in " + str(option_unit_time_search) + " in which you want the search to be repeated:", 10, 50, "5")
			data_vultek_alert_configuration.append(total_unit_time_search)
			telegram_bot_token = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the Telegram bot token:", 10, 50, "751988420:AAHrzn7RXWxVQQNha0tQUzyouE5lUcPde1g"), passphrase)
			data_vultek_alert_configuration.append(telegram_bot_token.decode("utf-8"))
			telegram_chat_id = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the Telegram channel identifier:", 10, 50, "-1002365478941"), passphrase)
			data_vultek_alert_configuration.append(telegram_chat_id.decode("utf-8"))
			integration_with_elastic = self.__dialog.createYesOrNoDialog("\nDo you want VulTek-Alert to integrate with ElasticSearch?", 8, 50, "Integration With ElasticSearch")
			if integration_with_elastic == "ok":
				data_vultek_alert_configuration.append(True)
				es_host = self.__dialog.createInputBoxToIPDialog("Enter the ElasticSearch IP address:", 8, 50, "localhost")
				data_vultek_alert_configuration.append(es_host)
				es_port = self.__dialog.createInputBoxToPortDialog("Enter the ElasticSearch listening port:", 8, 50, "9200")
				data_vultek_alert_configuration.append(es_port)
				use_ssl_tls = self.__dialog.createYesOrNoDialog("\nDo you require VulTek-Alert to communicate with ElasticSearch using the SSL/TLS protocol?", 8, 50, "SSL/TLS Connection")
				if use_ssl_tls == "ok":
					data_vultek_alert_configuration.append(True)
					verificate_certificate_ssl = self.__dialog.createYesOrNoDialog("\nDo you require VulTek-Alert to verificate the SSL certificate?", 8, 50, "Certificate Verification")
					if verificate_certificate_ssl == "ok":
						data_vultek_alert_configuration.append(True)
						path_certificate_file = self.__dialog.createFileDialog("/etc/VulTek-Alert-Suite/VulTek-Alert", 8, 50, "Select the CA certificate:", ".pem")
						data_vultek_alert_configuration.append(path_certificate_file)
					else:
						data_vultek_alert_configuration.append(False)
				else:
					data_vultek_alert_configuration.append(False)
				use_authentication_method = self.__dialog.createYesOrNoDialog("\nIs it required to use an authentication mechanism (HTTP authentication or API key) to connect to ElasticSearch?", 8, 50, "Authentication Method")
				if use_authentication_method == "ok":
					data_vultek_alert_configuration.append(True)
					option_authentication_method = self.__dialog.createRadioListDialog("Select a option:", 10, 55, self.__constants.OPTIONS_AUTHENTICATION_METHOD, "Authentication Method")
					data_vultek_alert_configuration.append(option_authentication_method)
					if option_authentication_method == "HTTP authentication":
						user_http_authentication = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the username for HTTP authentication:", 8, 50, "user_http"), passphrase)
						data_vultek_alert_configuration.append(user_http_authentication.decode("utf-8"))
						password_http_authentication = self.__utils.encryptDataWithAES(self.__dialog.createPasswordBoxDialog("Enter the user's password for HTTP authentication:", 8, 50, "password", True), passphrase)
						data_vultek_alert_configuration.append(password_http_authentication.decode("utf-8"))
					elif option_authentication_method == "API Key":
						api_key_id = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the API Key Identifier:", 8, 50, "VuaCfGcBCdbkQm-e5aOx"), passphrase)
						data_vultek_alert_configuration.append(api_key_id.decode("utf-8"))
						api_key = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the API Key:", 8, 50, "ui2lp2axTNmsyakw9tvNnw"), passphrase)
						data_vultek_alert_configuration.append(api_key.decode("utf-8"))
				else:
					data_vultek_alert_configuration.append(False)
				else:
					data_vultek_alert_configuration.append(False)
			self.__createFileYamlConfiguration(data_vultek_alert_configuration)
			if path.exists(self.__constants.PATH_FILE_CONFIGURATION):
				self.__dialog.createMessageDialog("\nConfiguration file created.", 7, 50, "Notification Message")
				self.__logger.generateApplicationLog("Configuration file created", 1, "__createConfiguration", use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		except ValueError as exception:
			self.__dialog.createMessageDialog("\nError to encrypt or decrypt the data. For more information, see the logs.", 8, 50, "Error Message")
			self.__logger.generateApplicationLog(exception, 3, "__createConfiguration", use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		except (FileNotFoundError, IOError, OSError) as exception:
			self.__dialog.createMessageDialog("\nError to create, open or read a file or path. For more information, see the logs.", 8, 50, "Error Message")
			self.__logger.generateApplicationLog(exception, 3, "__createConfiguration", use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		finally:
			self.__action_to_cancel()


	def modifyConfiguration(self):
		"""
		Method that allows to modify one or more values in the VulTek-Alert configuration file.
		"""
		try:
			options_fields_update = self.__dialog.createCheckListDialog("Select one or more options:", 10, 70, self.__constants.OPTIONS_FIELDS_UPDATE, "Configuration Fields")
			data_vultek_alert_configuration = self.__utils.readYamlFile(self.__constants.PATH_FILE_CONFIGURATION)
			hash_file_configuration_original = self.__utils.getHashFunctionToFile(self.__constants.PATH_FILE_CONFIGURATION)
			if "Level" in options_fields_update:
				if "low" in data_vultek_alert_configuration["options_level_vulnerabilities"]:
					self.__constants.OPTIONS_LEVEL_VULNERABILITIES[0][2] = 1
				if "moderate" in data_vultek_alert_configuration["options_level_vulnerabilities"]:
					self.__constants.OPTIONS_LEVEL_VULNERABILITIES[1][2] = 1
				if "important" in data_vultek_alert_configuration["options_level_vulnerabilities"]:
					self.__constants.OPTIONS_LEVEL_VULNERABILITIES[2][2] = 1
				if "critical" in data_vultek_alert_configuration["options_level_vulnerabilities"]:
					self.__constants.OPTIONS_LEVEL_VULNERABILITIES[3][2] = 1
				options_level_vulnerabilities = self.__dialog.createCheckListDialog("Select one or more options:", 12, 50, self.__constants.OPTIONS_LEVEL_VULNERABILITIES, "Vulnerabilities Levels")
				data_vultek_alert_configuration["options_level_vulnerabilities"] = options_level_vulnerabilities
				for i in range(4):
					self.__constants.OPTIONS_LEVEL_VULNERABILITIES[i][2] = 0
			if "Bot Token" in options_fields_update:
				passphrase = self.__utils.getPassphraseKeyFile(self.__constants.PATH_KEY_FILE)
				telegram_bot_token = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the Telegram bot token:", 10, 50, self.__utils.decryptDataWithAES(data_vultek_alert_configuration["telegram_bot_token"], passphrase).decode("utf-8")), passphrase)
				data_vultek_alert_configuration["telegram_bot_token"] = telegram_bot_token.decode("utf-8")
			if "Chat ID" in options_fields_update:
				passphrase = self.__utils.getPassphraseKeyFile(self.__constants.PATH_KEY_FILE)
				telegram_chat_id = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the Telegram channel identifier:", 10, 50, self.__utils.decryptDataWithAES(data_vultek_alert_configuration["telegram_chat_id"], passphrase).decode("utf-8")), passphrase)
				data_vultek_alert_configuration["telegram_chat_id"] = telegram_chat_id.decode("utf-8")
			self.__utils.createYamlFile(data_vultek_alert_configuration, self.__constants.PATH_FILE_CONFIGURATION)
			hash_file_configuration_new = self.__utils.getHashFunctionToFile(self.__constants.PATH_FILE_CONFIGURATION)
			if hash_file_configuration_new == hash_file_configuration_original:
				self.__dialog.createMessageDialog("\nThe configuration file was not modified.", 7, 50, "Notification Message")
			else:
				self.__dialog.createMessageDialog("\nThe configuration file was modified.", 7, 50, "Notification Message")
				self.__logger.generateApplicationLog("The configuration file was modified", 2, "__updateConfiguration", use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		except KeyError as exception:
			self.__dialog.createMessageDialog("\nKey Error: " + str(exception), 7, 50, "Error Message")
			self.__logger.generateApplicationLog("Key Error: " + str(exception), 3, "__updateConfiguration", use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		except ValueError as exception:
			self.__dialog.createMessageDialog("\nError to encrypt or decrypt the data. For more information, see the logs.", 8, 50, "Error Message")
			self.__logger.generateApplicationLog(exception, 3, "__updateConfiguration", use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		except (IOError, FileNotFoundError, OSError) as exception:
			self.__dialog.createMessageDialog("\nError to open, read or modify a file. For more information, see the logs.", 8, 50, "Error Message")
			self.__logger.generateApplicationLog(exception, 3, "__updateConfiguration", use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		finally:
			self.__action_to_cancel()


	def __createFileYamlConfiguration(self, data_vultek_alert_configuration):
		"""
		Method that creates the YAML file corresponding to the VulTek-Alert configuration.

		:arg data_vultek_alert_configuration: Data to be stored in the configuration file.
		"""
		data_vultek_alert_configuration_json = {
			"options_level_vulnerabilities" : data_vultek_alert_configuration[0],
			"telegram_bot_token" : data_vultek_alert_configuration[1],
			"telegram_chat_id" : data_vultek_alert_configuration[2]
		}

		self.__utils.createYamlFile(data_vultek_alert_configuration_json, self.__constants.PATH_FILE_CONFIGURATION)
		self.__utils.changeOwnerToPath(self.__constants.PATH_FILE_CONFIGURATION, self.__constants.USER, self.__constants.GROUP)