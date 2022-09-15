from os import path
from libPyLog import libPyLog
from libPyUtils import libPyUtils
from libPyDialog import libPyDialog
from .Constants_Class import Constants

"""
Class that manages what is related to the configuration of VulTek-Alert.
"""
class VulTekAlertConfiguration:
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
			self.__createYamlFileConfiguration(data_vultek_alert_configuration)
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
			options_fields_update = self.__dialog.createCheckListDialog("Select one or more options:", 14, 70, self.__constants.OPTIONS_FIELDS_UPDATE, "Configuration Fields")
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
			elif "Created Days Ago" in options_fields_update:
				created_days_ago = self.__dialog.createInputBoxToNumberDialog("Enter how many days ago the CVEs will be obtained:", 10, 50, str(data_vultek_alert_configuration["created_days_ago"]))
				data_vultek_alert_configuration["created_days_ago"] = int(created_days_ago)
			elif "Time Search" in options_fields_update:
				for number_unit_time in data_vultek_alert_configuration["time_search"]:
					number_unit_time_search_actual = number_unit_time
				for unit_time in self.__constants.OPTIONS_UNIT_TIME:
					if unit_time[0] == number_unit_time_search_actual:
						unit_time[2] = 1
					else:
						unit_time[2] = 0
				option_unit_time_search = self.__dialog.createRadioListDialog("Select a option:", 10, 50, self.__constants.OPTIONS_UNIT_TIME, "Unit Time")
				total_unit_time_search = self.__dialog.createInputBoxToNumberDialog("Enter the total in " + str(option_unit_time_search) + " in which you want the search to be repeated:", 10, 50, str(data_vultek_alert_configuration["time_search"][number_unit_time_search_actual]))
				data_vultek_alert_configuration["time_search"] = {option_unit_time_search : int(total_unit_time_search)}
			elif "Bot Token" in options_fields_update:
				passphrase = self.__utils.getPassphraseKeyFile(self.__constants.PATH_KEY_FILE)
				telegram_bot_token = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the Telegram bot token:", 10, 50, self.__utils.decryptDataWithAES(data_vultek_alert_configuration["telegram_bot_token"], passphrase).decode("utf-8")), passphrase)
				data_vultek_alert_configuration["telegram_bot_token"] = telegram_bot_token.decode("utf-8")
			elif "Chat ID" in options_fields_update:
				passphrase = self.__utils.getPassphraseKeyFile(self.__constants.PATH_KEY_FILE)
				telegram_chat_id = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the Telegram channel identifier:", 10, 50, self.__utils.decryptDataWithAES(data_vultek_alert_configuration["telegram_chat_id"], passphrase).decode("utf-8")), passphrase)
				data_vultek_alert_configuration["telegram_chat_id"] = telegram_chat_id.decode("utf-8")
			elif "Elastic" in options_fields_update:
				options_integration_elastic = self.__dialog.createCheckListDialog("Select one or more options:", 12, 70, self.__constants.OPTIONS_INTEGRATION_ELASTIC, "Integration ElasticSearch Fields")
				if "Host" in options_integration_elastic:
					es_host = self.__dialog.createInputBoxToIPDialog("Enter the ElasticSearch IP address:", 8, 50, data_vultek_alert_configuration["es_host"])
					data_vultek_alert_configuration["es_host"] = es_host
				elif "Port" in options_integration_elastic:
					es_port = self.__dialog.createInputBoxToPortDialog("Enter the ElasticSearch listening port:", 8, 50, str(data_vultek_alert_configuration["es_port"]))
					data_vultek_alert_configuration["es_port"] = int(es_port)
				elif "SSL/TLS" in options_integration_elastic:
					if data_vultek_alert_configuration["use_ssl_tls"] == True:
						option_ssl_tls_true = self.__dialog.createRadioListDialog("Select a option:", 10, 70, self.__constants.OPTIONS_SSL_TLS_TRUE, "SSL/TLS Connection")
						if option_ssl_tls_true == "Disable":
							del data_vultek_alert_configuration["verificate_certificate_ssl"]
							if "path_certificate_file" in data_vultek_alert_configuration:
								del data_vultek_alert_configuration["path_certificate_file"]
							data_vultek_alert_configuration["use_ssl_tls"] = False
						elif option_ssl_tls_true == "Certificate Verification":
							if data_vultek_alert_configuration["verificate_certificate_ssl"] == True:
								option_verification_certificate_true = self.__dialog.createRadioListDialog("Select a option:", 10, 70, self.__constants.OPTIONS_VERIFICATION_CERTIFICATE_TRUE, "Certificate Verification")
								if option_verification_certificate_true == "Disable":
									if "path_certificate_file" in data_vultek_alert_configuration:
										del data_vultek_alert_configuration["path_certificate_file"]
									data_vultek_alert_configuration["verificate_certificate_ssl"] = False
								elif option_verification_certificate_true == "Certificate File":
									path_certificate_file = self.__dialog.createFileDialog(data_vultek_alert_configuration["path_certificate_file"], 8, 50, "Select the CA certificate:", ".pem")
									data_vultek_alert_configuration["path_certificate_file"] = path_certificate_file
							else:
								option_verification_certificate_false = self.__dialog.createRadioListDialog("Select a option:", 8, 70, self.__constants.OPTIONS_VERIFICATION_CERTIFICATE_FALSE, "Certificate Verification")
								if option_verification_certificate_false == "Enable":
									data_vultek_alert_configuration["verificate_certificate_ssl"] = True
									path_certificate_file = self.__dialog.createFileDialog("/etc/VulTek-Alert-Suite/VulTek-Alert", 8, 50, "Select the CA certificate:", ".pem")
									verificate_certificate_ssl_json = {"path_certificate_file" : path_certificate_file}
									data_vultek_alert_configuration.update(verificate_certificate_ssl_json)
					else:
						option_ssl_tls_false = self.__dialog.createRadioListDialog("Select a option:", 8, 70, self.__constants.OPTIONS_SSL_TLS_FALSE, "SSL/TLS Connection")
						data_vultek_alert_configuration["use_ssl_tls"] = True
						verificate_certificate_ssl = self.__dialog.createYesOrNoDialog("\nDo you require VulTek-Alert to validate the SSL certificate?", 8, 50, "Certificate Verification")
						if verificate_certificate_ssl == "ok":
							path_certificate_file = self.__dialog.createFileDialog("/etc/VulTek-Alert-Suite/VulTek-Alert", 8, 50, "Select the CA certificate:", ".pem")
							verificate_certificate_ssl_json = {"verificate_certificate_ssl" : True, "path_certificate_file" : path_certificate_file}
						else:
							verificate_certificate_ssl_json = {"verificate_certificate_ssl" : False}
						data_vultek_alert_configuration.update(verificate_certificate_ssl_json)
				elif "Authentication" in options_integration_elastic:
					if data_vultek_alert_configuration["use_authentication_method"] == True:
						option_authentication_method_true = self.__dialog.createRadioListDialog("Select a option:", 10, 70, self.__constants.OPTIONS_AUTHENTICATION_TRUE, "Authentication Method")
						if option_authentication_method_true == "Disable":
							data_vultek_alert_configuration["use_authentication_method"] = False
							if data_vultek_alert_configuration["authentication_method"] == "API Key":
								del data_vultek_alert_configuration["api_key_id"]
								del data_vultek_alert_configuration["api_key"]
							elif data_vultek_alert_configuration["authentication_method"] == "HTTP authentication":
								del data_vultek_alert_configuration["user_http_authentication"]
								del data_vultek_alert_configuration["password_http_authentication"]
							del data_vultek_alert_configuration["authentication_method"]
						elif option_authentication_method_true == "Authentication Method":
							print("Hola")
					else:
						option_authentication_method_false = self.__dialog.createRadioListDialog("Select a option:", 8, 50, self.__constants.OPTIONS_AUTHENTICATION_FALSE, "Authentication Method")
						if option_authentication_method_false == "Enable":
							data_vultek_alert_configuration["use_authentication_method"] = True
							option_authentication_method = self.__dialog.createRadioListDialog("Select a option:", 10, 55, self.__constants.OPTIONS_AUTHENTICATION_METHOD, "Authentication Method")
							if option_authentication_method == "HTTP authentication":
								passphrase = self.__utils.getPassphraseKeyFile(self.__constants.PATH_KEY_FILE)
								user_http_authentication = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the username for HTTP authentication:", 8, 50, "user_http"), passphrase)
								password_http_authentication = self.__utils.encryptDataWithAES(self.__dialog.createPasswordBoxDialog("Enter the user's password for HTTP authentication:", 8, 50, "password", True), passphrase)
								http_authentication_json = {"authentication_method" : "HTTP authentication", "user_http_authentication" : user_http_authentication.decode("utf-8"), "password_http_authentication" : password_http_authentication.decode("utf-8")}
								data_vultek_alert_configuration.update(http_authentication_json)
							elif option_authentication_method == "API Key":
								passphrase = self.__utils.getPassphraseKeyFile(self.__constants.PATH_KEY_FILE)
								api_key_id = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the API Key Identifier:", 8, 50, "VuaCfGcBCdbkQm-e5aOx"), passphrase)
								api_key = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the API Key:", 8, 50, "ui2lp2axTNmsyakw9tvNnw"), passphrase)
								api_key_json = {"authentication_method" : "API Key", "api_key_id" : api_key_id.decode("utf-8"), "api_key" : api_key.decode("utf-8")}
								data_vultek_alert_configuration.update(api_key_json)
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


	def __createYamlFileConfiguration(self, data_vultek_alert_configuration):
		"""
		Method that creates the YAML file corresponding to the VulTek-Alert configuration.

		:arg data_vultek_alert_configuration (dict): Data to be stored in the configuration file.
		"""
		data_vultek_alert_configuration_json = {
			"options_level_vulnerabilities" : data_vultek_alert_configuration[0],
			"created_days_ago" : int(data_vultek_alert_configuration[1]),
			"time_search" : {data_vultek_alert_configuration[2] : int(data_vultek_alert_configuration[3])},
			"telegram_bot_token" : data_vultek_alert_configuration[4],
			"telegram_chat_id" : data_vultek_alert_configuration[5],
			"integration_with_elastic" : data_vultek_alert_configuration[6]
		}

		if data_vultek_alert_configuration[6] == True:
			integration_with_elastic_json = {"es_host" : data_vultek_alert_configuration[7], "es_port" : int(data_vultek_alert_configuration[8]), "use_ssl_tls" : data_vultek_alert_configuration[9]}
			data_vultek_alert_configuration_json.update(integration_with_elastic_json)
			if data_vultek_alert_configuration[9] == True:
				if data_vultek_alert_configuration[10] == True:
					verificate_certificate_ssl_json = {"verificate_certificate_ssl" : data_vultek_alert_configuration[10], "path_certificate_file" : data_vultek_alert_configuration[11]}
					last_index = 11
				else:
					verificate_certificate_ssl_json = {"verificate_certificate_ssl" : data_vultek_alert_configuration[10]}
					last_index = 10
				data_vultek_alert_configuration_json.update(verificate_certificate_ssl_json)
			else:
				last_index = 9
			if data_vultek_alert_configuration[last_index + 1] == True:
				if data_vultek_alert_configuration[last_index + 2] == "HTTP authentication":
					http_authentication_json = {"use_authentication_method" : data_vultek_alert_configuration[last_index + 1], "authentication_method" : data_vultek_alert_configuration[last_index + 2], "user_http_authentication" : data_vultek_alert_configuration[last_index + 3], "password_http_authentication" : data_vultek_alert_configuration[last_index + 4]}
					data_vultek_alert_configuration_json.update(http_authentication_json)
				elif data_vultek_alert_configuration[last_index + 2] == "API Key":
					api_key_json = {"use_authentication_method" : data_vultek_alert_configuration[last_index + 1], "authentication_method" : data_vultek_alert_configuration[last_index + 2], "api_key_id" : data_vultek_alert_configuration[last_index + 3], "api_key" : data_vultek_alert_configuration[last_index + 4]}
					data_vultek_alert_configuration_json.update(api_key_json)
			else:
				authentication_method_json = {"use_authentication_method" : data_vultek_alert_configuration[last_index + 1]}
				data_vultek_alert_configuration_json.update(authentication_method_json)

		self.__utils.createYamlFile(data_vultek_alert_configuration_json, self.__constants.PATH_FILE_CONFIGURATION)
		self.__utils.changeOwnerToPath(self.__constants.PATH_FILE_CONFIGURATION, self.__constants.USER, self.__constants.GROUP)