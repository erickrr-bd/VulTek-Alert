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
		vultek_alert_data = []
		try:
			passphrase = self.__utils.getPassphraseKeyFile(self.__constants.PATH_KEY_FILE)
			options_level_vulnerabilities = self.__dialog.createCheckListDialog("Select one or more options:", 11, 50, self.__constants.OPTIONS_LEVEL_VULNERABILITIES, "Criticality Levels")
			vultek_alert_data.append(options_level_vulnerabilities)
			created_days_ago = self.__dialog.createInputBoxToNumberDialog("Enter how many days ago the CVEs will be obtained:", 9, 50, "1")
			vultek_alert_data.append(created_days_ago)
			option_unit_time_search = self.__dialog.createRadioListDialog("Select a option:", 10, 50, self.__constants.OPTIONS_UNIT_TIME, "Unit Time")
			vultek_alert_data.append(option_unit_time_search)
			total_unit_time_search = self.__dialog.createInputBoxToNumberDialog("Enter the total in " + str(option_unit_time_search) + " in which you want the search to be repeated:", 9, 50, "5")
			vultek_alert_data.append(total_unit_time_search)
			telegram_bot_token = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the Telegram bot token:", 8, 50, "751988420:AAHrzn7RXWxVQQNha0tQUzyouE5lUcPde1g"), passphrase)
			vultek_alert_data.append(telegram_bot_token.decode("utf-8"))
			telegram_chat_id = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the Telegram channel identifier:", 8, 50, "-1002365478941"), passphrase)
			vultek_alert_data.append(telegram_chat_id.decode("utf-8"))
			integration_with_elastic = self.__dialog.createYesOrNoDialog("\nDo you want VulTek-Alert to integrate with ElasticSearch?", 8, 50, "Integration With ElasticSearch")
			if integration_with_elastic == "ok":
				vultek_alert_data.append(True)
				number_master_nodes_es = self.__dialog.createInputBoxToNumberDialog("Enter the number of master nodes in the ElasticSearch cluster:", 9, 50, "1")
				list_to_form_dialog = self.__utils.createListToDialogForm(int(number_master_nodes_es), "IP Address")
				ips_master_nodes_es = self.__dialog.createFormDialog("Enter the IP addresses of the ElasticSearch master nodes:", list_to_form_dialog, 15, 50, "ElasticSearch Hosts")
				vultek_alert_data.append(ips_master_nodes_es)
				es_port = self.__dialog.createInputBoxToPortDialog("Enter the ElasticSearch listening port:", 8, 50, "9200")
				vultek_alert_data.append(es_port)
				use_ssl_tls = self.__dialog.createYesOrNoDialog("\nDo you require VulTek-Alert to communicate with ElasticSearch using the SSL/TLS protocol?", 8, 50, "SSL/TLS Connection")
				if use_ssl_tls == "ok":
					vultek_alert_data.append(True)
					verificate_certificate_ssl = self.__dialog.createYesOrNoDialog("\nDo you require VulTek-Alert to verificate the SSL certificate?", 8, 50, "Certificate Verification")
					if verificate_certificate_ssl == "ok":
						vultek_alert_data.append(True)
						path_certificate_file = self.__dialog.createFileDialog("/etc/VulTek-Alert-Suite/VulTek-Alert", 8, 50, "Select the CA certificate:", ".pem")
						vultek_alert_data.append(path_certificate_file)
					else:
						vultek_alert_data.append(False)
				else:
					vultek_alert_data.append(False)
				use_authentication_method = self.__dialog.createYesOrNoDialog("\nIs it required to use an authentication mechanism (HTTP authentication or API key) to connect to ElasticSearch?", 9, 50, "Authentication Method")
				if use_authentication_method == "ok":
					vultek_alert_data.append(True)
					option_authentication_method = self.__dialog.createRadioListDialog("Select a option:", 9, 55, self.__constants.OPTIONS_AUTHENTICATION_METHOD, "Authentication Method")
					vultek_alert_data.append(option_authentication_method)
					if option_authentication_method == "HTTP authentication":
						user_http_authentication = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the username for HTTP authentication:", 8, 50, "user_http"), passphrase)
						vultek_alert_data.append(user_http_authentication.decode("utf-8"))
						password_http_authentication = self.__utils.encryptDataWithAES(self.__dialog.createPasswordBoxDialog("Enter the user's password for HTTP authentication:", 9, 50, "password", True), passphrase)
						vultek_alert_data.append(password_http_authentication.decode("utf-8"))
					elif option_authentication_method == "API Key":
						api_key_id = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the API Key Identifier:", 8, 50, "VuaCfGcBCdbkQm-e5aOx"), passphrase)
						vultek_alert_data.append(api_key_id.decode("utf-8"))
						api_key = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the API Key:", 8, 50, "ui2lp2axTNmsyakw9tvNnw"), passphrase)
						vultek_alert_data.append(api_key.decode("utf-8"))
				else:
					vultek_alert_data.append(False)
			else:
				vultek_alert_data.append(False)
			self.__createYamlFileConfiguration(vultek_alert_data)
			if path.exists(self.__constants.PATH_VULTEK_ALERT_CONFIGURATION_FILE):
				self.__dialog.createMessageDialog("\nVulTek-Alert configuration file created.", 7, 50, "Notification Message")
				self.__logger.generateApplicationLog("VulTek-Alert configuration file created", 1, "__createVulTelkAlertConfiguration", use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		except ValueError as exception:
			self.__dialog.createMessageDialog("\nError to encrypt or decrypt the data. For more information, see the logs.", 8, 50, "Error Message")
			self.__logger.generateApplicationLog(exception, 3, "__createVulTelkAlertConfiguration", use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		except (FileNotFoundError, IOError, OSError) as exception:
			self.__dialog.createMessageDialog("\nError to create, open or read a file or path. For more information, see the logs.", 8, 50, "Error Message")
			self.__logger.generateApplicationLog(exception, 3, "__createVulTelkAlertConfiguration", use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		finally:
			self.__action_to_cancel()


	def modifyConfiguration(self):
		"""
		Method that allows to modify one or more values in the VulTek-Alert configuration file.
		"""
		try:
			options_vultek_alert_update = self.__dialog.createCheckListDialog("Select one or more options:", 13, 70, self.__constants.OPTIONS_VULTEK_ALERT_UPDATE, "VulTek-Alert Configuration Update")
			vultek_alert_data = self.__utils.readYamlFile(self.__constants.PATH_VULTEK_ALERT_CONFIGURATION_FILE)
			hash_file_configuration_original = self.__utils.getHashFunctionToFile(self.__constants.PATH_VULTEK_ALERT_CONFIGURATION_FILE)
			if "Level" in options_vultek_alert_update:
				if "low" in vultek_alert_data["options_level_vulnerabilities"]:
					self.__constants.OPTIONS_LEVEL_VULNERABILITIES[0][2] = 1
				if "moderate" in vultek_alert_data["options_level_vulnerabilities"]:
					self.__constants.OPTIONS_LEVEL_VULNERABILITIES[1][2] = 1
				if "important" in vultek_alert_data["options_level_vulnerabilities"]:
					self.__constants.OPTIONS_LEVEL_VULNERABILITIES[2][2] = 1
				if "critical" in vultek_alert_data["options_level_vulnerabilities"]:
					self.__constants.OPTIONS_LEVEL_VULNERABILITIES[3][2] = 1
				options_level_vulnerabilities = self.__dialog.createCheckListDialog("Select one or more options:", 11, 50, self.__constants.OPTIONS_LEVEL_VULNERABILITIES, "Vulnerabilities Levels")
				vultek_alert_data["options_level_vulnerabilities"] = options_level_vulnerabilities
				for i in range(4):
					self.__constants.OPTIONS_LEVEL_VULNERABILITIES[i][2] = 0
			if "Created Days Ago" in options_vultek_alert_update:
				created_days_ago = self.__dialog.createInputBoxToNumberDialog("Enter how many days ago the CVEs will be obtained:", 9, 50, str(vultek_alert_data["created_days_ago"]))
				vultek_alert_data["created_days_ago"] = int(created_days_ago)
			if "Time Search" in options_vultek_alert_update:
				for number_unit_time in vultek_alert_data["time_search"]:
					number_unit_time_search_actual = number_unit_time
				for unit_time in self.__constants.OPTIONS_UNIT_TIME:
					if unit_time[0] == number_unit_time_search_actual:
						unit_time[2] = 1
					else:
						unit_time[2] = 0
				option_unit_time_search = self.__dialog.createRadioListDialog("Select a option:", 10, 50, self.__constants.OPTIONS_UNIT_TIME, "Unit Time")
				total_unit_time_search = self.__dialog.createInputBoxToNumberDialog("Enter the total in " + str(option_unit_time_search) + " in which you want the search to be repeated:", 9, 50, str(vultek_alert_data["time_search"][number_unit_time_search_actual]))
				vultek_alert_data["time_search"] = {option_unit_time_search : int(total_unit_time_search)}
			if "Bot Token" in options_vultek_alert_update:
				passphrase = self.__utils.getPassphraseKeyFile(self.__constants.PATH_KEY_FILE)
				telegram_bot_token = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the Telegram bot token:", 8, 50, self.__utils.decryptDataWithAES(vultek_alert_data["telegram_bot_token"], passphrase).decode("utf-8")), passphrase)
				vultek_alert_data["telegram_bot_token"] = telegram_bot_token.decode("utf-8")
			if "Chat ID" in options_vultek_alert_update:
				passphrase = self.__utils.getPassphraseKeyFile(self.__constants.PATH_KEY_FILE)
				telegram_chat_id = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the Telegram channel identifier:", 8, 50, self.__utils.decryptDataWithAES(vultek_alert_data["telegram_chat_id"], passphrase).decode("utf-8")), passphrase)
				vultek_alert_data["telegram_chat_id"] = telegram_chat_id.decode("utf-8")
			if "Elastic" in options_vultek_alert_update:
				if vultek_alert_data["integration_with_elastic"] == True:
					option_integration_es_true = self.__dialog.createRadioListDialog("Select a option", 9, 60, self.__constants.OPTIONS_INTEGRATION_ES_TRUE, "Integration with ElasticSearch")
					if option_integration_es_true == "Disable":
						vultek_alert_data["integration_with_elastic"] = False
						del vultek_alert_data["es_host"]
						del vultek_alert_data["es_port"]
						if vultek_alert_data["use_ssl_tls"] == True:
							if vultek_alert_data["verificate_certificate_ssl"] == True:
								del vultek_alert_data["path_certificate_file"]
							del vultek_alert_data["verificate_certificate_ssl"]
						if vultek_alert_data["use_authentication_method"] == True:
							if vultek_alert_data["authentication_method"] == "HTTP authentication":
								del vultek_alert_data["user_http_authentication"]
								del vultek_alert_data["password_http_authentication"]
							elif vultek_alert_data["authentication_method"] == "API Key":
								del vultek_alert_data["api_key_id"]
								del vultek_alert_data["api_key"]
							del vultek_alert_data["authentication_method"]
						del vultek_alert_data["use_ssl_tls"]
						del vultek_alert_data["use_authentication_method"]
					else:
						options_integration_elastic = self.__dialog.createCheckListDialog("Select one or more options:", 11, 70, self.__constants.OPTIONS_INTEGRATION_ELASTIC, "Integration ElasticSearch Fields")
						if "Host" in options_integration_elastic:
							option_es_hosts_update = self.__dialog.createMenuDialog("Select a option:", 10, 50, self.__constants.OPTIONS_ES_HOSTS_UPDATE, "ELasticSearch Hosts Menu")
							if option_es_hosts_update == "1":
								number_master_nodes_es = self.__dialog.createInputBoxToNumberDialog("Enter the number of master nodes in the ElasticSearch cluster:", 9, 50, "1")
								list_to_form_dialog = self.__utils.createListToDialogForm(int(number_master_nodes_es), "IP Address")
								ips_master_nodes_es = self.__dialog.createFormDialog("Enter the IP addresses of the ElasticSearch master nodes:", list_to_form_dialog, 15, 50, "Add ElasticSearch Hosts")
								vultek_alert_data["es_host"].extend(ips_master_nodes_es)
							elif option_es_hosts_update == "2":
								list_to_form_dialog = self.__utils.convertListToDialogForm(vultek_alert_data["es_host"], "IP Address")
								ips_master_nodes_es = self.__dialog.createFormDialog("Enter the IP addresses of the ElasticSearch master nodes:", list_to_form_dialog, 15, 50, "Update ElasticSearch Hosts")
								vultek_alert_data["es_host"] = ips_master_nodes_es
							elif option_es_hosts_update == "3":
								list_to_dialog = self.__utils.convertListToDialogList(vultek_alert_data["es_host"], "IP Address")
								options_es_hosts_remove = self.__dialog.createCheckListDialog("Select one or more options:", 15, 50, list_to_dialog, "Remove ElasticSearch Hosts")
								for option in options_es_hosts_remove:
									vultek_alert_data["es_host"].remove(option)
						if "Port" in options_integration_elastic:
							es_port = self.__dialog.createInputBoxToPortDialog("Enter the ElasticSearch listening port:", 8, 50, str(vultek_alert_data["es_port"]))
							vultek_alert_data["es_port"] = int(es_port)
						if "SSL/TLS" in options_integration_elastic:
							if vultek_alert_data["use_ssl_tls"] == True:
								option_ssl_tls_true = self.__dialog.createRadioListDialog("Select a option:", 9, 70, self.__constants.OPTIONS_SSL_TLS_TRUE, "SSL/TLS Connection")
								if option_ssl_tls_true == "Disable":
									del vultek_alert_data["verificate_certificate_ssl"]
									if "path_certificate_file" in vultek_alert_data:
										del vultek_alert_data["path_certificate_file"]
									vultek_alert_data["use_ssl_tls"] = False
								elif option_ssl_tls_true == "Certificate Verification":
									if vultek_alert_data["verificate_certificate_ssl"] == True:
										option_verification_certificate_true = self.__dialog.createRadioListDialog("Select a option:", 9, 70, self.__constants.OPTIONS_VERIFICATION_CERTIFICATE_TRUE, "Certificate Verification")
										if option_verification_certificate_true == "Disable":
											if "path_certificate_file" in vultek_alert_data:
												del vultek_alert_data["path_certificate_file"]
											vultek_alert_data["verificate_certificate_ssl"] = False
										elif option_verification_certificate_true == "Certificate File":
											path_certificate_file = self.__dialog.createFileDialog(vultek_alert_data["path_certificate_file"], 8, 50, "Select the CA certificate:", ".pem")
											vultek_alert_data["path_certificate_file"] = path_certificate_file
									else:
										option_verification_certificate_false = self.__dialog.createRadioListDialog("Select a option:", 8, 70, self.__constants.OPTIONS_VERIFICATION_CERTIFICATE_FALSE, "Certificate Verification")
										if option_verification_certificate_false == "Enable":
											vultek_alert_data["verificate_certificate_ssl"] = True
											path_certificate_file = self.__dialog.createFileDialog("/etc/VulTek-Alert-Suite/VulTek-Alert", 8, 50, "Select the CA certificate:", ".pem")
											verificate_certificate_ssl_json = {"path_certificate_file" : path_certificate_file}
											vultek_alert_data.update(verificate_certificate_ssl_json)
							else:
								option_ssl_tls_false = self.__dialog.createRadioListDialog("Select a option:", 8, 70, self.__constants.OPTIONS_SSL_TLS_FALSE, "SSL/TLS Connection")
								vultek_alert_data["use_ssl_tls"] = True
								verificate_certificate_ssl = self.__dialog.createYesOrNoDialog("\nDo you require VulTek-Alert to validate the SSL certificate?", 8, 50, "Certificate Verification")
								if verificate_certificate_ssl == "ok":
									path_certificate_file = self.__dialog.createFileDialog("/etc/VulTek-Alert-Suite/VulTek-Alert", 8, 50, "Select the CA certificate:", ".pem")
									verificate_certificate_ssl_json = {"verificate_certificate_ssl" : True, "path_certificate_file" : path_certificate_file}
								else:
									verificate_certificate_ssl_json = {"verificate_certificate_ssl" : False}
								vultek_alert_data.update(verificate_certificate_ssl_json)
						if "Authentication" in options_integration_elastic:
							if vultek_alert_data["use_authentication_method"] == True:
								option_authentication_true = self.__dialog.createRadioListDialog("Select a option:", 9, 50, self.__constants.OPTIONS_AUTHENTICATION_TRUE, "Authentication Method")
								if option_authentication_true == "Data":
									if vultek_alert_data["authentication_method"] == "HTTP authentication":
										option_authentication_method_true = self.__dialog.createRadioListDialog("Select a option:", 9, 60, self.__constants.OPTIONS_AUTHENTICATION_METHOD_TRUE, "HTTP Authentication")
										if option_authentication_method_true == "Data":
											options_http_authentication_data = self.__dialog.createRadioListDialog("Select a option:", 9, 60, self.__constants.OPTIONS_HTTP_AUTHENTICATION_DATA, "HTTP Authentication")	
											if "Username" in options_http_authentication_data:
												passphrase = self.__utils.getPassphraseKeyFile(self.__constants.PATH_KEY_FILE)
												user_http_authentication = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the username for HTTP authentication:", 8, 50, "user_http"), passphrase)									
												vultek_alert_data["user_http_authentication"] = user_http_authentication.decode("utf-8")
											elif "Password" in options_http_authentication_data:
												passphrase = self.__utils.getPassphraseKeyFile(self.__constants.PATH_KEY_FILE)
												password_http_authentication = self.__utils.encryptDataWithAES(self.__dialog.createPasswordBoxDialog("Enter the user's password for HTTP authentication:", 8, 50, "password", True), passphrase)
												vultek_alert_data["password_http_authentication"] = password_http_authentication.decode("utf-8")
										elif option_authentication_method_true == "Disable":
											passphrase = self.__utils.getPassphraseKeyFile(self.__constants.PATH_KEY_FILE)
											api_key_id = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the API Key Identifier:", 8, 50, "VuaCfGcBCdbkQm-e5aOx"), passphrase)
											api_key = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the API Key:", 8, 50, "ui2lp2axTNmsyakw9tvNnw"), passphrase)
											del vultek_alert_data["user_http_authentication"]
											del vultek_alert_data["password_http_authentication"]
											vultek_alert_data["authentication_method"] = "API Key"
											api_key_json = {"api_key_id" : api_key_id.decode("utf-8"), "api_key" : api_key.decode("utf-8")}
											vultek_alert_data.update(api_key_json)
									elif vultek_alert_data["authentication_method"] == "API Key":
										option_authentication_method_true = self.__dialog.createRadioListDialog("Select a option:", 9, 60, self.__constants.OPTIONS_AUTHENTICATION_METHOD_TRUE, "API Key")
										if option_authentication_method_true == "Data":
											options_api_key_data = self.__dialog.createCheckListDialog("Select one or more options:", 9, 50, self.__constants.OPTIONS_API_KEY_DATA, "API Key")
											if "API Key ID" in options_api_key_data:
												passphrase = self.__utils.getPassphraseKeyFile(self.__constants.PATH_KEY_FILE)
												api_key_id = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the API Key Identifier:", 8, 50, "VuaCfGcBCdbkQm-e5aOx"), passphrase)
												vultek_alert_data["api_key_id"] = api_key_id.decode("utf-8")
											elif "API Key" in options_api_key_data:
												passphrase = self.__utils.getPassphraseKeyFile(self.__constants.PATH_KEY_FILE)
												api_key = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the API Key:", 8, 50, "ui2lp2axTNmsyakw9tvNnw"), passphrase)
												vultek_alert_data["api_key"] = api_key.decode("utf-8")
										elif option_authentication_method_true == "Disable":
											passphrase = self.__utils.getPassphraseKeyFile(self.__constants.PATH_KEY_FILE)
											user_http_authentication = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the username for HTTP authentication:", 8, 50, "user_http"), passphrase)
											password_http_authentication = self.__utils.encryptDataWithAES(self.__dialog.createPasswordBoxDialog("Enter the user's password for HTTP authentication:", 8, 50, "password", True), passphrase)
											del vultek_alert_data["api_key_id"]
											del vultek_alert_data["api_key"]
											vultek_alert_data["authentication_method"] = "HTTP authentication"
											http_authentication_json = {"user_http_authentication" : user_http_authentication.decode("utf-8"), "password_http_authentication" : password_http_authentication.decode("utf-8")}
											vultek_alert_data.update(http_authentication_json)
								elif option_authentication_true == "Disable":
									vultek_alert_data["use_authentication_method"] = False
									if vultek_alert_data["authentication_method"] == "HTTP authentication":
										del vultek_alert_data["user_http_authentication"]
										del vultek_alert_data["password_http_authentication"]
									elif vultek_alert_data["authentication_method"] == "API Key":
										del vultek_alert_data["api_key_id"]
										del vultek_alert_data["api_key"]
									del vultek_alert_data["authentication_method"]
							else:
								option_authentication_false = self.__dialog.createRadioListDialog("Select a option:", 8, 50, self.__constants.OPTIONS_AUTHENTICATION_FALSE, "Authentication Method")
								if option_authentication_false == "Enable":
									vultek_alert_data["use_authentication_method"] = True
									option_authentication_method = self.__dialog.createRadioListDialog("Select a option:", 10, 55, self.__constants.OPTIONS_AUTHENTICATION_METHOD, "Authentication Method")
									if option_authentication_method == "HTTP authentication":
										passphrase = self.__utils.getPassphraseKeyFile(self.__constants.PATH_KEY_FILE)
										user_http_authentication = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the username for HTTP authentication:", 8, 50, "user_http"), passphrase)
										password_http_authentication = self.__utils.encryptDataWithAES(self.__dialog.createPasswordBoxDialog("Enter the user's password for HTTP authentication:", 8, 50, "password", True), passphrase)
										http_authentication_json = {"authentication_method" : "HTTP authentication", "user_http_authentication" : user_http_authentication.decode("utf-8"), "password_http_authentication" : password_http_authentication.decode("utf-8")}
										vultek_alert_data.update(http_authentication_json)
									elif option_authentication_method == "API Key":
										passphrase = self.__utils.getPassphraseKeyFile(self.__constants.PATH_KEY_FILE)
										api_key_id = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the API Key Identifier:", 8, 50, "VuaCfGcBCdbkQm-e5aOx"), passphrase)
										api_key = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the API Key:", 8, 50, "ui2lp2axTNmsyakw9tvNnw"), passphrase)
										api_key_json = {"authentication_method" : "API Key", "api_key_id" : api_key_id.decode("utf-8"), "api_key" : api_key.decode("utf-8")}
										vultek_alert_data.update(api_key_json)
				else:
					option_integration_es_false = self.__dialog.createRadioListDialog("Select a option", 8, 60, self.__constants.OPTIONS_INTEGRATION_ES_FALSE, "Integration with ElasticSearch")
					if option_integration_es_false == "Enable":
						vultek_alert_data["integration_with_elastic"] = True
						number_master_nodes_es = self.__dialog.createInputBoxToNumberDialog("Enter the number of master nodes in the ElasticSearch cluster:", 9, 50, "1")
						list_to_form_dialog = self.__utils.createListToDialogForm(int(number_master_nodes_es), "IP Address")
						ips_master_nodes_es = self.__dialog.createFormDialog("Enter the IP addresses of the ElasticSearch master nodes:", list_to_form_dialog, 15, 50, "ElasticSearch Hosts")
						es_port = self.__dialog.createInputBoxToPortDialog("Enter the ElasticSearch listening port:", 8, 50, "9200")
						integration_with_elastic_json = {"es_host" : ips_master_nodes_es, "es_port" : int(es_port)}
						vultek_alert_data.update(integration_with_elastic_json)
						use_ssl_tls = self.__dialog.createYesOrNoDialog("\nDo you require VulTek-Alert to communicate with ElasticSearch using the SSL/TLS protocol?", 8, 50, "SSL/TLS Connection")
						if use_ssl_tls == "ok":
							verificate_certificate_ssl = self.__dialog.createYesOrNoDialog("\nDo you require VulTek-Alert to verificate the SSL certificate?", 8, 50, "Certificate Verification")
							if verificate_certificate_ssl == "ok":
								path_certificate_file = self.__dialog.createFileDialog("/etc/VulTek-Alert-Suite/VulTek-Alert", 8, 50, "Select the CA certificate:", ".pem")
								use_ssl_tls_json = {"use_ssl_tls" : True, "verificate_certificate_ssl" : True, "path_certificate_file" : path_certificate_file}
							else:
								use_ssl_tls_json = {"use_ssl_tls" : True, "verificate_certificate_ssl" : False}
						else:
							use_ssl_tls_json = {"use_ssl_tls" : False}
						vultek_alert_data.update(use_ssl_tls_json)
						use_authentication_method = self.__dialog.createYesOrNoDialog("\nIs it required to use an authentication mechanism (HTTP authentication or API key) to connect to ElasticSearch?", 9, 50, "Authentication Method")
						if use_authentication_method == "ok":
							passphrase = self.__utils.getPassphraseKeyFile(self.__constants.PATH_KEY_FILE)
							option_authentication_method = self.__dialog.createRadioListDialog("Select a option:", 9, 55, self.__constants.OPTIONS_AUTHENTICATION_METHOD, "Authentication Method")
							if option_authentication_method == "HTTP authentication":
								user_http_authentication = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the username for HTTP authentication:", 8, 50, "user_http"), passphrase)
								password_http_authentication = self.__utils.encryptDataWithAES(self.__dialog.createPasswordBoxDialog("Enter the user's password for HTTP authentication:", 9, 50, "password", True), passphrase)
								use_authentication_method_json = {"use_authentication_method" : True, "authentication_method" : "HTTP authentication", "user_http_authentication" : user_http_authentication.decode("utf-8"), "password_http_authentication" : password_http_authentication.decode("utf-8")}
							elif option_authentication_method == "API Key":
								api_key_id = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the API Key Identifier:", 8, 50, "VuaCfGcBCdbkQm-e5aOx"), passphrase)
								api_key = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the API Key:", 8, 50, "ui2lp2axTNmsyakw9tvNnw"), passphrase)
								use_authentication_method_json = {"use_authentication_method" : True, "authentication_method" : "API Key", "api_key_id" : api_key_id.decode("utf-8"), "api_key" : api_key.decode("utf-8")}
						else:
							use_authentication_method_json = {"use_authentication_method" :  False}
						vultek_alert_data.update(use_authentication_method_json)
			self.__utils.createYamlFile(vultek_alert_data, self.__constants.PATH_VULTEK_ALERT_CONFIGURATION_FILE)
			hash_file_configuration_new = self.__utils.getHashFunctionToFile(self.__constants.PATH_VULTEK_ALERT_CONFIGURATION_FILE)
			if hash_file_configuration_new == hash_file_configuration_original:
				self.__dialog.createMessageDialog("\nVulTek-Alert configuration file not modified.", 7, 50, "Notification Message")
			else:
				self.__dialog.createMessageDialog("\nVulTek-Alert configuration file modified.", 7, 50, "Notification Message")
				self.__logger.generateApplicationLog("VulTek-Alert configuration file modified", 2, "__updateConfiguration", use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
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


	def showConfigurationData(self):
		"""
		Method that displays the data stored in the VulTek-Alert configuration file.
		"""
		try:
			vultek_alert_data = self.__utils.convertDataYamlFileToString(self.__constants.PATH_VULTEK_ALERT_CONFIGURATION_FILE)
			message_to_display = "\nVulTek-Alert Configuration:\n\n" + vultek_alert_data
			self.__dialog.createScrollBoxDialog(message_to_display, 18, 70, "VulTek-Alert Configuration")
		except (IOError, OSError, FileNotFoundError) as exception:
			self.__dialog.createMessageDialog("\nFailed to open or read a file. For more information, see the logs.", 8, 50, "Error Message")
			self.__logger.generateApplicationLog(exception, 3, "__showVulTekAlertConfiguration", use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		finally:
			self.__action_to_cancel()


	def __createYamlFileConfiguration(self, vultek_alert_data):
		"""
		Method that creates the YAML file corresponding to the VulTek-Alert configuration.

		:arg vultek_alert_data (dict): Data to be stored in the configuration file.
		"""
		vultek_alert_data_json = {
			"options_level_vulnerabilities" : vultek_alert_data[0],
			"created_days_ago" : int(vultek_alert_data[1]),
			"time_search" : {vultek_alert_data[2] : int(vultek_alert_data[3])},
			"telegram_bot_token" : vultek_alert_data[4],
			"telegram_chat_id" : vultek_alert_data[5],
			"integration_with_elastic" : vultek_alert_data[6]
		}

		if vultek_alert_data[6] == True:
			integration_with_elastic_json = {"es_host" : vultek_alert_data[7], "es_port" : int(vultek_alert_data[8]), "use_ssl_tls" : vultek_alert_data[9]}
			vultek_alert_data_json.update(integration_with_elastic_json)
			if vultek_alert_data[9] == True:
				if vultek_alert_data[10] == True:
					verificate_certificate_ssl_json = {"verificate_certificate_ssl" : vultek_alert_data[10], "path_certificate_file" : vultek_alert_data[11]}
					last_index = 11
				else:
					verificate_certificate_ssl_json = {"verificate_certificate_ssl" : vultek_alert_data[10]}
					last_index = 10
				vultek_alert_data_json.update(verificate_certificate_ssl_json)
			else:
				last_index = 9
			if vultek_alert_data[last_index + 1] == True:
				if vultek_alert_data[last_index + 2] == "HTTP authentication":
					http_authentication_json = {"use_authentication_method" : vultek_alert_data[last_index + 1], "authentication_method" : vultek_alert_data[last_index + 2], "user_http_authentication" : vultek_alert_data[last_index + 3], "password_http_authentication" : vultek_alert_data[last_index + 4]}
					vultek_alert_data_json.update(http_authentication_json)
				elif vultek_alert_data[last_index + 2] == "API Key":
					api_key_json = {"use_authentication_method" : vultek_alert_data[last_index + 1], "authentication_method" : vultek_alert_data[last_index + 2], "api_key_id" : vultek_alert_data[last_index + 3], "api_key" : vultek_alert_data[last_index + 4]}
					vultek_alert_data_json.update(api_key_json)
			else:
				authentication_method_json = {"use_authentication_method" : vultek_alert_data[last_index + 1]}
				vultek_alert_data_json.update(authentication_method_json)

		self.__utils.createYamlFile(vultek_alert_data_json, self.__constants.PATH_VULTEK_ALERT_CONFIGURATION_FILE)
		self.__utils.changeOwnerToPath(self.__constants.PATH_VULTEK_ALERT_CONFIGURATION_FILE, self.__constants.USER, self.__constants.GROUP)