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
			telegram_bot_token = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the Telegram bot token:", 10, 50, "751988420:AAHrzn7RXWxVQQNha0tQUzyouE5lUcPde1g"), passphrase)
			data_vultek_alert_configuration.append(telegram_bot_token.decode("utf-8"))
			telegram_chat_id = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the Telegram channel identifier:", 10, 50, "-1002365478941"), passphrase)
			data_vultek_alert_configuration.append(telegram_chat_id.decode("utf-8"))
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