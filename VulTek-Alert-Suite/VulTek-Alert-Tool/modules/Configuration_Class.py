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
		self.__utils = libPyUtils()
		self.__constants = Constants()
		self.__action_to_cancel = action_to_cancel
		self.__dialog = libPyDialog(self.__constants.BACKTITLE, action_to_cancel)
		self.__logger = libPyLog(self.__constants.NAME_FILE_LOG, self.__constants.NAME_LOG, self.__constants.USER, self.__constants.GROUP)


	def createConfiguration(self):
		"""
		Method that collects the information for the creation of the VulTek-Alert configuration file.
		"""
		data_configuration = []
		try:
			time_execution = self.__dialog.createTimeDialog("Choose the time:", 4, 10, -1, -1)
			data_configuration.append(str(time_execution[0]) + ':' + str(time_execution[1]))
			options_level_vulnerabilities = self.__dialog.createCheckListDialog("Select one or more options:", 12, 50, self.__constants.OPTIONS_LEVEL_VULNERABILITIES, "Vulnerabilities Levels")
			data_configuration.append(options_level_vulnerabilities)
			passphrase = self.__utils.getPassphraseKeyFile(self.__constants.PATH_KEY_FILE)
			telegram_bot_token = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the Telegram bot token:", 10, 50, "751988420:AAHrzn7RXWxVQQNha0tQUzyouE5lUcPde1g"), passphrase)
			data_configuration.append(telegram_bot_token.decode('utf-8'))
			telegram_chat_id = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the Telegram channel identifier:", 10, 50, "-1002365478941"), passphrase)
			data_configuration.append(telegram_chat_id.decode('utf-8'))
			self.__createFileYamlConfiguration(data_configuration)
			if path.exists(self.__constants.PATH_FILE_CONFIGURATION):
				self.__logger.createApplicationLog("Configuration file created", 1)
				self.__dialog.createMessageDialog("\nConfiguration file created.", 7, 50, "Notification Message")
			self.__action_to_cancel()
		except (FileNotFoundError, IOError, OSError) as exception:
			self.__logger.createApplicationLog(exception, 3)
			self.__dialog.createMessageDialog("\nError creating, opening or reading the file. For more information, see the logs.", 8, 50, "Error Message")
			self.__action_to_cancel()


	def modifyConfiguration(self):
		"""
		Method that allows to modify one or more values in the VulTek-Alert configuration file.
		"""
		options_fields_update = self.__dialog.createCheckListDialog("Select one or more options:", 12, 70, self.__constants.OPTIONS_FIELDS_UPDATE, "Configuration Fields")
		try:
			data_configuration = self.__utils.readYamlFile(self.__constants.PATH_FILE_CONFIGURATION)
			hash_file_configuration_original = self.__utils.getHashFunctionToFile(self.__constants.PATH_FILE_CONFIGURATION)
			if 'Time' in options_fields_update:
				time_execution_actual = data_configuration['time_execution'].split(':')
				time_execution = self.__dialog.createTimeDialog("Choose the time:", 4, 10, int(time_execution_actual[0]), int(time_execution_actual[1]))
				data_configuration['time_execution'] = str(time_execution[0]) + ':' + str(time_execution[1])
			if 'Level' in options_fields_update:
				if "low" in data_configuration['options_level_vulnerabilities']:
					self.__constants.OPTIONS_LEVEL_VULNERABILITIES[0][2] = 1
				if "moderate" in data_configuration['options_level_vulnerabilities']:
					self.__constants.OPTIONS_LEVEL_VULNERABILITIES[1][2] = 1
				if "important" in data_configuration['options_level_vulnerabilities']:
					self.__constants.OPTIONS_LEVEL_VULNERABILITIES[2][2] = 1
				if "critical" in data_configuration['options_level_vulnerabilities']:
					self.__constants.OPTIONS_LEVEL_VULNERABILITIES[3][2] = 1
				options_level_vulnerabilities = self.__dialog.createCheckListDialog("Select one or more options:", 12, 50, self.__constants.OPTIONS_LEVEL_VULNERABILITIES, "Vulnerabilities Levels")
				data_configuration['options_level_vulnerabilities'] = options_level_vulnerabilities
				for i in range(4):
					self.__constants.OPTIONS_LEVEL_VULNERABILITIES[i][2] = 0
			if 'Bot Token' in options_fields_update:
				passphrase = self.__utils.getPassphraseKeyFile(self.__constants.PATH_KEY_FILE)
				telegram_bot_token = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the Telegram bot token:", 10, 50, self.__utils.decryptDataWithAES(data_configuration['telegram_bot_token'], passphrase).decode('utf-8')), passphrase)
				data_configuration['telegram_bot_token'] = telegram_bot_token.decode('utf-8')
			if 'Chat ID' in options_fields_update:
				passphrase = self.__utils.getPassphraseKeyFile(self.__constants.PATH_KEY_FILE)
				telegram_chat_id = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the Telegram channel identifier:", 10, 50, self.__utils.decryptDataWithAES(data_configuration['telegram_chat_id'], passphrase).decode('utf-8')), passphrase)
				data_configuration['telegram_chat_id'] = telegram_chat_id.decode('utf-8')
			self.__utils.createYamlFile(data_configuration, self.__constants.PATH_FILE_CONFIGURATION)
			hash_file_configuration_new = self.__utils.getHashFunctionToFile(self.__constants.PATH_FILE_CONFIGURATION)
			if hash_file_configuration_new == hash_file_configuration_original:
				self.__dialog.createMessageDialog("\nThe configuration file was not modified.", 7, 50, "Notification Message")
			else:
				self.__logger.createApplicationLog("The configuration file was modified.", 2)
				self.__dialog.createMessageDialog("\nThe configuration file was modified.", 7, 50, "Notification Message")
			self.__action_to_cancel()
		except KeyError as exception:
			self.__logger.createApplicationLog("Key Error: " + str(exception), 3)
			self.__dialog.createMessageDialog("\nKey Error: " + str(exception) + '.', 7, 50, "Error Message")
			self.__action_to_cancel()
		except (IOError, FileNotFoundError, OSError) as exception:
			self.__logger.createApplicationLog(exception, 3)
			self.__dialog.createMessageDialog("\nError reading or modifying the configuration file. For more information, see the logs.", 8, 50, "Error Message")
			self.__action_to_cancel()


	def __createFileYamlConfiguration(self, data_configuration):
		"""
		Method that creates the YAML file corresponding to the VulTek-Alert configuration.

		:arg data_configuration: Data to be stored in the configuration file.
		"""
		data_configuration_json = {'time_execution' : data_configuration[0],
								   'options_level_vulnerabilities' : data_configuration[1],
								   'telegram_bot_token' : data_configuration[2],
								   'telegram_chat_id' : data_configuration[3]}

		self.__utils.createYamlFile(data_configuration_json, self.__constants.PATH_FILE_CONFIGURATION)
		self.__utils.changeOwnerToPath(self.__constants.PATH_FILE_CONFIGURATION, self.__constants.USER, self.__constants.GROUP)