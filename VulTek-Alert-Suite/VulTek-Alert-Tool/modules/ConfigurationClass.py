from os import path
from modules.UtilsClass import Utils

"""
Class that allows managing everything related to the VulTek-Alert configuration.
"""
class Configuration:
	"""
	Property that stores an object of the Utils class.
	"""
	utils = None

	"""
	Property that stores an object of the FormDialog class.
	"""
	form_dialog = None

	"""
	Property that stores the path of the VulTek-Alert configuration file.
	"""
	path_configuration_file = None

	"""
	Property that contains the options for the alert rule level.
	"""
	list_level_vulnerabilities = [["low", "Low level vulnerability", 0],
								  ["moderate", "Medium level vulnerability", 0],
								  ["important", "Important level vulnerability", 0],
								  ["critical", "Critical level vulnerability", 0]]

	"""
	Constructor for the Configuration class.

	Parameters:
	self -- An instantiated object of the Configuration class.
	form_dialog -- FormDialog class object.
	"""
	def __init__(self, form_dialog):
		self.form_dialog = form_dialog
		self.utils = Utils(form_dialog)
		self.path_configuration_file = self.utils.getPathVulTekAlert('conf') + "/vultek_alert_conf.yaml"

	"""
	Method that requests the data required to create the configuration file.

	Parameters:
	self -- An instantiated object of the Configuration class.
	"""
	def createConfiguration(self):
		data_configuration = []
		time_to_execute = self.form_dialog.getDataTime("Select the time of day the vulnerabilities will be obtained:", -1, -1)
		data_configuration.append(str(time_to_execute[0]) + ':' + str(time_to_execute[1]))
		options_level_vulnerabilities = self.form_dialog.getDataCheckList("Select one or more options:", self.list_level_vulnerabilities, "Vulnerability Level")
		data_configuration.append(options_level_vulnerabilities)
		telegram_bot_token = self.utils.encryptAES(self.form_dialog.getDataInputText("Enter the Telegram bot token:", "751988420:AAHrzn7RXWxVQQNha0tQUzyouE5lUcPde1g"))
		data_configuration.append(telegram_bot_token.decode('utf-8'))
		telegram_chat_id = self.utils.encryptAES(self.form_dialog.getDataInputText("Enter the Telegram channel identifier:", "-1002365478941"))
		data_configuration.append(telegram_chat_id.decode('utf-8'))
		self.createConfigurationFile(data_configuration)
		if not path.exists(self.path_configuration_file):
			self.form_dialog.d.msgbox(text = "\nError creating configuration file. For more information, see the logs.", height = 8, width = 50, title = "Error Message")
		else:
			self.utils.createVulTekAlertToolLog("Configuration file created", 1)
			self.form_dialog.d.msgbox(text = "\nConfiguration file created.", height = 7, width = 50, title = "Notification Message")
		self.form_dialog.mainMenu()

	"""
	Method that allows modifying one or more values of the configuration file.

	Parameters:
	self -- An instantiated object of the Configuration class.

	Exceptions:
	KeyError -- A Python KeyError exception is what is raised when you try to access a key that isn’t in a dictionary (dict). 	
	"""
	def updateConfiguration(self):
		list_fields_update = [("Time", "Time in which it runs on the day", 0),
							  ("Level", "Vulnerability level", 0),
							  ("Bot Token", "Telegram Bot Token", 0),
							  ("Chat ID", "Telegram channel identifier", 0)]

		flag_time_execution = 0
		flag_level_vulnerabilities = 0
		flag_telegram_bot_token = 0
		flag_telegram_chat_id = 0
		options_fields_update = self.form_dialog.getDataCheckList("Select one or more options:", list_fields_update, "Configuration Fields")
		for option in options_fields_update:
			if option == "Time":
				flag_time_execution = 1
			elif option == "Level":
				flag_level_vulnerabilities = 1
			elif option == "Bot Token":
				flag_telegram_bot_token = 1
			elif option == "Chat ID":
				flag_telegram_chat_id = 1
		try:
			hash_configuration_file_original = self.utils.getHashToFile(self.path_configuration_file)
			data_configuration = self.utils.readYamlFile(self.path_configuration_file, 'rU')
			if flag_time_execution == 1:
				time_to_execute_split = data_configuration['time_to_execute'].split(':')
				time_to_execute = self.form_dialog.getDataTime("Select the time of day the vulnerabilities will be obtained:", str(time_to_execute_split[0]), str(time_to_execute_split[1]))
				data_configuration['time_to_execute'] = str(time_to_execute[0]) + ':' + str(time_to_execute[1])
			if flag_level_vulnerabilities == 1:
				if "low" in data_configuration['options_level_vulnerabilities']:
					self.list_level_vulnerabilities[0][2] = 1
				if "moderate" in data_configuration['options_level_vulnerabilities']:
					self.list_level_vulnerabilities[1][2] = 1
				if "important" in data_configuration['options_level_vulnerabilities']:
					self.list_level_vulnerabilities[2][2] = 1
				if "critical" in data_configuration['options_level_vulnerabilities']:
					self.list_level_vulnerabilities[3][2] = 1
				options_level_vulnerabilities = self.form_dialog.getDataCheckList("Select one or more options:", self.list_level_vulnerabilities, "Vulnerability Level")
				data_configuration['options_level_vulnerabilities'] = options_level_vulnerabilities
			if flag_telegram_bot_token == 1:
				telegram_bot_token = self.utils.encryptAES(self.form_dialog.getDataInputText("Enter the Telegram bot token:", self.utils.decryptAES(data_configuration['telegram_bot_token']).decode('utf-8')))
				data_configuration['telegram_bot_token'] = telegram_bot_token.decode('utf-8')
			if flag_telegram_chat_id == 1:	
				telegram_chat_id = self.utils.encryptAES(self.form_dialog.getDataInputText("Enter the Telegram channel identifier:", self.utils.decryptAES(data_configuration['telegram_chat_id']).decode('utf-8')))
				data_configuration['telegram_chat_id'] = telegram_chat_id.decode('utf-8')
			self.utils.createYamlFile(data_configuration, self.path_configuration_file, 'w')
			hash_configuration_file_new = self.utils.getHashToFile(self.path_configuration_file)
			if hash_configuration_file_original == hash_configuration_file_new:
				self.form_dialog.d.msgbox(text = "\nConfiguration file not modified.", height = 7, width = 50, title = "Notification Message")
			else:
				self.utils.createVulTekAlertToolLog("Modified configuration file", 2)
				self.form_dialog.d.msgbox(text = "\nModified configuration file.", height = 7, width = 50, title = "Notification Message")
		except KeyError as exception:
			self.utils.createVulTekAlertToolLog("Key Error: " + str(exception), 3)
			self.form_dialog.d.msgbox(text = "\nError modifying the configuration file. For more information, see the logs.", height = 8, width = 50, title = "Error Message")
			self.form_dialog.mainMenu()

	"""
	Method that creates the YAML file corresponding to the configuration file.

	Parameters:
	self -- An instantiated object of the Configuration class.
	data_configuration -- Object that contains the data that will be stored in the configuration file.
	"""
	def createConfigurationFile(self, data_configuration):
		data_configuration_json = { 'time_to_execute' : data_configuration[0],
									'options_level_vulnerabilities' : data_configuration[1],
									'telegram_bot_token' : data_configuration[2],
									'telegram_chat_id' : data_configuration[3] }

		self.utils.createYamlFile(data_configuration_json, self.path_configuration_file, 'w')
