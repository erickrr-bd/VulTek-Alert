from os import path
from sys import exit
from libPyDialog import libPyDialog
from .Constants_Class import Constants
from .VulTek_Alert_Service_Class import VulTekAlertService
from .VulTek_Alert_Agent_Service_Class import VulTekAlertAgentService
from .VulTek_Alert_Configuration_Class import VulTekAlertConfiguration
from .VulTek_Alert_Agent_Configuration_Class import VulTekAlertAgentConfiguration

"""
Class that manages what is related to the interfaces and actions of VulTek-Alert-Tool.
"""
class VulTekAlertTool:
	"""
	Attribute that stores an object of the libPyDialog class.
	"""
	__dialog = None

	"""
	Attribute that stores an object of the Constants class.
	"""
	__constants = None


	def __init__(self):
		"""
		Method that corresponds to the constructor of the class.
		"""
		self.__constants = Constants()
		self.__dialog = libPyDialog(self.__constants.BACKTITLE, self.mainMenu)


	def mainMenu(self):
		"""
		Method that shows the "Main" menu of the application.
		"""
		option_main_menu = self.__dialog.createMenuDialog("Select a option:", 12, 50, self.__constants.OPTIONS_MAIN_MENU, "Main Menu")
		self.__switchMainMenu(int(option_main_menu))


	def __serviceMenu(self):
		"""
		Method that shows the "Service" menu.
		"""
		option_service_menu = self.__dialog.createMenuDialog("Select a option:", 11, 50, self.__constants.OPTIONS_SERVICE_MENU, "Service Menu")
		self.__switchServiceMenu(int(option_service_menu))


	def __vulTekAlertAgentMenu(self):
		"""
		Method that shows the "VulTek-Alert-Agent" menu.
		"""
		option_vultek_alert_agent_menu = self.__dialog.createMenuDialog("Select a option:", 9, 50, self.__constants.OPTIONS_VULTEK_ALERT_AGENT_MENU, "VulTek-Alert-Agent Menu")
		self.__switchVulTekAlertAgentMenu(int(option_vultek_alert_agent_menu))


	def __vulTekAlertAgentServiceMenu(self):
		"""
		Method that shows the "VulTek-Alert-Agent Service" menu.
		"""
		option_vultek_alert_agent_service_menu = self.__dialog.createMenuDialog("Select a option:", 11, 50, self.__constants.OPTIONS_SERVICE_MENU, "VulTek-Alert-Agent Service Menu")
		self.__switchVulTekAlertAgentServiceMenu(int(option_vultek_alert_agent_service_menu))


	def __switchMainMenu(self, option):
		"""
		Method that executes a certain action based on the number of the option chosen in the "Main" menu.

		:arg option (integer): Option number.
		"""
		if option == 1:
			self.__defineConfiguration()
		elif option == 2:
			self.__serviceMenu()
		elif option == 3:
			self.__vulTekAlertAgentMenu()
		elif option == 4:
			self.__showApplicationAbout()
		elif option == 5:
			exit(1)


	def __switchServiceMenu(self, option):
		"""
		Method that executes a certain action based on the number of the option chosen in the "Service" menu.

		:arg option (integer): Option number.
		"""
		vultek_alert_service = VulTekAlertService(self.mainMenu)
		if option == 1:
			vultek_alert_service.startService()
		elif option == 2:
			vultek_alert_service.restartService()
		elif option == 3:
			vultek_alert_service.stopService()
		elif option == 4:
			vultek_alert_service.getActualStatusService()


	def __switchVulTekAlertAgentMenu(self, option):
		"""
		Method that executes a certain action based on the number of the option chosen in the "VulTek-Alert-Agent" menu.

		:arg option (integer): Option number.
		"""
		if option == 1:
			self.__defineVulTekAlertAgentConfiguration()
		elif option == 2:
			self.__vulTekAlertAgentServiceMenu()


	def __switchVulTekAlertAgentServiceMenu(self, option):
		"""
		Method that executes a certain action based on the number of the option chosen in the "VulTek-Alert-Agent Service" menu.

		:arg option (integer): Option number.
		"""
		vultek_alert_agent_service = VulTekAlertAgentService(self.mainMenu)
		if option == 1:
			vultek_alert_agent_service.startService()
		elif option == 2:
			vultek_alert_agent_service.restartService()
		elif option == 3:
			vultek_alert_agent_service.stopService()
		elif option == 4:
			vultek_alert_agent_service.getActualStatusService()


	def __defineConfiguration(self):
		"""
		Method that defines the action to perform on the VulTek-Alert configuration (create or modify).
		"""
		vultek_alert_configuration = VulTekAlertConfiguration(self.mainMenu)
		if not path.exists(self.__constants.PATH_VULTEK_ALERT_CONFIGURATION_FILE):
			option_configuration_false = self.__dialog.createRadioListDialog("Select a option:", 8, 50, self.__constants.OPTIONS_CONFIGURATION_FALSE, "VulTek-Alert Configuration Options")
			if option_configuration_false == "Create":
				vultek_alert_configuration.createConfiguration()
		else:
			option_configuration_true = self.__dialog.createRadioListDialog("Select a option:", 9, 50, self.__constants.OPTIONS_CONFIGURATION_TRUE, "VulTek-Alert Configuration Options")
			if option_configuration_true == "Modify":
				vultek_alert_configuration.modifyConfiguration()
			elif option_configuration_true == "Show":
				vultek_alert_configuration.showConfigurationData()


	def __defineVulTekAlertAgentConfiguration(self):
		"""
		Method that defines the action to perform on the VulTek-Alert-Agent configuration (create or modify).
		"""
		vultek_alert_agent_configuration = VulTekAlertAgentConfiguration(self.mainMenu)
		if not path.exists(self.__constants.PATH_VULTEK_ALERT_AGENT_CONFIGURATION_FILE):
			option_configuration_false = self.__dialog.createRadioListDialog("Select a option:", 8, 50, self.__constants.OPTIONS_CONFIGURATION_FALSE, "VulTek-Alert-Agent Configuration Options")
			if option_configuration_false == "Create":
				vultek_alert_agent_configuration.createConfiguration()
		else:
			option_configuration_true = self.__dialog.createRadioListDialog("Select a option:", 9, 50, self.__constants.OPTIONS_CONFIGURATION_TRUE, "VulTek-Alert-Agent Configuration Options")
			if option_configuration_true == "Modify":
				vultek_alert_agent_configuration.modifyConfiguration()
			elif option_configuration_true == "Show":
				vultek_alert_agent_configuration.showConfigurationData()


	def __showApplicationAbout(self):
		"""
		Method that shows the "About" of the application.
		"""
		message_to_show = "\nCopyright@2022 Tekium. All rights reserved.\nVulTek-Alert v3.2.1\nAuthor: Erick Rodriguez\nEmail: erickrr.tbd93@gmail.com, erodriguez@tekium.mx\n" + "License: GPLv3\n\nEasy alerting of published vulnerabilities in the Red Hat Security\nData API."
		self.__dialog.createScrollBoxDialog(message_to_show, 13, 70, "About")