from os import path
from sys import exit
from libPyDialog import libPyDialog
from .Constants_Class import Constants
from .Configuration_Class import Configuration

class VulTekAlertTool:

	__dialog = None

	__constants = None

	def __init__(self):
		self.__constants = Constants()
		self.__dialog = libPyDialog(self.__constants.BACKTITLE, self.mainMenu)


	def mainMenu(self):
		"""
		Method that shows the main menu of the application.
		"""
		option_main_menu = self.__dialog.createMenuDialog("Select a option:", 12, 50, self.__constants.OPTIONS_MAIN_MENU, "Main Menu")
		self.__switchMainMenu(int(option_main_menu))


	def __switchMainMenu(self, option):
		"""
		Method that executes a certain action based on the number of the option chosen in the Main menu.

		:arg option: Option number.
		"""
		if option == 1:
			self.__defineConfiguration()
		elif option == 2:
			print("Hola")
		elif option == 3:
			print("Hola")
		elif option == 4:
			exit(1)


	def __defineConfiguration(self):
		"""
		Method that defines the action to perform on the VulTek-Alert configuration (create or modify).
		"""
		configuration = Configuration(self.mainMenu)
		if not path.exists(self.__constants.PATH_FILE_CONFIGURATION):
			option_configuration_false = self.__dialog.createRadioListDialog("Select a option:", 8, 50, self.__constants.OPTIONS_CONFIGURATION_FALSE, "Configuration Options")
			if option_configuration_false == "Create":
				configuration.createConfiguration()
		else:
			option_configuration_true = self.__dialog.createRadioListDialog("Select a option:", 8, 50, self.__constants.OPTIONS_CONFIGURATION_TRUE, "Configuration Options")
			if option_configuration_true == "Modify":
				configuration.modifyConfiguration()