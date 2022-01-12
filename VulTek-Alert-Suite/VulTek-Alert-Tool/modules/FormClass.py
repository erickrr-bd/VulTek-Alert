from os import path
from sys import exit
from dialog import Dialog
from modules.UtilsClass import Utils
from modules.ServiceClass import Service
from modules.ConfigurationClass import Configuration

"""
Class that allows managing the graphical interfaces of VulTek-Alert-Tool.
"""
class FormDialog:
	"""
	Property that stores an object of class Dialog.
	"""
	d = None

	"""
	Property that stores an object of the Utils class.
	"""
	utils = None

	"""
	Constructor for the FormDialog class.

	Parameters:
	self -- An instantiated object of the FormDialog class.
	"""
	def __init__(self):
		self.d = Dialog(dialog = "dialog")
		self.d.set_background_title("VULTEK-ALERT-TOOL")
		self.utils = Utils(self)

	"""
	Method that generates the menu interface.

	Parameters:
	self -- An instantiated object of the FormDialog class.
	text -- Text displayed on the interface.
	options -- List of options that make up the menu.
	title -- Title displayed on the interface.

	Return:
	tag_menu -- Chosen option.
	"""
	def getMenu(self, text, options, title):
		code_menu, tag_menu = self.d.menu(text = text, choices = options, title = title)
		if code_menu == self.d.OK:
			return tag_menu
		if code_menu == self.d.CANCEL:
			self.mainMenu()

	"""
	Method that generates an interface with several available options, and where only one of them can be chosen.

	Parameters:
	self -- An instantiated object of the FormDialog class.
	text -- Text displayed on the interface.
	options -- List of options that make up the interface.
	title -- Title displayed on the interface.

	Return:
	tag_radiolist -- Chosen option.
	"""
	def getDataRadioList(self, text, options, title):
		while True:
			code_radiolist, tag_radiolist = self.d.radiolist(text = text, width = 65, choices = options, title = title)
			if code_radiolist == self.d.OK:
				if len(tag_radiolist) == 0:
					self.d.msgbox(text = "\nSelect at least one option.", height = 7, width = 50, title = "Error Message")
				else:
					return tag_radiolist
			elif code_radiolist == self.d.CANCEL:
				self.mainMenu()

	"""
	Method that generates an interface with several available options, and where you can choose one or more of them.

	Parameters:
	self -- An instantiated object of the FormDialog class.
	text -- Text displayed on the interface.
	options -- List of options that make up the interface.
	title -- Title displayed on the interface.

	Return:
	tag_checklist -- List with the chosen options.
	"""
	def getDataCheckList(self, text, options, title):
		while True:
			code_checklist, tag_checklist = self.d.checklist(text = text, width = 75, choices = options, title = title)
			if code_checklist == self.d.OK:
				if len(tag_checklist) == 0:
					self.d.msgbox(text = "\nSelect at least one option.", height = 7, width = 50, title = "Error Message")
				else:
					return tag_checklist
			elif code_checklist == self.d.CANCEL:
				self.mainMenu()

	"""
	Method that generates an interface to enter text.

	Parameters:
	self -- An instantiated object of the FormDialog class.
	text -- Text displayed on the interface.
	initial_value -- Default value shown on the interface.

	Return:
	tag_inputbox -- Text entered.
	"""
	def getDataInputText(self, text, initial_value):
		while True:
			code_inputbox, tag_inputbox = self.d.inputbox(text = text, height = 10, width = 50, init = initial_value)
			if code_inputbox == self.d.OK:
				if tag_inputbox == "":
					self.d.msgbox(text = "\nInvalid data entered. Required value (not empty).", height = 8, width = 50, title = "Error Message")
				else:
					return tag_inputbox
			elif code_inputbox == self.d.CANCEL:
				self.mainMenu()

	"""
	Method that generates an interface with scroll box.

	Parameters:
	self -- An instantiated object of the FormDialog class.
	text -- Text displayed on the interface.
	title -- Title displayed on the interface.
	"""
	def getScrollBox(self, text, title):
		code_scrollbox = self.d.scrollbox(text = text, height = 15, width = 70, title = title)

	"""
	Method that generates the interface for entering data of the time type.

	Parameters:
	self -- An instantiated object of the FormDialog class.
	text -- Text that will be shown to the user.
	hour -- Hour entered.
	minutes -- Minutes entered.

	Return:
	tag_timebox -- Time entered.
	"""
	def getDataTime(self, text, hour, minutes):
		code_timebox, tag_timebox = self.d.timebox(text = text, height = 5, width = 30, hour = hour, minute = minutes, second = 00)
		if code_timebox == self.d.OK:
			return tag_timebox
		if code_timebox == self.d.CANCEL:
			self.mainMenu()

	"""
	Method that defines the actions to be carried out around the VulTek-Alert configuration.

	Parameters:
	self -- An instantiated object of the FormDialog class.
	"""
	def defineConfiguration(self):
		list_configuration_false = [("Create", "Create the configuration file", 0)]

		list_configuration_true = [("Modify", "Modify the configuration file", 0)]
		
		configuration = Configuration(self)
		if not path.exists(configuration.path_configuration_file):
			option_configuration_false = self.getDataRadioList("Select a option:", list_configuration_false, "Configuration Options")
			if option_configuration_false == "Create":
				configuration.createConfiguration()
		else:
			option_configuration_true = self.getDataRadioList("Select a option:", list_configuration_true, "Configuration Options")
			if option_configuration_true == "Modify":
				configuration.updateConfiguration()

	"""
	Method that displays a message on the screen with information about the application.

	Parameters:
	self -- An instantiated object of the FormDialog class.
	"""
	def getAbout(self):
		message = "\nCopyright@2022 Tekium. All rights reserved.\nVulTek-Alert v3.0\nAuthor: Erick Rodríguez\nEmail: erickrr.tbd93@gmail.com, erodriguez@tekium.mx\n" + "License: GPLv3\n\nApplication that obtains the daily vulnerabilities of the Red\nHat Security Data API and sends them as an alert to a Telegram\nchannel."
		self.getScrollBox(message, "About")
		self.mainMenu()

	"""
	Method that launches an action based on the option chosen in the main menu.

	Parameters:
	self -- An instantiated object of the FormDialog class.
	option -- Chosen option.
	"""
	def switchMmenu(self, option):
		if option == 1:
			self.defineConfiguration()
		elif option == 2:
			self.serviceMenu()
		elif option == 3:
			self.getAbout()
		elif option == 4:
			exit(0)

	"""
	Method that launches an action based on the option chosen in the VulTek-Alert service menu.

	Parameters:
	self -- An instantiated object of the FormDialog class.
	option -- Chosen option.
	"""
	def switchMService(self, option):
		service = Service(self)
		if option == 1:
			service.startService()
		elif option == 2:
			service.restartService()
		elif option == 3:
			service.stopService()
		elif option == 4:
			service.getStatusService()

	"""
	Method that defines the menu on the actions to be carried out in the main menu.

	Parameters:
	self -- An instantiated object of the FormDialog class.
	"""
	def mainMenu(self):
		options_mm = [("1", "VulTek-Alert Configuration"),
					  ("2", "VulTek-Alert Service"),
					  ("3", "About"),
					  ("4", "Exit")]

		option_mm = self.getMenu("Select a option:", options_mm, "Main Menu")
		self.switchMmenu(int(option_mm))

	"""
	Method that defines the menu on the actions to be carried out on the VulTek-Alert service.

	Parameters:
	self -- An instantiated object of the FormDialog class.
	"""
	def serviceMenu(self):
		options_ms = [("1", "Start Service"),
					  ("2", "Restart Service"),
					  ("3", "Stop Service"),
					  ("4", "Service Status")]

		option_ms = self.getMenu("Select a option:", options_ms, "VulTek-Alert Service")
		self.switchMService(int(option_ms))