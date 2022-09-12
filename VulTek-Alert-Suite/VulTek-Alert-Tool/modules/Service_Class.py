from libPyLog import libPyLog
from io import open as open_io
from libPyUtils import libPyUtils
from os import system, path, remove
from libPyDialog import libPyDialog
from .Constants_Class import Constants

"""
Class that manages what is related to the VulTek-Alert service.
"""
class Service:
	"""
	Attribute that stores an object of the libPyUtils class.
	"""
	__utils = None

	"""
	Attribute that stores an object of the libPyDialog class.
	"""
	__dialog = None

	"""
	Attribute that stores an object of the libPyLog class.
	"""
	__logger = None

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


	def startService(self):
		"""
		Method to start the VulTek-Alert service.
		"""
		result = system("systemctl start vultek-alert.service")
		if int(result) == 0:
			self.__dialog.createMessageDialog("\nService started.", 7, 50, "Notification Message")
			self.__logger.generateApplicationLog("Service started", 1, "__serviceVulTekAlert", use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		elif int(result) == 1280:
			self.__dialog.createMessageDialog("\nFailed to start service. Not found.", 7, 50, "Error Message")
			self.__logger.generateApplicationLog("Failed to start service. Not found.", 3, "__serviceVulTekAlert", use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		self.__action_to_cancel()


	def restartService(self):
		"""
		Method to restart the VulTek-Alert service.
		"""
		result = system("systemctl restart vultek-alert.service")
		if int(result) == 0:
			self.__dialog.createMessageDialog("\nService restarted.", 7, 50, "Notification Message")
			self.__logger.generateApplicationLog("Service restarted", 1, "__serviceVulTekAlert", use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		elif int(result) == 1280:
			self.__dialog.createMessageDialog("\nFailed to restart service. Not found.", 7, 50, "Error Message")
			self.__logger.generateApplicationLog("Failed to restart service. Not found.", 3, "__serviceVulTekAlert", use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		self.__action_to_cancel()


	def stopService(self):
		"""
		Method to stop the VulTek-Alert service.
		"""
		result = system("systemctl stop vultek-alert.service")
		if int(result) == 0:
			self.__dialog.createMessageDialog("\nService stopped.", 7, 50, "Notification Message")
			self.__logger.generateApplicationLog("Service stopped", 1, "__serviceVulTekAlert", use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		elif int(result) == 1280:
			self.__dialog.createMessageDialog("\nFailed to stop service. Not found.", 7, 50, "Error Message")
			self.__logger.generateApplicationLog("Failed to stop service. Not found.", 3, "__serviceVulTekAlert", use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		self.__action_to_cancel()


	def getActualStatusService(self):
		"""
		Method to get the current status of the VulTek-Alert service.
		"""
		if path.exists("/tmp/vultek_alert.status"):
			remove("/tmp/vultek_alert.status")
		system('(systemctl is-active --quiet vultek-alert.service && echo "VulTek-Alert service is running!" || echo "VulTek-Alert service is not running!") >> /tmp/vultek_alert.status')
		system('echo "Detailed service status:" >> /tmp/vultek_alert.status')
		system('systemctl -l status vultek-alert.service >> /tmp/vultek_alert.status')
		with open_io("/tmp/vultek_alert.status", 'r', encoding = 'utf-8') as status_file:
			self.__dialog.createScrollBoxDialog(status_file.read(), 15, 70, "VulTek-Alert Service")
		self.__action_to_cancel()