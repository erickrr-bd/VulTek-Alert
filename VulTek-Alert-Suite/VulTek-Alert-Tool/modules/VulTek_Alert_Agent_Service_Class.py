from libPyLog import libPyLog
from io import open as open_io
from libPyUtils import libPyUtils
from os import system, path, remove
from libPyDialog import libPyDialog
from .Constants_Class import Constants

"""
Class that manages what is related to the VulTek-Alert-Agent service.
"""
class VulTekAlertAgentService:
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
		Method to start the VulTek-Alert-Agent service.
		"""
		result = system("systemctl start vultek-alert-agent.service")
		if int(result) == 0:
			self.__dialog.createMessageDialog("\nVulTek-Alert-Agent service started.", 7, 50, "Notification Message")
			self.__logger.generateApplicationLog("VulTek-Alert-Agent service started", 1, "__serviceVulTekAlertAgent", use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		elif int(result) == 1280:
			self.__dialog.createMessageDialog("\nFailed to start VulTek-Alert-Agent service. Not found.", 8, 50, "Error Message")
			self.__logger.generateApplicationLog("Failed to start VulTek-Alert-Agent service. Not found.", 3, "__serviceVulTekAlertAgent", use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		self.__action_to_cancel()


	def restartService(self):
		"""
		Method to restart the VulTek-Alert-Agent service.
		"""
		result = system("systemctl restart vultek-alert-agent.service")
		if int(result) == 0:
			self.__dialog.createMessageDialog("\nVulTek-Alert-Agent service restarted.", 7, 50, "Notification Message")
			self.__logger.generateApplicationLog("VulTek-Alert-Agent service restarted", 1, "__serviceVulTekAlertAgent", use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		elif int(result) == 1280:
			self.__dialog.createMessageDialog("\nFailed to restart VulTek-Alert-Agent service. Not found.", 8, 50, "Error Message")
			self.__logger.generateApplicationLog("Failed to restart VulTek-Alert-Agent service. Not found.", 3, "__serviceVulTekAlertAgent", use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		self.__action_to_cancel()


	def stopService(self):
		"""
		Method to stop the VulTek-Alert-Agent service.
		"""
		result = system("systemctl stop vultek-alert-agent.service")
		if int(result) == 0:
			self.__dialog.createMessageDialog("\nVulTek-Alert-Agent service stopped.", 7, 50, "Notification Message")
			self.__logger.generateApplicationLog("VulTek-Alert-Agent service stopped", 1, "__serviceVulTekAlertAgent", use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		elif int(result) == 1280:
			self.__dialog.createMessageDialog("\nFailed to stop VulTek-Alert-Agent service. Not found.", 8, 50, "Error Message")
			self.__logger.generateApplicationLog("Failed to stop VulTek-Alert-Agent service. Not found.", 3, "__serviceVulTekAlertAgent", use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		self.__action_to_cancel()


	def getActualStatusService(self):
		"""
		Method to get the current status of the VulTek-Alert-Agent service.
		"""
		if path.exists("/tmp/vultek_alert_agent.status"):
			remove("/tmp/vultek_alert_agent.status")
		system('(systemctl is-active --quiet vultek-alert-agent.service && echo "VulTek-Alert-Agent service is running!" || echo "VulTek-Alert-Agent service is not running!") >> /tmp/vultek_alert_agent.status')
		system('echo "Detailed service status:" >> /tmp/vultek_alert_agent.status')
		system('systemctl -l status vultek-alert-agent.service >> /tmp/vultek_alert_agent.status')
		with open_io("/tmp/vultek_alert_agent.status", 'r', encoding = "utf-8") as status_file:
			self.__dialog.createScrollBoxDialog(status_file.read(), 15, 70, "VulTek-Alert-Agent Service")
		self.__action_to_cancel()