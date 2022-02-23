from io import open as open_io
from os import system, path, remove
from modules.UtilsClass import Utils

"""
Class that manages the VulTek-Alert service or daemon.
"""
class Service:
	"""
	Variable that stores an object of the Utils class.
	"""
	utils = None

	"""
	Variable that stores an object of the FormDialog class.
	"""
	form_dialog = None

	"""
	Constructor for the Service class.

	Parameters:
	self -- An instantiated object of the Service class.
	form_dialog -- FormDialog class object.
	"""
	def __init__(self, form_dialog):
		self.form_dialog = form_dialog
		self.utils = Utils(form_dialog)

	"""
	Method that starts the VulTek-Alert service.

	Parameters:
	self -- An instantiated object of the Service class.
	"""
	def startService(self):
		result = system("systemctl start vultek-alert.service")
		if int(result) == 0:
			self.utils.createVulTekAlertToolLog("VulTek-Alert service started", 1)
			self.form_dialog.d.msgbox(text = "\nVulTek-Alert service started.", height = 7, width = 50, title = "Notification Message")
		if int(result) == 1280:
			self.utils.createVulTekAlertToolLog("Failed to start vultek-alert.service. Service not found.", 3)
			self.form_dialog.d.msgbox(text = "\nFailed to start vultek-alert.service. Service not found.", height = 7, width = 50, title = "Error Message")
		self.form_dialog.mainMenu()

	"""
	Method that restarts the VulTek-Alert service.

	Parameters:
	self -- An instantiated object of the Service class.
	"""
	def restartService(self):
		result = system("systemctl restart vultek-alert.service")
		if int(result) == 0:
			self.utils.createVulTekAlertToolLog("VulTek-Alert service restarted", 1)
			self.form_dialog.d.msgbox(text = "\nVulTek-Alert service restarted.", height = 7, width = 50, title = "Notification Message")
		if int(result) == 1280:
			self.utils.createVulTekAlertToolLog("Failed to restart vultek-alert.service. Service not found.", 3)
			self.form_dialog.d.msgbox(text = "\nFailed to restart vultek-alert.service. Service not found.", height = 7, width = 50, title = "Error Message")
		self.form_dialog.mainMenu()

	"""
	Method that stops the VulTek-Alert service.

	Parameters:
	self -- An instantiated object of the Service class.
	"""
	def stopService(self):
		result = system("systemctl stop vultek-alert.service")
		if int(result) == 0:
			self.utils.createVulTekAlertToolLog("VulTek-Alert service stopped", 1)
			self.form_dialog.d.msgbox(text = "\nVulTek-Alert service stopped.", height = 7, width = 50, title = "Notification Message")	
		if int(result) == 1280:
			self.utils.createVulTekAlertToolLog("Failed to stop vultek-alert.service: Service not found", 3)
			self.form_dialog.d.msgbox(text = "\nFailed to stop vultek-alert.service. Service not found.", height = 7, width = 50, title = "Error Message")
		self.form_dialog.mainMenu()

	"""
	Method that obtains the status of the VulTek-Alert service.

	Parameters:
	self -- An instantiated object of the Service class.
	"""
	def getStatusService(self):
		if path.exists('/tmp/vultek_alert.status'):
			remove('/tmp/vultek_alert.status')
		system('(systemctl is-active --quiet vultek-alert.service && echo "VulTek-Alert service is running!" || echo "VulTek-Alert service is not running!") >> /tmp/vultek_alert.status')
		system('echo "Detailed service status:" >> /tmp/vultek_alert.status')
		system('systemctl -l status vultek-alert.service >> /tmp/vultek_alert.status')
		with open_io('/tmp/vultek_alert.status', 'r', encoding = 'utf-8') as file_status:
			self.form_dialog.getScrollBox(file_status.read(), title = "Status Service")
		self.form_dialog.mainMenu()