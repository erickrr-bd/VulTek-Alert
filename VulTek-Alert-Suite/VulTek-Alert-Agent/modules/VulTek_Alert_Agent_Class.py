from os import popen
from datetime import datetime
from libPyLog import libPyLog
from time import sleep,strftime
from libPyUtils import libPyUtils
from .Constants_Class import Constants
from libPyTelegram import libPyTelegram

"""
Class that manages the operation of VulTek-Alert-Agent.
"""
class VulTekAlertAgent:
	"""
	Attribute that stores an object of the libPyUtils class.
	"""
	__utils = None

	"""
	Attribute that stores an object of the libPyLog class.
	"""
	__logger = None

	"""
	Attribute that stores an object of the libPyTelegram class.
	"""
	__telegram = None

	"""
	Attribute that stores an object of the Constants class.
	"""
	__constants = None


	def __init__(self):
		"""
		Method that corresponds to the constructor of the class.
		"""
		self.__logger = libPyLog()
		self.__utils = libPyUtils()
		self.__constants = Constants()
		self.__telegram = libPyTelegram()


	def startVulTekAlertAgent(self):
		"""
		Method that starts the VulTek-Alert-Agent application.
		"""
		try:
			vultek_alert_agent_data = self.__utils.readYamlFile(self.__constants.PATH_VULTEK_ALERT_AGENT_CONFIGURATION_FILE)
			first_execution_time = vultek_alert_agent_data["first_execution_time"].split(':')
			second_execution_time = vultek_alert_agent_data["second_execution_time"].split(':')
			passphrase = self.__utils.getPassphraseKeyFile(self.__constants.PATH_KEY_FILE)
			telegram_bot_token = self.__utils.decryptDataWithAES(vultek_alert_agent_data["telegram_bot_token"], passphrase).decode("utf-8")
			telegram_chat_id = self.__utils.decryptDataWithAES(vultek_alert_agent_data["telegram_chat_id"], passphrase).decode("utf-8")
			self.__logger.generateApplicationLog("VulTek-Alert-Agent v3.2.1", 1, "__start", use_stream_handler = True)
			self.__logger.generateApplicationLog("@2022 Tekium. All rights reserved.", 1, "__start", use_stream_handler = True)
			self.__logger.generateApplicationLog("Author: Erick Rodriguez", 1, "__start", use_stream_handler = True)
			self.__logger.generateApplicationLog("Email: erodriguez@tekium.mx, erickrr.tbd93@gmail.com", 1, "__start", use_stream_handler = True)
			self.__logger.generateApplicationLog("License: GPLv3", 1, "__start", use_stream_handler = True)
			self.__logger.generateApplicationLog("VulTek-Alert-Agent started", 1, "__start", use_stream_handler = True)
			while True:
				result_status_vultek_alert_service = popen('(systemctl is-active --quiet vultek-alert.service && echo "Running" || echo "Not running")')
				status_vultek_alert_service_aux = result_status_vultek_alert_service.readlines()
				for status in status_vultek_alert_service_aux:
					status_vultek_alert_service = status.rstrip('\n')
				if status_vultek_alert_service == "Not running":
					message_to_send = self.__generateTelegramMessage(status_vultek_alert_service)
					response_status_code = self.__telegram.sendMessageTelegram(telegram_bot_token, telegram_chat_id, message_to_send)
					self.__createLogByTelegramCode(response_status_code)
				else:
					now = datetime.now()
					if(now.hour == int(first_execution_time[0]) and now.minute == int(first_execution_time[1])) or (now.hour == int(second_execution_time[0]) and now.minute == int(second_execution_time[1])):
						message_to_send = self.__generateTelegramMessage(status_vultek_alert_service)
						response_status_code = self.__telegram.sendMessageTelegram(telegram_bot_token, telegram_chat_id, message_to_send)
						self.__createLogByTelegramCode(response_status_code)
				self.__logger.generateApplicationLog("VulTek-Alert service status: " + status_vultek_alert_service, 1, "__start", use_stream_handler = True, use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
				sleep(60)
		except KeyError as exception:
			self.__logger.generateApplicationLog("Key Error: " + str(exception), 3, "__start", use_stream_handler = True, use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		except (OSError, FileNotFoundError) as exception:
			self.__logger.generateApplicationLog("Error to start Telk-Alert-Agent. For more information, see the logs.", 3, "__start", use_stream_handler = True)
			self.__logger.generateApplicationLog(exception, 3, "__start", use_stream_handler = True, use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)


	def __generateTelegramMessage(self, status_vultek_alert_service):
		"""
		Method that generates the Telegram message based on the current state of the VulTek-Alert service.

		Returns the Telegram message formed.

		:arg status_telk_alert_service (string): Current state of the VulTek-Alert service.
		"""
		message_telegram = "" + u'\u26A0\uFE0F' + "VulTek-Alert Service " + u'\u26A0\uFE0F' + '\n\n' + u'\u23F0' + "Service Status Validation Time: " + strftime("%c") + "\n\n\n"
		if status_vultek_alert_service == "Not running":
			message_telegram += "Service VulTek-Alert Status: " + u'\U0001f534' + "\n\n"
		elif status_vultek_alert_service == "Running":
			message_telegram += "Service VulTek-Alert Status: " + u'\U0001f7e2' + "\n\n"
		message_telegram += "" + u'\U0001f4cb' + " " + "Note 1: The green circle indicates that the VulTek-Alert service is working without problems." + "\n\n"
		message_telegram += "" + u'\U0001f4cb' + " " + "Note 2: The red circle indicates that the VulTek-Alert service is not working. Report to an administrator." + "\n\n"
		return message_telegram


	def __createLogByTelegramCode(self, response_status_code):
		"""
		Method that creates a log based on the HTTP code received as a response.

		:arg response_status_code (integer): HTTP code received in the response when sending the alert to Telegram.
		"""
		if response_status_code == 200:
			self.__logger.generateApplicationLog("Telegram message sent.", 1, "__sendTelegramMessage", use_stream_handler = True, use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		elif response_status_code == 400:
			self.__logger.generateApplicationLog("Telegram message not sent. Status: Bad request.", 3, "__sendTelegramMessage", use_stream_handler = True, use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		elif response_status_code == 401:
			self.__logger.generateApplicationLog("Telegram message not sent. Status: Unauthorized.", 3, "__sendTelegramMessage", use_stream_handler = True, use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)
		elif response_status_code == 404:
			self.__logger.generateApplicationLog("Telegram message not sent. Status: Not found.", 3, "__sendTelegramMessage", use_stream_handler = True, use_file_handler = True, name_file_log = self.__constants.NAME_FILE_LOG, user = self.__constants.USER, group = self.__constants.GROUP)