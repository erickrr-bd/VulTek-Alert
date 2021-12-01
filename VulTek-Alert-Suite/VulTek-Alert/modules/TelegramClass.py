from time import strftime
from datetime import datetime
from pycurl import Curl, HTTP_CODE
from urllib.parse import urlencode
from modules.UtilsClass import Utils

"""
Class that allows you to manage the sending of alerts through Telegram.
"""
class Telegram:
	"""
	Property that stores an object of type Utils.
	"""
	utils = None

	"""
	Constructor for the Telegram class.

	Parameters:
	self -- An instantiated object of the Telegram class.
	"""
	def __init__(self):
		self.utils = Utils()

	"""
	Method that sends the alert to the telegram channel.

	Parameters:
	self -- Instance object.
	telegram_chat_id -- Telegram channel identifier to which the letter will be sent.
	telegram_bot_token -- Token of the Telegram bot that is the administrator of the Telegram channel to which the alerts will be sent.
	message -- Message to be sent to the Telegram channel.
	"""
	def sendTelegramAlert(self, telegram_chat_id, telegram_bot_token, message):
		if len(message) > 4096:
			message = "The size of the message in Telegram (4096) has been exceeded. Overall size: " + str(len(message))
		c = Curl()
		url = 'https://api.telegram.org/bot' + str(telegram_bot_token) + '/sendMessage'
		c.setopt(c.URL, url)
		data = { 'chat_id' : telegram_chat_id, 'text' : message }
		pf = urlencode(data)
		c.setopt(c.POSTFIELDS, pf)
		c.perform_rs()
		status_code = c.getinfo(HTTP_CODE)
		c.close()
		self.getStatusByTelegramCode(status_code)

	"""
	Method that generates the message that will be sent by Telegram.

	Parameters:
	self -- An instantiated object of the Telegram class.
	cve -- Common Vulnerabilities and Exposures.
	public_date -- Date of publication of the vulnerability.
	severity -- Severity level of vulnerability.
	bugzilla_description -- Description of the vulnerability. 
	cwe -- Common Weakness Enumeration.
	cvss3_scoring_vector -- Scoring vector of Common Vulnerability Scoring System.
	cvss3_score -- Score of Common Vulnerability Scoring System.

	Return:
	message -- Message to be sent in the alert.
	"""
	def getVulnerabilityMessage(self, cve, public_date, severity, bugzilla_description, cwe, cvss3_scoring_vector, cvss3_score):
		message = u'\u26A0\uFE0F' + " " + 'VulTek-Alert' +  " " + u'\u26A0\uFE0F' + "\n\n" + u'\u23F0' + " Alert sent: " + strftime("%c") + "\n\n\n"
		message += u'\u2611\uFE0F' + " CVE: " + cve + '\n'
		message += u'\u2611\uFE0F' + " Public Date: " + public_date + '\n'
		message += u'\u2611\uFE0F' + " Severity: " + severity + '\n'
		message += u'\u2611\uFE0F' + " Description: " + bugzilla_description + '\n'
		message += u'\u2611\uFE0F' + " CWE: " + str(cwe) + '\n'
		message += u'\u2611\uFE0F' + " CVSS3 Scoring Vector: " + str(cvss3_scoring_vector) + '\n'
		message += u'\u2611\uFE0F' + " CVSS3 Score: " + str(cvss3_score) + '\n'
		return message

	"""
	Method that generates the message that will be sent in the alert when CVE's are not found.

	Parameters:
	self -- An instantiated object of the Telegram class.
	severity -- Severity level of vulnerability.

	Return:
	message -- Message to be sent in the alert.
	"""
	def getNotVulnerabilityFoundMessage(self, severity):
		message = u'\u26A0\uFE0F' + " " + 'VulTek-Alert' +  " " + u'\u26A0\uFE0F' + "\n\n" + u'\u23F0' + " Alert sent: " + strftime("%c") + "\n\n\n"
		message += u'\u270F\uFE0F' + " No CVE's of the following severity were found: " + severity
		return message
	
	"""
	Method that prints the status of the alert delivery based on the response HTTP code.

	Parameters:
	self -- An instantiated object of the Telegram class.
	telegram_code -- HTTP code in response to the request made to Telegram.
	"""
	def getStatusByTelegramCode(self, telegram_code):
		if telegram_code == 200:
			self.utils.createVulTekAlertLog("Telegram message sent.", 1)
			print("Telegram message sent.")
		elif telegram_code == 400:
			self.utils.createVulTekAlertLog("Telegram message not sent. Status: Bad request.", 3)
			print("Telegram message not sent. Status: Bad request.")
		elif telegram_code == 401:
			self.utils.createVulTekAlertLog("Telegram message not sent. Status: Unauthorized.", 3)
			print("Telegram message not sent. Status: Unauthorized.")
		elif telegram_code == 404:
			self.utils.createVulTekAlertLog("Telegram message not sent. Status: Not found.", 3)
			print("Telegram message not sent. Status: Not found.")