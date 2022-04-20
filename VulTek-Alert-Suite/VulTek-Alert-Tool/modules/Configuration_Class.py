from libPyLog import libPyLog
from libPyUtils import libPyUtils
from libPyDialog import libPyDialog
from .Constants_Class import Constants

class Configuration:

	__utils = None

	__logger = None

	__dialog = None

	__constants = None

	__action_to_cancel = None

	def __init__(self, action_to_cancel):
		self.__utils = libPyUtils()
		self.__constants = Constants()
		self.__action_to_cancel = action_to_cancel
		self.__dialog = libPyDialog(self.__constants.BACKTITLE, action_to_cancel)
		self.__logger = libPyLog(self.__constants.NAME_FILE_LOG, self.__constants.NAME_LOG, self.__constants.USER, self.__constants.GROUP)


	def createConfiguration(self):
		"""
		"""
		data_configuration = []
		try:
			options_level_vulnerabilities = self.__dialog.createCheckListDialog("Select one or more options:", 12, 50, self.__constants.OPTIONS_LEVEL_VULNERABILITIES, "Vulnerabilities Levels")
			data_configuration.append(options_level_vulnerabilities)
			passphrase = self.__utils.getPassphraseKeyFile(self.__constants.PATH_KEY_FILE)
			telegram_bot_token = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the Telegram bot token:", 10, 50, "751988420:AAHrzn7RXWxVQQNha0tQUzyouE5lUcPde1g"), passphrase)
			data_configuration.append(telegram_bot_token.decode('utf-8'))
			telegram_chat_id = self.__utils.encryptDataWithAES(self.__dialog.createInputBoxDialog("Enter the Telegram channel identifier:", 10, 50, "-1002365478941"), passphrase)
			data_configuration.append(telegram_chat_id.decode('utf-8'))
			print(data_configuration)
			self.__action_to_cancel()
		except (FileNotFoundError, IOError, OSError) as exception:
			self.__dialog.createMessageDialog("\nError creating, opening or reading the file. For more information, see the logs.", 8, 50, "Error Message")
			self.__action_to_cancel()
