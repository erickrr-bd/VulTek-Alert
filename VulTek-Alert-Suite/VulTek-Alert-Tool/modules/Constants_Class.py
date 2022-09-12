"""
Class that manages all the constant variables of the application.
"""
class Constants:
	"""
	Title that is shown in the background of the application.
	"""
	BACKTITLE = "VULTEK-ALERT-TOOL"

	"""
	Absolute path of the VulTek-Alert configuration file.
	"""
	PATH_FILE_CONFIGURATION = "/etc/VulTek-Alert-Suite/VulTek-Alert/configuration/vultek_alert_conf.yaml"

	"""
	Absolute path of the file where the key for the encryption/decryption process is stored.
	"""
	PATH_KEY_FILE = "/etc/VulTek-Alert-Suite/VulTek-Alert/configuration/key"

	"""
	Absolute path of the application logs.
	"""
	NAME_FILE_LOG = "/var/log/VulTek-Alert/vultek-alert-tool-log-"

	"""
	Name of the user created for the operation of the application.
	"""
	USER = "vultek_alert"

	"""
	Name of the group created for the operation of the application.
	"""
	GROUP = "vultek_alert"

	"""
	Options displayed in the "Main" menu.
	"""
	OPTIONS_MAIN_MENU = [("1", "VulTek-Alert Configuration"),
				  	  	 ("2", "VulTek-Alert Service"),
				  	  	 ("3", "About"),
			      	  	 ("4", "Exit")]

	"""
	Options that are shown when the configuration file does not exist.
	"""
	OPTIONS_CONFIGURATION_FALSE = [("Create", "Create the configuration file", 0)]

	"""
	Options that are shown when the configuration file exists.
	"""
	OPTIONS_CONFIGURATION_TRUE = [("Modify", "Modify the configuration file", 0)]

	"""
	Options that are shown when a value is going to be modified in the VulTek-Alert configuration.
	"""
	OPTIONS_FIELDS_UPDATE = [("Level", "Vulnerability level", 0),
							 ("Bot Token", "Telegram Bot Token", 0),
							 ("Chat ID", "Telegram channel identifier", 0)]

	"""
	Options displayed in the "Service" menu.
	"""
	OPTIONS_SERVICE_MENU = [("1", "Start Service"),
				            ("2", "Restart Service"),
				            ("3", "Stop Service"),
				            ("4", "Service Status")]

	"""
	Options that show the level of criticality of the vulnerabilities.
	"""
	OPTIONS_LEVEL_VULNERABILITIES = [["low", "Low level vulnerability", 0],
								     ["moderate", "Medium level vulnerability", 0],
								     ["important", "Important level vulnerability", 0],
								     ["critical", "Critical level vulnerability", 0]]

	"""
	Options that are displayed to select an unit time.
	"""
	OPTIONS_UNIT_TIME = [["minutes", "Time expressed in minutes", 1],
					  	 ["hours", "Time expressed in hours", 0],
					  	 ["days", "Time expressed in days", 0]]

	"""
	Options that are displayed to select an authentication method.
	"""
	OPTIONS_AUTHENTICATION_METHOD = [("HTTP authentication", "Use HTTP Authentication", 0),
								     ("API Key", "Use API Key", 0)]