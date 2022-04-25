"""
Class that manages all the constant variables of the application.
"""
class Constants:
	"""
	Absolute path of the VulTek-Alert configuration file.
	"""
	PATH_FILE_CONFIGURATION = "/etc/VulTek-Alert-Suite/VulTek-Alert/configuration/vultek_alert_conf.yaml"

	"""
	Absolute path of the file where the key for the encryption/decryption process is stored.
	"""
	PATH_KEY_FILE = "/etc/VulTek-Alert-Suite/VulTek-Alert/configuration/key"

	"""
	Absolute path of the file corresponding to the CVE's database.
	"""
	PATH_DATABASE_FILE = "/etc/VulTek-Alert-Suite/VulTek-Alert/database/database_cves.yaml"

	"""
	Absolute path of the application logs.
	"""
	NAME_FILE_LOG = "/var/log/VulTek-Alert/vultek-alert-log-"

	"""
	Name of the application logs.
	"""
	NAME_LOG = "VULTEK_ALERT_LOG"

	"""
	Name of the user created for the operation of the application.
	"""
	USER = "vultek_alert"

	"""
	Name of the group created for the operation of the application.
	"""
	GROUP = "vultek_alert"