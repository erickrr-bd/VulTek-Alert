"""
Class that manages all the constant variables of the application.
"""
class Constants:
	"""
	Absolute path of the VulTek-Alert-Agent configuration file.
	"""
	PATH_VULTEK_ALERT_AGENT_CONFIGURATION_FILE = "/etc/VulTek-Alert-Suite/VulTek-Alert-Agent/configuration/vultek_alert_agent_conf.yaml"

	"""
	Absolute path of the file where the key for the encryption/decryption process is stored.
	"""
	PATH_KEY_FILE = "/etc/VulTek-Alert-Suite/VulTek-Alert/configuration/key"

	"""
	Absolute path of the application logs.
	"""
	NAME_FILE_LOG = "/var/log/VulTek-Alert/vultek-alert-agent-log-"

	"""
	Name of the user created for the operation of the application.
	"""
	USER = "vultek_alert"

	"""
	Name of the group created for the operation of the application.
	"""
	GROUP = "vultek_alert"