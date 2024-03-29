"""
Class that manages all the constant variables of the application.
"""
class Constants:
	"""
	Title that is shown in the background of the application.
	"""
	BACKTITLE = "VULTEK-ALERT-TOOL v3.2.1 by Erick Rodriguez"

	"""
	Absolute path of the VulTek-Alert configuration file.
	"""
	PATH_VULTEK_ALERT_CONFIGURATION_FILE = "/etc/VulTek-Alert-Suite/VulTek-Alert/configuration/vultek_alert_conf.yaml"

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
				  	  	 ("3", "VulTek-Alert-Agent"),
				  	  	 ("4", "About"),
			      	  	 ("5", "Exit")]

	"""
	Options that are shown when the configuration file does not exist.
	"""
	OPTIONS_CONFIGURATION_FALSE = [("Create", "Create the configuration file", 0)]

	"""
	Options that are shown when the configuration file exists.
	"""
	OPTIONS_CONFIGURATION_TRUE = [("Modify", "Modify the configuration file", 0),
								  ("Show", "Show the configuration data", 0)]

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

	"""
	Options that are shown when a value is going to be modified in the VulTek-Alert configuration.
	"""
	OPTIONS_VULTEK_ALERT_UPDATE = [("Level", "Vulnerability level", 0),
							 	   ("Created Days Ago", "Time range in which CVE's will be searched", 0),
							       ("Time Search", "Time in which the search will be repeated", 0),
							       ("Bot Token", "Telegram Bot Token", 0),
							       ("Chat ID", "Telegram channel identifier", 0),
							       ("Elastic", "Integration with ElasticSearch",0)]

	"""
	Options that are displayed when the elastic integration is enabled.
	"""
	OPTIONS_INTEGRATION_ES_TRUE = [("Data", "Modify integration data", 0),
								   ("Disable", "Disable integration with ElasticSearch", 0)]

	"""
	Options that are displayed when the elastic integration is disabled.
	"""
	OPTIONS_INTEGRATION_ES_FALSE = [("Enable", "Enable integration with ElasticSearch", 0)]

	"""
	Options that can be modified in the "Integration with ElasticSearch" section.
	"""
	OPTIONS_INTEGRATION_ELASTIC = [("Host", "ElasticSearch Host", 0),
							 	   ("Port", "ElasticSearch Port", 0),
							 	   ("SSL/TLS", "Enable or disable SSL/TLS connection", 0),
							 	   ("Authentication", "Enable or disable authentication method", 0)]

	"""
	Options that are displayed when "ElasticSearch hosts" option is modify.
	"""
	OPTIONS_ES_HOSTS_UPDATE = [("1", "Add New Hosts"),
							   ("2", "Modify Hosts"),
							   ("3", "Remove Hosts")]

	"""
	Options displayed when the use of SSL/TLS is enabled.
	"""
	OPTIONS_SSL_TLS_TRUE = [("Disable", "Disable SSL/TLS communication", 0),
							("Certificate Verification", "Modify certificate verification", 0)]

	"""
	Options displayed when the use of SSL/TLS is disabled.
	"""
	OPTIONS_SSL_TLS_FALSE = [("Enable", "Enable SSL/TLS communication", 0)]

	"""
	Options displayed when SSL certificate verification is enabled.
	"""
	OPTIONS_VERIFICATION_CERTIFICATE_TRUE = [("Disable", "Disable certificate verification", 0),
								   		     ("Certificate File", "Change certificate file", 0)]

	"""
	Options displayed when SSL certificate verification is disabled.
	"""
	OPTIONS_VERIFICATION_CERTIFICATE_FALSE = [("Enable", "Enable certificate verification", 0)]

	"""
	Options that are displayed when authentication is enabled.
	"""
	OPTIONS_AUTHENTICATION_TRUE = [("Data", "Modify authentication method", 0),
								   ("Disable", "Disable authentication method", 0)]

	"""
	Options that are displayed when modify an authentication method.
	"""
	OPTIONS_AUTHENTICATION_METHOD_TRUE = [("Data", "Modify authentication method data", 0),
								   	      ("Disable", "Disable authentication method", 0)]

	"""
	Options that are displayed when authentication is disabled.
	"""
	OPTIONS_AUTHENTICATION_FALSE = [("Enable", "Enable authentication", 0)]

	"""
	Options that are displayed when the HTTP authentication credentials are to be modified.
	"""
	OPTIONS_HTTP_AUTHENTICATION_DATA = [("Username", "Username for HTTP Authentication", 0),
								 		("Password", "User password", 0)]

	"""
	Options that are displayed when the API Key credentials are to be modified.
	"""
	OPTIONS_API_KEY_DATA = [("API Key ID", "API Key Identifier", 0),
							("Api Key", "API Key", 0)]

	"""
	Options displayed in the "Service" menu.
	"""
	OPTIONS_SERVICE_MENU = [("1", "Start Service"),
				            ("2", "Restart Service"),
				            ("3", "Stop Service"),
				            ("4", "Service Status")]

	"""
	Options displayed in the "VulTek-Alert-Agent" menu.
	"""
	OPTIONS_VULTEK_ALERT_AGENT_MENU = [("1", "Configuration"),
							   		   ("2", "VulTek-Alert-Agent Service")]

	"""
	Options that are shown when a value is going to be modified in the VulTek-Alert-Agent configuration.
	"""
	OPTIONS_VULTEK_ALERT_AGENT_UPDATE = [("First Execution", "First time the service is validated", 0),
							 			 ("Second Execution", "Second time the service is validated", 0),
							 			 ("Bot Token", "Telegram Bot Token", 0),
							 			 ("Chat ID", "Telegram channel identifier", 0)]