#! /usr/bin/env python3

from modules.VulTek_Alert_Tool_Class import VulTekAlertTool

"""
Attribute that stores an object of the VulTekAlertTool class.
"""
vultek_alert_tool = VulTekAlertTool()

"""
Main function of the application
"""
if __name__ == "__main__":	
	while True:
		vultek_alert_tool.mainMenu()