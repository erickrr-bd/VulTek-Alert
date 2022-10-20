#! /usr/bin/env python3

from modules.VulTek_Alert_Agent_Class import VulTekAlertAgent

"""
Attribute that stores an object of the VulTekAlertAgent class.
"""
vultek_alert_agent = VulTekAlertAgent()

"""
Main function of the application
"""
if __name__ == "__main__":
	vultek_alert_agent.startVulTekAlertAgent()