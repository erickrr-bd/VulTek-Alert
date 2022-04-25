#! /usr/bin/env python3

from modules.VulTek_Alert_Class import VulTekAlert

"""
Attribute that stores an object of the VulTekAlert class.
"""
vultek_alert = VulTekAlert()

"""
Main function of the application.
"""
if __name__ == "__main__":	
		vultek_alert.startVulTekAlert()