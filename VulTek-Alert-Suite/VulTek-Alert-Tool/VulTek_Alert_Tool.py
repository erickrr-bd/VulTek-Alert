#! /usr/bin/env python3

from modules.FormClass import FormDialog

"""
Property that stores an object of the FormDialog class.
"""
form = FormDialog()

"""
Main function of the application
"""
if __name__ == "__main__":	
	while True:
		form.mainMenu()