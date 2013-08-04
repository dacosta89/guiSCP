#!/usr/bin/python

from Tkinter import *
import paramiko
from paramiko import scp
import base64
import os
import sys

hostfile = './scpHosts.txt'
pathfile = './scpFilePaths.txt'
command = "touch"


def SSHClient(host, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=username, password=password, timeout=3)
    return client

class Main_tk(object):

	#############################################################
	# Function: Initialize Self
	#############################################################
	def __init__(self, master=None, title=None):
		self.master = master
		self.title = title
		self.createWidgets()
		
		self.master.protocol("WM_DELETE_WINDOW", self.cancelPressed)  # When the X is clicked
	
	#############################################################
	# Creates all the Widgets
	#############################################################
	def createWidgets(self):

		# Main Frame
		mainFrame = Frame(self.master)
		mainFrame.pack()
	
		#############################################################
		# Host List Frame
		#############################################################
		hostListFrame = Frame(mainFrame)
		hostListFrame.pack(side=LEFT, padx=(20, 0), pady=20)
        
		# Hosts List Label
		hostListLabel = Label(hostListFrame, text="Hosts")
		hostListLabel.pack(side=TOP, anchor=W, padx=100)
		
		#############################################################
		# Configure Hosts Buttons
		#############################################################
		hostButtonFrame = Frame(hostListFrame)
		hostButtonFrame.pack(side=RIGHT, padx=10, pady=10)
		
		self.addButton = Button(hostButtonFrame, text="Add Host", command=self.addHostButtonPressed)
		self.addButton.pack(side=TOP, pady=(0,10))
		
		self.delButton = Button(hostButtonFrame, text="Remove Host", command=self.delHostButtonPressed)
		self.delButton.pack(side=BOTTOM)
		
		self.editButton = Button(hostButtonFrame, text="Edit Host", command=self.editHostButtonPressed)
		self.editButton.pack(side=BOTTOM, pady=(0,10))
		
		#############################################################
		# Host Scroll Bars and Listbox
		#############################################################
		yscrollBar = Scrollbar(hostListFrame)
		yscrollBar.pack(side=RIGHT, fill=Y)
		
		xscrollBar = Scrollbar(hostListFrame, orient=HORIZONTAL)
		xscrollBar.pack(side=BOTTOM, fill=X)
		
		self.hostListBox = Listbox(hostListFrame, width=40, height=20, selectmode=EXTENDED, exportselection=0)
		self.hostListBox.pack(side=LEFT, fill=Y)
		xscrollBar.config(command=self.hostListBox.xview)          							# Horizontal Scrollbar config
		yscrollBar.config(command=self.hostListBox.yview)          							# Vertical Scrollbar config
		self.hostListBox.config(yscrollcommand=yscrollBar.set, xscrollcommand=xscrollBar.set)  				# Listbox config
		
		#############################################################
		# Configure File Path Frame
		#############################################################
		optionsFrame = Frame(mainFrame)
		optionsFrame.pack(side=RIGHT, padx=(10, 0), pady=5)
		
		fpButtonFrame = Frame(optionsFrame)
		fpButtonFrame.pack(side=BOTTOM, padx=10, pady=3)
		
		chbxFrame = Frame(optionsFrame)
		chbxFrame.pack(side=TOP, padx=10, pady=3)
		
		#############################################################
		# File Path List Frame
		#############################################################
		filePathFrame = Frame(mainFrame)
		filePathFrame.pack(side=RIGHT, padx=(10, 0), pady=20)
        
		# File Path Label
		filePathLabel = Label(filePathFrame, text="Local Path -> Remote Path")
		filePathLabel.pack(side=TOP, anchor=W, padx=65)
		
		################################################################
		# Add and Configure Checkboxes + File Permissions Entry + Label
		################################################################
		self.touchCheckVariable = IntVar()
		self.permissionsCheckVariable = IntVar()
	
		self.touchCheckbox = Checkbutton(chbxFrame, text='Touch File', variable=self.touchCheckVariable, onvalue=1, offvalue=0)
		self.touchCheckbox.pack(side=TOP, pady=(0, 2))
		self.permissionsCheckbox = Checkbutton(chbxFrame, text='File Permissions', variable=self.permissionsCheckVariable, onvalue=1, offvalue=0)
		self.permissionsCheckbox.pack(side=LEFT, pady=(0, 3))
		
		self.permissionsLabel = Label(chbxFrame, text="i.e. 755")
		self.permissionsLabel.pack(side=RIGHT)
		self.permissionsEntry = Entry(chbxFrame, width=4)
		self.permissionsEntry.pack(side=RIGHT)

		#############################################################
		# Configure File Path Buttons
		#############################################################
		self.fpAddButton = Button(fpButtonFrame, text="Add File Paths", command=self.addPathButtonPressed)
		self.fpAddButton.pack(side=TOP, pady=(0,10))
		
		self.fpDelButton = Button(fpButtonFrame, text="Remove File Paths", command=self.delPathButtonPressed)
		self.fpDelButton.pack(side=BOTTOM)
		
		self.fpEditButton = Button(fpButtonFrame, text="Edit File Paths", command=self.editPathButtonPressed)
		self.fpEditButton.pack(side=BOTTOM, pady=(0,10))
		
		#############################################################
		# File Path Scroll Bars and Listbox
		#############################################################
		yscrollBar = Scrollbar(filePathFrame)
		yscrollBar.pack(side=RIGHT, fill=Y)
		
		xscrollBar = Scrollbar(filePathFrame, orient=HORIZONTAL)
		xscrollBar.pack(side=BOTTOM, fill=X)
		
		self.filePathListBox = Listbox(filePathFrame, width=50, height=20, selectmode=EXTENDED, exportselection=0)
		self.filePathListBox.pack(side=LEFT, fill=Y)
		xscrollBar.config(command=self.filePathListBox.xview)          							# Horizontal Scrollbar config
		yscrollBar.config(command=self.filePathListBox.yview)          							# Vertical Scrollbar config
		self.filePathListBox.config(yscrollcommand=yscrollBar.set, xscrollcommand=xscrollBar.set)  			# Listbox config
		
		#############################################################
		# Configure Launch, Cancel, and Help Buttons
		#############################################################
		launchButtonFrame = Frame(mainFrame)
		launchButtonFrame.pack(side=TOP, pady=(20,0))
		
		self.launchButton = Button(launchButtonFrame, text="Launch", background="GREEN", command=self.launchPressed)
		self.launchButton.pack(side=TOP, pady=(0, 5))

		self.cancelButton = Button(launchButtonFrame, text="Cancel", background="RED", command=self.cancelPressed)
		self.cancelButton.pack(side=TOP)

		self.helpButton = Button(launchButtonFrame, text="Help", command=self.helpPressed)
		self.helpButton.pack(side=TOP, pady=(15,0))	

		#############################################################
		# Add to List Frames using default files
		#############################################################
		f1 = open(hostfile, "r")
		for line in f1.readlines():
			ip, name, user, password = '', '', '', ''
			for i, word in enumerate(line.split()):
				if i == 0:
					name = word.strip()
				elif i == 1:
					ip = word.strip()
				elif i == 2:
					user = word.strip()
				elif i == 3:
					password = word.strip()
			if name and ip and user and password:
				item = "%s -> %s (%s) (%s)" % (name, ip, user, password)
				self.hostListBox.insert(END, item)
			elif name and ip and user:
				item = "%s -> %s (%s) ()" % (name, ip, user)
				self.hostListBox.insert(END, item)
			elif name and ip:
				item = "%s -> %s () ()" % (name, ip)
				self.hostListBox.insert(END, item)
		f1.close()

		f2 = open(pathfile, "r")
		state = 0
		for line in f2.readlines():
			localpath = ''
			remotepath = ''
    			for i, word in enumerate(line.split()):
					if state == 0:
						if word[-1:] == '\\':
							localpath += "%s " % word
						elif word.find('.')!=-1:	# Found period
							if word.rfind('.') > word.rfind('/'):
								localpath += word
								state = 1
							elif word[-1:] == '/':
								localpath += word
								state = 1
							else:
								localpath += word
								state = 1
						elif word.find('.')==-1:	# No period
							if word[-1:] == '/':
								localpath += word
								state = 1
							else:
								localpath += word
								state = 1
					elif state == 1:
						if word[-1:] == '\\':
							remotepath += "%s " % word
						elif word.rfind('.') > word.rfind('/'):
							remotepath += word
							state = 0
						elif word[-1:] == '/':
							remotepath += word
							state = 0
						else:
							remotepath += word
							state = 0
					if localpath and remotepath:
						item = "%s -> %s" % (localpath, remotepath)
						self.filePathListBox.insert(END, item)
		f2.close()

	#############################################################
	# Function: When Launch Button is Pressed
	#
	# Reads the selected values from both Lists and kicks off
	# the the ssh connections with the hosts and secure copies
	# the files to those hosts
	#############################################################
	def launchPressed(self):
		if self.hostListBox.curselection() and self.filePathListBox.curselection():
			first = True
			for i, val1 in enumerate(self.hostListBox.curselection()):
				try:
					#############################################################
					# Cycle through the selected Hosts to connect to
					#############################################################
					print 'Connecting to host %s...' % (self.hostListBox.get(self.hostListBox.curselection()[i]).split()[0])
					'''
					f1 = open(hostfile, "r")
					for k in f1.readlines():
						ip = ''
						name = ''
						user = ''
						for m, word in enumerate(k.split()):
							if m == 0:
								name = word.strip()
							elif m == 1:
								ip = word.strip()
							elif m == 2:
								user = word.strip()
							if name and ip and user and m == 3:
								if name == self.hostListBox.get(self.hostListBox.curselection()[i]).split()[0] and ip == self.hostListBox.get(self.hostListBox.curselection()[i]).split()[2] and user == self.hostListBox.get(self.hostListBox.curselection()[i]).split()[3][1:-1]:
									ssh = SSHClient(self.hostListBox.get(self.hostListBox.curselection()[i]).split()[2], self.hostListBox.get(self.hostListBox.curselection()[i]).split()[3][1:-1], base64.b64decode(word))
									secureCP = scp.SCPClient(ssh.get_transport())
									continue
					'''
					if self.hostListBox.get(self.hostListBox.curselection()[i]).split()[3][1:-1] and base64.b64decode(self.hostListBox.get(self.hostListBox.curselection()[i]).split()[4][1:-1]):
						ssh = SSHClient(self.hostListBox.get(self.hostListBox.curselection()[i]).split()[2], self.hostListBox.get(self.hostListBox.curselection()[i]).split()[3][1:-1], base64.b64decode(self.hostListBox.get(self.hostListBox.curselection()[i]).split()[4][1:-1]))
						secureCP = scp.SCPClient(ssh.get_transport())
					else:
						if first:
							print 'yes'
							self.editHostButtonPressed(duringLaunch=True, f=True)
							first = False
						else:
							print 'no'
							self.editHostButtonPressed(duringLaunch=True, f=False)
						continue
					############################################################################################################
					# Cycle through the selected File Paths and parse the local and remote paths to be used to copy the file(s)
					############################################################################################################
					for j, val2 in enumerate(self.filePathListBox.curselection()):
						try:
							index=0
							state=0
							dirFlag=0
							fileList=[]
							lp = ''
							rp = ''
							f = ''
							temp = self.filePathListBox.get(self.filePathListBox.curselection()[j]).split()
							while True:
								try:
									if state==0 and temp[index] != '->':
										if temp[index][-1:] == '\\':
											lp += "%s " % temp[index][:-1]
										else:
											lp += temp[index]
											if temp[index].rfind('.')!=-1:
												if temp[index].rfind('.') > temp[index].rfind('/'): 				#grab file name
													f = temp[index][temp[index].rfind('/')+1:]
												elif temp[index][-1:] == '/':
													dirFlag = 1
											elif temp[index].rfind('.')==-1:
												if temp[index][-1:] == '/':
													dirFlag = 1
									elif temp[index] == '->':
										state = 1
									elif state==1:
										if temp[index][-1:] == '\\':
											rp += "%s " % temp[index][:-1]
										else:
											rp += temp[index]
									index+=1
								except IndexError:
									break
							######################################################################################################
							# Check that the Remote Directory Used exists and checks if the file being transfered already exists
							######################################################################################################
							print 'Begin Transferring %s to host %s' % (lp, self.hostListBox.get(self.hostListBox.curselection()[i]).split()[0])
							pathChecker = "[ -d " + rp + " ] && echo 'Directory found' || echo 'Directory not found'"""
							stdin, stdout1, stderr = ssh.exec_command(pathChecker)
							if stdout1.readlines()[0].replace('\n','') == "Directory found":
								fileChecker = "[ -f " + rp + f + " ] && echo 'file found' || echo 'file not found'"""
								stdin, stdout2, stderr = ssh.exec_command(fileChecker)
								if stdout2.readlines()[0].replace('\n','') == "file found":
									temp = "chmod +w %s%s" % (rp, f)
									ssh.exec_command(temp)
									secureCP.put(lp, rp)
								else:
									if not dirFlag:
										secureCP.put(lp, rp)
									else:
										temp = "find %s -exec chmod +w {} \;" % (rp)
										ssh.exec_command(temp)
										secureCP.put(lp, rp, recursive=True)
								stdout2.close()
							else:
								mkdirCommand = "mkdir -p " + rp
								ssh.exec_command(mkdirCommand)
								if not dirFlag:
									secureCP.put(lp, rp)
								else:
									secureCP.put(lp, rp, recursive=True)
							print 'Successfully Transferred %s to host %s' % (lp, self.hostListBox.get(self.hostListBox.curselection()[i]).split()[0])
							stdout1.close()
							######################################################################################################
							# If Touch File is checked then it will run the Touch command on that file
							######################################################################################################
							if self.touchCheckVariable.get():
								if not dirFlag:
									temp = command
									temp += " %s%s" % (rp, f)
									stdin, stdout, stderr = ssh.exec_command(temp)
									print 'Successfully touched file on host %s' % (self.hostListBox.get(self.hostListBox.curselection()[i]).split()[0])
								else:
									temp = command
									temp += " %s -exec touch {} \;" % (rp)
									stdin, stdout, stderr = ssh.exec_command(temp)
									print 'Successfully touched files on host %s' % (self.hostListBox.get(self.hostListBox.curselection()[i]).split()[0])
							######################################################################################################
							# If Change Permissions is checked then it will run the chmod <value> command on that file
							######################################################################################################	
							if self.permissionsCheckVariable.get() and self.permissionsEntry.get():  # [:1] First Digit, [1:-1] Middle Digit, [-1:] Last Digit
								if ( len(self.permissionsEntry.get()) == 3 and ( self.permissionsEntry.get()[:1] >= '0' and self.permissionsEntry.get()[:1] <= '7' ) and
									( self.permissionsEntry.get()[1:-1] >= '0' and self.permissionsEntry.get()[1:-1] <= '7' ) and
									( self.permissionsEntry.get()[-1:] >= '0' and self.permissionsEntry.get()[-1:] <= '7' )):
									if not dirFlag:
										temp = "chmod %s %s%s" % (self.permissionsEntry.get(), rp, f)
										stdin, stdout, stderr = ssh.exec_command(temp)
										print 'Successfully changed file permissions for %s%s on host %s' % (rp, f, self.hostListBox.get(self.hostListBox.curselection()[i]).split()[0])
									else:
										temp = "find %s -exec chmod %s {} \;" % (rp, self.permissionsEntry.get())
										stdin, stdout, stderr = ssh.exec_command(temp)
										print 'Successfully changed file permissions for %s on host %s' % (rp, self.hostListBox.get(self.hostListBox.curselection()[i]).split()[0])
						except:
							pass
					ssh.close()
				except:
					print 'ERROR: Could not connect to...%s' % (self.hostListBox.get(self.hostListBox.curselection()[i]).split()[0])
		#f1.close()
		if self.hostListBox.curselection() and self.filePathListBox.curselection():
			print 'Transferring Completed'
			print ''
	
	#############################################################
	# Kills Program
	#############################################################
	def cancelPressed(self):
		try:
			self.addHost.destroy()
		except AttributeError:
			pass
		except TclError:
			pass
		try:
			self.help.destroy()
		except AttributeError:
			pass
		except TclError:
			pass
		try:
			self.delHost.destroy()
		except AttributeError:
			pass
		except TclError:
			pass
		try:
			self.addPath.destroy()
		except AttributeError:
			pass
		except TclError:
			pass
		try:
			self.delHost.destroy()
		except AttributeError:
			pass
		except TclError:
			pass
		try:
			for i, val in enumerate(self.openWindows):
				self.openWindows[i][0].destroy()
		except AttributeError:
			pass
		except TclError:
			pass
		self.master.destroy()

	#############################################################
	# Help Information is displayed
	#############################################################
	def helpPressed(self):
		def help_cancel():
			self.help.destroy()
			self.touchCheckbox.config(state=NORMAL)
			self.permissionsCheckbox.config(state=NORMAL)
			self.launchButton.config(state=NORMAL)
			self.cancelButton.config(state=NORMAL)
			self.helpButton.config(state=NORMAL)
			self.delButton.config(state=NORMAL)
			self.editButton.config(state=NORMAL)
			self.addButton.config(state=NORMAL)
			self.fpDelButton.config(state=NORMAL)
			self.fpEditButton.config(state=NORMAL)
			self.fpAddButton.config(state=NORMAL)
			self.hostListBox.config(state=NORMAL)
			self.filePathListBox.config(state=NORMAL)
			self.permissionsEntry.config(state=NORMAL)

		# Disable all other Widgets
		self.touchCheckbox.config(state=DISABLED)
		self.permissionsCheckbox.config(state=DISABLED)
		self.launchButton.config(state=DISABLED)
		self.cancelButton.config(state=DISABLED)
		self.helpButton.config(state=DISABLED)
		self.delButton.config(state=DISABLED)
		self.editButton.config(state=DISABLED)
		self.addButton.config(state=DISABLED)
		self.fpDelButton.config(state=DISABLED)
		self.fpEditButton.config(state=DISABLED)
		self.fpAddButton.config(state=DISABLED)
		self.hostListBox.config(state=DISABLED)
		self.filePathListBox.config(state=DISABLED)
		self.permissionsEntry.config(state=DISABLED)
		
		# Creates a new window to add host
		self.help = Tk()
		self.help.protocol("WM_DELETE_WINDOW", help_cancel)  # When the X is clicked
		self.help.title("Help")
		
		textFrame = Frame(self.help)
		textFrame.pack(side=TOP, padx=20, pady=20)
		
		textBoxscrollBar = Scrollbar(textFrame)
		textBoxscrollBar.pack(side=RIGHT, fill=Y)
		
		TextBox = Text(textFrame)
		TextBox.config(width=80, height=30)
		TextBox.pack(side=LEFT, fill=Y)
		textBoxscrollBar.config(command=TextBox.yview)
		TextBox.insert(END, "Author: Derrick DaCosta\n"
							"Current Version: 1.3\n" 
							"Last Updated: 2013-04-02\n"
							"\n"
							"--------------------------------------------------------------------------------\n"
							"\n"
							" Version History\n"
							"\n"
							" 1.0 - Original Release: Basic Functionality\n"
							" 1.1 - New Enhancements: Add new directory to Remote Location if one does not\n"
							"       exist already\n"
							" 1.2 - Bug Fixes: Program now skips Host if unable to connect after 3 seconds\n"
							"       New Enhancements: Added ability to change file permissions\n"
							"                         Multiple Usernames and Encrypted Passwords for Hosts\n"
							" 1.3 - New Enhancements: Copy, Touch, and Change File Permissions for whole\n"
							"                         directories\n"
							"                         Edit existing entries\n"
							"\n"
							"--------------------------------------------------------------------------------\n"
							"\n"
							"TODO\n"
							"Text box for additional commands to run\n"
							"File Browser for doing the local and remote file paths\n"
							"\n"
							"Description:\n"
							"\tThis tool was created to implement ease-of-use and quickness when doing\n"
							"a secure copy to multiple machines.  The tool reads the \"scpHosts.txt\" file\n"
							"to get a saved list of the known Hosts and the \"scpFilePaths.txt\" to get a\n"
							"saved list of the known local and remote file paths to send files to.\n"
							"\n"
							"Editing or Additions to those files, the following formats are expected:\n"
							"\n"
							"scpHosts.txt:\n"
							"<Hostname> <IP Address>\n"
							"\n"
							"scpFilePaths.txt:\n"
							"<Local Path> <Remote Path>\n")
		
			
	#############################################################
	# Function: When Host List Add Button is Pressed
	#
	# Creates a new Window to add Hosts
	#############################################################		
	def addHostButtonPressed(self):
	
		#############################################################
		# Function: appendHost
		#
		# If Host name and IP Address fields are filled in then
		# host is added to the main list and the host file
		#############################################################
		def appendHost():
			if hostEntry.get() and IPentry.get():
				self.touchCheckbox.config(state=NORMAL)
				self.permissionsCheckbox.config(state=NORMAL)
				self.launchButton.config(state=NORMAL)
				self.cancelButton.config(state=NORMAL)
				self.helpButton.config(state=NORMAL)
				self.delButton.config(state=NORMAL)
				self.editButton.config(state=NORMAL)
				self.addButton.config(state=NORMAL)
				self.fpDelButton.config(state=NORMAL)
				self.fpEditButton.config(state=NORMAL)
				self.fpAddButton.config(state=NORMAL)
				self.hostListBox.config(state=NORMAL)
				self.filePathListBox.config(state=NORMAL)
				self.permissionsEntry.config(state=NORMAL)
				f1 = open(hostfile, "a+")
				appendfile = "%s %s %s %s\n" % (hostEntry.get(), IPentry.get(), userEntry.get(), base64.b64encode(passEntry.get()))
				f1.write(appendfile)
				f1.close()
				item = "%s -> %s (%s) (%s)" % (hostEntry.get(), IPentry.get(), userEntry.get(), base64.b64encode(passEntry.get()))
				self.hostListBox.insert(END, item)
				self.addHost.destroy()
		
		#############################################################
		# Function: OnPressEnterappendHost
		#
		# If Host name and IP Address fields are filled in then
		# host is added to the main list and the host file
		#############################################################
		def OnPressEnterappendHost(event):
			if hostEntry.get() and IPentry.get():
				self.touchCheckbox.config(state=NORMAL)
				self.permissionsCheckbox.config(state=NORMAL)
				self.launchButton.config(state=NORMAL)
				self.cancelButton.config(state=NORMAL)
				self.helpButton.config(state=NORMAL)
				self.delButton.config(state=NORMAL)
				self.editButton.config(state=NORMAL)
				self.addButton.config(state=NORMAL)
				self.fpDelButton.config(state=NORMAL)
				self.fpEditButton.config(state=NORMAL)
				self.fpAddButton.config(state=NORMAL)
				self.hostListBox.config(state=NORMAL)
				self.filePathListBox.config(state=NORMAL)
				self.permissionsEntry.config(state=NORMAL)
				f1 = open(hostfile, "a+")
				appendfile = "%s %s %s %s\n" % (hostEntry.get(), IPentry.get(), userEntry.get(), base64.b64encode(passEntry.get()))
				f1.write(appendfile)
				f1.close()
				item = "%s -> %s (%s) (%s)" % (hostEntry.get(), IPentry.get(), userEntry.get(), base64.b64encode(passEntry.get()))
				self.hostListBox.insert(END, item)
				self.addHost.destroy()

		#############################################################
		# Function: add_cancel
		#
		# kills the add, enables the widgets, and destroys the window
		#############################################################
		def add_cancel(event=None):
			self.addHost.destroy()
			self.touchCheckbox.config(state=NORMAL)
			self.permissionsCheckbox.config(state=NORMAL)
			self.launchButton.config(state=NORMAL)
			self.cancelButton.config(state=NORMAL)
			self.helpButton.config(state=NORMAL)
			self.delButton.config(state=NORMAL)
			self.editButton.config(state=NORMAL)
			self.addButton.config(state=NORMAL)
			self.fpDelButton.config(state=NORMAL)
			self.fpEditButton.config(state=NORMAL)
			self.fpAddButton.config(state=NORMAL)
			self.hostListBox.config(state=NORMAL)
			self.filePathListBox.config(state=NORMAL)
			self.permissionsEntry.config(state=NORMAL)

		# Disable all other Widgets
		self.touchCheckbox.config(state=DISABLED)
		self.permissionsCheckbox.config(state=DISABLED)
		self.launchButton.config(state=DISABLED)
		self.cancelButton.config(state=DISABLED)
		self.helpButton.config(state=DISABLED)
		self.delButton.config(state=DISABLED)
		self.editButton.config(state=DISABLED)
		self.addButton.config(state=DISABLED)
		self.fpDelButton.config(state=DISABLED)
		self.fpEditButton.config(state=DISABLED)
		self.fpAddButton.config(state=DISABLED)
		self.hostListBox.config(state=DISABLED)
		self.filePathListBox.config(state=DISABLED)
		self.permissionsEntry.config(state=DISABLED)
		
		# Creates a new window to add host
		self.addHost = Tk()
		self.addHost.protocol("WM_DELETE_WINDOW", add_cancel)  # When the X is clicked
		self.addHost.title("Add Hosts to List")
		self.addHost.bind("<Return>", OnPressEnterappendHost)

		# Host Frame
		hostFrame = Frame(self.addHost)
		hostFrame.pack(side=TOP, padx=20, pady=(20, 0))
		
		# Host Label
		hostLabel = Label(hostFrame, text="Hostname")
		hostLabel.pack(side=LEFT)
		hostEntry = Entry(hostFrame)
		hostEntry.pack(side=RIGHT) 
		
		# IP Frame
		IPFrame = Frame(self.addHost)
		IPFrame.pack(side=TOP, padx=20)

		# IP Label
		IPLabel = Label(IPFrame, text="IP Address")
		IPLabel.pack(side=LEFT)
		IPentry = Entry(IPFrame)
		IPentry.pack(side=RIGHT)
		
		# Username Frame
		userFrame = Frame(self.addHost)
		userFrame.pack(side=TOP, padx=20, pady=(20, 0))
		
		# Username Label
		userLabel = Label(userFrame, text="Username")
		userLabel.pack(side=LEFT)
		userEntry = Entry(userFrame)
		userEntry.pack(side=RIGHT) 
		
		# Password Frame
		passFrame = Frame(self.addHost)
		passFrame.pack(side=TOP, padx=20)
		
		# Password Label
		passLabel = Label(passFrame, text="Password ")
		passLabel.pack(side=LEFT)
		passEntry = Entry(passFrame, show=u"\u2022")
		passEntry.pack(side=RIGHT)
		
		# Add + Cancel Button Frame
		button2Frame = Frame(self.addHost)
		button2Frame.pack(side=BOTTOM, pady=(0, 20))
		
		# Configure Add and Cancel Buttons
		selButton1 = Button(button2Frame, text="Add", command=appendHost)
		selButton1.pack(side=LEFT, padx=20, pady=(10,0))
		cancelButton1 = Button(button2Frame, text="Cancel", command=add_cancel)
		cancelButton1.pack(side=RIGHT, padx=20, pady=(10,0))

	#############################################################
	# Function: When Host List Edit Button is Pressed
	#
	# Creates a new Window to Edit Hosts
	#############################################################	
	def editHostButtonPressed(self, duringLaunch=False, f=False):

		#############################################################
		# Function: updateAppendPath
		#
		# If Host name and IP Address fields are still filled in then
		# host is updated to the main list and the path file
		#############################################################
		def updateAppendHost():
			# Retrieve original local and remote path to compare with and replace with old values
			oldhst, oldipaddr, oldusr, oldps, hst, ipaddr, usr, ps, olditem, newitem, newfile = '', '', '', '', '', '', '', '', '', '', ''
			oldfile = []
			window = 0
			found = False
			for i, val1 in enumerate(self.openWindows):
				for j, val2 in enumerate(self.openWindows[i]):
					if j == 0:
						if self.openWindows[i][0].focus_get() != None:
							found = True
							window = i
					elif j == 1 and found:
						hst = self.openWindows[window][j].get()
					elif j == 2 and found:
						ipaddr = self.openWindows[window][j].get()
					elif j == 3 and found:
						usr = self.openWindows[window][j].get()
					elif j == 4 and found:
						ps = self.openWindows[window][j].get()
					elif j == 5 and found:
						oldhst = self.openWindows[window][j]
					elif j == 6 and found:
						oldipaddr = self.openWindows[window][j]
					elif j == 7 and found:
						oldusr = self.openWindows[window][j]
					elif j == 8 and found:
						oldps = self.openWindows[window][j]
						olditem = "%s -> %s (%s) (%s)" % (oldhst, oldipaddr, oldusr, base64.b64encode(oldps))
						oldfile.append(oldhst)
						oldfile.append(oldipaddr)
						oldfile.append(oldusr)
						newitem = "%s -> %s (%s) (%s)" % (hst, ipaddr, usr, base64.b64encode(ps))
						newfile = "%s %s %s %s\n" % (hst, ipaddr, usr, base64.b64encode(ps))
						print olditem
						print oldfile
						print newitem
						print newfile
						break
			
			if olditem and newitem:
				print 'In 3'
				f1 = open(hostfile, 'r+')
				fout = ''
				for k, line in enumerate(f1.readlines()):								# Read through path file
					if line.split()[:-1] == oldfile and int(self.openWindows[window][9]) == k:		# Check if curser selection matches what is in file
						fout += newfile
						#self.hostListBox.delete(k)
						#self.hostListBox.insert(END, newitem)
					else:															#
						fout += "%s" % line											#
				f1.close()
				open(hostfile, 'w').close()    										# Clear content for rewrite
				f1 = open(hostfile, 'w')
				f1.write(fout)
				f1.close()
			
				#self.hostListBox.delete(int(self.openWindows[window][9]))
				#self.hostListBox.insert(END, newitem)
				
				for i, val in enumerate(self.openWindows):
					if self.openWindows[i][0].focus_get() != None:
						self.openWindows[i][0].destroy()
						self.openWindows.pop(i)
						break
				if len(self.openWindows) == 0:
					self.touchCheckbox.config(state=NORMAL)
					self.permissionsCheckbox.config(state=NORMAL)
					self.launchButton.config(state=NORMAL)
					self.cancelButton.config(state=NORMAL)
					self.helpButton.config(state=NORMAL)
					self.delButton.config(state=NORMAL)
					self.editButton.config(state=NORMAL)
					self.addButton.config(state=NORMAL)
					self.fpDelButton.config(state=NORMAL)
					self.fpEditButton.config(state=NORMAL)
					self.fpAddButton.config(state=NORMAL)
					self.hostListBox.config(state=NORMAL)
					self.filePathListBox.config(state=NORMAL)
					self.permissionsEntry.config(state=NORMAL)
					
						
		#############################################################
		# Function: OnPressEnterUpdateAppendPath
		#
		# If Host name and IP Address fields are still filled in then
		# host is updated to the main list and the path file
		#############################################################
		def OnPressEnterUpdateAppendHost(event):
			# Retrieve original local and remote path to compare with and replace with old values
			oldhst, oldipaddr, oldusr, oldps, hst, ipaddr, usr, ps, olditem, newitem, newfile = '', '', '', '', '', '', '', '', '', '', ''
			oldfile = []
			window = 0
			found = False
			for i, val1 in enumerate(self.openWindows):
				for j, val2 in enumerate(self.openWindows[i]):
					if j == 0:
						if self.openWindows[i][0].focus_get() != None:
							found = True
							window = i
					elif j == 1 and found:
						hst = self.openWindows[window][j].get()
					elif j == 2 and found:
						ipaddr = self.openWindows[window][j].get()
					elif j == 3 and found:
						usr = self.openWindows[window][j].get()
					elif j == 4 and found:
						ps = self.openWindows[window][j].get()
					elif j == 5 and found:
						oldhst = self.openWindows[window][j]
					elif j == 6 and found:
						oldipaddr = self.openWindows[window][j]
					elif j == 7 and found:
						oldusr = self.openWindows[window][j]
					elif j == 8 and found:
						oldps = self.openWindows[window][j]
						olditem = "%s -> %s (%s) (%s)" % (oldhst, oldipaddr, oldusr, base64.b64encode(oldps))
						oldfile.append(oldhst)
						oldfile.append(oldipaddr)
						oldfile.append(oldusr)
						newitem = "%s -> %s (%s) (%s)" % (hst, ipaddr, usr, base64.b64encode(ps))
						newfile = "%s %s %s %s\n" % (hst, ipaddr, usr, base64.b64encode(ps))
						break
			
			if olditem and newitem:
				f1 = open(hostfile, 'r+')
				fout = ''
				for k, line in enumerate(f1.readlines()):								# Read through path file
					if line.split()[:-1] == oldfile and int(self.openWindows[window][9]) == k:		# Check if curser selection matches what is in file
						fout += newfile
					else:															#
						fout += "%s" % line											#
				f1.close()
				open(hostfile, 'w').close()    										# Clear content for rewrite
				f1 = open(hostfile, 'w')
				f1.write(fout)
				f1.close()
				
				for i, val in enumerate(self.openWindows):
					if self.openWindows[i][0].focus_get() != None:
						self.openWindows[i][0].destroy()
						self.openWindows.pop(i)
						break
				if len(self.openWindows) == 0:
					self.touchCheckbox.config(state=NORMAL)
					self.permissionsCheckbox.config(state=NORMAL)
					self.launchButton.config(state=NORMAL)
					self.cancelButton.config(state=NORMAL)
					self.helpButton.config(state=NORMAL)
					self.delButton.config(state=NORMAL)
					self.editButton.config(state=NORMAL)
					self.addButton.config(state=NORMAL)
					self.fpDelButton.config(state=NORMAL)
					self.fpEditButton.config(state=NORMAL)
					self.fpAddButton.config(state=NORMAL)
					self.hostListBox.config(state=NORMAL)
					self.filePathListBox.config(state=NORMAL)
					self.permissionsEntry.config(state=NORMAL)


		#############################################################
		# Function: add_cancel
		#
		# kills the edit, enables the widgets, and destroys the window
		#############################################################
		def add_cancel(event=None):
			for i, val in enumerate(self.openWindows):
				if self.openWindows[i][0].focus_get() != None:
					self.openWindows[i][0].destroy()
					self.openWindows.pop(i)
			if len(self.openWindows) == 0:
				self.touchCheckbox.config(state=NORMAL)
				self.permissionsCheckbox.config(state=NORMAL)
				self.launchButton.config(state=NORMAL)
				self.cancelButton.config(state=NORMAL)
				self.helpButton.config(state=NORMAL)
				self.delButton.config(state=NORMAL)
				self.editButton.config(state=NORMAL)
				self.addButton.config(state=NORMAL)
				self.fpDelButton.config(state=NORMAL)
				self.fpEditButton.config(state=NORMAL)
				self.fpAddButton.config(state=NORMAL)
				self.hostListBox.config(state=NORMAL)
				self.filePathListBox.config(state=NORMAL)
				self.permissionsEntry.config(state=NORMAL)

		if self.hostListBox.curselection():
			# Disable all other Widgets
			self.touchCheckbox.config(state=DISABLED)
			self.permissionsCheckbox.config(state=DISABLED)
			self.launchButton.config(state=DISABLED)
			self.cancelButton.config(state=DISABLED)
			self.helpButton.config(state=DISABLED)
			self.delButton.config(state=DISABLED)
			self.editButton.config(state=DISABLED)
			self.addButton.config(state=DISABLED)
			self.fpDelButton.config(state=DISABLED)
			self.fpEditButton.config(state=DISABLED)
			self.fpAddButton.config(state=DISABLED)
			self.hostListBox.config(state=DISABLED)
			self.filePathListBox.config(state=DISABLED)
			self.permissionsEntry.config(state=DISABLED)
			
			if duringLaunch and f:
				self.openWindows = []
				f = False
			elif not duringLaunch:
				self.openWindows = []
			#tempWindows = []
			#match = 0
			
			# Takes the Host cursor selection and creates a new Tk 
			# window and fills in the data to be edited
			for i, value in enumerate(self.hostListBox.curselection()):				# Go through curser selections
				try:													#
					h, ip, u, p = '', '', '', ''
					temp = self.hostListBox.get(self.hostListBox.curselection()[i]).replace('->','').replace('(','').replace(')','').split()	# Parse out curser selection
					for l, word in enumerate(temp):									#
						if l == 0:													#
							h = word
						elif l == 1:												#
							ip = word
						elif l == 2:												#
							u = word
						elif l == 3:
							p = word

					# Creates a new window to add paths
					self.editHost = Tk()
					self.editHost.protocol("WM_DELETE_WINDOW", add_cancel)  # When the X is clicked
					self.editHost.title("Edit Hosts")
					self.editHost.bind("<Return>", OnPressEnterUpdateAppendHost)
					
					# Host Frame
					hostFrame = Frame(self.editHost)
					hostFrame.pack(side=TOP, padx=20, pady=(20, 0))
					
					# Host Label
					hostLabel = Label(hostFrame, text="Hostname")
					hostLabel.pack(side=LEFT)
					hostEntry = Entry(hostFrame)
					hostEntry.pack(side=RIGHT)
					hostEntry.insert(0, h)
					
					# IP Frame
					IPFrame = Frame(self.editHost)
					IPFrame.pack(side=TOP, padx=20)

					# IP Label
					IPLabel = Label(IPFrame, text="IP Address")
					IPLabel.pack(side=LEFT)
					IPentry = Entry(IPFrame)
					IPentry.pack(side=RIGHT)
					IPentry.insert(0, ip)
					
					# Username Frame
					userFrame = Frame(self.editHost)
					userFrame.pack(side=TOP, padx=20, pady=(20, 0))
					
					# Username Label
					userLabel = Label(userFrame, text="Username")
					userLabel.pack(side=LEFT)
					userEntry = Entry(userFrame)
					userEntry.pack(side=RIGHT)
					userEntry.insert(0, u)
					
					# Password Frame
					passFrame = Frame(self.editHost)
					passFrame.pack(side=TOP, padx=20)
					
					# Password Label
					passLabel = Label(passFrame, text="Password ")
					passLabel.pack(side=LEFT)
					passEntry = Entry(passFrame, show=u"\u2022")
					passEntry.pack(side=RIGHT)
					passEntry.insert(0, base64.b64decode(p))
					
					# Add + Cancel Button Frame
					button2Frame = Frame(self.editHost)
					button2Frame.pack(side=BOTTOM, pady=(0, 20))
					
					# Configure Add and Cancel Buttons
					selButton1 = Button(button2Frame, text="Update", command=updateAppendHost)
					selButton1.pack(side=LEFT, padx=20, pady=(10,0))
					cancelButton1 = Button(button2Frame, text="Cancel", command=add_cancel)
					cancelButton1.pack(side=RIGHT, padx=20, pady=(10,0))
					
					match = 0				
					if duringLaunch:
						print 'In 1'
						if u == '' or p == '':
							print 'In 2'
							print self.openWindows
							if self.openWindows:
								print 'In 3'
								print len(self.openWindows)
								for z, dat in enumerate(self.openWindows):
									print self.openWindows[z][0]
									print self.editHost
									if self.openWindows[z][0] == self.editHost:
										print 'In 4'
										match = 1
								if not match:
									print 'In 5'
									self.openWindows.append([self.editHost, hostEntry, IPentry, userEntry, passEntry, h, ip, u, base64.b64decode(p), self.hostListBox.curselection()[i]])
									#tempWindows.append([self.editHost, hostEntry, IPentry, userEntry, passEntry, h, ip, u, base64.b64decode(p), self.hostListBox.curselection()[i]])
							else:
								self.openWindows.append([self.editHost, hostEntry, IPentry, userEntry, passEntry, h, ip, u, base64.b64decode(p), self.hostListBox.curselection()[i]])
								#tempWindows.append([self.editHost, hostEntry, IPentry, userEntry, passEntry, h, ip, u, base64.b64decode(p), self.hostListBox.curselection()[i]])
					else:
						self.openWindows.append([self.editHost, hostEntry, IPentry, userEntry, passEntry, h, ip, u, base64.b64decode(p), self.hostListBox.curselection()[i]])
						
					#print self.openWindows
					
					
				except:
					pass
		
	#############################################################
	# Function: When Host List Remove Button is Pressed
	#
	# Creates a new Window to remove Hosts
	#############################################################	
	def delHostButtonPressed(self):
		
		#################################################################
		# Function: removeHost
		#
		# If any Hosts are highlighted then the hosts is removed the list
		#################################################################
		def removeHost():
			if delListBox.curselection():
				self.touchCheckbox.config(state=NORMAL)
				self.permissionsCheckbox.config(state=NORMAL)
				self.launchButton.config(state=NORMAL)
				self.cancelButton.config(state=NORMAL)
				self.helpButton.config(state=NORMAL)
				self.delButton.config(state=NORMAL)
				self.editButton.config(state=NORMAL)
				self.addButton.config(state=NORMAL)
				self.fpDelButton.config(state=NORMAL)
				self.fpEditButton.config(state=NORMAL)
				self.fpAddButton.config(state=NORMAL)
				self.hostListBox.config(state=NORMAL)
				self.filePathListBox.config(state=NORMAL)
				self.permissionsEntry.config(state=NORMAL)
				f1 = open(hostfile, 'r+')
				fout = ''
				match = 0
				for k, line in enumerate(f1.readlines()):												# Read through hosts file
					for i, value in enumerate(delListBox.curselection()):				# Go through curser selections
						final = []														#
						temp = delListBox.get(delListBox.curselection()[i]).replace('->','').replace('(','').replace(')','').split()	# Parse out curser selection
						for l, word in enumerate(temp):									#
							if l == 0:													#
								final.append(word)										#
							elif l == 1:												#
								final.append(word)										#
							elif l == 2:												#
								final.append(word)										#
						if len(line.split()) > 3:
							if line.split()[:-1] == final :									# Check if curser selection matches what is in file
								match = 1												#
							else:
								pass
						else:
							if line.split() == final:										# Check if curser selection matches what is in file
								match = 1
							else:
								pass
						for j in range(self.hostListBox.size()):						# Remove from Listbox
							if delListBox.get(delListBox.curselection()[i]) == self.hostListBox.get(j):
								self.hostListBox.delete(j)
					if not match:
						fout += "%s" % line
					match = 0
				f1.close()
				open(hostfile, 'w').close()    # Clear content for rewrite
				f1 = open(hostfile, 'w')
				f1.write(fout)
				f1.close()
				self.delHost.destroy()
		
		def OnPressEnterRemoveHost(event):
			if delListBox.curselection():
				self.touchCheckbox.config(state=NORMAL)
				self.permissionsCheckbox.config(state=NORMAL)
				self.launchButton.config(state=NORMAL)
				self.cancelButton.config(state=NORMAL)
				self.helpButton.config(state=NORMAL)
				self.delButton.config(state=NORMAL)
				self.editButton.config(state=NORMAL)
				self.addButton.config(state=NORMAL)
				self.fpDelButton.config(state=NORMAL)
				self.fpEditButton.config(state=NORMAL)
				self.fpAddButton.config(state=NORMAL)
				self.hostListBox.config(state=NORMAL)
				self.filePathListBox.config(state=NORMAL)
				self.permissionsEntry.config(state=NORMAL)
				f1 = open(hostfile, 'r+')
				fout = ''
				match = 0
				for k, line in enumerate(f1.readlines()):												# Read through hosts file
					for i, value in enumerate(delListBox.curselection()):				# Go through curser selections
						final = []														#
						temp = delListBox.get(delListBox.curselection()[i]).replace('->','').replace('(','').replace(')','').split()	# Parse out curser selection
						for l, word in enumerate(temp):									#
							if l == 0:													#
								final.append(word)										#
							elif l == 1:												#
								final.append(word)										#
							elif l == 2:												#
								final.append(word)										#
						if len(line.split()) > 3:
							if line.split()[:-1] == final :									# Check if curser selection matches what is in file
								match = 1												#
							else:
								pass
						else:
							if line.split() == final:										# Check if curser selection matches what is in file
								match = 1
							else:
								pass
						for j in range(self.hostListBox.size()):						# Remove from Listbox
							if delListBox.get(delListBox.curselection()[i]) == self.hostListBox.get(j):
								self.hostListBox.delete(j)
					if not match:
						fout += "%s" % line
					match = 0
				f1.close()
				open(hostfile, 'w').close()    # Clear content for rewrite
				f1 = open(hostfile, 'w')
				f1.write(fout)
				f1.close()
				self.delHost.destroy()

		def del_cancel(event=None):
			self.delHost.destroy()
			self.touchCheckbox.config(state=NORMAL)
			self.permissionsCheckbox.config(state=NORMAL)
			self.launchButton.config(state=NORMAL)
			self.cancelButton.config(state=NORMAL)
			self.helpButton.config(state=NORMAL)
			self.delButton.config(state=NORMAL)
			self.editButton.config(state=NORMAL)
			self.addButton.config(state=NORMAL)
			self.fpDelButton.config(state=NORMAL)
			self.fpEditButton.config(state=NORMAL)
			self.fpAddButton.config(state=NORMAL)
			self.hostListBox.config(state=NORMAL)
			self.filePathListBox.config(state=NORMAL)
			self.permissionsEntry.config(state=NORMAL)

		# Disable all other Widgets
		self.touchCheckbox.config(state=DISABLED)
		self.permissionsCheckbox.config(state=DISABLED)
		self.launchButton.config(state=DISABLED)
		self.cancelButton.config(state=DISABLED)
		self.helpButton.config(state=DISABLED)
		self.delButton.config(state=DISABLED)
		self.editButton.config(state=DISABLED)
		self.addButton.config(state=DISABLED)
		self.fpDelButton.config(state=DISABLED)
		self.fpEditButton.config(state=DISABLED)
		self.fpAddButton.config(state=DISABLED)
		self.hostListBox.config(state=DISABLED)
		self.filePathListBox.config(state=DISABLED)
		self.permissionsEntry.config(state=DISABLED)

		# Creates a new window to Delete Host
		self.delHost = Tk()
		self.delHost.protocol("WM_DELETE_WINDOW", del_cancel)  # When the X is clicked
		self.delHost.title("Remove Hosts from List")
		self.delHost.bind("<Return>", OnPressEnterRemoveHost)
		
		delListFrame = Frame(self.delHost)
		delListFrame.pack(side=TOP, padx=20, pady=20)
        
		delyscrollBar = Scrollbar(delListFrame)
		delyscrollBar.pack(side=RIGHT, fill=Y)
		
		delxscrollBar = Scrollbar(delListFrame, orient=HORIZONTAL)
		delxscrollBar.pack(side=BOTTOM, fill=X)

		delListBox = Listbox(delListFrame, width=40, height=20, selectmode=EXTENDED)
		delListBox.pack(side=LEFT, fill=Y)
		delxscrollBar.config(command=delListBox.xview)          # Horizontal Scrollbar config
		delyscrollBar.config(command=delListBox.yview)          # Vertical Scrollbar config
		delListBox.config(yscrollcommand=delyscrollBar.set, xscrollcommand=delxscrollBar.set)  # Listbox config
		
		for value in range(self.hostListBox.size()):
			delListBox.insert(value, self.hostListBox.get(value))
			
		button3Frame = Frame(self.delHost)
		button3Frame.pack(side=BOTTOM, pady=(0, 20))
		
		selButton2 = Button(button3Frame, text="Remove", command=removeHost)
		selButton2.pack(side=LEFT, padx=20)
		cancelButton2 = Button(button3Frame, text="Cancel", command=del_cancel)
		cancelButton2.pack(side=RIGHT, padx=20)
			

	#############################################################
	# Function: When Path List Add Button is Pressed
	#
	# Creates a new Window to add Paths
	#############################################################		
	def addPathButtonPressed(self):
	
		#############################################################
		# Function: appendPath
		#
		# If Host name and IP Address fields are filled in then
		# host is added to the main list and the path file
		#############################################################
		def appendPath():
			if localpathEntry.get() and remotepathEntry.get():
				self.touchCheckbox.config(state=NORMAL)
				self.permissionsCheckbox.config(state=NORMAL)
				self.launchButton.config(state=NORMAL)
				self.cancelButton.config(state=NORMAL)
				self.helpButton.config(state=NORMAL)
				self.delButton.config(state=NORMAL)
				self.editButton.config(state=NORMAL)
				self.addButton.config(state=NORMAL)
				self.fpDelButton.config(state=NORMAL)
				self.fpEditButton.config(state=NORMAL)
				self.fpAddButton.config(state=NORMAL)
				self.hostListBox.config(state=NORMAL)
				self.filePathListBox.config(state=NORMAL)
				self.permissionsEntry.config(state=NORMAL)
				f1 = open(pathfile, "a+")
				if remotepathEntry.get()[-1:] != '/':
					if remotepathEntry.get().find('.')!=-1:
						if remotepathEntry.get().rfind('.') > remotepathEntry.get().rfind('/'):
							appendfile = "%s %s\n" % (localpathEntry.get(), remotepathEntry.get())
							f1.write(appendfile)
						else:
							appendfile = "%s %s\n" % (localpathEntry.get(), remotepathEntry.get())
							f1.write(appendfile)
					else:
						appendfile = "%s %s\n" % (localpathEntry.get(), remotepathEntry.get())
						f1.write(appendfile)
				else:
					appendfile = "%s %s\n" % (localpathEntry.get(), remotepathEntry.get())
					f1.write(appendfile)
				f1.close()
				if remotepathEntry.get()[-1:] != '/':
					if remotepathEntry.get().find('.')!=-1:
						if remotepathEntry.get().rfind('.') > remotepathEntry.get().rfind('/'):
							item = "%s -> %s" % (localpathEntry.get(), remotepathEntry.get())
						else:
							item = "%s -> %s" % (localpathEntry.get(), remotepathEntry.get())
					else:
						item = "%s -> %s" % (localpathEntry.get(), remotepathEntry.get())
				else:
					item = "%s -> %s" % (localpathEntry.get(), remotepathEntry.get())
				self.filePathListBox.insert(END, item)
				self.addPath.destroy()
		
		#############################################################
		# Function: OnPressEnterappendPath
		#
		# If Host name and IP Address fields are filled in then
		# host is added the to main list and the path file
		#############################################################
		def OnPressEnterappendPath(event):
			if localpathEntry.get() and remotepathEntry.get():
				self.touchCheckbox.config(state=NORMAL)
				self.permissionsCheckbox.config(state=NORMAL)
				self.launchButton.config(state=NORMAL)
				self.cancelButton.config(state=NORMAL)
				self.helpButton.config(state=NORMAL)
				self.delButton.config(state=NORMAL)
				self.editButton.config(state=NORMAL)
				self.addButton.config(state=NORMAL)
				self.fpDelButton.config(state=NORMAL)
				self.fpEditButton.config(state=NORMAL)
				self.fpAddButton.config(state=NORMAL)
				self.hostListBox.config(state=NORMAL)
				self.filePathListBox.config(state=NORMAL)
				self.permissionsEntry.config(state=NORMAL)
				f1 = open(pathfile, "a+")
				if remotepathEntry.get()[-1:] != '/':
					if remotepathEntry.get().find('.')!=-1:
						if remotepathEntry.get().rfind('.') > remotepathEntry.get().rfind('/'):
							appendfile = "%s %s\n" % (localpathEntry.get(), remotepathEntry.get())
							f1.write(appendfile)
						else:
							appendfile = "%s %s\n" % (localpathEntry.get(), remotepathEntry.get())
							f1.write(appendfile)
					else:
						appendfile = "%s %s\n" % (localpathEntry.get(), remotepathEntry.get())
						f1.write(appendfile)
				else:
					appendfile = "%s %s\n" % (localpathEntry.get(), remotepathEntry.get())
					f1.write(appendfile)
				f1.close()
				if remotepathEntry.get()[-1:] != '/':
					if remotepathEntry.get().find('.')!=-1:
						if remotepathEntry.get().rfind('.') > remotepathEntry.get().rfind('/'):
							item = "%s -> %s" % (localpathEntry.get(), remotepathEntry.get())
						else:
							item = "%s -> %s" % (localpathEntry.get(), remotepathEntry.get())
					else:
						item = "%s -> %s" % (localpathEntry.get(), remotepathEntry.get())
				else:
					item = "%s -> %s" % (localpathEntry.get(), remotepathEntry.get())
				self.filePathListBox.insert(END, item)
				self.addPath.destroy()


		#############################################################
		# Function: add_cancel
		#
		# kills the add, enables the widgets, and destroys the window
		#############################################################
		def add_cancel(event=None):
			self.addPath.destroy()
			self.touchCheckbox.config(state=NORMAL)
			self.permissionsCheckbox.config(state=NORMAL)
			self.launchButton.config(state=NORMAL)
			self.cancelButton.config(state=NORMAL)
			self.helpButton.config(state=NORMAL)
			self.delButton.config(state=NORMAL)
			self.editButton.config(state=NORMAL)
			self.addButton.config(state=NORMAL)
			self.fpDelButton.config(state=NORMAL)
			self.fpEditButton.config(state=NORMAL)
			self.fpAddButton.config(state=NORMAL)
			self.hostListBox.config(state=NORMAL)
			self.filePathListBox.config(state=NORMAL)
			self.permissionsEntry.config(state=NORMAL)

		# Disable all other Widgets
		self.touchCheckbox.config(state=DISABLED)
		self.permissionsCheckbox.config(state=DISABLED)
		self.launchButton.config(state=DISABLED)
		self.cancelButton.config(state=DISABLED)
		self.helpButton.config(state=DISABLED)
		self.delButton.config(state=DISABLED)
		self.editButton.config(state=DISABLED)
		self.addButton.config(state=DISABLED)
		self.fpDelButton.config(state=DISABLED)
		self.fpEditButton.config(state=DISABLED)
		self.fpAddButton.config(state=DISABLED)
		self.hostListBox.config(state=DISABLED)
		self.filePathListBox.config(state=DISABLED)
		self.permissionsEntry.config(state=DISABLED)
		
		# Creates a new window to add paths
		self.addPath = Tk()
		self.addPath.protocol("WM_DELETE_WINDOW", add_cancel)  # When the X is clicked
		self.addPath.title("Add Paths to List")
		self.addPath.bind("<Return>", OnPressEnterappendPath)

		# Local Path Frame
		localpathFrame = Frame(self.addPath)
		localpathFrame.pack(side=TOP, padx=20, pady=(20, 0))
		
		# Local Path Label
		localpathLabel = Label(localpathFrame, text="Local Path")
		localpathLabel.pack(side=LEFT)
		localpathEntry = Entry(localpathFrame, width=30)
		localpathEntry.pack(side=RIGHT) 
		
		# Remote Path Frame
		remotepathFrame = Frame(self.addPath)
		remotepathFrame.pack(side=TOP, padx=20)

		# Remote Path Label
		remotepathLabel = Label(remotepathFrame, text="Remote Path")
		remotepathLabel.pack(side=LEFT)
		remotepathEntry = Entry(remotepathFrame, width=30)
		remotepathEntry.pack(side=RIGHT)

		# Add + Cancel Button Frame
		button4Frame = Frame(self.addPath)
		button4Frame.pack(side=BOTTOM, pady=(0, 20))
		
		# Configure Add and Cancel Buttons
		selButton3 = Button(button4Frame, text="Add", command=appendPath)
		selButton3.pack(side=LEFT, padx=20, pady=(10,0))
		cancelButton3 = Button(button4Frame, text="Cancel", command=add_cancel)
		cancelButton3.pack(side=RIGHT, padx=20, pady=(10,0))

	
	#############################################################
	# Function: When Host List Edit Button is Pressed
	#
	# Creates a new Window to Edit Hosts
	#############################################################	
	def editPathButtonPressed(self):
	
		#############################################################
		# Function: updateAppendPath
		#
		# If Local Path and Remote Path fields are still filled in then
		# path is updated to the path list and the path file
		#############################################################
		def updateAppendPath():
			# Retrieve original local and remote path to compare with and replace with old values
			lp, rp, olditem, newitem, appendfile = '', '', '', '', ''
			window = 0
			found = False
			for i, val1 in enumerate(self.openWindows):
				for j, val2 in enumerate(self.openWindows[i]):
					if j == 0:
						if self.openWindows[i][0].focus_get() != None:
							found = True
							window = i
					elif j == 3 and found:
						lp = self.openWindows[window][j]
					elif j == 4 and found:
						rp = self.openWindows[window][j]
						olditem = "%s -> %s" % (lp, rp)
						break
			if found:
				# self.openWindows[window][1] = local path
				# self.openWindows[window][2] = remote path
				if self.openWindows[window][1].get() and self.openWindows[window][2].get():
					if self.openWindows[window][2].get()[-1:] != '/':
						if self.openWindows[window][2].get().find('.')!=-1:
							if self.openWindows[window][2].get().rfind('.') > self.openWindows[window][2].get().rfind('/'):
								appendfile = "%s %s\n" % (self.openWindows[window][1].get(), self.openWindows[window][2].get())
							else:
								appendfile = "%s %s\n" % (self.openWindows[window][1].get(), self.openWindows[window][2].get())
						else:
							appendfile = "%s %s\n" % (self.openWindows[window][1].get(), self.openWindows[window][2].get())
					else:
						appendfile = "%s %s\n" % (self.openWindows[window][1].get(), self.openWindows[window][2].get())

					if self.openWindows[window][2].get()[-1:] != '/':
						if self.openWindows[window][2].get().find('.')!=-1:
							if self.openWindows[window][2].get().rfind('.') > self.openWindows[window][2].get().rfind('/'):
								newitem = "%s -> %s" % (self.openWindows[window][1].get(), self.openWindows[window][2].get())
							else:
								newitem = "%s -> %s" % (self.openWindows[window][1].get(), self.openWindows[window][2].get())
						else:
							newitem = "%s -> %s" % (self.openWindows[window][1].get(), self.openWindows[window][2].get())
					else:
						newitem = "%s -> %s" % (self.openWindows[window][1].get(), self.openWindows[window][2].get())
			
			#print "new: %s change on: %s" % (newitem, self.openWindows[window][5])
			#print "old: %s change on: %s" % (olditem, self.openWindows[window][5])
			if olditem and newitem:
				f1 = open(pathfile, 'r+')
				fout = ''
				state = 0
				curserfinal = []													#
				curserfinal.append(lp)												#
				curserfinal.append(rp)												#
				for k, line in enumerate(f1.readlines()):											# Read through path file
					filefinal = []													#
					localpath = ''
					remotepath = ''
					for n, word in enumerate(line.split()):							# Cycle through path file
						if state == 0:												#
							if word[-1:] == '\\':									# Parse Results
								localpath += "%s " % word							#
							elif word.find('.')!=-1:								# Local Path
								if word.rfind('.') > word.rfind('/'):				#
									localpath += word								#
									state = 1										#
								elif word.strip()[-1:] == '/':
									localpath += word
									state = 1
								else:
									localpath += word
									state = 1
							elif word.find('.')==-1:								# No period
								if word.strip()[-1:] == '/':
									localpath += word
									state = 1
								else:
									localpath += word
									state = 1
						elif state == 1:											# Remote Path
							if word[-1:] == '\\':									#
								remotepath += "%s " % word							#
							elif word.strip()[-1:] == '/':							#
								remotepath += word									#
								state = 0											#
							else:
								remotepath += word									#
								state = 0											#
						if localpath and remotepath:								# Append Both
							filefinal.append(localpath)								#
							filefinal.append(remotepath)							#
					if curserfinal == filefinal and int(self.openWindows[window][5]) == k:	# Check if curser selection matches what is in file
						fout += appendfile											#
						#if self.filePathListBox.get(k) == olditem:
						self.filePathListBox.delete(k)
						self.filePathListBox.insert(k, newitem)
					else:															#
						fout += "%s" % line											#
				f1.close()
				open(pathfile, 'w').close()    										# Clear content for rewrite
				f1 = open(pathfile, 'w')
				f1.write(fout)
				f1.close()
				
				for i, val in enumerate(self.openWindows):
					if self.openWindows[i][0].focus_get() != None:
						self.openWindows[i][0].destroy()
						self.openWindows.pop(i)
						break
				if len(self.openWindows) == 0:
					self.touchCheckbox.config(state=NORMAL)
					self.permissionsCheckbox.config(state=NORMAL)
					self.launchButton.config(state=NORMAL)
					self.cancelButton.config(state=NORMAL)
					self.helpButton.config(state=NORMAL)
					self.delButton.config(state=NORMAL)
					self.editButton.config(state=NORMAL)
					self.addButton.config(state=NORMAL)
					self.fpDelButton.config(state=NORMAL)
					self.fpEditButton.config(state=NORMAL)
					self.fpAddButton.config(state=NORMAL)
					self.hostListBox.config(state=NORMAL)
					self.filePathListBox.config(state=NORMAL)
					self.permissionsEntry.config(state=NORMAL)
					
						
		#############################################################
		# Function: OnPressEnterUpdateAppendPath
		#
		# If Host name and IP Address fields are still filled in then
		# host is updated to the main list and the path file
		#############################################################
		def OnPressEnterUpdateAppendPath(event):
			# Retrieve original local and remote path to compare with and replace with old values
			lp, rp, olditem, newitem, appendfile = '', '', '', '', ''
			window = 0
			found = False
			for i, val1 in enumerate(self.openWindows):
				for j, val2 in enumerate(self.openWindows[i]):
					if j == 0:
						if self.openWindows[i][0].focus_get() != None:
							found = True
							window = i
					elif j == 3 and found:
						lp = self.openWindows[window][j]
					elif j == 4 and found:
						rp = self.openWindows[window][j]
						olditem = "%s -> %s" % (lp, rp)
						break
			if found:
				# self.openWindows[window][1] = local path
				# self.openWindows[window][2] = remote path
				if self.openWindows[window][1].get() and self.openWindows[window][2].get():
					if self.openWindows[window][2].get()[-1:] != '/':
						if self.openWindows[window][2].get().find('.')!=-1:
							if self.openWindows[window][2].get().rfind('.') > self.openWindows[window][2].get().rfind('/'):
								appendfile = "%s %s\n" % (self.openWindows[window][1].get(), self.openWindows[window][2].get())
							else:
								appendfile = "%s %s\n" % (self.openWindows[window][1].get(), self.openWindows[window][2].get())
						else:
							appendfile = "%s %s\n" % (self.openWindows[window][1].get(), self.openWindows[window][2].get())
					else:
						appendfile = "%s %s\n" % (self.openWindows[window][1].get(), self.openWindows[window][2].get())

					if self.openWindows[window][2].get()[-1:] != '/':
						if self.openWindows[window][2].get().find('.')!=-1:
							if self.openWindows[window][2].get().rfind('.') > self.openWindows[window][2].get().rfind('/'):
								newitem = "%s -> %s" % (self.openWindows[window][1].get(), self.openWindows[window][2].get())
							else:
								newitem = "%s -> %s" % (self.openWindows[window][1].get(), self.openWindows[window][2].get())
						else:
							newitem = "%s -> %s" % (self.openWindows[window][1].get(), self.openWindows[window][2].get())
					else:
						newitem = "%s -> %s" % (self.openWindows[window][1].get(), self.openWindows[window][2].get())
			
			#print "new: %s change on: %s" % (newitem, self.openWindows[window][5])
			#print "old: %s change on: %s" % (olditem, self.openWindows[window][5])
			if olditem and newitem:
				f1 = open(pathfile, 'r+')
				fout = ''
				state = 0
				curserfinal = []													#
				curserfinal.append(lp)												#
				curserfinal.append(rp)												#
				for k, line in enumerate(f1.readlines()):											# Read through path file
					filefinal = []													#
					localpath = ''
					remotepath = ''
					for n, word in enumerate(line.split()):							# Cycle through path file
						if state == 0:												#
							if word[-1:] == '\\':									# Parse Results
								localpath += "%s " % word							#
							elif word.find('.')!=-1:								# Local Path
								if word.rfind('.') > word.rfind('/'):				#
									localpath += word								#
									state = 1										#
								elif word.strip()[-1:] == '/':
									localpath += word
									state = 1
								else:
									localpath += word
									state = 1
							elif word.find('.')==-1:								# No period
								if word.strip()[-1:] == '/':
									localpath += word
									state = 1
								else:
									localpath += word
									state = 1
						elif state == 1:											# Remote Path
							if word[-1:] == '\\':									#
								remotepath += "%s " % word							#
							elif word.strip()[-1:] == '/':							#
								remotepath += word									#
								state = 0											#
							else:
								remotepath += word									#
								state = 0											#
						if localpath and remotepath:								# Append Both
							filefinal.append(localpath)								#
							filefinal.append(remotepath)							#
					if curserfinal == filefinal and int(self.openWindows[window][5]) == k:	# Check if curser selection matches what is in file
						fout += appendfile											#
						self.filePathListBox.delete(k)
						self.filePathListBox.insert(k, newitem)
					else:															#
						fout += "%s" % line											#
				f1.close()
				open(pathfile, 'w').close()    										# Clear content for rewrite
				f1 = open(pathfile, 'w')
				f1.write(fout)
				f1.close()
				
				for i, val in enumerate(self.openWindows):
					if self.openWindows[i][0].focus_get() != None:
						self.openWindows[i][0].destroy()
						self.openWindows.pop(i)
						break
				if len(self.openWindows) == 0:
					self.touchCheckbox.config(state=NORMAL)
					self.permissionsCheckbox.config(state=NORMAL)
					self.launchButton.config(state=NORMAL)
					self.cancelButton.config(state=NORMAL)
					self.helpButton.config(state=NORMAL)
					self.delButton.config(state=NORMAL)
					self.editButton.config(state=NORMAL)
					self.addButton.config(state=NORMAL)
					self.fpDelButton.config(state=NORMAL)
					self.fpEditButton.config(state=NORMAL)
					self.fpAddButton.config(state=NORMAL)
					self.hostListBox.config(state=NORMAL)
					self.filePathListBox.config(state=NORMAL)
					self.permissionsEntry.config(state=NORMAL)


		#############################################################
		# Function: add_cancel
		#
		# kills the edit, enables the widgets, and destroys the window
		#############################################################
		def add_cancel(event=None):
			for i, val in enumerate(self.openWindows):
				if self.openWindows[i][0].focus_get() != None:
					self.openWindows[i][0].destroy()
					self.openWindows.pop(i)
			if len(self.openWindows) == 0:
				self.touchCheckbox.config(state=NORMAL)
				self.permissionsCheckbox.config(state=NORMAL)
				self.launchButton.config(state=NORMAL)
				self.cancelButton.config(state=NORMAL)
				self.helpButton.config(state=NORMAL)
				self.delButton.config(state=NORMAL)
				self.editButton.config(state=NORMAL)
				self.addButton.config(state=NORMAL)
				self.fpDelButton.config(state=NORMAL)
				self.fpEditButton.config(state=NORMAL)
				self.fpAddButton.config(state=NORMAL)
				self.hostListBox.config(state=NORMAL)
				self.filePathListBox.config(state=NORMAL)
				self.permissionsEntry.config(state=NORMAL)

		if self.filePathListBox.curselection():
			# Disable all other Widgets
			self.touchCheckbox.config(state=DISABLED)
			self.permissionsCheckbox.config(state=DISABLED)
			self.launchButton.config(state=DISABLED)
			self.cancelButton.config(state=DISABLED)
			self.helpButton.config(state=DISABLED)
			self.delButton.config(state=DISABLED)
			self.editButton.config(state=DISABLED)
			self.addButton.config(state=DISABLED)
			self.fpDelButton.config(state=DISABLED)
			self.fpEditButton.config(state=DISABLED)
			self.fpAddButton.config(state=DISABLED)
			self.hostListBox.config(state=DISABLED)
			self.filePathListBox.config(state=DISABLED)
			self.permissionsEntry.config(state=DISABLED)
			
			self.openWindows = []
			tempCurseSel = []
			
			# Takes the File Path cursor selection and creates a new Tk 
			# window and fills in the data to be edited
			for i, val in enumerate(self.filePathListBox.curselection()):
				try:
					index=0
					state=0
					lp, rp = '', ''
					temp = self.filePathListBox.get(self.filePathListBox.curselection()[i]).split()
					while True:
						try:
							if state==0 and temp[index] != '->':
								if temp[index][-1:] == '\\':
									lp += "%s " % temp[index][:-1]
								else:
									lp += temp[index]
							elif temp[index] == '->':
								state = 1
							elif state==1:
								if temp[index][-1:] == '\\':
									rp += "%s " % temp[index][:-1]
								else:
									rp += temp[index]
							index+=1
						except IndexError:
							break
					# Creates a new window to add paths
					self.editPath = Tk()
					self.editPath.protocol("WM_DELETE_WINDOW", add_cancel)  # When the X is clicked
					self.editPath.title("Edit Paths")
					self.editPath.bind("<Return>", OnPressEnterUpdateAppendPath)
					
					#self.openWindows.append(self.editPath) # Append all Tk() instances so they can be removed later

					# Local Path Frame
					localpathFrame = Frame(self.editPath)
					localpathFrame.pack(side=TOP, padx=20, pady=(20, 0))
					
					# Local Path Label
					localpathLabel = Label(localpathFrame, text="Local Path")
					localpathLabel.pack(side=LEFT)
					localpathEntry = Entry(localpathFrame, width=30)
					localpathEntry.pack(side=RIGHT)
					localpathEntry.insert(0, lp)
					
					# Remote Path Frame
					remotepathFrame = Frame(self.editPath)
					remotepathFrame.pack(side=TOP, padx=20)

					# Remote Path Label
					remotepathLabel = Label(remotepathFrame, text="Remote Path")
					remotepathLabel.pack(side=LEFT)
					remotepathEntry = Entry(remotepathFrame, width=30)
					remotepathEntry.pack(side=RIGHT)
					remotepathEntry.insert(0, rp)

					# Append all Tk() information to the List
					self.openWindows.append([self.editPath, localpathEntry, remotepathEntry, lp, rp, self.filePathListBox.curselection()[i]])
					tempCurseSel.append(self.filePathListBox.curselection()[i])
					
					# Add + Cancel Button Frame
					button4Frame = Frame(self.editPath)
					button4Frame.pack(side=BOTTOM, pady=(0, 20))
					
					# Configure Add and Cancel Buttons
					selButton3 = Button(button4Frame, text="Update", command=updateAppendPath)
					selButton3.pack(side=LEFT, padx=20, pady=(10,0))
					cancelButton3 = Button(button4Frame, text="Cancel", command=add_cancel)
					cancelButton3.pack(side=RIGHT, padx=20, pady=(10,0))
				except:
					pass
	
	#############################################################
	# Function: When Host List Remove Button is Pressed
	#
	# Creates a new Window to remove Hosts
	#############################################################	
	def delPathButtonPressed(self):
		
		#############################################################
		# Function: removeHost
		#
		# If any Host are highlighted then host is removed the list
		#############################################################
		def removePath():
			if delListBox.curselection():
				self.touchCheckbox.config(state=NORMAL)
				self.permissionsCheckbox.config(state=NORMAL)
				self.launchButton.config(state=NORMAL)
				self.cancelButton.config(state=NORMAL)
				self.helpButton.config(state=NORMAL)
				self.delButton.config(state=NORMAL)
				self.editButton.config(state=NORMAL)
				self.addButton.config(state=NORMAL)
				self.fpDelButton.config(state=NORMAL)
				self.fpEditButton.config(state=NORMAL)
				self.fpAddButton.config(state=NORMAL)
				self.hostListBox.config(state=NORMAL)
				self.filePathListBox.config(state=NORMAL)
				self.permissionsEntry.config(state=NORMAL)
				f1 = open(pathfile, 'r+')
				fout = ''
				match = 0
				state = 0
				for k in f1.readlines():												# Read through path file
					for i, value in enumerate(delListBox.curselection()):				# Go through curser selections
						curserfinal = []												#
						filefinal = []													#
						temp = delListBox.get(delListBox.curselection()[i]).split('->')	# Parse out curser selection
						localpath = ''
						remotepath = ''
						for m, word in enumerate(temp):									# Cycle through curser selection
							if state == 0:												#
								if word[-1:] == '\\':									# Parse Results
									localpath += "%s " % word							#
								elif word.find('.')!=-1:								# Period Found
									if word.rfind('.') > word.rfind('/'):				#
										localpath += word								#
										state = 1										#
									elif word.strip()[-1:] == '/':
										localpath += word
										state = 1
									else:
										localpath += word
										state = 1
								elif word.find('.')==-1:	# No period
									if word.strip()[-1:] == '/':
										localpath += word
										state = 1
									else:
										localpath += word
										state = 1
							elif state == 1:											# Remote Path
								if word[-1:] == '\\':									#
									remotepath += "%s " % word							#
								elif word.strip()[-1:] == '/':							#
									remotepath += word									#
									state = 0											#
								else:
									remotepath += word									#
									state = 0											#
							if localpath and remotepath:								# Append Both
								curserfinal.append(localpath[:-1])						#
								curserfinal.append(remotepath[1:])						#
						
						localpath = ''
						remotepath = ''
						for n, word in enumerate(k.split()):							# Cycle through path file
							if state == 0:												#
								if word[-1:] == '\\':									# Parse Results
									localpath += "%s " % word							#
								elif word.find('.')!=-1:								# Local Path
									if word.rfind('.') > word.rfind('/'):				#
										localpath += word								#
										state = 1										#
									elif word.strip()[-1:] == '/':
										localpath += word
										state = 1
									else:
										localpath += word
										state = 1
								elif word.find('.')==-1:	# No period
									if word.strip()[-1:] == '/':
										localpath += word
										state = 1
									else:
										localpath += word
										state = 1
							elif state == 1:											# Remote Path
								if word[-1:] == '\\':									#
									remotepath += "%s " % word							#
								elif word.strip()[-1:] == '/':							#
									remotepath += word									#
									state = 0											#
								else:
									remotepath += word									#
									state = 0											#
							if localpath and remotepath:								# Append Both
								filefinal.append(localpath)								#
								filefinal.append(remotepath)							#
						if curserfinal == filefinal:									# Check if curser selection matches what is in file
							match = 1													#
						else:															#
							pass														#
						for j in range(self.filePathListBox.size()):					# Remove from Listbox
							if delListBox.get(delListBox.curselection()[i]) == self.filePathListBox.get(j):
								self.filePathListBox.delete(j)
					if not match:
						fout += "%s" % k
					match = 0
				f1.close()
				open(pathfile, 'w').close()    # Clear content for rewrite
				f1 = open(pathfile, 'w')
				f1.write(fout)
				f1.close()
				self.delHost.destroy()
		
		def OnPressEnterRemovePath(event):
			if delListBox.curselection():
				self.touchCheckbox.config(state=NORMAL)
				self.permissionsCheckbox.config(state=NORMAL)
				self.launchButton.config(state=NORMAL)
				self.cancelButton.config(state=NORMAL)
				self.helpButton.config(state=NORMAL)
				self.delButton.config(state=NORMAL)
				self.editButton.config(state=NORMAL)
				self.addButton.config(state=NORMAL)
				self.fpDelButton.config(state=NORMAL)
				self.fpEditButton.config(state=NORMAL)
				self.fpAddButton.config(state=NORMAL)
				self.hostListBox.config(state=NORMAL)
				self.filePathListBox.config(state=NORMAL)
				self.permissionsEntry.config(state=NORMAL)
				f1 = open(pathfile, 'r+')
				fout = ''
				match = 0
				state = 0
				for k in f1.readlines():												# Read through path file
					for i, value in enumerate(delListBox.curselection()):				# Go through curser selections
						curserfinal = []												#
						filefinal = []													#
						temp = delListBox.get(delListBox.curselection()[i]).split('->')	# Parse out curser selection
						localpath = ''
						remotepath = ''
						for m, word in enumerate(temp):									# Cycle through curser selection
							if state == 0:												#
								if word[-1:] == '\\':									# Parse Results
									localpath += "%s " % word							#
								elif word.find('.')!=-1:								# Local Path
									if word.rfind('.') > word.rfind('/'):				#
										localpath += word								#
										state = 1										#
									elif word.strip()[-1:] == '/':
										localpath += word								#
										state = 1										#
									else:												#
										localpath += word								#
										state = 1
								elif word.find('.')==-1:								#
									if word.strip()[-1:] == '/':
										localpath += word
										state = 1
									else:
										localpath += word
										state = 1
							elif state == 1:											# Remote Path
								if word[-1:] == '\\':									#
									remotepath += "%s " % word							#
								elif word[-1:] == '/':									#
									remotepath += word									#
									state = 0											#
								else:
									remotepath += word									#
									state = 0											#
							if localpath and remotepath:								# Append Both
								curserfinal.append(localpath[:-1])						#
								curserfinal.append(remotepath[1:])						#
						
						localpath = ''
						remotepath = ''
						for n, word in enumerate(k.split()):							# Cycle through path file
							if state == 0:												#
								if word[-1:] == '\\':									# Parse Results
									localpath += "%s " % word							#
								elif word.find('.')!=-1:								# Local Path
									if word.rfind('.') > word.rfind('/'):				#
										localpath += word								#
										state = 1										#
									elif word.strip()[-1:] == '/':
										localpath += word								#
										state = 1										#
									else:												#
										localpath += word								#
								elif word.find('.')==-1:								#
									if word.strip()[-1:] == '/':
										localpath += word
										state = 1
									else:
										localpath += word
										state = 1
							elif state == 1:											# Remote Path
								if word[-1:] == '\\':									#
									remotepath += "%s " % word							#
								elif word[-1:] == '/':									#
									remotepath += word									#
									state = 0											#
								else:
									remotepath += word									#
									state = 0											#
							if localpath and remotepath:								# Append Both
								filefinal.append(localpath)								#
								filefinal.append(remotepath)							#
						if curserfinal == filefinal:									# Check if curser selection matches what is in file
							match = 1													#
						else:															#
							pass														#
						for j in range(self.filePathListBox.size()):					# Remove from Listbox
							if delListBox.get(delListBox.curselection()[i]) == self.filePathListBox.get(j):
								self.filePathListBox.delete(j)
					if not match:
						fout += "%s" % k
					match = 0
				f1.close()
				open(pathfile, 'w').close()    # Clear content for rewrite
				f1 = open(pathfile, 'w')
				f1.write(fout)
				f1.close()
				self.delHost.destroy()

		def del_cancel(event=None):
			self.delHost.destroy()
			self.touchCheckbox.config(state=NORMAL)
			self.permissionsCheckbox.config(state=NORMAL)
			self.launchButton.config(state=NORMAL)
			self.cancelButton.config(state=NORMAL)
			self.helpButton.config(state=NORMAL)
			self.delButton.config(state=NORMAL)
			self.editButton.config(state=NORMAL)
			self.addButton.config(state=NORMAL)
			self.fpDelButton.config(state=NORMAL)
			self.fpEditButton.config(state=NORMAL)
			self.fpAddButton.config(state=NORMAL)
			self.hostListBox.config(state=NORMAL)
			self.filePathListBox.config(state=NORMAL)
			self.permissionsEntry.config(state=NORMAL)

		# Disable all other Widgets
		self.touchCheckbox.config(state=DISABLED)
		self.permissionsCheckbox.config(state=DISABLED)
		self.launchButton.config(state=DISABLED)
		self.cancelButton.config(state=DISABLED)
		self.helpButton.config(state=DISABLED)
		self.delButton.config(state=DISABLED)
		self.editButton.config(state=DISABLED)
		self.addButton.config(state=DISABLED)
		self.fpDelButton.config(state=DISABLED)
		self.fpEditButton.config(state=DISABLED)
		self.fpAddButton.config(state=DISABLED)
		self.hostListBox.config(state=DISABLED)
		self.filePathListBox.config(state=DISABLED)
		self.permissionsEntry.config(state=DISABLED)

		# Creates a new window to Delete Host
		self.delHost = Tk()
		self.delHost.protocol("WM_DELETE_WINDOW", del_cancel)  # When the X is clicked
		self.delHost.title("Remove Paths from List")
		self.delHost.bind("<Return>", OnPressEnterRemovePath)
		
		delListFrame = Frame(self.delHost)
		delListFrame.pack(side=TOP, padx=20, pady=20)
        
		delyscrollBar = Scrollbar(delListFrame)
		delyscrollBar.pack(side=RIGHT, fill=Y)
		
		delxscrollBar = Scrollbar(delListFrame, orient=HORIZONTAL)
		delxscrollBar.pack(side=BOTTOM, fill=X)

		delListBox = Listbox(delListFrame, width=40, height=20, selectmode=EXTENDED)
		delListBox.pack(side=LEFT, fill=Y)
		delxscrollBar.config(command=delListBox.xview)          # Horizontal Scrollbar config
		delyscrollBar.config(command=delListBox.yview)          # Vertical Scrollbar config
		delListBox.config(yscrollcommand=delyscrollBar.set, xscrollcommand=delxscrollBar.set)  # Listbox config
		
		for value in range(self.filePathListBox.size()):
			delListBox.insert(value, self.filePathListBox.get(value))
			
		button5Frame = Frame(self.delHost)
		button5Frame.pack(side=BOTTOM, pady=(0, 20))
		
		selButton4 = Button(button5Frame, text="Remove", command=removePath)
		selButton4.pack(side=LEFT, padx=20)
		cancelButton4 = Button(button5Frame, text="Cancel", command=del_cancel)
		cancelButton4.pack(side=RIGHT, padx=20)


#############################################################
# Main Loop
#############################################################
if __name__ == "__main__":
	root = Tk()
	app = Main_tk(root)    #starts the new gui program
	root.title("Secure Copy Tool")
	mainloop()                	 			#runs until user quits
