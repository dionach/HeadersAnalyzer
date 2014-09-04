# Copyright (c) 2014, Antonio Sanchez
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the author nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from burp import ITab
from burp import IExtensionStateListener
from javax import swing
from java.awt import Font
from java.awt.datatransfer import StringSelection
from java.awt.datatransfer import DataFlavor
from java.awt import Toolkit
import java.lang as lang
import re
import pickle

class BurpExtender(IBurpExtender, IScannerCheck, ITab, IExtensionStateListener):

    def	registerExtenderCallbacks(self, callbacks):
        
        print "Loading..."

        self._callbacks = callbacks
        self._callbacks.setExtensionName("Headers Analyzer")
        self._callbacks.registerScannerCheck(self)
        self._callbacks.registerExtensionStateListener(self)
        
        self.initGui()
        self._callbacks.addSuiteTab(self)
        self.extensionLoaded()

        # Variable to keep a browsable structure of the issues find on each host
        # later used in the export function.
        self.global_issues = {} 

        print "Loaded!"

        return

    def saveExtensionSetting(self, name, value):
        try:
            self._callbacks.saveExtensionSetting(name, value)
        except Exception:
            print ('Error saving extension settings')

    # Save current settings when the extension is unloaded or Burp is closed
    def extensionUnloaded(self):
        config = {
            'interestingHeadersCB' : self.interestingHeadersCB.isSelected(),
            'securityHeadersCB' : self.securityHeadersCB.isSelected(),
            'xFrameOptionsCB' : self.xFrameOptionsCB.isSelected(),
            'xContentTypeOptionsCB' : self.xContentTypeOptionsCB.isSelected(),
            'xXssProtectionCB' : self.xXssProtectionCB.isSelected(),
            'HstsCB' : self.HstsCB.isSelected(),
            'CorsCB' : self.CorsCB.isSelected(),
            'contentSecurityPolicyCB' : self.contentSecurityPolicyCB.isSelected(),
            'xPermittedCrossDomainPoliciesCB' : self.xPermittedCrossDomainPoliciesCB.isSelected(),
            'boringHeadersList' : self.getBoringHeadersList() 
        }
        
        for key, value in config.iteritems():   # For each config value
            self.saveExtensionSetting(key, pickle.dumps(value))

        return

    # Restore last configuration
    def extensionLoaded(self):
        try:
            self.interestingHeadersCB.setSelected(pickle.loads(self._callbacks.loadExtensionSetting('interestingHeadersCB')))
            self.securityHeadersCB.setSelected(pickle.loads(self._callbacks.loadExtensionSetting('securityHeadersCB')))
            self.xFrameOptionsCB.setSelected(pickle.loads(self._callbacks.loadExtensionSetting('xFrameOptionsCB')))
            self.xContentTypeOptionsCB.setSelected(pickle.loads(self._callbacks.loadExtensionSetting('xContentTypeOptionsCB')))
            self.xXssProtectionCB.setSelected(pickle.loads(self._callbacks.loadExtensionSetting('xXssProtectionCB')))
            self.HstsCB.setSelected(pickle.loads(self._callbacks.loadExtensionSetting('HstsCB')))
            self.CorsCB.setSelected(pickle.loads(self._callbacks.loadExtensionSetting('CorsCB')))
            self.contentSecurityPolicyCB.setSelected(pickle.loads(self._callbacks.loadExtensionSetting('contentSecurityPolicyCB')))
            self.xPermittedCrossDomainPoliciesCB.setSelected(pickle.loads(self._callbacks.loadExtensionSetting('xPermittedCrossDomainPoliciesCB')))
            self.boringHeadersList.setListData(pickle.loads(self._callbacks.loadExtensionSetting('boringHeadersList')))

            print "Extension settings restored!"
        except:
            self.interestingHeadersCB.setSelected(True)
            self.securityHeadersCB.setSelected(True)
            self.xFrameOptionsCB.setSelected(True)
            self.xContentTypeOptionsCB.setSelected(True)
            self.xXssProtectionCB.setSelected(True)
            self.HstsCB.setSelected(True)
            self.CorsCB.setSelected(True)
            self.contentSecurityPolicyCB.setSelected(True)
            self.xPermittedCrossDomainPoliciesCB.setSelected(True)
            empty = []
            self.boringHeadersList.setListData(empty)

            print "Error restoring extension settings (first time loading the extension?)"

    def initGui(self):

        # Define elements        
        self.tab = swing.JPanel()
        self.settingsLabel = swing.JLabel("Settings:")
        self.settingsLabel.setFont(Font("Tahoma", 1, 12));
        self.boringHeadersLabel = swing.JLabel("Boring Headers")
        self.pasteButton = swing.JButton("Paste", actionPerformed=self.paste)
        self.loadButton = swing.JButton("Load", actionPerformed=self.load)
        self.removeButton = swing.JButton("Remove", actionPerformed=self.remove)
        self.clearButton = swing.JButton("Clear", actionPerformed=self.clear)
        self.jScrollPane1 = swing.JScrollPane()
        self.boringHeadersList = swing.JList()
        self.addButton = swing.JButton("Add", actionPerformed=self.add)
        self.addTF = swing.JTextField("New item...", focusGained=self.emptyTF, focusLost=self.fillTF)
        self.interestingHeadersCB = swing.JCheckBox("Check for Interesting Headers")
        self.securityHeadersCB = swing.JCheckBox("Check for Security Headers", actionPerformed=self.onSelect)
        self.xFrameOptionsCB = swing.JCheckBox("X-Frame-Options")
        self.xContentTypeOptionsCB = swing.JCheckBox("X-Content-Type-Options")
        self.xXssProtectionCB = swing.JCheckBox("X-XSS-Protection")
        self.HstsCB = swing.JCheckBox("Strict-Transport-Security (HSTS)")
        self.CorsCB = swing.JCheckBox("Access-Control-Allow-Origin (CORS)")
        self.contentSecurityPolicyCB = swing.JCheckBox("Content-Security-Policy")
        self.xPermittedCrossDomainPoliciesCB = swing.JCheckBox("X-Permitted-Cross-Domain-Policies")
        self.outputLabel = swing.JLabel("Output:")
        self.outputLabel.setFont(Font("Tahoma", 1, 12));
        self.logsLabel = swing.JLabel("Logs")
        self.jScrollPane2 = swing.JScrollPane()
        self.logsTA = swing.JTextArea()
        self.exportButton = swing.JButton("Export in report friendly format", actionPerformed=self.export)

        self.jScrollPane1.setViewportView(self.boringHeadersList)
        self.logsTA.setColumns(20)
        self.logsTA.setRows(7)
        self.jScrollPane2.setViewportView(self.logsTA)

        # Configure layout

        layout = swing.GroupLayout(self.tab)
        self.tab.setLayout(layout)
        layout.setHorizontalGroup(
            layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(33, 33, 33)
                .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(83, 83, 83)
                        .addComponent(self.boringHeadersLabel))
                    .addComponent(self.settingsLabel)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(self.interestingHeadersCB)
                        .addGap(149, 149, 149)
                        .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                            .addComponent(self.securityHeadersCB)
                            .addComponent(self.HstsCB)
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(swing.GroupLayout.Alignment.TRAILING, layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                                        .addGroup(layout.createSequentialGroup()
                                            .addComponent(self.xFrameOptionsCB)
                                            .addGap(83, 83, 83))
                                        .addGroup(layout.createSequentialGroup()
                                            .addComponent(self.xContentTypeOptionsCB)
                                            .addGap(47, 47, 47)))
                                    .addGroup(layout.createSequentialGroup()
                                        .addComponent(self.xXssProtectionCB)
                                        .addGap(83, 83, 83)))
                                .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(self.xPermittedCrossDomainPoliciesCB)
                                    .addComponent(self.contentSecurityPolicyCB)
                                    .addComponent(self.CorsCB)))))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(self.addButton)
                            .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                                .addComponent(self.outputLabel)
                                .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.TRAILING, False)
                                    .addComponent(self.removeButton, swing.GroupLayout.DEFAULT_SIZE, swing.GroupLayout.DEFAULT_SIZE, lang.Short.MAX_VALUE)
                                    .addComponent(self.pasteButton, swing.GroupLayout.DEFAULT_SIZE, swing.GroupLayout.DEFAULT_SIZE, lang.Short.MAX_VALUE)
                                    .addComponent(self.loadButton, swing.GroupLayout.DEFAULT_SIZE, swing.GroupLayout.DEFAULT_SIZE, lang.Short.MAX_VALUE)
                                    .addComponent(self.clearButton, swing.GroupLayout.DEFAULT_SIZE, swing.GroupLayout.PREFERRED_SIZE, lang.Short.MAX_VALUE))))
                        .addPreferredGap(swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                            .addComponent(self.jScrollPane1, swing.GroupLayout.PREFERRED_SIZE, 200, swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(self.addTF, swing.GroupLayout.PREFERRED_SIZE, 200, swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(self.jScrollPane2, swing.GroupLayout.PREFERRED_SIZE, 450, swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(self.logsLabel)
                            .addComponent(self.exportButton))))
                .addContainerGap(26, lang.Short.MAX_VALUE))
        )

        layout.setVerticalGroup(
            layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(41, 41, 41)
                .addComponent(self.settingsLabel)
                .addGap(31, 31, 31)
                .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(self.interestingHeadersCB)
                    .addComponent(self.securityHeadersCB))
                .addGap(26, 26, 26)
                .addComponent(self.boringHeadersLabel)
                .addPreferredGap(swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(self.pasteButton)
                                .addPreferredGap(swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(self.loadButton)
                                .addPreferredGap(swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(self.removeButton)
                                .addPreferredGap(swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(self.clearButton))
                            .addComponent(self.jScrollPane1, swing.GroupLayout.PREFERRED_SIZE, 138, swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(18, 18, 18)
                        .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(self.addButton)
                            .addComponent(self.addTF, swing.GroupLayout.PREFERRED_SIZE, swing.GroupLayout.DEFAULT_SIZE, swing.GroupLayout.PREFERRED_SIZE)))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(self.xFrameOptionsCB)
                            .addComponent(self.CorsCB))
                        .addPreferredGap(swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                            .addComponent(self.xContentTypeOptionsCB)
                            .addComponent(self.contentSecurityPolicyCB, swing.GroupLayout.Alignment.TRAILING))
                        .addPreferredGap(swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(self.xXssProtectionCB)
                            .addComponent(self.xPermittedCrossDomainPoliciesCB))
                        .addPreferredGap(swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addComponent(self.HstsCB)))
                .addGap(30, 30, 30)
                .addComponent(self.outputLabel)
                .addPreferredGap(swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(self.logsLabel)
                .addGap(8, 8, 8)
                .addComponent(self.jScrollPane2, swing.GroupLayout.PREFERRED_SIZE, 250, swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(self.exportButton)
                .addContainerGap(swing.GroupLayout.DEFAULT_SIZE, lang.Short.MAX_VALUE))
        )

    # ITab 
    def getTabCaption(self):
        return("Headers Analyzer")

    def getUiComponent(self):
        return self.tab
 
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if (existingIssue.getIssueName() == newIssue.getIssueName()):
            return -1
        else:
            return 0

    # Event listeners
    def emptyTF(self,e):
        source = e.getSource()
        if source.getText() == "New item...":
            source.setText("")

    def fillTF(self,e):
        source = e.getSource()
        if not source.getText():
            source.setText("New item...")

    def onSelect(self, e):
        source = e.getSource()
        if source.isSelected():
            self.xFrameOptionsCB.setEnabled(True)
            self.xContentTypeOptionsCB.setEnabled(True)
            self.xXssProtectionCB.setEnabled(True)
            self.HstsCB.setEnabled(True)
            self.CorsCB.setEnabled(True)
            self.contentSecurityPolicyCB.setEnabled(True)
            self.xPermittedCrossDomainPoliciesCB.setEnabled(True)
        else:
            self.xFrameOptionsCB.setEnabled(False)
            self.xContentTypeOptionsCB.setEnabled(False)
            self.xXssProtectionCB.setEnabled(False)
            self.HstsCB.setEnabled(False)
            self.CorsCB.setEnabled(False)
            self.contentSecurityPolicyCB.setEnabled(False)
            self.xPermittedCrossDomainPoliciesCB.setEnabled(False)

    def paste(self, e):
        clipboard = self.getClipboardText()
        
        if clipboard != None and clipboard != "":
            lines = clipboard.split('\n')
            current = self.getBoringHeadersList()
            
            for line in lines:
                if line not in current and not line.isspace():
                    current.append(line)
            
            self.boringHeadersList.setListData(current)

    def clear(self, e):
        empty = []
        self.boringHeadersList.setListData(empty) 

    def remove(self, e):
        indices = self.boringHeadersList.getSelectedIndices().tolist()
        current = self.getBoringHeadersList()

        for index in reversed(indices):   
            del current[index]

        self.boringHeadersList.setListData(current)

    def load(self, e):
        chooseFile = swing.JFileChooser()
        ret = chooseFile.showDialog(self.tab, "Choose file")

        if ret == swing.JFileChooser.APPROVE_OPTION:
            file = chooseFile.getSelectedFile()
            filename = file.getCanonicalPath()
            try:
                f = open(filename, "r")
                text = f.readlines()
        
                if text:
                    text = [line for line in text if not line.isspace()]
                    text = [line.rstrip('\n') for line in text]
                    self.boringHeadersList.setListData(text)
            except IOError as e:
                print "Error reading file.\n" + str(e)

    def add(self, e):
        source = e.getSource()

        current = self.getBoringHeadersList()
        current.append(self.addTF.getText())
        self.boringHeadersList.setListData(current)

        self.addTF.setText("New item...")

    def getBoringHeadersList(self):
        model = self.boringHeadersList.getModel()
        current = []
   
        for i in range(0, model.getSize()):
            current.append(model.getElementAt(i))

        return current


    # Browses the "global_issues" var. 
    def export(self, e):
        output = ""

        for host,headers in self.global_issues.iteritems(): # For each host
            output += "\nHost: " + host 

            for issue, headers_list in headers.iteritems():  # For each type of issue (interesting, missing, misconfigured)
                if len(headers_list) > 0:
                    output += "\n" + issue + ":\n"

                    for item in headers_list:   # For each header found in that type of issue
                        output += item + "\n"

        self.setClipboardText(output)
        print output

        swing.JOptionPane.showMessageDialog(self.tab, "Output copied to the clipboard and sent to standard output!", "Information", swing.JOptionPane.INFORMATION_MESSAGE)
    
    # Aux functions to get and set system clipboard
    def getClipboardText(self):
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        contents = clipboard.getContents(None)
        gotText = (contents != None) and contents.isDataFlavorSupported(DataFlavor.stringFlavor)
        
        if gotText:
            return contents.getTransferData(DataFlavor.stringFlavor)
        else:
            return None

    def setClipboardText(self, text):
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(text), None)
       
    # Burp Scanner invokes this method for each base request/response that is passively scanned.
    def doPassiveScan(self, baseRequestResponse):       
        self._requestResponse = baseRequestResponse
        
        scan_issues = []
        scan_issues = self.findHeaders()
        
        # doPassiveScan needs to return a list of scan issues, if any, and None otherwise
        if len(scan_issues) > 0:
            return scan_issues
        else:
            return None
            
    def findHeaders(self):
        self._helpers = self._callbacks.getHelpers()
        self.scan_issues = []
        
        response = self._requestResponse.getResponse()
        requestInfo = self._helpers.analyzeResponse(response)
        headers = requestInfo.getHeaders()
        headers_dict = {}

        host = self._requestResponse.getHttpService().getHost() 

        # If host hasn't been scanned before, we create it in global_issues
        if host not in self.global_issues:  
            self.global_issues[host] ={} 
            self.global_issues[host]["Interesting"] = []
            self.global_issues[host]["Missing"] = []
            self.global_issues[host]["Misconfigured"] = []

        # Store headers in a dict to facilitate their manipulation
        for header in headers:
            header_split = header.split(':', 1)
            if len(header_split) > 1:   # To get rid of "HTTP/1.1 200 OK" and other response codes 
                headers_dict[header_split[0].lower()] = header_split[1]

        if self.interestingHeadersCB.isSelected():
            self.findInteresting(host, headers_dict)
        
        if self.securityHeadersCB.isSelected():
            self.findSecure(host, headers_dict)
        
        return (self.scan_issues)
        
    def findInteresting(self, host, headers):
        list_boring_headers = []
        model = self.boringHeadersList.getModel()
   
        # Get list of boring headers from the GUI JList
        for i in range(0, model.getSize()):
            list_boring_headers.append(model.getElementAt(i))
        
        issuename = "Interesting Header(s)"
        issuelevel = "Low"
        issuedetail = "<p>The response includes the following potentially interesting headers:</p><ul>"
        log = "[+] Interesting Headers found: " + host + "\n"
        found = 0

        for header in headers:
            if header.lower() not in list_boring_headers:
                issuedetail += "<li>Header name: <b>" + header + "</b>. Header value: <b>" + headers[header] + "</b></li>"

                log += "    Header name:" + header + " Header value:" + headers[header] + "\n"
                
                host = self._requestResponse.getHttpService().getHost()
                report = header + ":" + headers[header]
                if report not in self.global_issues[host]["Interesting"]:   # If header not already in the list we store it
                    self.global_issues[host]["Interesting"].append(report)

                found += 1
        
        issuedetail += "</ul>"

        if found > 0:
            # Create a ScanIssue object and append it to our list of issues, marking the reflected parameter value in the response.
            self.scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
	            self._helpers.analyzeRequest(self._requestResponse).getUrl(), 
                issuename, issuelevel, issuedetail))

            self.logsTA.append(log)
          
    def findSecure(self, host, headers):
        issuename = "Lack or Misconfiguration of Security Header(s)"
        issuelevel = "Low"
        issuedetail = """<p>The response lacks or includes the following misconfigured security headers.</p>
                         <p>Please note that some of these issues could be false positives, a manual review 
                         is recommended</p><br>  
                      """
        badheaders = []
        missingsecurity = []
        
        if self.xFrameOptionsCB.isSelected():
            # X-Frame-Options
            try:
                m = re.search("SAMEORIGIN|DENY", headers["x-frame-options"], re.IGNORECASE)
                if not m:
                    badheaders.append("x-frame-options")
            except Exception as e:
                missingsecurity.append("x-frame-options")
        
        if self.xContentTypeOptionsCB.isSelected():
            # X-Content-Type-Options: nosniff
            try:
                m = re.search("nosniff", headers["x-content-type-options"], re.IGNORECASE)
                if not m:
                    badheaders.append("x-content-type-options")
            except Exception as e:
                missingsecurity.append("x-content-type-options")

        if self.xXssProtectionCB.isSelected():
            # X-XSS-Protection
            try:
                m = re.search("0", headers["x-xss-protection"], re.IGNORECASE)
                if not m:
                    badheaders.append("x-xss-protection")
            except Exception as e:
                pass

        if self.HstsCB.isSelected():
            # Strict-Transport-Security (HSTS)
            try:
                m = re.search("max-age=(\d+)", headers["strict-transport-security"], re.IGNORECASE)
                if int(m.group(1)) < (60*60*24 * 30):     # Flag if less than 30 days
                    badheaders.append("strict-transport-security")
            except Exception as e:
                missingsecurity.append("strict-transport-security")
        
        if self.CorsCB.isSelected():
            # Access-Control-Allow-Origin (CORS)
            try:
                m = re.search("\*", headers["access-control-allow-origin"], re.IGNORECASE)
                if not m:
                    badheaders.append("x-xss-protection")
            except Exception as e:
                pass

        if self.contentSecurityPolicyCB.isSelected():
            # Content-Security-Policy
            if not ("content-security-policy" in headers or "x-content-security-policy" in headers or "x-webkit-csp" in headers):
                        missingsecurity.append("content-security-policy")    
       
        if self.xPermittedCrossDomainPoliciesCB.isSelected():
            # X-Permitted-Cross-Domain-Policies
            try:
                m = re.search("master-only", headers["x-permitted-cross-domain-policies"], re.IGNORECASE)
                if not m:
                    badheaders.append("x-permitted-cross-domain-policies")
            except Exception as e:
                missingsecurity.append("x-permitted-cross-domain-policies")
        
        if len(badheaders) > 0 or len(missingsecurity) > 0:     
            if len(badheaders) > 0:
                issuedetail += "<p>Potentially misconfigured headers:</p><ul>"
                log = "[+] Potentially miconfigured headers found: " + host + "\n"
                
                for bad in badheaders:
                    issuedetail += "<li>Header name: <b>" + bad + "</b>. Header value: <b>" + headers[bad] + "</b></li>"

                    log += "    Header name:" + bad + " Header value:" + headers[bad] + "\n"
                    
                    host = self._requestResponse.getHttpService().getHost()
                    report = bad + ":" + headers[bad]
                    if report not in self.global_issues[host]["Misconfigured"]:     # If header not already in the list we store it
                        self.global_issues[host]["Misconfigured"].append(report)
            
                issuedetail += "</ul>"
                
                self.logsTA.append(log)
                    
            if len(missingsecurity) > 0:
                issuedetail += "<p>Missing headers:</p><ul>"
                log = "[+] Missing security headers: " + host + "\n"
                
                for missing in missingsecurity:
                    issuedetail += "<li>Header name: <b>" + missing + "</b>.</li>"
                    log += "    Header name:" + missing + "\n"
                
                    host = self._requestResponse.getHttpService().getHost()
                    if missing not in self.global_issues[host]["Missing"]:      # If header not already in the list we store it
                        self.global_issues[host]["Missing"].append(missing)

                issuedetail += "</ul>"

                self.logsTA.append(log)

            # Create a ScanIssue object and append it to our list of issues, marking
            # the reflected parameter value in the response.
            self.scan_issues.append(ScanIssue(self._requestResponse.getHttpService(),
	            self._helpers.analyzeRequest(self._requestResponse).getUrl(),
                issuename, issuelevel, issuedetail))

# Implementation of the IScanIssue interface with simple constructor and getter methods
class ScanIssue(IScanIssue):
    def __init__(self, httpservice, url, name, severity, detailmsg):
        self._url = url
        self._httpservice = httpservice
        self._name = name
        self._severity = severity
        self._detailmsg = detailmsg

    def getUrl(self):
        return self._url

    def getHttpMessages(self):
        return None

    def getHttpService(self):
        return self._httpservice 

    def getRemediationDetail(self):
        return None

    def getIssueDetail(self):
        return self._detailmsg

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueType(self):
        return 0

    def getIssueName(self):
        return self._name

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"
