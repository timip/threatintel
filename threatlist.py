#!/usr/bin/python

import requests
import os
import re
import zlib
import time
import sys
import shutil
from datetime import datetime

from time import gmtime, strftime
from netaddr import iprange_to_cidrs
from StringIO import StringIO

destDir = "/tech/threatlist"
procDir = "/tech/threatlist"

# DO NOT EDIT ANY CONTENT BELOW THIS LINE

foutPath = destDir + "/threatlist.csv"
tfoutPath = procDir + "/threatlist.temp"
logPath = procDir + "/threatlist.log"

global success
success = True

def logging(content):
        log_output.write(str(datetime.now()) + ":" + content + '\n')
        log_output.flush()

def logDone():
        logging("Update Finish")

def commit():
        shutil.copy(tfoutPath, foutPath)
        os.remove(tfoutPath)

def formatter(name, category, sev, input):
        try:
                print name + ": Trying zlib32"
                ef_input = zlib.decompress(StringIO(input).read(), zlib.MAX_WBITS|32)
        except Exception, e:
                try:
                        print name + ": Trying -zlib"
                        ef_input = zlib.decompress(StringIO(input).read(), -zlib.MAX_WBITS)
                except Exception, e:
                        print name + ": Trying plain text"
                        ef_input = input
        print name + ": Extracting Fields"
        extractField(name, category, ef_input, sev)

def extractField(name, category, input, sev):
        global success
        sev = sev.strip()
        if category == 'ip':
                for line in StringIO(input):
                        if len(line.strip()) == 0:
                                continue
                        elif "#" in line.strip():
                                continue
			elif "/" in line.strip():
                                tf_output.write(line.strip() + "," + name + "(" + sev + ")\n")
			else:
				tf_output.write(line.strip() + "/32," + name + "(" + sev + ")\n")
                logging("Extract Field Complete: name=" + name + " category=" + category + " sev=" + sev)
        elif category == 'range':
                for line in StringIO(input):
                        if len(line.strip()) == 0:
                                continue
                        elif "#" in line:
                                continue
                        elif ":" in line:
                                reObj = re.search('(.*):([0-9]+.[0-9]+.[0-9]+.[0-9]+)-([0-9]+.[0-9]+.[0-9]+.[0-9]+).*',line.strip())
                                iprange_start = reObj.group(2)
                                iprange_end = reObj.group(3)
                                ipranges = list(iprange_to_cidrs(iprange_start, iprange_end))
                                for iprange in ipranges:
                                        tf_output.write(str(iprange) + "," + reObj.group(1).replace(",", "") + "(" + sev + ")\n")
                logging("Extract Field Complete: name=" + name + " category=" + category + " sev=" + sev)
        elif category == 'col':
                for line in StringIO(input):
                        if len(line.strip()) == 0:
                                continue
                        elif "#" in line:
                                continue
                        elif "Start" in line:
                                continue
                        else:
                                reObj = re.search('([0-9]+.[0-9]+.[0-9]+.[0-9]+)\s+([0-9]+.[0-9]+.[0-9]+.[0-9]+).*',line.strip())
                                iprange_st = reObj.group(1)
                                iprange_ed = reObj.group(2)
                                ipranges = list(iprange_to_cidrs(iprange_st, iprange_ed))
                                for iprange in ipranges:
                                        tf_output.write(str(iprange) + "," + name + "(" + sev + ")\n")
                logging("Extract Field Complete: name=" + name + " category=" + category + " sev=" + sev)
        else:
                print 'No category has defined'
                logging("Extract Field Failure: No category has defined name=" + name + " category=" + category + " sev=" + sev + " input=" + input)
                success = False

def readThreatlist():
        global success
        try:
                threatlist =  open('./threatlist.in.csv', 'rU')
                next(threatlist, None) #skip the headers
                for line in threatlist :
                        cells = line.split(",")
                        try:
                                req = requests.get(cells[1], allow_redirects=True)
                                formatter(cells[0], cells[2], cells[3], req.content)
                                req = None
                        except requests.exceptions.ConnectionError as e:
                                print 'Request failed Error: ' + str(e)
                                logging("Request failed Error: " + str(e))
                                threatlist+=e+","
			except IndexError as ie:
				print 'Skip line: ' + cells
                        time.sleep(3)
                threatlist.close()
                logging("Read Threat list Success")
        except (OSError, IOError) as e:
                errorMsg = str(e)
                print errorMsg
                success = False
                logging("Read Threat List Failure: " + errorMsg)

def readcustomlist():
        try:
                customlist = open('./customlist.csv','rU')
                next(customlist, None)
                for line in customlist :
                        tf_output.write(line)
                customlist.close()
                logging("Read custom list Success")
        except (OSError, IOError) as e:
                errorMsg = str(e)
                logging("Read custom list Failure: " + errorMsg)

log_output = open(logPath, 'a')
tf_output = open(tfoutPath, 'w')
tf_output.write("iprange,threat\n")

logging("Start")

readThreatlist()
readcustomlist()
logDone()

tf_output.flush()
tf_output.close()

if success:
        commit()
        logging("Comment Success")
else:
        logging("Commit is not performed due to unsuccessful threatlist download")

logging("End")

log_output.flush()
log_output.close()

