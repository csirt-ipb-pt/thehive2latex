#!/usr/bin/env python
# -*- coding: utf-8 -*-
# https://thehive-project.github.io/TheHive4py/reference/api/#thehive4py.api.TheHiveApi.find_cases
# https://github.com/TheHive-Project/TheHive4py/tree/1.x/samples

import sys
import os
import json
from datetime import datetime
import requests
from requests.auth import HTTPBasicAuth
from thehive4py.api import TheHiveApi

# Input function that receives the first variable defined when the script is invoked. That variable is the case number. If none given, it will asks for the case number.
try:
    casenumber = int(sys.argv[1])
except:
    casenumber = int(input("Case Number: "))

path = os.getcwd() # Variable that obtains the full path where the host is invoking the script.
fileToSearch = ( (str(path) + '/config.txt')) # Variable containing the path to the configuration file. 
config = dict([]) # Dictionary that stores the values of the configuration.
listconfig = ("URL", "API", "Classification", "User", "Pass") # List containing the names used to store the values on the dictionary.

# Function that extracts the values from the configuration file and adds them to the dictionary.
try:
    tempFile = open( fileToSearch, 'r' )
except IOError:
    print(f"File \"{fileToSearch}\" Can't Be Accessed!")
else:
    df = list(tempFile)
    
    for x in range(0, len(df)):
        val = str(df[x]).split("\n")
        config[listconfig[x]] = val[0]

dict_case_type = dict([("GEN", f"{(str(path) + '/Internal-report-Case_#_' + str(casenumber) + '/casetype/GEN.tex')}")]) # Dictionary containing the path to different files that give different introductions to the full report depending on the case type. 
api = TheHiveApi(config["URL"], config["API"], cert=False) # Variable that invokes API Calls. Change the cert variable to True if the server certificate is valid, or remove it if the connection is insecure.

# Dictionary containing the path to each mitre file, that gives different introductions to each tactic. 
dict_mitre = dict([("reconnaissance", f"{(str(path) + '/Internal-report-Case_#_' + str(casenumber) + '/mitre/reconnaissance.txt')}"), ("resource-development", f"{(str(path) + '/Internal-report-Case_#_' + str(casenumber) + '/mitre/resource_development.txt')}"), ("initial-access", f"{(str(path) + '/Internal-report-Case_#_' + str(casenumber) + '/mitre/initial_access.txt')}"), ("execution", f"{(str(path) + '/Internal-report-Case_#_' + str(casenumber) + '/mitre/execution.txt')}"), ("persistence", f"{(str(path) + '/Internal-report-Case_#_' + str(casenumber) + '/mitre/persistence.txt')}"), ("privilege-escalation", f"{(str(path) + '/Internal-report-Case_#_' + str(casenumber) + '/mitre/privilege_escalation.txt')}"), ("defense-evasion", f"{(str(path) + '/Internal-report-Case_#_' + str(casenumber) + '/mitre/defense_evasion.txt')}"), ("credential-access", f"{(str(path) + '/Internal-report-Case_#_' + str(casenumber) + '/mitre/credential_access.txt')}"), ("discovery", f"{(str(path) + '/Internal-report-Case_#_' + str(casenumber) + '/mitre/discovery.txt')}"), ("lateral-movement", f"{(str(path) + '/Internal-report-Case_#_' + str(casenumber) + '/mitre/lateral_movement.txt')}"), ("collection", f"{(str(path) + '/Internal-report-Case_#_' + str(casenumber) + '/mitre/collection.txt')}"), ("command-and-control", f"{(str(path) + '/Internal-report-Case_#_' + str(casenumber) + '/mitre/command_and_control.txt')}"), ("exfiltration", f"{(str(path) + '/Internal-report-Case_#_' + str(casenumber) + '/mitre/exfiltration.txt')}"), ("impact", f"{(str(path) + '/Internal-report-Case_#_' + str(casenumber) + '/mitre/impact.txt')}")])

# Variables containing common latex commands.
subsection = str("\subsection{")
itemize = str("\\begin{itemize}")
enditemize = str("\end{itemize}")
beginlisting = str("\\begin{lstlisting}[language=HTML, breaklines=true, columns=fullflexible, frame=single,basicstyle=\\footnotesize{}]")
endlisting = str("\end{lstlisting}")
firsttablecolumentry = str("\cellcolor{Gray!60} \color{Black} \\textbf{")
secondtablecolumentry = str("\color{Black} ")
thirdtablecolumentry = str("\paragraph{}")

# List that contains the full path and name of the files where the output of the script will be saved.
filetosave = ((str(path) + '/Internal-report-Case_#_' + str(casenumber) + '/main.tex'), (str(path) + '/Internal-report-Case_#_' + str(casenumber) + '/infodoincidente.tex'), (str(path) + '/Internal-report-Case_#_' + str(casenumber) + '/resumo.tex'), (str(path) + '/Internal-report-Case_#_' + str(casenumber) + '/followup.tex'), (str(path) + '/Internal-report-Case_#_' + str(casenumber) + '/fullreport.tex'), (str(path) + '/Internal-report-Case_#_' + str(casenumber) + '/Observables.tex'), (str(path) + '/Internal-report-Case_#_' + str(casenumber) + '/classification.tex'))

filetoopen = ((str(path) + '/Internal-report-Case_#_' + str(casenumber) + '/main_part2.tex'), (str(path) + '/Internal-report-Case_#_' + str(casenumber) + '/Observables_part2.tex')) # List that contains the full path and name of the files that the Script will open to read it's content.
tasklogdictionary = dict([]) # Dictionary that stores the task logs.

# Function that if the API CALL returns an error, prints the error and exits the script.
def error(er):
    print('ko: {}/{}'.format(er.status_code, er.text))
    sys.exit(0)

# Function that receives the TLP level and returns the level used to represent the protocol.
def getTLP(tlp):
        if(tlp == 0):
            tlp = str('\\newcommand\\tlp{green}')
        elif(tlp == 2):
            tlp = str('\\newcommand\\tlp{amber+strict}')
        elif(tlp == 3):
            tlp = str('\\newcommand\\tlp{red}')
        else:
            tlp = str("\\newcommand\\tlp{clear}")
        
        return tlp

# Function that makes an API Call to obtain the case information from TheHive.
def case(id):
    response = api.get_case(id)

    if response.status_code == 200:
        resp = json.loads(json.dumps(response.json(), indent=4, sort_keys=True))
    else:
        error(response)
    
    return resp

# Function that makes an API Call and obtains the case Tasks information from TheHive.
def task(case_id):
    tasks = api.get_case_tasks(case_id)

    if tasks.status_code == 200:
        tk = json.loads(json.dumps(tasks.json(), indent=4, sort_keys=True))
    else:
       error(tasks)
    
    return tk

# Function that makes an API Call to obtain the case Tasks Logs from TheHive.
def task_logs(task_id):
    tasklogs = api.get_task_logs(task_id)

    if tasklogs.status_code == 200:
        tkl = json.loads(json.dumps(tasklogs.json(), indent=4, sort_keys=True))
    else:
        error(tasklogs)
    
    return tkl

# Function that makes an API Call and obtains the case observables from TheHive.
def observable(case_id):
    observables = api.get_case_observables(case_id)

    if observables.status_code == 200:
        ob = json.loads(json.dumps(observables.json(), indent=4, sort_keys=True))
    else:
        error(observables)
    
    return ob

# Function that makes an API Call and obtains the case ttps from TheHive.
def ttps(case_id):
    r = requests.get(
        f"{config['URL']}/api/v1/pattern/case/{case_id}", 
        auth=HTTPBasicAuth(f"{config['User']}", f"{config['Pass']}"),
        verify=False
    )

    if r.status_code == 200:
        tt = json.loads(json.dumps(r.json(), indent=4, sort_keys=True))
    else:
        error(r)

    return tt

# Creates a directory and extracts the contents of the template zip file into it. If the directory can't be created, the script stops.
try:
    os.system(f"mkdir -p {path}/Internal-report-Case_#_{casenumber}/")
except:
    print("Something went wrong!")
    sys.exit(0)
else:
    os.system(f"unzip -q 'Internal-report-Case # Template.zip' -d ./Internal-report-Case_#_{casenumber}/")

response = case(casenumber) # Invokes case function.
res = dict(response) # Converts output of case function into a dictionary.
title = str(res['title']) # Stores case Title.
casetype = str() # Variable that stores the case classification.

# Removes TheHive predefine classification from the title.
classe = str(config["Classification"]).split(",")

for x in range(0, len(classe)):
    tmp = str(classe[x] + " ")
    if tmp in title:
        title = title.split(f"{tmp}")
        casetype = str(classe[x])
        break
    elif classe[x] in title:
        title = title.split(f"{classe[x]}")
        casetype = str(classe[x])
        break

if len(title) == 2:
    title = (title[1] + "}")
else:
    title = (res['title'] + "}")

# Opens tempfile to append the output of the Script. Writes the case Title, invokes the tlp function and writes the TLP. Opens the first filetoopen and writes its content into the main file.
try:
    tempFile = open( filetosave[0], 'a+' )
except:
    print(f"File \"{filetosave[0]}\" Can't Be Accessed!")
else:
    with tempFile:
        command = str('\\newcommand\\titulo{[\# ')
        tempFile.write(f"{command}{casenumber}] {title}\n")
        tempFile.write(getTLP(res['tlp']))

        try:
            tf = open( filetoopen[0], 'r+')
        except:
            print("Something went wrong!")
            sys.exit(0)
        else:
            with tf:
                tempor = list(tf)
                tempFile.write(''.join(tempor))

# Function that checks if custom fields exist in the case and extract the Additional information/attachment value from it. Then it writes the output.
if bool(res["customFields"]) != False:
    attachment = str(res["customFields"]).split('\'string\': \'')
    attachment = attachment[1].split('\'}}')
    attachment = attachment[0].split(('\\' + '\\n'))

    try:
        tempFile = open( filetosave[1], 'a+' )
    except:
        print(f"File \"{filetosave[1]}\" Can't Be Accessed!")
    else:
        with tempFile:
            for i in range(0, len(attachment)):
                tempFile.write(f"{attachment[i]}\n")

# Writes description.
try:
    tempFile = open( filetosave[2], 'a+' )
except:
    print(f"File \"{filetosave[2]}\" Can't Be Accessed!")
else:
    with tempFile:
        tempFile.write(res['description'])

# Checks if summary is not empty and writes its value.
if bool(res["summary"]) != False:
    try:
        tempFile = open( filetosave[3], 'a+' )
    except:
        print(f"File \"{filetosave[3]}\" Can't Be Accessed!")
    else:
        with tempFile:
            tempFile.write(f"{res['summary']}")

# Function that opens retrieves the introduction to the full report depending on the case type and writes its content into the fullreport.tex file.
for keys in dict_case_type:
    if keys == casetype:
        try:
            tempFile = open( filetosave[4], 'a+' )
        except:
            print(f"File \"{filetosave[4]}\" Can't Be Accessed!")
        else:
            with tempFile:
                try:
                    tf = open( dict_case_type[keys], 'r+')
                except:
                    print("Something went wrong!")
                    sys.exit(0)
                else:
                    with tf:
                        temporary = list(tf)
                        tempFile.write(''.join(temporary))

tasks = task(response['id']) # Invokes task function.

# Converts task function output to a dictionary and stores the task order, group and id to tasklogdictionary.
for i in range(0, len(tasks)):
    tkd = dict(tasks[i])
    tasklogdictionary[tkd['order']] = (tkd['group'], tkd['id'])

# Function that, on a for loop, invokes tasklog function and by the order the tasks are created. Then it extracts the time related with the creation of the task logs, converts it to a timestamp and stores its values on a dictionary. Lastly, it opens tempfile and writes the Task Log by order and date it was created on the output file, checks if there are Markdown code and converts it into an itemize list or a listing.
for i in range(0, len(tasklogdictionary)):
    timelist = list()
    stage = dict([])
    taskloggroup = str(tasklogdictionary[i]).split(', ')
    tasklogid = taskloggroup[1].split('\'')
    tasklogid = tasklogid[1]
    taskloggroup = taskloggroup[0].split('\'')
    taskloggroup = taskloggroup[1]
    tasklog = task_logs(tasklogid)

    if bool(tasklog) != False:
        try:
            tempFile = open( filetosave[4], 'a+' )
        except:
            print(f"File \"{filetosave[4]}\" Can't Be Accessed!")
        else:
            with tempFile:

                item = int(0)
                listing = int(0)
                closebracks = str("}\n\n")

                tempFile.write(f"{subsection}{taskloggroup}{closebracks}{itemize}\n")

                for x in range(0, len(tasklog)):
                    tl = dict(tasklog[x])

                    dt = int(tl["createdAt"] / 1000)
                    date = datetime.fromtimestamp(dt)

                    timelist.append(date)

                    stage[date] = tl["message"]

                timelist.sort()

                for x in range(0, len(timelist)):
                    tempFile.write(f"    \item  {timelist[x]}\n\n")

                    tmp = str(stage[timelist[x]]).split("\n")

                    for z in range(0, len(tmp)):
                        if "--" not in tmp[z] and "- " in tmp[z] and item == 0 and listing != 1 and z == (len(tmp) - 1):
                            item = int(0)
                            val = str(tmp[z]).split("- ")
                            tempFile.write(f"    {itemize}\n")
                            tempFile.write(f"        \item {val[1]}\n")
                            tempFile.write(f"    {enditemize}\n")
                        elif "--" not in tmp[z] and "- " in tmp[z] and item == 0 and listing != 1 and z != (len(tmp) - 1):
                            item = int(1)
                            val = str(tmp[z]).split("- ")
                            tempFile.write(f"    {itemize}\n")
                            tempFile.write(f"        \item {val[1]}\n")
                        elif "- " in tmp[z] and item == 1 and z == (len(tmp) - 1):
                            item = int(0)
                            val = str(tmp[z]).split("- ")
                            tempFile.write(f"        \item {val[1]}\n")
                            tempFile.write(f"    {enditemize}\n")
                        elif "- " not in tmp[z] and item == 1:
                            item = int(0)
                            tempFile.write(f"    {enditemize}\n")
                            tempFile.write(f"    {tmp[z]}\n")
                        elif "- " in tmp[z] and item == 1:
                            val = str(tmp[z]).split("- ")
                            tempFile.write(f"        \item {val[1]}\n")
                        elif "-----" in tmp[z] and listing == 0:
                            listing = int(1)
                            tempFile.write(f"    {beginlisting}\n")
                        elif "-----" not in tmp[z] and listing == 1 and z == (len(tmp) - 1):
                            listing = int(0)
                            tempFile.write(f"        {tmp[z]}\n")
                            tempFile.write(f"    {endlisting}\n")
                        elif "-----" not in tmp[z] and listing == 1:
                            tempFile.write(f"        {tmp[z]}\n")
                        elif "-----" in tmp[z] and listing == 1:
                            listing = int(0)
                            tempFile.write(f"    {endlisting}\n")
                        else:
                            tempFile.write(f"    {tmp[z]}\n")

                        if z == (len(tmp) - 1):
                            tempFile.write("\n")
                tempFile.write(f"{enditemize}\n")

# Function that  calls the API to obtain the ttps associated with the case, and obtains their tactics name, technics name and description, and appends them to the classification file in an itemize list. An introduction to each tactic is also provided, using the files available on the mitre directory.
tt = ttps(casenumber)

if tt != "":
    ttp = dict([])

    for x in range(0, len(tt)):
        tmp = dict(tt[x])
        tactic = str(tmp['tactics']).split("'")

        if tactic[1] not in ttp.keys():
            ttp[tactic[1]] = {f"{tmp['name']}" : str(tmp['description'])}
        elif tmp['name'] not in ttp[tactic[1]]:
            ttp[tactic[1]][tmp['name']] = str(tmp['description'])
    
    try:
        tpFile = open( filetosave[6], 'a+' )
    except:
        print(f"File \"{filetosave[6]}\" Can't Be Accessed!")
    else:
        with tpFile:
            tpFile.write(f"{itemize}\n")

            for keys in dict_mitre.keys():
                if keys in ttp.keys():
                    try:
                        tempFile = open( dict_mitre[keys], 'r+' )
                    except:
                        print(f"File \"{dict_mitre[keys]}\" Can't Be Accessed!")
                    else:
                        with tempFile:
                            df = list(tempFile)
                            for x in range(0, len(df)):
                                tpFile.write(f"{df[x]}\n")
                            tpFile.write(f"        {itemize}\n")

                            for k in ttp[keys].keys():
                                tpFile.write("\n            \item \\textbf{%s} - " % (k))

                                for y in range(0, len(ttp[keys][k])):
                                    tpFile.write(f"{ttp[keys][k][y]}")
                            
                            tpFile.write(f"\n        {enditemize}\n\n")
            tpFile.write(f"{enditemize}")

observables = observable(response['id']) # Invokes the observable function.

# Function that extracts the observables output, obtains its type, value, description and the responders name and results. It also checks if any _ is present in the responder name and adds an \ before _ if true. Lastly, it opens tempfile and writes on latex format the entries to the table.
for i in range(0, len(observables)):
    vlist = list()
    ob = dict(observables[i])
    rp = str(ob["reports"]).split("}, ")

    for x in range(0, len(rp)):
        if x == 0:
            try:
                rp_name = rp[x].split("{\'")
                rp_name = rp_name[1].split("\'")
                rp_name = rp_name[0]
            except:
                pass
        else:
            rp_name = rp[x].split("\'")
            rp_name = rp_name[1]

        if "_" in rp_name:
            v = rp_name.split("_")
            p_name = str()

            for y in range(0, len(v)):
                if y == 0:
                    p_name = v[y]
                else:
                    p_name = (p_name + "\_" + v[y])
            rp_name = p_name

        value = rp[x].split(",")

        for z in range(0, len(value)):
            if "value" not in value[z]:
                pass
            else:
                try:
                    v = value[z].split("\'")
                    vlist.append(f"{rp_name}: {v[3]}\n\n")
                except:
                    pass
    try:
        tempFile = open( filetosave[5], 'a+' )
    except:
        print(f"File \"{filetosave[5]}\" Can't Be Accessed!")
    else:
        with tempFile:
            tempFile.write(f"{firsttablecolumentry}{(ob['dataType'] + '}')} & {secondtablecolumentry}{ob['data']} & {secondtablecolumentry}{ob['message']} & {secondtablecolumentry}{''.join(vlist)}{thirdtablecolumentry}\\\\ \n\n")

# Opens the second filetoopen and writes its content into the main file.
try:
    tempFile = open( filetosave[5], 'a+' )
except:
    print(f"File \"{filetosave[5]}\" Can't Be Accessed!")
else:
    with tempFile:
        try:
            tf = open( filetoopen[1], 'r+')
        except:
            print("Something went wrong!")
            sys.exit(0)
        else:
            with tf:
                tempor = list(tf)
                tempFile.write(''.join(tempor))

# Lastly, removes temporary files and zips the contents of the directory into a zip and removes the folder containing the latex files.
try:
    os.system(f"rm -r {path}/Internal-report-Case_#_{casenumber}/main_part2.tex && rm -r {path}/Internal-report-Case_#_{casenumber}/Observables_part2.tex && rm -r {path}/Internal-report-Case_#_{casenumber}/mitre && rm -r {path}/Internal-report-Case_#_{casenumber}/casetype")
    os.system(f"cd ./Internal-report-Case_#_{casenumber}/ && zip -q -r ../'Internal-report-Case # {casenumber}.zip' *")
except:
    print("Something went wrong!")
    sys.exit(0)
else:
    os.system(f"rm -r ./Internal-report-Case_#_{casenumber}/")