# TheHive to LaTeX Documentation

The following document is a guide on how to document an incident on TheHive so that it can be extracted using `thehive_to_latex.py` Script.

The Script was developed and tested for TheHive4.

It uses the TheHive API to make requests to the platform, where, using the case number specified in the Script invocation, it processes the responses to extract the case information and generates a zip file with the LaTeX code.

## Prerequisites

Install the required dependencies using the following commands.

```
pip3 install -r requirements.txt

apt-get install zip unzip -y
```

## Language 

The Script was originally developed to generate reports in PT. It was later updated to generate reports in EN.

In order to generate the report, change the file name with the corresponding language to be used, to `Internal-report-Case # Template.zip`

### LaTeX Code

Before using the Script to generate the report, edit the main_part2.tex file inside the zip.

The following LaTeX code give an example on which lines should be edited.

```
\lhead{CSIRT@IPB.PT Internal Report} % Report left header text
```

```
\includegraphics[width=0.5\textwidth]{CSIRT-Logo.png}\\[1cm] % Include a department/university logo

\textsc{\large csirt@ipb.pt\footnote{Computer Security Incident Response Team for Polytechnic Institute of Bragança}}\\[0.5cm] % Major heading
    
\textsc{\large CSIRT Internal Report. {\colorbox{black}{\textbf{\color{white}\href{https://www.cncs.gov.pt/pt/certpt/tlp/}{TLP:} {\color{\tlp} \MakeUppercase{\tlp}}}}}}\\[0.5cm] % Minor heading 
```

``` 
Auditor \textsc{1} \\ % Auditors names
```

```
Supervisor \textsc{1} \\ % Supervisors names
```

```
\textsc{CSIRT@IPB}\\ % Recipients names
\textsc{Dest 1}
```

## Structure

Each of these fields is extracted to generate the report from TheHive. 

### Attachment/Additional Information → Incident Information

A case custom field used to describe the type of incident and the equipments related to the incident.

When filing the field, it's not possible to add paragraphs, so if need be, add an '\n' where a paragraph should be. The Script will replace them when writing the report.

If left empty, the Script will not add this field to the report.

The custom case field configuration can be seen in the following image.

![](./Attachment.png?raw=true)

### Description → Summary

This field is used as a summary/abstract to the report.

It needs to be populated in order for the Script to work.

### Case Closed/Summary → Follow UP

This is a brief field describing the reason why the case was closed and any measure that the responsible entity took to remove the vulnerability/malware, etc...

### Task Logs → Full Report

Each task log will be added to the report with the date that the entry was created and the message of the log. Make sure not to upload an attachment with no message.

For each task log, the Script checks to see if there are any Markdown listings present, in which case it will convert them to LaTeX itemizings.

The Script also checks if there are five or more `-` present in a row, in which case it will add the following text inside a lstlisting, until it finds five or more `-` in a row or the task log ends.

This can be useful to highlight code or content such as emails.

- Example:

```
Text that will not be inside of lstlisting.

--------------
Text that will be inside of lstlisting.
--------------

Text that will not be inside of lstlisting.
```

### Observable → Observable Table

The Script will extract the observables of the case and generate a table with its information.

Make sure to add a description to each observable.

## config.txt

Make sure to edit the `config.txt` file and fill it with all the required information.

```
#TheHive URL
#Users API Key
#List of Title prefixes defined on the case templates. EX: EMAIL,GEN,SYS COMP,NET,MALWARE,DOS,VULN
#Username
#Password
```

The Title prefixes are defined on the case templates. Make sure to copy the exact Title prefixes name from TheHive.

## Full Report - Brief Introductions

The Script provides a functionality where it allows the user to generate files containing introductions to different types of incidents.  

These introductions will then be added to the Full Report section on the report, depending on the Title prefixes defined on the case templates.

These introductions vary from case templates. They should provide an introduction to the section as well as the different phases of the case template used.

An example of an introduction to a generic incident can be seen inside the casetype folder, inside the zip file. 

In order for the user to add other introductions, create a new file and add it to the zip, then change the following line of code on the Script in order for it to be able to import and write those introductions to the Full Report section. Also make sure that the Title prefixes are present in the `config.txt` file, and the same Title prefixes are used on the dictionary.

+ Example:

    ```
    dict_case_type = dict([("GEN", f"{(str(path) + '/Internal-report-Case_#_' + str(casenumber) + '/casetype/GEN.tex')}"), ("SYS COMP", f"{(str(path) + '/Internal-report-Case_#_' + str(casenumber) + '/casetype/SYS COMP.tex')}")])
    ```
    + config.txt

    ```
    #TheHive URL
    #Users API Key
    GEN,SYS COMP
    #Username
    #Password
    ```

## TTPS

In case TTPS are not being defined or used on the TheHive, the Script can be altered so that it does not require the username and password to be defined on the `config.txt` file.

For that, make sure to remove the User and Pass from the following line of code from the Script.

```
listconfig = ("URL", "API", "Classification", "User", "Pass") 
```

Then delete the following lines of code.

```
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
```

```
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
```

Lastly, make sure to remove the Username and Password from the `config.txt` file.

## Generate Report

To generate the report, execute the following command:

```
python3 thehive_to_latex.py casenumber
```

This will generate a zip file containing the LaTeX documents.