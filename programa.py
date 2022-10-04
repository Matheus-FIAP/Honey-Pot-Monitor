import json, logging, os, sys, ctypes, pathlib
CurrentUser=os.getlogin()
ThisFile=str(sys.argv[0])
LogFileExist=False
IsLogFileIntact=False
CfgFileExist=False
ev1=0
ev2=0
ev3=0
ev4=0
# This program first checks for components of itw own (log file an configuration file)

# This Checks for logfile
def check_for_log_file():
    global LogFileExist,LogFile
    CheckLogFile=(str(pathlib.Path(__file__).parent.resolve()) + "\\" + "logfile.txt")
    CheckLogFile.replace("\\", "\\\\")
    if os.path.isfile(CheckLogFile) is True:
        LogFileExist=True
        LogFile=(CheckLogFile)
    else:
        # Create logfile if none was found
        File=(str(pathlib.Path(__file__).parent.resolve()) + "\\" + "logfile.txt")
        File.replace("\\", "\\\\")
        CreateFile=open(File, 'a')
        CreateFile.close
        LogFileExist=True
    LogFile=(str(pathlib.Path(__file__).parent.resolve()) + "\\" + "logfile.txt")

# Configure the format of logfile

def config_log_file(LogFileExist):
    global IsLogFileIntact
    if LogFileExist is True:
        logging.basicConfig(filename=LogFile, level=logging.DEBUG, format="%(asctime)s %(message)s", filemode="a")
        try:
            logging.debug("Program started")
        except:
            print("Could not write to logfile")
        else:
            IsLogFileIntact=True
    else:
        check_for_log_file()

# This ensures the program is run as admin

#def check_privileges():
#    try:
#        IsAdmin = (os.getuid() == 0)
#    except AttributeError:
#        IsAdmin = ctypes.windll.shell32.IsUserAnAdmin() != 0
#    return IsAdmin
#assert(check_privileges == "True"), "Attention !!! Programs is recommended to be executed as Admin"
# Check for Honeypot the firt time the program is executed

# This checks for configuration in defaults.json

def check_for_config_file():
    global CfgFile, CfgFileExist
    CheckCfgFile=(str(pathlib.Path(__file__).parent.resolve()) + "\\" + "defaults.json")
    CheckCfgFile.replace("\\", "\\\\")
    if os.path.isfile(CheckCfgFile) is True:
        CfgFileExist=True
        CfgFile=(CheckCfgFile)
        logging.debug("Config file found at " + CfgFile)
    else:
        logging.debug("None configuration was found, generating defaults...")
        # Create standard config file if none was found
        configuration={}
        configuration["Directory_to_Detect"]=["C:\\Users\\{}".format(CurrentUser)]
        configuration["HoneypotFilenames"]=['cyber', 'policy', 'insurance', 'endorsement', 'supplementary', 'underwriting', 'terms', 'bank', '2020', '2021', '2022', 'statement', 'contract', 'financial']
        configuration["HoneypotExtensions"]=[".c",".h",".m",".ai",".cs",".db",".db",".nd",".pl",".ps",".py",\
          ".rm",".3dm",".3ds","3fr",".3g2",".3gp",".ach",".arw",".asf",".asx",\
          ".avi",".bak",".bay",".cdr",".cer",".cpp",".cr2",".crt",".crw",".dbf",\
          ".dcr",".dds",".der",".des",".dng",".doc",".dtd",".dwg",".dxf",".dxg",\
          ".eml",".eps",".erf",".fla",".flv",".hpp",".iif",".jpe",".jpg",".kdc",\
          ".key",".lua",".m4v",".max",".mdb",".mdf",".mef",".mov",".mp3",".mp4",\
          ".mpg",".mrw",".msg",".nef",".nk2",".nrw",".oab",".obj",".odb",".odc",\
          ".odm",".odp",".ods",".odt",".orf",".ost",".p12",".p7b",".p7c",".pab",\
          ".pas",".pct",".pdb",".pdd",".pdf",".pef",".pem",".pfx",".pps",".ppt",\
          ".prf",".psd",".pst",".ptx",".qba",".qbb",".qbm",".qbr",".qbw",".qbx",\
          ".qby",".r3d",".raf",".raw",".rtf",".rw2",".rwl",".sql",".sr2",".srf",\
          ".srt",".srw",".svg",".swf",".tex",".tga",".thm",".tlg",".txt",".vob",\
          ".wav",".wb2",".wmv",".wpd",".wps",".x3f",".xlk",".xlr",".xls",".yuv",\
          ".back",".docm",".docx",".flac",".indd",".java",".jpeg",".pptm",".pptx",\
          ".xlsb",".xlsm",".xlsx"]
        configuration["IgnoreEntries"]=[".vscode", "AppData"]
        configuration["MaximumHoneyPots"]=30
        configuration["MaximumEventsForScan"]=5
        configuration["ScanIdleTime"]=15
        File=(str(pathlib.Path(__file__).parent.resolve()) + "\\" + "defaults.json")
        File.replace("\\", "\\\\")
        with open(File, 'w') as fconfig:
            json.dump(configuration, fconfig, indent=2)
        logging.debug("Config generated at " + File)
        CfgFileExist=True
 
check_for_log_file()
config_log_file(LogFileExist)
check_for_config_file()

# Main function is execute after checking config and log file

if CfgFileExist is True and LogFileExist is True and IsLogFileIntact is True:

    import re, hashlib, csv, random, string, time, math

    # Variables (got from configuration file)
    def load_config():
        global configuration, Directory, words, extensions, Ignore, Maximum_HoneyPots, MaximumEvents, TimeEvent
        try:
            with open('defaults.json', 'r') as fconfig:
                configuration=json.load(fconfig)
                if "Directory_to_Detect" in configuration:
                    Directory=(configuration["Directory_to_Detect"][0])
                else:
                    Directory="C:\\Users\\{}".format(CurrentUser)
                if "HoneypotFilenames" in configuration:
                    words=(configuration["HoneypotFilenames"])
                else:
                    words=['cyber', 'policy', 'insurance', 'endorsement', 'supplementary', 'underwriting', 'terms', 'bank', '2020', '2021', '2022', 'statement', 'contract', 'financial']
                if "HoneypotExtensions" in configuration:
                    extensions=(configuration["HoneypotExtensions"])
                else:
                    extensions=[".c",".h",".m",".ai",".cs",".db",".db",".nd",".pl",".ps",".py",\
              ".rm",".3dm",".3ds","3fr",".3g2",".3gp",".ach",".arw",".asf",".asx",\
              ".avi",".bak",".bay",".cdr",".cer",".cpp",".cr2",".crt",".crw",".dbf",\
              ".dcr",".dds",".der",".des",".dng",".doc",".dtd",".dwg",".dxf",".dxg",\
              ".eml",".eps",".erf",".fla",".flv",".hpp",".iif",".jpe",".jpg",".kdc",\
              ".key",".lua",".m4v",".max",".mdb",".mdf",".mef",".mov",".mp3",".mp4",\
              ".mpg",".mrw",".msg",".nef",".nk2",".nrw",".oab",".obj",".odb",".odc",\
              ".odm",".odp",".ods",".odt",".orf",".ost",".p12",".p7b",".p7c",".pab",\
              ".pas",".pct",".pdb",".pdd",".pdf",".pef",".pem",".pfx",".pps",".ppt",\
              ".prf",".psd",".pst",".ptx",".qba",".qbb",".qbm",".qbr",".qbw",".qbx",\
              ".qby",".r3d",".raf",".raw",".rtf",".rw2",".rwl",".sql",".sr2",".srf",\
              ".srt",".srw",".svg",".swf",".tex",".tga",".thm",".tlg",".txt",".vob",\
              ".wav",".wb2",".wmv",".wpd",".wps",".x3f",".xlk",".xlr",".xls",".yuv",\
              ".back",".docm",".docx",".flac",".indd",".java",".jpeg",".pptm",".pptx",\
              ".xlsb",".xlsm",".xlsx"]
                if "IgnoreEntries" in configuration:
                    Ignore=(configuration["IgnoreEntries"])
                else:
                    Ignore=[".vscode", "AppData"]
                if "MaximumHoneyPots" in configuration:
                    Maximum_HoneyPots=(configuration["MaximumHoneyPots"])
                    if Maximum_HoneyPots == "0":
                        logging.error("Value of MaximumHoneypots in configuration file cannot be 0. Changing to 50")
                        Maximum_HoneyPots=50
                else:
                    Maximum_HoneyPots=30
                if "MaximumEventsForScan" in configuration:
                    MaximumEvents=(configuration["MaximumEventsForScan"])
                    if MaximumEvents == "0":
                        logging.error("Value of MaximumEvents in configuration file cannot be 0. Changing to 5")
                        MaximumEvents=5
                else:
                    MaximumEvents=5
                if "ScanIdleTime" in configuration:
                    TimeEvent=(configuration["ScanIdleTime"])
                else:
                    TimeEvent=15
        except:
            logging.error("Unable to load configuration, going with the defaults")
            Directory="C:\\Users\\{}".format(CurrentUser)
            words=['cyber', 'policy', 'insurance', 'endorsement', 'supplementary', 'underwriting', 'terms', 'bank', '2020', '2021', '2022', 'statement', 'contract', 'financial']
            extensions=[".c",".h",".m",".ai",".cs",".db",".db",".nd",".pl",".ps",".py",\
          ".rm",".3dm",".3ds","3fr",".3g2",".3gp",".ach",".arw",".asf",".asx",\
          ".avi",".bak",".bay",".cdr",".cer",".cpp",".cr2",".crt",".crw",".dbf",\
          ".dcr",".dds",".der",".des",".dng",".doc",".dtd",".dwg",".dxf",".dxg",\
          ".eml",".eps",".erf",".fla",".flv",".hpp",".iif",".jpe",".jpg",".kdc",\
          ".key",".lua",".m4v",".max",".mdb",".mdf",".mef",".mov",".mp3",".mp4",\
          ".mpg",".mrw",".msg",".nef",".nk2",".nrw",".oab",".obj",".odb",".odc",\
          ".odm",".odp",".ods",".odt",".orf",".ost",".p12",".p7b",".p7c",".pab",\
          ".pas",".pct",".pdb",".pdd",".pdf",".pef",".pem",".pfx",".pps",".ppt",\
          ".prf",".psd",".pst",".ptx",".qba",".qbb",".qbm",".qbr",".qbw",".qbx",\
          ".qby",".r3d",".raf",".raw",".rtf",".rw2",".rwl",".sql",".sr2",".srf",\
          ".srt",".srw",".svg",".swf",".tex",".tga",".thm",".tlg",".txt",".vob",\
          ".wav",".wb2",".wmv",".wpd",".wps",".x3f",".xlk",".xlr",".xls",".yuv",\
          ".back",".docm",".docx",".flac",".indd",".java",".jpeg",".pptm",".pptx",\
          ".xlsb",".xlsm",".xlsx"]
            Ignore=[".vscode", "AppData"]
            Maximum_HoneyPots=30
        CurrentConfiguration={}
        CurrentConfiguration["Directory_to_Detect"]=Directory
        CurrentConfiguration["HoneypotFilenames"]=words
        CurrentConfiguration["HoneypotExtensions"]=extensions
        CurrentConfiguration["IgnoreEntries"]=Ignore
        CurrentConfiguration["MaximumHoneyPots"]=Maximum_HoneyPots
        CurrentConfiguration["MaximumEventsForScan"]=MaximumEvents
        CurrentConfiguration["ScanIdleTime"]=TimeEvent
        DropCurrentCfg=(str(pathlib.Path(__file__).parent.resolve()) + "\\" + "defaults.json")
        DropCurrentCfg.replace("\\", "\\\\")
        with open(DropCurrentCfg, 'w') as dcconfig:
            json.dump(configuration, dcconfig, indent=2)
        logging.debug("Current configuration was dropped at " + DropCurrentCfg)
        logging.debug("Configuration loaded. Starting program...")

    def check_for_honeypots():
        # Runs only once as the program is executed, and check and delete all honeypots to create new ones
        # Checks and validates if any honeypot was found in current user folder and its size
        n=0
        for subdir, dirs, files in os.walk(Directory):
            for entries in Ignore:
                if entries in subdir:
                    break
            else:
                for FileNames in words:
                    for Ext in extensions:
                        ExistingPath=(subdir + "\\" + FileNames + Ext)
                        ExistingPath.replace("\\", "\\\\")
                        if os.path.isfile(ExistingPath) is True:
                            # If found, it will erased to new one be created
                            os.remove(ExistingPath)
                            logging.debug("Honeypot detected at " + ExistingPath + " was removed")
                            n=n+1
        logging.debug(str(n) + " Honeypots were removed")

    # This defines how many honeypots will be created at each Current User Directory and update Count and Maximum in configuration file
    def Counts():
        NOfFolder=[]
        for subdir, dirs, files in os.walk(Directory):
            for entries in Ignore:
                if entries in subdir:
                    break
            else:
                Formatted_subdirs=subdir.replace("\\\\", "\\")
                NOfFolder.append(Formatted_subdirs)
        Each_Honeypots=math.floor((Maximum_HoneyPots / int(len(NOfFolder))))
        if Each_Honeypots == 0:
            Each_Honeypots=1
            logging.error("Value of MaximumHoneypot was too low to populate all directories in choosen path. Changing to 1")
        return Each_Honeypots

    # Create honeypots

    def create_honeypots():
        global honeypot
        n=0
        c=1
        honeypot={}
        for subdir, dirs, files in os.walk(Directory):
                for entries in Ignore:
                    if entries in subdir:
                        break
                else:
                    for max in range(0, Counts()):
                        chars = ''.join([random.choice(string.ascii_letters) for i in range(1024*1024)])
                        Generator=str((random.choice(words) + random.choice(extensions)))
                        FullPath=(subdir + "\\" + Generator)
                        tmp={1:FullPath, 2:Generator}
                        honeypot[c]=tmp
                        with open(FullPath, 'w') as honeypotf:
                            honeypotf.write(chars)
                            logging.debug("Honeypot created at " + FullPath)
                            n=n+1
                        c=c+1
        logging.debug(str(n) + " Honeypots were created")

    # This part will handle the scanning of files

    def scan_honeypots():
        # Dicictionary structure : 
        # Tag: Folder[1] (Full Path of honeypot), Name of file[2], MD5 Hash[3], SHA-256 Hash[4], File Size[5], File CTIME[6] (Creation Time), File ATIME[7] (Last Access Time), File MTIME[8] (Last Modification Time)
        global honeypot, OutputFile
        for tag, folder in honeypot.items():
            md5hash=hashlib.md5()
            sha256hash=hashlib.sha256()
            with open(folder[1], 'rb') as hasher:
                try:
                    content=hasher.read()
                    md5hash.update(content)
                    file_hash=md5hash.hexdigest()
                except:
                    logging.error("Could not get md5 hash of " + folder + ". This may harm monitoring...")
                else:
                    honeypot[tag][3]=file_hash
            with open(folder[1], 'rb') as hasher:
                try:
                    content=hasher.read()
                    sha256hash.update(content)
                    file_hash=sha256hash.hexdigest()
                except:
                    logging.error("Could not get sha256 hash of " + folder  + ". This may harm monitoring...")
                else:
                    honeypot[tag][4]=file_hash
            with open(folder[1], 'rb'):
                try:
                    size=os.path.getsize(folder[1])
                    creation=os.path.getctime(folder[1])
                    access=os.path.getatime(folder[1])
                    change=os.path.getmtime(folder[1])
#                    time.asctime(time.localtime(creation))
#                    time.asctime(time.localtime(modified))
#                    time.asctime(time.localtime(change))
                except:
                    logging.error("Could not get size/ctime/atime or mtime of " + folder  + ". This may harm monitoring...")
                else:
                    honeypot[tag][5]=size
                    honeypot[tag][6]=creation
                    honeypot[tag][7]=access
                    honeypot[tag][8]=change
        OutputFile=(str(pathlib.Path(__file__).parent.resolve()) + "\\" + "monitor.json")
        with open(OutputFile, 'w') as outputjson:
            json.dump(honeypot, outputjson, indent=2)
        logging.debug("Hashes of file generated at " + OutputFile)
            

    # This part will monitor any changes to honeypots

    def monitor_honeypots():
        # It adds to honeypots boolean values: IsFileStillExist[9], IsMd5Equal[10], IsSha256Equal[11], IsSameSize[12], IsSameFile[13], WasAccessed[14], IsChanged[15])
        for tag, folder in honeypot.items():
            if os.path.exists(folder[1]):
                honeypot[tag][9]=True
                md5hash=hashlib.md5()
                sha256hash=hashlib.sha256()
                with open(folder[1], 'rb') as hasher:
                    try:
                        content=hasher.read()
                        md5hash.update(content)
                        mfile_hash=md5hash.hexdigest()
                    except:
                        logging.error("Could not get md5 hash of " + folder[1] + ". This may harm monitoring...")
                    else:
                        if mfile_hash == honeypot[tag][3]:
                            honeypot[tag][10]=True
                        else:
                            honeypot[tag][10]=False
                with open(folder[1], 'rb') as hasher:
                    try:
                        content=hasher.read()
                        sha256hash.update(content)
                        sfile_hash=sha256hash.hexdigest()
                    except:
                        logging.error("Could not get sha256 hash of " + folder[1]  + ". This may harm monitoring...")
                    else:
                        if sfile_hash == honeypot[tag][4]:
                            honeypot[tag][11]=True
                        else:
                            honeypot[tag][11]=False
                with open(folder[1], 'rb'):
                    try:
                        size=os.path.getsize(folder[1])
                        creation=os.path.getctime(folder[1])
                        access=os.path.getatime(folder[1])
                        change=os.path.getmtime(folder[1])
    #                    time.asctime(time.localtime(creation))
    #                    time.asctime(time.localtime(modified))
    #                    time.asctime(time.localtime(change))
                    except:
                        logging.error("Could not get size/ctime/atime or mtime of " + folder[1]  + ". This may harm monitoring...")
                    else:
                        if size == honeypot[tag][5]:
                            honeypot[tag][12]=True
                        else:
                            honeypot[tag][12]=False
                        if creation == honeypot[tag][6]:
                            honeypot[tag][13]=True
                        else:
                            honeypot[tag][13]=False
                        if access == honeypot[tag][7]:
                            honeypot[tag][14]=True
                        else:
                            honeypot[tag][14]=False
                        if change == honeypot[tag][8]:
                            honeypot[tag][15]=True
                        else:
                            honeypot[tag][15]=False
                if honeypot[tag][10] == True and honeypot[tag][11] == True and honeypot[tag][12] == True and honeypot[tag][13] == True and honeypot[tag][15] == True:
                    logging.debug("File " + folder[1] + " is intact!")
                else:
                    if honeypot[tag][10] == False:
                        msg=("MD5 of " + folder[1] +  " was changed. Before: ", honeypot[tag][3], " - After: " + mfile_hash)
                        logging.debug(str(msg))
                        ev1+1
                    if honeypot[tag][11] == False:
                        msg=("SHA-256 of " + folder[1] + " was changed. Before: ", honeypot[tag][4], " After: " + sfile_hash)
                        logging.debug(str(msg))
                        ev2+1
                    if honeypot[tag][12] == False:
                        msg=("Size of " + folder[1] + " was changed. Before: ", honeypot[tag][5], " Bytes - After: ", size, " Bytes")
                        logging.debug(str(msg))
                        ev3+1
                    if honeypot[tag][13] == False:
                        msg=("The file at  " + folder[1] + " is not the same it was created before. Before: ", honeypot[tag][6], " - After: ", creation, ". Deleting...")
                        logging.debug(str(msg))
                        del honeypot[tag]
                    if honeypot[tag][14] == False:
                        msg=("The file " + folder[1] + " was acessed. Before: ", honeypot[tag][6], " - After ", access)
                        logging.debug(str(msg))
                    elif honeypot[tag][15] == False:
                        msg=("The file " + folder[1] + " was modified. Before: ", honeypot[tag][7], " - After ", change)
                        logging.debug(str(msg))
                        ev4+1
            else:
                logging.debug("File " + folder[1] + " was not found. Deleting its entry...")
                del honeypot[tag]
    # This is the execution parte of the program

    load_config()
    check_for_honeypots()
    create_honeypots()
    scan_honeypots()
    n=1
    while True:
        monitor_honeypots()
        time.sleep(TimeEvent)
        logging.debug("Scan run " + str(n) + " times")
        n=n+1
        if ev1 == MaximumEvents or ev2 == MaximumEvents or ev3 == MaximumEvents or ev4 == MaximumEvents:
            logging.debug("ALERT!!!! MaximumEvents was reached. Could be Ransomware activity")
        else:
            ev1=0
            ev2=0
            ev3=0
            ev4=0

else:
    logging.basicConfig(level=logging.CRITICAL, format="%(asctime)s %(message)s")
    logging.critical("Program could not create a new log or configuration file. Exiting")