#Joseph Avanzato
#joeavanzato@gmail.com
#Written in Python 3.6.2:5fd33b5

#P-MATCH - FILE HASHER AND STRING MATCHER for Windows Systems in Python

#Don't email me telling me it sucks cause I already know.
#I'm a bad/new programmer and if you're reading this I'm sorry.  I realize in hindsight about 10,000 things I could've done better that I didn't think of in the moment because I'm an idiot.
#I'm actually even surprised this code runs without more errors.
#Because I didn't do a proper initial design, this was essentially made by 'patchwork', with the hashing module done first then work started on the binary analysis portion.
#I didn't want to re-do everything because I'm slightly lazy and it would require more effort than I wish to expend on something that barely works in the first place.  
#This was initially started as a means to practice python and evolved into a final project for coursework at RIT
#TO-DO: Lots and Lots...

import os, hashlib, ntpath, time, datetime, struct, binascii, re
from re import split

#os for walking directories, checking if path/directory/file exists for options, setting paths, normalizing paths
#hashlib for MD5/SHA1/SHA256 hash functionality
#ntpath for getting base file name regardless of path on Windows -easy references
#datetime/time for getting time and displaying formatted
#struct for messing with certain C-structs for PE files (NOT ACTUALLY USED CURRENTLY- ENVISIONED FOR USE WITH PULLING OUT SPECIFIC PE HEADER INFORMATIO)
#binascii for data conversions(Hex, Binary, ASCII, etc)
#re for string manipulation stuff/retrieving printable strings from files/setting up regexp patterns

#A .txt file stored in given directory for hash-database comparison (1-hash per new-line of hash-type set in execution, i.e. variable 'ht') -MUST BE SET TO PROER FORMAT (32 chars for MD5, 40 for SHA1, 64 for SHA256)
#'filesignatures.txt' stored in script directory for binary-analysis file-signature checking operations (ASCII HEX SIGNATURE, ASCII HEX OFFSET, DESCRIPTION)- Ensure no extra white space at EOF -NEED TO CHANGE THIS TO SIT ANYWHERE, NOT IN SCRIPT CD
#A *.txt file delimited by newlines containing strings for comparing in Binary Mode is required when utilzing database mode

#This software allows for simple virus scanning via a comparative hash analysis or binary string comparisons.
#The hash  analysis allows users to specify a base directory from which to intialize recursive(n) scanning operations.
#Scanning will examine and optionally walk through all sub-directories, performing either MD5, SHA1 or SHA256.
#The user may also specify a single hash, hash database or binary file for comparison to the generated hash-list (hashset.txt).
#In addition, the user will have the option to individually check each generated hash against www.VirustTotal.com. #TO DO TO DO TO DO
#Binary Analysis mode allows the user to specify either a pre-built strings signature file or a binary file from which a signature will be generated.
#This program also loads from (filesignatures.txt) in Script Directory a list of SIGNATURES, OFFSETS and DESCRIPTIONS for various file headers.
#These may be useful in finding an executable which has attempted to disguise its file extension.

print("")
print("P-MATCH - A Python based recursive file hasher and binary string-matching tool for Windows Systems")
print("This software allows users to compile a comprehensive hash database of their current file system, perform individual or batch comparisons and utilize basic string matching analysis.")

global recur #Tracks desired recursion
global choice #Tracks initial desired run-option
global path #Tracks starting directory
global filelist #Stores files in current working directory
global scansize #Tracks max file threshold
global dirlist #Tracks directories stored in current working directory
global ht #Tracks desired hashing mechanism
global time2 #me being dumb
global hash #temp hash string
global localhashlist #list of generated hashes
global localfilelist #list of associated filenames
global skiplist #list of skipped files during scan
global printthese #list of characters scanned for during reg-exp string match
global matchlist #initializing now because later is a problem
global stringmatches
global allstringmatches

#initializing certain global variables because they might not get setup properly following certain execution pathways
allstringmatches = []
stringmatches = []
matchlist = []
printthese = r"0-9a-zA-Z/\,.-:_%$[\]'()<> " #setting up for reg-exp matching later
localhashlist = [] #initiates hash/file/skip lists for later
localfilelist = []
skiplist = []
scansize = 0

def isRecur(): #Checks if the user wishes to perform a recursive file system or single directory scan.
        global recur
        recur = input("Recursive Sub-Directory scan from Base Path? (Can cause crashes/take a long time) (n, N, y, Y) : ")
        if (len(recur) > 1):
            print("Error : Only enter one character...")
            isRecur() #Restarts if entered string length greater than one
        else:
            pass
        if ('n' in recur) or ('N' in recur):
            print("Recursive Scanning Disabled")
            maxSize() #Moves to next User Input, File Scan Threshold
        elif ('y' in recur) or ('Y' in recur):
            print("Recursive Scanning Enabled")
            maxSize()
        else:
            print("Error : Please enter an appropriate option (n, N, y, Ye)")
            isRecur()

def maxSize(): #Determines max size for file scanning in megabytes
    global scansize
    scansize = input("Enter the threshold file size for scanning in MegaBytes (will skip files greater than): ")
    try:
        test = int(scansize)
    except ValueError:
        print("Error : Please enter a number...")
        maxSize()
    test = int(scansize) #Prepares test variable in integer format
    test = test*1000000 #converts megabytes to bytes for whole-integer less than comparison

    if (test < 1000000): #ensures input must be at least 1 megabyte
        print("Lowest Scanning Size is 1 MegaByte...")
        maxSize()

    elif ('s' in choice) or ('S' in choice):
        print("Selected Threshold is "+scansize+" MegaBytes")
        hashType()
    elif ('b' in choice) or ('B' in choice):
        print("Selected Threshold is "+scansize+" MegaBytes")
        scanforPE()
    
def start(): #Initializes program by letting user choose between Hash Scan/Comparison or Binary Analysis
    global choice
    global startdir
    startdir = os.getcwd()
    choice = input("Enter S for a statistical hash analysis or B for a binary-string analysis (s, S, b, B): ")
    if (len(choice) > 1):
        print("Only enter one character...")
        start()
    else:
        pass
    if ('s' in choice) or ('S' in choice):
        getPath()
    elif ('b' in choice) or ('B' in choice):
        binaryStart()
    else:
        print("Error : Please enter an appropriate option (s, S, b, B)....")
        start()

def getPath(): #Lets the user choose an existing base path
    global path
    path = input("Please type the base path where scanning will begin, include trailing slashes (Default: C:/Users/) : ")
    if path == "":
        path = os.path.normpath("C:/Users/") #Sets Default Path
        print("Selected Path : " + path)
        isRecur()
    elif os.path.isdir(path) == False:
        print("Error : The path you entered does not exist. Try again.")
        getPath()
    elif os.path.isdir(path) == True:  
        print("Selected Path : " + path)
        isRecur()

def hashType(): #Lets user determine hashing methodology, set through global var ht, tempvar gives string name(MD5, SHA1, SHA256)
    global ht
    global tempvar
    print ("Please choose the desired hashing mechanism.")
    ht = input("Enter 1 for MD5, 2 for SHA1 or 3 for SHA256 : ")
    try:
        testht = int(ht)
    except ValueError:
        print("ERROR : ENTER AN APPROPRIATE NUMBER")
        hashType()
    ht = int(ht)
    if (ht == 1):
        tempvar = "MD5"
        localScan()
    elif (ht == 2): 
        tempvar = "SHA1"
        localScan()
    elif (ht == 3):
        tempvar = "SHA256"
        localScan()
    else:
        print("Please enter 1, 2 or 3...")
        hashType()

def localScan(): #Gets hash comparison method, verifies INT, sets up Hash Comparison Input with compareType, sorts flow for recursion/no recursion
    global cd 
    global hashsrc
    cd = os.getcwd() #Checks current directory for reference
    hashsrc = input("Would you like to supply a known hash (1), hash database (2) or binary file (3) for hash sample? (0 no comparison) : ")
    try: #tests if number
        x = int(hashsrc)
    except ValueError:
        print("Please enter an appropriate number")
        localScan() #restarts if not pure int
    print("Switching working directory from "+cd+" to "+path)
    compareType()
    os.chdir(path) #Changes current working directory to specified path
    print("Analyzing files contained in "+path)
    print("Aggregating Files to temporary array...")

    if (recur == "n") or (recur =="N"):
        getContents()
    else:
        prepRecur()
        afterHash()

def prepRecur(): #Reads all files recursively from input 'path' and passes to check for getting rid of bad files, checking size and passing to hash (doesn't actually do anything it turns out, need to refactor this...)
    #try:
    for roots, subdirs, files in os.walk(path):
        for file in files:
                check(file, roots)
    #except OSError:
        #return

def check(file,rootpath): #Performs isfile check, size check and finally hashes
    os.chdir(rootpath)
    global localhashlist
    global localfilelist
    if os.path.isfile(file) == False: #checks if directory or file 
        pass #skips to next instruction after logging name
    elif os.path.getsize(file) > (int(scansize)*1000000): #getsize operates at byte level, must modify operands
        size = str((os.path.getsize(file))/1000000)
        name = ntpath.basename(file)
        skiplist.append(rootpath)
        skiplist.append(name)
        skiplist.append(size)
        print(name+" is excluded from scanning. (Size : "+size+" MB)")
    else:
        hashFile(file)
        print(hash.hexdigest()+"  "+file) #prints upon completion
        localhashlist.append(hash.hexdigest())
        localfilelist.append(ntpath.basename(file))

def getContents(): #Gets list of files, processes directory
    global localhashlist #temp list for local directory hashes
    global localfilelist #temp list for local directory fle names
    global currentpath

    currentpath = os.getcwd()
    print("Getting Directory Contents for "+currentpath)
    filelist = os.listdir()
    for file in filelist:
        if os.path.isdir(file) == True: #checks if directory or file 
            pass #skips to next instruction after logging name
            
        else: 
            if os.path.getsize(file) > (int(scansize)*1000000): #getsize operates at byte level, must modify operands for proper comparison
                name = ntpath.basename(file)
                size = str((os.path.getsize(file))/1000000)
                print(name+" is excluded from scanning. (Size : "+size+" MB)")
                skiplist.append(name)
                skiplist.append(size)
            else:
                hashFile(file) #sends to hash flow control
                print(hash.hexdigest()+"  "+file) #prints upon completion
                localhashlist.append(hash.hexdigest())
                localfilelist.append(ntpath.basename(file))
    afterHash()

def afterHash(): #Prepares time/date for writing to hash file, tries comparison function, calls finishing hashOutput 
    global binhash
    os.chdir(path)
    global time2 #editing global variable
    time2 = time.strftime("%H-%M(%m-%d-%Y)")
    time2 = time2+tempvar+"-HashResults.txt" #Sets name inheriting current date/time and hash-type used
    print("")
    h = len(localhashlist)
    print("Hashing operations complete. "+str(h)+" files stepped through.")
    if (int(hashsrc) == 3):
        hashFile(ntpath.basename(binfileloc))
        print(hash.hexdigest()+"  "+ntpath.basename(binfileloc)) #prints upon completion
        binhash = hash.hexdigest()
    
    #try:
    toCompare()
    #except OSError:
        #print("ERROR COMPARING HASHES.txt")
    hashOutput()
    #print("File Names and resultant Hash Values stored in "+path+" under the name "+time2)
    print("If this file does not exist, please ensure trailing slash was used in directory specification")
    print("The default file output type is space delimited.")
    print("")

def compareType(): #Stores associated hash/database/binary for requested comparison
    global knownhash # single hash
    global hashdbloc # database path
    global binfileloc # binary path
    global binfilename # binary base name
    global binhash # hash of input binary 
    global hashdbname

    x = int(hashsrc)
    if (x == 1): #Single Hash Input
        if (ht == 1):
            knownhash = input("Please enter MD5 hash : ")
            while not len(knownhash) == 32: #Checks Input size but does NOT check for special characters, Add Later
                knownhash = input("Error : Please enter an appropriate MD5 hash with 32 characters : ")
        elif (ht == 2):
            knownhash = input("Please enter SHA1 hash : ")
            while not len(knownhash) == 40:
                knownhash = input("Error : Please enter an appropriate SHA1 hash with 40 characters : ")
        elif (ht == 3):
            knownhash = input("Please enter SHA256 hash : ")
            while not len(knownhash) == 64:
                knownhash = input("Error : Please enter an appropriate SHA256 hash with 64 characters : ")
    elif (x == 2):
        hashdbloc = input("Please enter full path to hash database file : ")#set up dir. input validation
        if (os.path.isdir(hashdbloc) == True) and (os.path.isfile(ntpath.basename(hashdbloc)) == False): 
            print("ERROR: Directory EXISTS BUT FILE NOT FOUND")
            compareType()
        elif (os.path.isdir(hashdbloc) == False) and (os.path.isfile(ntpath.basename(hashdbloc)) == True):
            hashdbname = ntpath.basename(hashdbloc)
            print("File Detected : "+hashdbname)
    elif (x == 3):
        binfileloc = input("Please enter full file path to binary sample for hashing : ")
        if (os.path.isdir(binfileloc) == True) and (os.path.isfile(binfileloc) == False): #If it's a directory but not a file...
            print("ERROR : DIRECTORY EXISTS BUT FILE NOT FOUND")
            compareType()
        elif (os.path.isdir(binfileloc) == False) and (os.path.isfile(binfileloc) == True): #If it's a file and not a directory!
            binfilename = ntpath.basename(binfileloc)
            print("File Detected : "+binfilename)
        #hashFile(ntpath.basename(binfileloc))
        #binhash = hash.hexdigest()
        #print("The calculated "+tempvar+" hash for "+ntpath.basename(binfileloc)+" is "+binhash)

    else:
        print("No comparison selected.")
        
def toCompare(): #compares known hash, generated hash or hash database to output file
    global matches
    global hsh
    matches = []
    hsh = []
    cdtmp = os.getcwd()
    hs = int(hashsrc)
    if (hs == 2): #Hash Database Input MUST TEST!!! ---> SEEMS TO WORK OK!!
        temp = []
        print("")
        print("Entering database comparison...")
        print("")
        with open(hashdbloc) as tmphsh:
            for newline in tmphsh:
                h = newline.split() #hashset contains 1 hash value per line
                hsh.append(h) 
        i = len(hsh) #Gets length for iterating through all hashes in input set
        g = 0
        while g < i: #iterates all temp values through hashlist comparison
            c = hsh[g] #includes 2 extra chars on each end
            badchars = ("'[]")
            c = str(c)
            lenc = len(c)-2 #stripping extra from string
            c = (c[2:lenc]) #start 2, go length of hash value
            q = len(localhashlist)
            x = 0
            while x < q:
                a = localhashlist[x] #iterating through hash/name lists simultaneously
                b = localfilelist[x]
                if (c == a): #Checks if output hash from analysis matches database hash
                    matches.append(b)
                    x = x + 1
                else:
                    x = x + 1
            g = g + 1
        z = len(matches)
        y = 0
        name = str(time2)
        file = open("Matches FOR "+name, 'w')
        while y < z:
            m = matches[y]
            file.write(m+"\n")
            print("A match was detected with "+m)
            y = y + 1
        print("")
        print("Match List Successfully written to Matches FOR "+name)
        file.close()
        return
    elif (hs == 1) or (hs == 3): #Single hash input from text or binary 
        print("Entering single hash comparison...")
        i = len(localhashlist) #Gets length of while loop
        #print(i) #Testing
        x = 0
        c = "a"
        if (hs == 1): #Checks hash source
            c = knownhash
        elif (hs == 3):
            c = binhash
        while x < i:
            a = localhashlist[x] #iterating through hash/name lists simultaneously
            b = localfilelist[x]
            if (c == a):
                matches.append(b)#file name stored in match list
                x = x + 1
            else:
                x = x + 1
                pass
        z = len(matches)
        y = 0
        while y < z:
            m = matches[y]
            print("A match was detected with "+m)
            y = y + 1
        return
    else:
        return
            
def hashOutput(): #Forms Output File name and iterates through hash/filename arrays in order to write values to file
    name = str(time2)
    os.chdir(path)
    dir = str(path+"/")+str(name) #Setting file name to current time/date, appending slash
    try:
        file = open(dir, "w") 
        i = len(localhashlist) #Getting length of list
        x = 0
        while x < i:
            a = localhashlist[x] #iterating through hash/name lists simultaneously
            b = localfilelist[x]
            try:
                file.write(a+","+b + "\n") #Comma-delimited output, can change
            except:
                print("ERROR WRITING "+a+" OR "+b+" TO FILE")
            x = x + 1
        file.close()
        print("Hash Outputs successfully written to "+name)
    except OSError:
        print("ERROR WRITING HASH OUTPUTS")

    try:
        file = open("Skip-List for "+name, "w") 
        i = len(skiplist) #Getting length of list
        x = 0
        if ('y' in recur) or ('Y' in recur):
            while x < i:
                a = skiplist[x]#iterating through hash/name lists simultaneously
                x = x + 1
                b = skiplist[x]
                x = x + 1
                c = skiplist[x]
                try:
                    file.write(a+b+" "+c+" MB""\n") #Comma-delimited output, can change
                except:
                    print("ERROR WRITING "+a+b+" OR "+c+" TO FILE")
                x = x + 1
        else:
             while x < i:
                 a = skiplist[x] #iterating through hash/name lists simultaneously
                 x = x + 1
                 b = skiplist[x]
                 x = x + 1
                 try:
                    file.write(a+" SIZE,  "+b+" MB""\n") #Comma-delimited output, can change
                 except:
                    print("ERROR WRITING "+a+" OR "+b+" TO FILE")
        file.close()
    except OSError:
        print("ERROR WRITING SKIP LIST")
        pass
    print("Skip List Successfully written to Skip-List for "+name)

def hashFile(file): #Gets current hash type and sends file for processing to appropriate mechanism, data flow control
    global ht
    ht = int(ht)
    if ht == 1:
        doMD5(file)
    elif ht == 2:
        doSHA1(file)
    elif ht == 3:
        doSHA256(file)

def doMD5(file): #Gets MD5 of input file, realized I could easily make these one larger switch statement, hindsight..might fix..
    global hash
    hash = hashlib.md5()
    try:
        with open(ntpath.basename(file), 'rb') as tempfile: #opens file in read-binary mode
            prep = tempfile.read() #buffers file
            hash.update(prep) #updates has for next segment
    except OSError:
        return

def doSHA1(file): #Gets SHA1 of input file
    bs = 65536 #sets Block Size
    global hash
    hash = hashlib.sha1()
    try:
        with open(ntpath.basename(file), 'rb') as tempfile: 
            prep = tempfile.read(bs)
            while len(prep) > 0: #keeps loop going until buffer empty i.e. done reading file
                hash.update(prep)
                prep = tempfile.read(bs)
    except OSError:
        return

def doSHA256(file): #Gets SHA256 of input file
    bs = 65536 #sets Block Size
    global hash
    hash = hashlib.sha256()
    try:
        with open(ntpath.basename(file), 'rb') as tempfile: 
            prep = tempfile.read(bs)
            while len(prep) > 0: #keeps loop going until buffer empty i.e. done reading file
                hash.update(prep)
                prep = tempfile.read(bs)
    except OSError:
        return

def binaryStart(): #Will initialize binary analysis operations - Provide signature file or binary - either stringExtract or PE header/section comparison, sort by .exe or all (will fix), also check file signatures and only go PE if MZ detected
    global mode
    global path
    loadSigs() #Loads file signatures, offsets and descriptions from filesignatures.txt in script home directory
    print("This mode allows the user to specify a signature file directly or select a malware binary for a file-system comparison")
    mode = input("(1) to provide signature file, (2) to provide binary file : ") #Strings separated by comma or bin. file for string-extraction
    try:
        int(mode)
    except ValueError:
        print("ERROR : ENTER VALID OPTION (1,2)") #come on man, enter only a number!
        binaryStart()
    if (int(mode) == 1) or (int(mode) == 2):
        pass
    else:
        while (int(mode) != 1) or (int(mode) != 2):
            mode = input("ERROR : ENTER VALID OPTION (1,2) ") #ENTER THE RIGHT NUMBER!!!
            try:
                int(mode)
            except ValueError:
                print("ERROR : ONLY NUMBERS") #We already went through this
                binaryStart()
    printSigs()
    preExtract()
    if (int(mode) == 1): #TO DO STILL - ADD SCANDB FUNCTIONALITY
        getPath2() #must reenable for production CHANGE
        #scanDB()
    elif (int(mode) == 2): #no difference in if/elif loop right now, fix
        getPath2() #must reenable for production CHANGE
        #path = os.path.normpath("C:/Users/Joe/Documents/Classes Fall 2017/Malware/bobpointers/bobpointers.exe") #Sets Default Path CHANGE
        #scanSample()

def getPath2(): #Gets path for database/binary sample as user input, checks if valid directory/file exist before succeeding
    global path
    if (int(mode) == 1):
        path = input("Please enter full path for strings signature file : ")
        if (os.path.isdir(os.path.normpath(path)) == True) and (os.path.isfile(ntpath.basename(path)) == False):
            print("ERROR : DIRECTORY EXISTS BUT FILE NOT FOUND")
            getPath2()
        elif (os.path.isdir(os.path.normpath(path)) == False) and (os.path.isfile(path) == True):
            print("Database successfully located at "+path)
            print("Initiating signature database scan...")
            scanDB()
        else:
            print("ERROR : PATH NOT FOUND")
            getPath2()
    elif (int(mode) == 2):
        path = input("Please enter full path for Binary Sample : ")
        if (os.path.isdir(path) == True) and (os.path.isfile(path) == False): #If it's a directory but not a file...
            print("ERROR : DIRECTORY EXISTS BUT FILE NOT FOUND")
            getPath2()
        elif (os.path.isdir(path) == False) and (os.path.isfile(path) == True): #If it's a file and not a directory!
            print("Binary file successfully located at "+path)
            print("Initiating binary sample scan...")
            scanSample()
        else:
            print("ERROR : PATH NOT FOUND") #This covers false/false and true/true exceptions
            getPath2()
    else:
        print("ERROR : SHOULDN'T EVER SEE THIS IF MODE SANITIZED PROPERLY")
        binaryStart()

def scanforPE(): #Recursive file system scan for PE files - poorly thoughout logical tests for file/directory/path existence verifying user input
    global path
    global scanpath
    global skiplist
    skiplist = []
    if (scansize == 0):
        maxSize()
    scanpath = input("Please enter base directory for recursive scan : ")
    if (os.path.isdir(scanpath) == True):
        pass
    elif (os.path.isdir(scanpath) == False):
        print("ERROR : DIRECTORY NOT FOUND AT "+scanpath)
        scanforPE()
    else:
        print("ERROR : NOT A PROPER PATH")
        scanforPE()
    ends = input("Search only .exe (1) or all files (2)? :")
    if (int(ends) == 1):
        print("Scanning from "+path+" for executable files..")
        for roots, subdirs, files in os.walk(scanpath):
            for file in files:
                try: #In case permission or other related error
                    if ntpath.basename(file).endswith(".exe"): #Gets only executables
                        os.chdir(roots)
                        isPE(file, roots)
                except OSError:
                    pass
        finished()
    elif (int(ends) == 2): 
        print("Scanning from "+path+" for all files..")
        try:
            for roots, subdirs, files in os.walk(scanpath):
                for file in files:
                    try: #As above
                        #temppath = os.path.join(roots+ntpath.basename(file))
                        os.chdir(roots)
                        isPE(file, roots)
                    except OSError:
                        pass
        except StopIteration:
            pass
        finished()
    else:
        print("ERROR : ENTER VALID OPTION")
        scanforPE()

def isPE(file, rp): #Tests files against expected DOS/EXE header for typical PE binaries -ensures PE file before passing for information extraction (But doesn't actually right now)
    print("Testing... "+file)
    try:
        scanTmp(file, rp)
    except:
        return
        print("ERROR READING "+file)

   
def scanTmp(file, rp): #Scans input files from scanforPE/isPE (which does nothing for now), Gets value error if file for some reason is read wrong (permissions error, etc), passes to appropriate functions for extraction/comparisons
    global dumptmp
    global tmpread
    global skiplist
    global tmpfilestrings
    if (scansize == 0):
        maxSize()
    if (os.path.getsize(file) > (int(scansize)*1000000)):
        print(file+" excluded from scanning")
        skiplist.append(file)
        skiplist.append(os.path.getsize(file))
        return
    tmpfilestrings = []
    print("Dumping... "+file)
    name = file
    with open(file, 'rb') as tmp: #Could modify this to have it only read required bytes for signature...TODO
        tmpread = tmp.read() #Reads first 40000(CHANGED TO ALL) bytes of file, need to mess with exact value for performance vs accuracy for average signature offset (most are 0 and require much less of file to be read)
    dumptmp = binascii.hexlify(tmpread).upper()
    tst = dumptmp
    try:
        tst = type(bytes)
    except ValueError:
        print("ERROR READING "+file)
        return
    print(file+" Successfully dumped.")
    checkSig(dumptmp, name) #Check file signature
    extractStrings(tmpread) #Get Strings
    tmpfilestrings = tmplist #Store strings although I could probably skip this and go straight from extract to compare
    stringCompare(name, tmpfilestrings, dumpstrings) #Compare to bin/database

def scanDB(): #Scans/Imports database signature information
    print("Scanning signature database..") #MUST TEST
    tempdir = os.getcwd() #Saves CWD
    global dumpstrings
    dumpstrings = []
    os.chdir(os.path.dirname(path)) #Reverts to home folder
    with open(ntpath.basename(path)) as stringset:
        for newline in stringset:
            a = newline.split() #sigfile contains 3 values delimited via spaces, appended to siglist in triples
            dumpstrings.append(a) 

    os.chdir(tempdir) #Sets to last CWD before home
    print("Detected Strings Shown Below...")
    print("")
    print(str(dumpstrings))
    scanforPE()

def scanSample(): #Scans specified file and  first checks if PE - extracts info. depending on user choices
    global dumpbin #hex version of initial file binary dump
    global first #initial binary dump
    global dumpstrings #strings once extracted from extractStrings
    dumpstrings = [] 
    dirname = os.path.dirname(path) #Gets directory of binary
    os.chdir(dirname) #switch to it
    binname = ntpath.basename(path) #Get file name
    name = binname #passed to checkSig
    with open(binname, 'rb') as tmp: #Open binary sample and read entire thing
        first = tmp.read() #Read entire file
    dumpbin = binascii.hexlify(first).upper() #does binary -> Hex in uppercase
    #print(dumpbin)
    print("")
    print("Opening "+binname)
    print("")
    print("Dumping Binary -> Hex Conversion")
    print("")
    tst = dumpbin
    try: #Ensures file properly read
        tst = type(bytes)
    except ValueError:
        print("ERROR READING FILE")
        getPath2()
    print("Initializing Binary Sample Scan...")
    print("")
    checkSig(dumpbin,name) #checking signature by passing hex dump and file name
    os.chdir(dirname)
    #preExtract()
    extractStrings(first) #add input
    dumpstrings = tmplist
    scanforPE()

def printSigs(): #Prints File Header Signatures when called
    print("")
    print("")
    print("<--------------------STORED SIGNATURES, OFFSETS and DESCRIPTIONS-------------------->")
    print("")
    print("")
    i = len(siglist) #Gets length of siglist as filled by loadSigs
    x = 0
    while x < i:
        a = siglist[x]
        x = x + 1
        b = siglist[x]
        x = x + 1
        c = siglist[x]
        print(a+"   0x"+b+"   "+c)
        x = x + 1
    print("")
    print("<--------------------END OF SIGNATURE LIST-------------------->")     
    print("")

def loadSigs(): #fills sigfile with tuple values from filesignatures.txt (SIGNATURE OFFSET DESCRIPTION) NEED TO CHANGE THIS TO SIT WHEREVER
    tempdir = os.getcwd() #Saves CWD
    os.chdir(startdir) #Reverts to home folder
    global siglist
    siglist = []
    print("")
    print("Reading filesignatures.txt and storing learned file signatures...")
    print("")

    with open("filesignatures.txt") as sigfile:
        for newline in sigfile:
            a, b, c = newline.split() #sigfile contains 3 values delimited via spaces, appended to siglist in triples
            siglist.append(a) 
            siglist.append(b)
            siglist.append(c)
    os.chdir(tempdir) #Sets to last CWD before home


def checkSig(bin, name): #Loops through signatures stored in filesignatures.txt, No real application to this program but was fun to make
    global lena
    global lenb
    print("Checking Signature... "+name)
    i = len(siglist)
    x = 0
    bin = binascii.unhexlify(bin) #Putting Hex rep into binary data
    #print(bin)
    while x < i:
        a = siglist[x]
        test = siglist[x]
        a = hex(int(a, 16)) #Putting ASCII str from sigfile into base-16 int then Hex
        a = bytes(a, 'utf8').upper() #Then UTF8 byte object
        x = x + 1
        b = siglist[x]
        b = str(int(b,16)) #Getting offset as Hex
        x = x + 1
        c = siglist[x]
        x = x + 1
        lenb = len(b)
        tmpbinsig2 = hex(int(test, 16)).upper() #Putting signature into uppercase
        lensig = len(tmpbinsig2) - 2 #for removing 0x counting towards length for getting substring
        lenstr = str(lensig) #Getting length for slicing bin
        #print(tmpbinsig2)
        getSubstring(bin, lenb, lenstr) #Passes slice parameters for retrieving tmpbinsig for sig comparison from appropriate location
        tmpa = a[3:lensig] #Cuts off b'0x
        #print(a)
        if (tmpbinsig.find(tmpa) == 1):#checks if tmpa inside tmpbinsig
        #if (bin.find(a) == 1) and (int(loc) == int(b)): #At specific offset (OLD bad method I was using that was super slow, searched entire binary for signature...)
            #loc = bin.find(a)
            #if (int(loc) == int(b)):
            #loc = hex(loc)
            #a = str(a)
            a = a.decode("utf-8", errors="ignore")
            print("Signature "+a+ " DETECTED for : "+c+" At OFFSET "+b)
            return
            #else:
                #print("No Signature Detected for : "+c)
                #pass
        else: 
            pass
    print("ERROR: NO SIGNATURE DETECTED!")

def getSubstring(string, start, length): #Takes file and cuts out string from Hex according to signature in use for testing against known-sigs
    global tmpbinsig
    s = start 
    l = length
    #print(s)
    #print(l)
    s = int(s) - 1 #Because strings indexed from 0 and len of offset will return 1 at 0
    #print(s)
    l = int(l) + 1
    tmpbinsig  = string[s:l]
    tmpbinsig = binascii.hexlify(tmpbinsig).upper()

def preExtract(): #Run before actual string extraction once, sets minimum string length to pull, ensures validity, prepares regular expression for string matching
    global minstring
    global stringexp
    global stringpat
    minstring = input("Please enter minimum string length for detection : ")
    print("")
    testmin = minstring
    try:
        testmin = int(testmin)
    except ValueError:
        print("ERROR : INTEGER REQUIRED")
        preExtract()
    minstring = int(minstring)
    stringexp = '[%s]{%d,}' % (printthese, minstring) #[] gives character set, {} sets min. repeat of previous RE for return of characters
    stringpat = re.compile(stringexp) #prepares string pattern for use in checking UTF-8 dumps
    return

def extractStrings(file): #This will extract all pre-specified reg-expressions above a specified length from file
    global tmpstrings
    global tmplist
    tmplist = []
    file = file.decode("utf-8", errors="ignore") #Ignore errors in attempts to decode byte stream to UTF-8, because there are many
    #print(file)
    tmpstrings = (stringpat.findall(file))
    lentemp = len(tmpstrings)
    x = 0
    #tmplist.append(lentemp) #Appending count of total strings pulled from temporary file to index(0) of list
    while x < lentemp:
        tmplist.append(tmpstrings[x])
        #print(tmpstrings[x]) #Testing 
        x = x + 1
    return

def stringCompare(fname, a, b): #Where A is list of strings dumped from temp. file and B is list of strings dumped from sample binary or signature file
    global percmatch
    global matchlist
    global stringmatches
    global allstringmatches
    stringmatches = []
    print("Comparing Extracted Strings...")
    lensa = len(a) #Legnth of source temporary file from recursive search
    lensb = len(b) #length of binary dump, used for % match against strings in a
    #print(lensa)
    #print(lensb)
    x = 0
    y = 0
    listtmp = []
    count = 0
    #print("Test1")
    #while x < lensb: #iterates through all strings from binary dump
    for x in range(0, lensb):
        #print("Test2")
        p = b[x] #Element from binary or database dump, passed to function as b
        #print("Test3")
        #while y < lensa: #iterates through all strings in temp file
        for y in range(0, lensa):
            #print("Test4")
            q = a[y] #Element from array holding temporary file strings
            #y = y + 1
            #if (p == q): #Original
            #print(p) #Testing
            #print(q) #Testing
            
            if (str(q) in str(p)) and (str(q) not in listtmp): #Switched to this because List comparison is weird and I didn't want to slice characters from start/end again
                listtmp.append(str(q))
                count = count + 1
                stringmatches.append(str(q)) #
            else:
                pass
        #x = x + 1
    percmatch = (count/lensb)*100 #Gets percentage as 'strings from b in a'/'strings in b' to determine related strings
    percmatch = round(percmatch, 3) #Rounds float to thousandth 
    if percmatch != 0:
        matchlist.append(fname)
        matchlist.append(percmatch)
        allstringmatches.append(stringmatches)
    print(str(percmatch)+"% estimated string match with source binary or database, matching strings listed below.")
    print(stringmatches)
    print("")
    return

def finished(): #Runs once all other functions complete, writes matchlist, skiplist, prints files which had non-0 % match
    global matchlist
    global time2
    os.chdir(scanpath) #Switch to base scan path for file writing
    time2 = time.strftime("%H-%M(%m-%d-%Y)")
    matchtime = time2+".txt"
    skiptime = time2+".txt"
    print("<----------LIST OF DETECTED STRING PERCENTAGES---------->")
    x = 0
    i = len(matchlist)
    name = str(time2)
    if (i == 0):
        print("")
        print("No string matches found in scanned files...")
        print("")
    else:
        c = 0
        while x < i: #Iterates to print list of non-0 string-matches as given in stringCompare
            #as1 = allstringmatches[x]
            a = matchlist[x]
            x = x + 1
            b = matchlist[x]
            x = x + 1
            print(str(a)+" : "+str(b)+"% estimated match with following strings "+str(allstringmatches[c])) #prints filenames, percentage match detected
            c = c + 1
    if  (i == 0):
        pass
    else:
        try:
            file = open("Match-List for "+matchtime, "w") 
            c = 0
            x = 0
            #print(i)
            #print(x)
            if (i > 0):
                while x < i:
                    #as1 = allstringmatches[x]
                    a = matchlist[x] #iterating through hash/name lists simultaneously
                    x = x + 1
                    b = matchlist[x]
                    x = x + 1
                    #tmplist = []
                    #tmplist = allstringmatches[c]
                    file.write(str(a)+" "+str(b)+"%,  "+str(allstringmatches[c])+"\n") #Comma-delimited output, can change
                    c = c + 1
                file.close()
                print("Match List Successfully written to Match-List for "+matchtime)
        except:
            print("ERROR WRITING MATCH LIST")
            pass
    try:
        file = open("Skip-List for "+skiptime, "w") 
        i = len(skiplist) #Getting length of list
        x = 0
        if (i > 0):
            while x < i:
                a = skiplist[x] #iterating through hash/name lists simultaneously
                x = x + 1
                b = (skiplist[x]/1000000)
                x = x + 1
                file.write(str(a)+" "+str(b)+" MB""\n") #Comma-delimited output, can change
            file.close()
    except OSError:
        print("ERROR WRITING SKIP-LIST")
        pass
    print("Skip List Successfully written to Skip-List for "+skiptime)
    print("Program operations complete...")
    tmp = input("Would you like to restart?")
    
start() #Starts code initialization

