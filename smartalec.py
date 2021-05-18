import textwrap
import frida
import os
import sys
import frida.core
import argparse
import logging
import datetime
import json
import fnmatch

logo = """
  __  __ __   __   ___  _____    __   _    ___  ___ 
/' _/|  V  | /  \ | _ \|_   _|  /  \ | |  | __|/ _/ 
`._`.| \_/ || /\ || v /  | |   | /\ || |_ | _|| \__ 
|___/|_| |_||_||_||_|_\  |_|   |_||_||___||___|\__/   
    
            𝕋𝕖𝕝𝕝𝕤 𝕪𝕠𝕦 𝕨𝕙𝕒𝕥 𝕘𝕠𝕥 𝕝𝕠𝕒𝕕𝕖𝕕!

        (っ◔◡◔)っ ♥ Made by !nfinite Hacks ♥
        """

# Main Menu
def MENU():
    parser = argparse.ArgumentParser(
        prog='smartalec',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("Welcome to Smart Alec. \nSome exemplary usage includes:\nTo capture the complete state of the device, run : python3.7 SmartAlec.py -cap all -name session1\nTo compare the state captured between session1 and session2, use: python3.7 SmartAlec.py -cmp session1:session2\nTo dump a particular module from a particular process, use: python3.7 SmartAlec.py -d\n")
)

    parser.add_argument('-capture', type=str, metavar="capture",
                        help='def: \'all\' or def: \'com.sample.package.name\'')
    parser.add_argument('-compare', type=str, metavar="compare",
                        help='def: \'oldDirPath:newDirPath\'')
    parser.add_argument('-name', type=str, metavar="name",
                        help= 'name of capture session. (def: \'base\')')
    parser.add_argument('-dump', action='store_true',
                        help="Dump")
    parser.add_argument('-verbose', action='store_true',
                        help='verbose')
    parser.add_argument('-read-only', action='store_true',
                        help="dump read-only parts of memory")
    parser.add_argument('-read-executable', action='store_true',
                        help="dump read-executable parts of memory")
    parser.add_argument('-max-size', type=int, metavar="bytes",
                        help='maximum size of dump file in bytes (def: 20971520)')
    args = parser.parse_args()
    return args


print(logo)
#print("Welcome to Smart Alec. \n Some exemplary usage includes:\n To capture the complete state of the device, run : python3.7 SmartAlec.py -cap all -name session1\nTo compare the state captured between session1 and session2, use: python3.7 SmartAlec.py -cmp session1:session2\nTo dump a particular module from a particular process, use: python3.7 SmartAlec.py -d\n")

arguments = MENU()

# ***** Setting up Configurations ******
CAPTURE = arguments.capture
global DIRECTORY
DEBUG_LEVEL = logging.INFO
MAX_SIZE = 20971520
PERMS = 'r-x'

if arguments.read_only:
    PERMS = 'r--'

if arguments.read_executable:
    PERMS = 'r-x'

#TODO: Implement logging.
if arguments.verbose:
    DEBUG_LEVEL = logging.DEBUG
logging.basicConfig(format='%(levelname)s:%(message)s', level=DEBUG_LEVEL)


# ******* Setting up a session ***********
def setupSession():
    if arguments.name is not None:
        DIRECTORY = arguments.name
        if os.path.isdir(DIRECTORY):
            print("Directory already exist! Pls pick a different name " + DIRECTORY)
            sys.exit(1)
        else:
            os.mkdir(DIRECTORY)
            print("Output directory setup!")
    else:
        print("Current Directory: " + str(os.getcwd()))
        DIRECTORY = os.path.join(os.getcwd(), str(datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')))
        print("Output directory is set to: " + str(DIRECTORY))
        if not os.path.exists(DIRECTORY):
            print("Creating directory...")
            os.mkdir(DIRECTORY)
    return DIRECTORY

#********** Defining some utility functions ************
#TODO: Separate into Utility Class

# Method to receive messages from Javascript API calls
def on_message(message, data):
   print("[on_message] message:", message, "data:", data)

def getAllProcesses():
    cmd = 'frida-ps -U > ' + os.path.join(DIRECTORY, 'processes.txt')
    os.system(cmd)

def getProcessList():
    processes = set()
    with open(os.path.join(DIRECTORY, 'processes.txt'), 'r') as processfile:
        lines = processfile.readlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            words = line.split(" ")
            if (len(words) < 3 or words[0] == "PID" or "---" in words[0]):
                continue
            processes.add(words[2])
    return processes

#Return 0= Not equal at all, 1 = Equal, 2 = Modified
def isEqualEnumModuleJson(mod1json, mod2json):
    if (len(mod1json.keys()) != len(mod2json.keys())):
        return 0
    
    if("base" in mod1json.keys()):
        if ("base" not in mod2json.keys()):
            return 0
        
        #if (mod1json["base"] != mod2json["base"]):
        #    return 0

    if("file" in mod1json.keys()):
        if ("file" not in mod2json.keys()):
            return 0
        
        if (mod1json["file"]["path"] != mod2json["file"]["path"]):
            return 0
        
        #file path is same but protection or size changed! TODO: Add catch for cases when key doesn't exist (not likely)
        if (mod1json["file"] != mod2json["file"] or mod1json["size"] != mod2json["size"] or mod1json["protection"] != mod2json["protection"]):
            return 2
    return 1

#******** Capture the "state" of the device. state implies all the loaded modules in process(es) of interest.
#TODO: Only "all" supported currently, it can be extended to support a particular process as well.
if (CAPTURE == "all"):
    DIRECTORY = setupSession()
    getAllProcesses()
    processes = getProcessList()
    device = frida.get_usb_device()
    modulesDirPath = os.path.join(DIRECTORY, "modules")
    print(modulesDirPath)
    os.mkdir(modulesDirPath)
    global session
    global script
    for process in processes:
        try:
            session = device.attach(process)
            script = session.create_script(
                """'use strict';
                rpc.exports = {
                    enumerateRanges: function (prot) {
                        return Process.enumerateRangesSync(prot);
                    }
                };""")
            
            script.on("message", on_message)
            script.load()
            agent = script.exports
            ranges = agent.enumerate_ranges(PERMS)
            f = open(os.path.join(modulesDirPath, process+ ".txt"), "w")
            f.write(json.dumps(ranges))
            f.close()
            print("Enumerated modules in " + process)
            script.unload()
        except Exception as e:
            print("Skipped " + process)
            f = open(os.path.join(DIRECTORY, "skipped"+ ".txt"), "a+")
            f.write(str(process)+ ": Error " + str(e) + "\n")
            f.close()
        
    session.detach()


#******** Used to compare and dump json diff two captured states and generates an analysis file *********
def dumpTheJsonDiff(oldModulesEnum, newModulesEnum, analysisFile):
    deleted = []
    appeared = []
    modified = {}

    for e in oldModulesEnum:
        #only comparing modules with loaded file path, todo:change this behaviour
        if ("file" in e.keys()):
            found = False
            for f in newModulesEnum:
                cmpRes = isEqualEnumModuleJson(e, f)
                if cmpRes > 0 :
                    if cmpRes == 2:
                        modified[json.dumps(e)] = json.dumps(f)
                    newModulesEnum.remove(f)
                    found = True
                    break

            if not found:
                deleted.append(e)  
    

    print("Modules Deleted: " + str(len(deleted)) + "\n******************************")
    analysisFile.write("Modules Deleted: " + str(len(deleted)) + "\n******************************\n")

    for mod in deleted:
        print(json.dumps(mod)+"\n\n")
        analysisFile.write(json.dumps(mod)+"\n\n")

    print("Modules Modified: " + str(len(modified)) + "\n******************************")
    analysisFile.write("Modules Modified: " + str(len(modified)) + "\n******************************\n")


    for mod in modified.keys():
        keymod = json.loads(mod)
        valuemod = json.loads(modified[mod])
        print("Module File: " + keymod["file"]["path"] + " \n")
        print(keymod["file"]["path"] + " \n")
        print("Size: " + str(keymod["size"]) + " => " + str(valuemod["size"]) + "\n")
        print("Protection: " + keymod["protection"] + " => " + valuemod["protection"] + "\n")
        print("File Size : " + str(keymod["file"]["size"]) + " => " + str(valuemod["file"]["size"]) + "\n")
        print("File Offset : " + str(keymod["file"]["offset"]) + " => " + str(valuemod["file"]["offset"]) + "\n")

        analysisFile.write("Module File: " + keymod["file"]["path"] + " \n")
        analysisFile.write(keymod["file"]["path"] + " \n")
        analysisFile.write("Size: " + str(keymod["size"]) + " => " + str(valuemod["size"]) + "\n")
        analysisFile.write("Protection: " + keymod["protection"] + " => " + valuemod["protection"] + "\n")
        analysisFile.write("File Size : " + str(keymod["file"]["size"]) + " => " + str(valuemod["file"]["size"]) + "\n")
        analysisFile.write("File Offset : " + str(keymod["file"]["offset"]) + " => " + str(valuemod["file"]["offset"]) + "\n")


    for mod in newModulesEnum:
        if ("file" in mod.keys()):
            appeared.append(mod)

    print("Modules Appeared: " + str(len(appeared)) + "\n******************************")
    analysisFile.write("Modules Appeared: " + str(len(appeared)) + "\n******************************\n")
    
    for mod in appeared:
        if "path" in mod["file"].keys():
            if "/data/" in mod["file"]["path"]:
                print("$$$$ Attention! Looks like it loaded from data partition $$$$$\n")
                analysisFile.write("$$$$ Attention! Looks like it loaded from data partition $$$$\n")
        
        print(json.dumps(mod)+"\n\n")
        analysisFile.write(json.dumps(mod)+"\n\n")

    print("\n******************************\n")
    analysisFile.write("\n******************************\n")

#******** Used to compare two captured states and generates an analysis file *********
if arguments.compare is not None:
    dirs = arguments.compare.split(":")
    if len(dirs) != 2:
        print("Pls enter the directories to compare in this format, smartalec.py -cmp oldDirPath:newDirPath")
        sys.exit(1)
    oldDir = arguments.compare.split(":")[0]
    newDir = arguments.compare.split(":")[1]

    oldProcesses = set()
    newProcesses = set()

    oldDirModulePath = os.path.join(oldDir, "modules")
    newDirModulePath = os.path.join(newDir, "modules")
    if not os.path.exists(oldDirModulePath) or not os.path.exists(newDirModulePath):
        print('Input directories do not exist or modules dir inside them does not exist, pls enter correct input.')
        sys.exit(1)
    
    listOfFiles = os.listdir(oldDirModulePath)
    pattern = "*.txt"
    for entry in listOfFiles:
        if fnmatch.fnmatch(entry, pattern):
            oldProcesses.add(entry)

    listOfFiles = os.listdir(newDirModulePath)
    pattern = "*.txt"
    for entry in listOfFiles:
        if fnmatch.fnmatch(entry, pattern):
            newProcesses.add(entry)
    
    f = open(os.path.basename(oldDir) + "_" + os.path.basename(newDir) + "_analysis.txt", "a+")

    if not len(oldProcesses) == len(newProcesses):
        print("No of processes running has changed\n\n")
        f.write("No of processes running has changed\n\n")
    
    #Finding processes killed
    print("Processes killed: ")
    f.write("Processes killed: \n")
    killed = False;

    for p in oldProcesses:
        if (p in newProcesses):
            newProcesses.remove(p)
        else:
            print(p)
            f.write(p+"\n")
            killed = True

    if not killed:
        print("No processes killed!\n\n")
        f.write("No processes killed!\n\n")       

    #Finding processes spawned
    print("Processes Spawned: ")
    f.write("Processes Spawned: \n\n")
    spawned = False;

    for p in newProcesses:
        print(p)
        f.write(p+"\n")
        spawned = True

    if not spawned:
        print("No processes spawned!\n\n")
        f.write("No processes spawned!\n\n")       

    #Finding processes modified
    print("Processes Modified: ")
    f.write("Processes Modified: \n")
    for p in oldProcesses:
        newProcessModulesPath = os.path.join(newDirModulePath, p)
        if not os.path.exists(newProcessModulesPath):
            print("Process not found in new setup")
            continue

        with open(os.path.join(oldDirModulePath, p), 'r') as oldProcessMods:
            oldModulesEnum = json.loads(oldProcessMods.read().replace("\'", "\""))

        with open(newProcessModulesPath, 'r') as newProcessMods:
            newModulesEnum = json.loads(newProcessMods.read().replace("\'", "\""))

        if not oldModulesEnum == newModulesEnum:
            print("something changed! Look out for process: " + p + "\nIf no modules are shown below, it's likely the base addresses, not major, refer the dumped files for more details.\n\n")
            f.write("something changed! Look out for process: " + p + "\nIf no modules are shown below, it's likely the base addresses, not major, refer the dumped files for more details.\n\n")
            dumpTheJsonDiff(oldModulesEnum, newModulesEnum, f)
        

#Dump file
def dump_to_file(agent, base, size, pname, path):
    try:
        filename = pname
        dump =  agent.read_memory(base, size)
        f = open(os.path.join(path,filename), 'wb')
        f.write(dump)
        f.close()
        print(filename + " dumped successfully!\n")
    except Exception as e:
        print("[!]"+str(e))
        print("Oops, memory access violation!")

if arguments.dump :
    process = input('Process: ')
    module = input('Module: ')
    #base = input('Base Address: ')
    #offset = input('Offset: ')
    #size = int(input('Size: '))
    outputDirPath = input('Output Directory Path: ')

    device = frida.get_usb_device()

    try:
        session = device.attach(process)
        script = session.create_script(
            """'use strict';

            rpc.exports = {
            enumerateModules: function () {
                return Process.enumerateModulesSync();
            },
            readMemory: function (address, size) {
                return Memory.readByteArray(ptr(address), size);
            }
            };
            """)
        script.on("message", on_message)
        script.load()
        agent = script.exports
        enumModulesJsonString = json.dumps(agent.enumerate_modules())
        enumModulesJson = json.loads(enumModulesJsonString)
        
        global base
        global size
        found = False
        for mod in enumModulesJson:
            if mod["name"] == module:
                if "base" in mod.keys():
                    base = mod["base"]
                else:
                    continue
                if "size" in mod.keys():
                    size = int(mod["size"])
                else:
                    continue
                found = True
        
        if not found:
            print ("Module name/properties not found, pls recheck the input value.")
            sys.exit(1)

        dump_to_file(agent, base, size, process + "_" + module, outputDirPath)
        script.unload()
        session.detach()
    
    except Exception as e:
        print("Exception: " + str(e))


print("Thanks for using Smart Alec!")