import os
import subprocess
from pprint import pprint
import random
import uuid
import time
import pandas as pd
import numpy as np
import pickle
import string
import mutatemethods as MnM


def getRandomString(length):
    # choose from all lowercase letter
    letters = string.printable
    result_str = "".join(random.choice(letters) for i in range(length))
    # print("Random string of length", length, "is:", result_str)
    return result_str


class Runner:
    mostRecentHash: str = None
    hashList = []
    currPathCov: float = 0.0
    seedQCov = {}
    seedQDict = {}
    pathQDict = {}
    pathFrequency = {}
    failedPathHashLs = []
    successPathHashLs = []
    crashPathHashLs = []
    seedFile: str = "./python/seed.txt"
    projectTestingDir = None
    coverageFile: str = "crypt_test.c.gcov"

    ##hide
    crashExitCode:dict = None

    def __init__(self, pwd: str):
        self.projectTestingDir = pwd

    def getAesInputs(self, folder: str) -> bool:
        import glob

        os.chdir(self.projectTestingDir)
        os.chdir("./python/results")
        files = glob.glob("**/*.txt")
        for f in files:
            os.remove(f)
        os.chdir(self.projectTestingDir)
        fileList = os.listdir(folder)
        os.chdir(folder)
        # print(fileList)
        # populate the
        for filename in fileList:
            os.chdir(self.projectTestingDir)
            os.chdir(folder)
            print()
            print("----------------------")
            print(filename)
            with open(filename, "r") as file:
                lines = file.read()
                # print(lines)
                endplain = "\nendplain\n"
                plain = key = key2 = iv = iv2 = algo = ""
                plain = lines[: lines.index(endplain)]
                # print(plain)
                lines = lines[lines.index(endplain) + len(endplain) :]
                algo, key, key2, iv, iv2 = lines.split("\n")
                # print(iv2)
                inputDict = {
                    "key": key,
                    "key2": key2,
                    "iv": iv,
                    "iv2": iv2,
                    "algo": algo,
                    "plain": plain,
                }
                self.runTest(inputDict)
            # except Exception as e:
            #     print(e)
            #     return False
        return True

    def createSeedFile(
        self, key: str, key2: str, IV: str, IV2: str, algo: str, plain: str
    ) -> str:
        os.chdir(self.projectTestingDir)
        fileStr = ""
        fileStr += plain + "\nendplain\n"
        fileStr += algo + "\n"
        fileStr += key + "\n"
        fileStr += key2 + "\n"
        fileStr += IV + "\n"
        fileStr += IV2
        with open(self.seedFile, "w") as f:
            f.write(fileStr)
        return self.seedFile

    def isCrash(self, path: dict) -> bool:
        return path[375] == 0

    def crashNoPathCov(self, exitCode: int) -> dict:
        # we create a path where 375 is 0 this is the main method return success line
        # we also add the value of its exitCode. so a unique crash is based on its exiCode
        return {375: 0, "exit": exitCode}

    def runScriptUbuntu(self) -> int:
        # 0 no crash, path generated
        # -1 crash, no path generated
        # 1 crash, with path generated
        # 2 some execution failure not related to test script
        # we need to compile and then execute binary to be able to run coverage.
        # print()
        self.crashExitCode = None
        try:
            os.chdir(self.projectTestingDir)
        except Exception as e:
            print(e)
            print("unable to change pwd")
            return 2
        compileStr = "gcc --coverage crypt_test.c -o crypt_test -lmbedcrypto -lmbedtls"
        if os.system(compileStr) != 0:
            print("did not compile")
            return 2
        runTest = ["./crypt_test", self.seedFile]
        exitCode = subprocess.run(runTest, stdout=subprocess.DEVNULL).returncode
        print("Binary Execution Exit code: " + str(exitCode))
        if exitCode > 1 or exitCode < 0:
            print("runtime Program crash no path generated")
            self.crashExitCode = exitCode
            return -1       
        import re
        coverage = ["gcov", "crypt_test.c", "-m"]
        p = subprocess.run(coverage, stdout=subprocess.PIPE)
        currPathCov = p.stdout.decode()
        regpattern = r"(?<=Lines executed:)(.*)(?=%)"
        self.currPathCov = float(re.search(regpattern, currPathCov).group(0))
        if p.returncode != 0:
            self.currPathCov = p.stdout.decode()
            print("coverage gcov failed")
            return 2
        deletenotes = "rm -rf crypt_test.gc*"
        os.system(deletenotes)
        # print("completed one cycle")
        return exitCode

    def getPathCovFile(self, input: dict) -> int:
        # run the test and return
        key = input["key"]
        key2 = input["key2"]
        iv = input["iv"]
        iv2 = input["iv2"]
        algo = input["algo"]
        plain = input["plain"]
        self.createSeedFile(key, key2, iv, iv2, algo, plain)
        # print("seed file path")
        # print(seedFilePath)
        exitStatus = self.runScriptUbuntu()
        return exitStatus

    def parseFile(self, filename: str) -> dict:
        with open(filename, "r") as file:
            lines_dict = {}
            for line in file:
                columns = line.split()
                # print(columns[0])
                # Get the first column for the dictionary value (how many counts the line has been executed)
                first_column = columns[0].split(":")[0]
                key = columns[1].split(":")[0]
                # print("first columns "+first_column)
                # print(key)

                # Check if the count is -, since - means it is not executable so we don't need it
                if first_column[0] == "-":
                    continue

                # Able to be executed but have not been executed, might be an interesting path
                if first_column.startswith("#####"):
                    # Set the value of the line to 0 in lines_dict
                    lines_dict[key] = 0
                else:
                    # Add into lines dict
                    lines_dict[key] = int(first_column)

            # Print out the dictionary
            # for key, value in lines_dict.items():
            #    print(key +" "+ value)

            return lines_dict

    def isInteresting(self, lines_dict1: dict, lines_dict2: dict) -> bool:
        # the is interesting returns true if the two provided paths are different
        keys1 = list(lines_dict1.keys())
        keys2 = list(lines_dict2.keys())
        if keys1 != keys2:
            return True
        targetMatches = len(
            keys1
        )  # we want all lines to match if it is not interesting
        numMatches = 0
        i = 0

        while i < len(keys1):
            # print("i "+str(i))

            key1 = keys1[i]
            key2 = keys2[i]

            if key1 == key2 and lines_dict1[key1] == lines_dict2[key2]:
                # print("Line '{}' has the same execution count in both files.".format(key1))
                numMatches += 1
                i += 1
            else:
                i += 1

        return numMatches != targetMatches

    def isInterestingOuter(self, newpath: dict) -> bool:
        if len(self.hashList) == 0:
            return True
        for oldpathId in self.hashList:
            oldpath = self.pathQDict[oldpathId]
            if self.isInteresting(oldpath, newpath) == False:
                self.pathFrequency[oldpathId] += 1
                return False
        return True

    def runTest(self, inputDict) -> int:
        # exit codes
        # 0 is intersting not fail
        # 1 is interesting and fail or crash
        # -1 is not interesting
        exitCodeRunTest:int = -1 # this variable is what we want to return at the end of the method
        exitCode: int = self.getPathCovFile(inputDict)
        isfail = False
        isCrash = False
        if exitCode == 2:
            print("gcc compiling issue or gcov execution issue")
            return exit()
        elif exitCode == -1:
            print("crash")
            isCrash = True
        elif exitCode == 1:
            print("failure")
            isfail = True
        elif exitCode == 0:
            print("success")
            isfail = False
        else:
            print("unknown exitcode crash")

        # if crash
        if (isCrash):
            path: dict = self.crashNoPathCov(self.crashExitCode)    
        else:
            covFilePath = self.coverageFile
            path: dict = self.parseFile(covFilePath)
        # print(path)
        interesting: bool = self.isInterestingOuter(path)
        if interesting:
            ids = str(uuid.uuid4())
            self.seedQDict[ids] = inputDict
            self.pathQDict[ids] = path
            self.hashList.append(ids)
            self.pathFrequency[ids] = 1
            self.mostRecentHash = ids
            self.seedQCov[ids] = self.currPathCov  
            # print("interesting path found")
            print(self.seedQCov)
            if isfail:
                print("path is a failing path")
                self.failedPathHashLs.append(ids)
                exitCodeRunTest = 1
            elif isCrash:
                self.crashPathHashLs.append(ids)
                exitCodeRunTest = 1                
            else:
                print("path is a successful path")
                exitCodeRunTest = 0
            self.writeDiskSeedQ(isfail, isCrash, ids)
        # print("path is not unique")
        return exitCodeRunTest

    def getSeed(self) -> int:
        # get random seed
        hashind = random.randint(0, len(self.hashList) - 1)
        return self.hashList[hashind]

    def writeDiskSeedQ(self, isFail: bool, isCrash: bool, ids: str) -> bool:
        # this writes the seed txt file to the results folder
        import glob
        import json

        os.chdir(self.projectTestingDir)
        mainfolder = "./python/results"
        os.chdir(mainfolder)
        if isFail == False and isCrash == False:
            filename = "./successQ/" + str(ids) + "_path.txt"
            seedString = json.dumps(self.seedQDict[ids])
            # print(seedString)
            with open(filename, "w") as f:
                f.write(seedString)
        if isFail == True and isCrash == False:
            filename = "./failQ/" + str(ids) + "_path.txt"
            seedString = json.dumps(self.seedQDict[ids])
            # print(seedString)
            with open(filename, "w") as f:
                f.write(seedString)
        if isFail == False and isCrash == True:
            filename = "./crashQ/" + str(ids) + "_path.txt"
            seedString = json.dumps(self.seedQDict[ids])
            # print(seedString)
            with open(filename, "w") as f:
                f.write(seedString)
        files = glob.glob("**/*.txt")
        # print(files)
        return


class Fuzzer:
    alpha_i = 2
    alpha_max = 150000
    pwd: str = None
    runner: Runner
    seedFreq: dict = (
        {}
    )  # number of times a seed has been selected in mainLoop for fuzzing
    currSeed: dict = None  # this is the dict containing all seed arguments
    mutationLs: list = [
        "replaceChar",
        "insertWhite",
        "algo",
        "delChar",
        "insertChar",
        "flipRandChar",
        "incrChar",
        "decrChar",
        "pollute",
    ]
    defaultEpochs: int = None
    iterCount: int = 0
    timelineYFails: list = []
    timelineYSuccess: list = []
    timelineYCrashes: list = []
    timelineYPaths: list = []
    timelineYIterations: list = []
    timelineX: list = []
    timelineMutatorSel = {
        "replaceChar": 0,
        "insertWhite": 0,
        "algo": 0,
        "delChar": 0,
        "insertChar": 0,
        "flipRandChar": 0,
        "incrChar": 0,
        "decrChar": 0,
        "pollute": 0,
        "total": 0,
    }
    crashinput = {'key': '\x08¢\x08`\x082L [\x0f\x1f  ¡   (()\x0bónN\x02\x03\x03    -    ;ó~~~#-\x8a\x83"äää333\xa06«xV \x1e \x13\x0f   \x86kr\x05\x06\x0622T\x86CCCU& Z `\x15\x15\x15\x8aj  c%6åÅå   )))\x17\x169<m$mÿ`A==  ! R\x1e!>\x0b0q m\x1dKL\x00LE\x89s\x7f\x7f\x7f ÔÔÔ4 ((!  Û;\r\x7f Z!\\Ó!!\x0b\x0b\x0c\x0b../.\x0f\x0f\x0f\x0f\x99 j²}ll\x91ë\'£\x00!\x7f \x83 \x01!!!jvA  ©\t)AA  \x99\x7f"""!=\x81"¤k\x84_wS    \x90\x1d\x1d\x1d\x81  øøQ! \x07Î\x87  \x84ssQ. .~   çh:ÑÑÑ\x0f  !\r_ð \x83\x83\x83\x83\x83  g½½!  %  \x01 \x1f   k kk --\\\\]', 'key2': '^\x1ey\x1e\x13cabhRt\x98>\x9e \x91\x91 .\x12G(G1\x9bf# 2\x89\x8a\x88 \x056 9" (\x1a\x0b \x1f"p8\x9d\x9d\x9d\x1f]! /»gh glÃ\x04g z\x1cfF3\x0e\x0e§§9Y\x18O\x1f  \x01 !\x14g?\x88\x0b%\x1f %8êêêêêttt r#Êuv  !\x13 YW5DD+D //Û/ 3 "aS\x1f#^VRRR!EÖ×ÔÔÀ!!6¢MºT\x9aí>ÝÝÝé(ìê@]\x1fNf\x1e\x1f¾b[\'H\'h êz)!!¿@ \\ äZ¦{«zs\x0b1 !¤Ûßr  . "k®h qo  t\x1e1 \x9c+ ììì#( :$p1\n0   }\tIH]!|||nnnBAfA\x14\x15\x15ÛÚ :Û()^^   \x1f7éJnò±V ñòó!,I&%ãââ\x1f\x1f" \x1f\x1f < Hölllìé ºs\x7f+cúú}}l@ fg+zH  3   Ø\x1d]!Ç 6   !$ Í$$', 'iv': '2 í  Z# \x00(#Y \'Y(`%))9)+IANäW8põ ok *` 5(¦ÃP\x049ð ¨   \x1f\x1f\x1f¥{?\x7f? ? -y\x1fppoEè èzzccc0 1006 ©©¹:"\x8d" \x1f  ---UU!! · > w_¼»uU¤  \x8d   !E\\\\\\5tEª,ÅÅÅ\x9bc#  #\x1f3\x0c!% #\x00  0 3be´  ¦ ¦v pwoGS \x06m\x1f\x1c\x1c\x1c\x9e\r\'\xad¬\xady!!!! ; \x1d\x86\x85\x0b\x0b2\x1f r«rr; @@@\x8c\x8c¡íî¶s!apÊ//\'/a6)*"     \x1f 4!¡¡¡j\tj99\t÷\x10aR\x1e\r/\t %o\x1d!  !5ðõ x ¬§Ää\x1fãp!# "\x7f@óK\x1b\x1c\x1a\t,,,,,\x1d( J  ª ªº`!@\x86ommm#"""fff $0`N \x1f.\x1fHH~~G\x1f\x1f\x1f', 'iv2': '®®\xad !\x1f""\x1f- \'#\x04$\x8a\x1f$\x86|\x07d\x17$ M\x9a\x1f\\Å\x1f\x1f  µ   T T\x1e=.\x8a!ì%%%\xa0\xa0\xa0\xa0$& \x89   ¼\r\n\\z\xad\x9c op+0.\x0c0\x11ÚÛ$ÛK`     ·mP l\x0bª\\\\\\\x1f\x1f\x1f   \x93 g!\x1b%kÁÁ\\\x1c\\\\!t"    \x0b\x912 6.mù\x1f\x1f\x1f |||\x17mAOOx1 6?6\x1700 0!0`ae vE - z\x0b  ^\x1féò òÌòó!\x01!  \x1eHB\x10l{{S\x92&PQT^^N_\x0e  \x814 \x1f\x1fö(^L "q 0    Q ^Q^¥¥xy 9L!\x8a \x9at PÍ  |}T~}¬ L¶    \r¦cab!LL6T Á!\x0b$$\x1euax`8\x01\x01\x11   P   !p2****\t\t*', 'algo': 'CFB128', 'plain': '\x9f\x9f\x9f\x0ed # N\x85~øü\x0fü5G\x1fOÓ\x998 4\x9f  b cb \x0c \t\x01\x02\x010!!\x06!!!"\x1f\x1f þ·ý àÆ\x0eWÍ°RE*$ \x1f\x02_e£c\x07  HHH0?!@!` \\  ÿÿ321j©\x1f2999\x9bL2 UkÆÎÞ!"! ~Avvv \x1f!\x1f     \x1fS\x1f{\x12F 9>nnn~!,\x7f! WUV\x1f"m)  a \x1c \x1e"# I\x02V!(^]<_ÖØ !\x17\x19E 4òYYY\x1b \x1f-&&   \x1e@i\x1c~    $o  ¡¡8xxx\x1f¯d\x02\x02\x01\x8e\x7f}\\Y!Ü\x1f G \x1d  @ \x99ýý\t\x0f.ðððõy[(%$\x1f\x1f\x1f\x1f\x0e\x0e\x1f  4 \x9b1`¥A¶¶\x96\x94!\x1f!D (\x02~~\x1e\x1f> ]  \x839 =xD}!4 WÏ h\x0c\x0c\x0cv fÌ,\x90Â\x0b}~weJJKô-11wB ÐÏÏ\x83\x85\x85\x85Ck!\x85!\x96)%\x93\x94  y !!  h \x1f  (((qqq\x1e\x0e !e~? .\x1f y>g\x90\x90°x\x17XXX\x80\r\x80ã CUXXX(Ò6+ààà$e=3q (n( L KKS7N¨?^!pppss '}

    def __init__(
        self, pwd: str, seedFolder: str, defaultEpochs: int = 20, runGetAesInput=True
    ) -> None:
        self.pwd = pwd
        self.defaultEpochs = defaultEpochs
        if runGetAesInput == True:
            self.runner = Runner(pwd)
            self.runner.getAesInputs(seedFolder)
            print("Completed initialised of prepared inputs")
        else:
            self.runner = Runner(pwd)
            print(
                "runnr object attribute is set to None, please use loadRunner() to load a serialised runner object instance"
                "any losses in results folder may be retrieved from runner dump"
            )

    def arg2Fuzz(self, input: dict) -> str:
        # at random select variable and return key
        # we do not return algo, as it uses its own mutation method.
        keylist = list(input.keys())
        keylist.remove("algo")
        key = random.choice(keylist)
        print("chosen " + key)
        return key

    def delChar(self, input: dict) -> dict:
        mutated_dict = input.copy()
        key = self.arg2Fuzz(mutated_dict)

        if isinstance(mutated_dict[key], str):
            fuzzed = MnM.delete_character(mutated_dict[key])
            mutated_dict[key] = fuzzed
            print("delChar")
            print("old dict 1" + str(input))
            print("new dict 1" + str(mutated_dict))
        return mutated_dict

    def insertChar(self, input: dict) -> dict:
        mutated_dict = input.copy()
        key = self.arg2Fuzz(mutated_dict)

        if isinstance(mutated_dict[key], str):
            fuzzed = MnM.insert_character(mutated_dict[key])
            mutated_dict[key] = fuzzed
            print("insertChar")
            print("old dict 1" + str(input))
            print("new dict 1" + str(mutated_dict))
        return mutated_dict

    def flipRandChar(self, input: dict) -> dict:
        mutated_dict = input.copy()
        key = self.arg2Fuzz(mutated_dict)

        if isinstance(mutated_dict[key], str):
            fuzzed = MnM.flip_random_character(mutated_dict[key])
            mutated_dict[key] = fuzzed
            print("flipRandChar")
            print("old dict 1" + str(input))
            print("new dict 1" + str(mutated_dict))
        return mutated_dict

    def incrChar(self, input: dict) -> dict:
        mutated_dict = input.copy()
        key = self.arg2Fuzz(mutated_dict)

        if isinstance(mutated_dict[key], str):
            fuzzed = MnM.increment_character(mutated_dict[key])
            mutated_dict[key] = fuzzed
            print("incrChar")
            print("old dict 1" + str(input))
            print("new dict 1" + str(mutated_dict))
        return mutated_dict

    def decrChar(self, input: dict) -> dict:
        mutated_dict = input.copy()
        key = self.arg2Fuzz(mutated_dict)

        if isinstance(mutated_dict[key], str):
            fuzzed = MnM.decrement_character(mutated_dict[key])
            mutated_dict[key] = fuzzed
            print("decrChar")
            print("old dict 1" + str(input))
            print("new dict 1" + str(mutated_dict))
        return mutated_dict

    def pollute(self, input: dict) -> dict:
        mutated_dict = input.copy()
        key = self.arg2Fuzz(mutated_dict)

        if isinstance(mutated_dict[key], str):
            fuzzed = MnM.pollute(mutated_dict[key])
            mutated_dict[key] = fuzzed
            print("pollute")
            print("old dict 1" + str(input))
            print("new dict 1" + str(mutated_dict))
        return mutated_dict

    def algoMutation(self, input: dict) -> dict:
        print("mutation algo selected")
        output = input.copy()
        algoOptions = ["CBC", "CFB128", "CTR", "ECB", "fail"]
        newValue = random.choice(algoOptions)
        if newValue == "fail":
            newValue = getRandomString(random.randint(0, 8))
        output["algo"] = newValue
        print("old dict 2" + str(input))
        print("new dict 2" + str(output))
        return output

    def replaceChar(self, input: dict) -> dict:
        # replace character
        # make a copy of the input dictionary
        print("replaceChar selected")

        mutated_dict = input.copy()

        # select a random key from the dictionary
        keylist = list(mutated_dict.keys())
        keylist.remove("algo")
        key = random.choice(keylist)

        if isinstance(mutated_dict[key], str):
            plain_list = list(mutated_dict[key])
            # randomly choose a position to modify
            position = random.randint(0, len(plain_list) - 1)

            # randomly choose a replacement character
            new_char = random.choice(string.printable)

            # replace the character at the chosen position with the new character
            plain_list[position] = new_char

            # convert the list back to a string and update the 'plain' field in the mutated dictionary
            mutated_dict[key] = "".join(plain_list)

        print("old dict 0" + str(input))
        print("new dict 0" + str(mutated_dict))

        return mutated_dict

    def insertWhite(self, input: dict) -> dict:
        print("insertWhite selected")
        # insert whitespace
        # make a copy of the input dictionary
        mutated_dict = input.copy()

        # select a random key from the dictionary
        keylist = list(mutated_dict.keys())
        keylist.remove("algo")
        key = random.choice(keylist)
        # check if the value corresponding to the selected key is a string
        if isinstance(mutated_dict[key], str):
            # get the string value from the selected key
            value = mutated_dict[key]
            # choose a random position in the string
            position = random.randint(0, len(value))
            # insert a white space character at the chosen position
            value = value[:position] + " " + value[position:]
            # update the value in the dictionary
            mutated_dict[key] = value

        print("old dict 2" + str(input))
        print("new dict 2" + str(mutated_dict))

        return mutated_dict

    def initialiseSeedFreq(self) -> bool:
        # before calling fuzzing, we populate the seedFreq which is the number of times the seed is called from CoreFuzzer.mainLoop()
        try:
            for hashval in self.runner.hashList:
                self.seedFreq[hashval] = 0
        except Exception as e:
            print(e)
            return False
        return True

    def updateSeedFreq(self, seedHash: str) -> bool:
        try:
            self.seedFreq[seedHash] += 1
        except Exception as e:
            print(e)
            return False
        return True

    def assignEnergy(self, currSeed: str) -> int:
        pathfreq = self.runner.pathFrequency
        valueArr = np.array(list(pathfreq.values()))
        ave = np.mean(valueArr)
        # print(ave)
        numTimesPathExecute = pathfreq[currSeed]
        numTimesSeedChosen = self.seedFreq[currSeed]
        print(numTimesPathExecute)
        print(numTimesSeedChosen)
        # formaula is taken from CGF slides
        if numTimesPathExecute <= ave:
            print("< ave")
            currfraction = numTimesPathExecute / np.sum(valueArr)
            energy = int(self.alpha_i / currfraction * 2 ** (numTimesSeedChosen))
        else:
            # equals to alpha_i / times path executed
            print("> ave")
            energy = int(self.alpha_i / numTimesPathExecute) + 1
        energy = min(energy, self.alpha_max)
        # print(energy)
        return energy

    def getMutator(self) -> int:
        return random.randint(0, len(self.mutationLs) - 1)

    def fuzzInput(self) -> dict:
        # randomly choose mutation
        ind = self.getMutator()
        mutator = self.mutationLs[ind]
        print(mutator)
        # return fuzzed seed

        self.timelineMutatorSel["total"] += 1
        if mutator == "replaceChar":
            self.timelineMutatorSel["replaceChar"] += 1
            fuzzed = self.replaceChar(self.currSeed)
        elif mutator == "insertWhite":
            self.timelineMutatorSel["insertWhite"] += 1
            fuzzed = self.insertWhite(self.currSeed)
        elif mutator == "algo":
            self.timelineMutatorSel["algo"] += 1
            fuzzed = self.algoMutation(self.currSeed)
        elif mutator == "delChar":
            self.timelineMutatorSel["delChar"] += 1
            fuzzed = self.delChar(self.currSeed)
        elif mutator == "insertChar":
            self.timelineMutatorSel["insertChar"] += 1
            fuzzed = self.insertChar(self.currSeed)
        elif mutator == "flipRandChar":
            self.timelineMutatorSel["flipRandChar"] += 1
            fuzzed = self.flipRandChar(self.currSeed)
        elif mutator == "incrChar":
            self.timelineMutatorSel["incrChar"] += 1
            fuzzed = self.incrChar(self.currSeed)
        elif mutator == "decrChar":
            self.timelineMutatorSel["decrChar"] += 1
            fuzzed = self.decrChar(self.currSeed)
        elif mutator == "pollute":
            self.timelineMutatorSel["pollute"] += 1
            fuzzed = self.pollute(self.currSeed)
        # print("New Input Selected "+str(fuzzed))
        return fuzzed

    def innerLoop(self, energy: int) -> None:
        # looping based on energy
        # print("_______________________ new inner loop")
        for i in range(energy):
            self.currSeed = self.fuzzInput()
            # run new fuzzed seed
            try:
                exitCode = self.runner.runTest(self.currSeed)
                # 0 is interesting not fail
                # 1 is intersting and fail
                # -1 is not interesting
                # now we update the seedFrequency and currSeed,
                if exitCode >= 0:
                    hashSeed = self.runner.mostRecentHash
                    self.seedFreq[hashSeed] = 0

            except Exception as e:
                print("innerloop")
                print(e)
                self.getSnapshot()
                self.writeDisk()
                self.dumpRunner("./python/dumpCrash.pkl")
                exit(1)
            # count the iteration
            self.iterCount += 1
            if i % 20 == 0:
                assert self.getSnapshot() == True
                assert self.writeDisk() == True  # comment out later
        return

    def mainLoop(self, epochs: int = None) -> None:
        if epochs == None:
            epochs = self.defaultEpochs
        currEpoch = 0
        self.initialiseSeedFreq()
        print("\n\n_______________________ new main loop")
        while currEpoch < epochs:
            print("\n------------------ epoch " + str(currEpoch))
            pprint(self.seedFreq)
            seedHash = self.runner.getSeed()
            self.updateSeedFreq(seedHash)  # update the record
            self.currSeed = self.runner.seedQDict[seedHash]
            energy = self.assignEnergy(seedHash)
            print("energy " + str(energy))
            self.innerLoop(energy)
            currEpoch += 1
        return

    def getSnapshot(self) -> bool:
        try:
            successPaths = len(self.runner.successPathHashLs)
            crashPaths = len(self.runner.crashPathHashLs)
            failurePaths = len(self.runner.failedPathHashLs)
            totalPathsQ = len(self.runner.pathQDict.keys())
            self.timelineYFails.append(failurePaths)
            self.timelineYPaths.append(totalPathsQ)
            self.timelineYIterations.append(self.iterCount)
            self.timelineYCrashes.append(crashPaths)
            self.timelineX.append(time.time())
        except Exception as e:
            print(e)
            return False
        return True

    def writeDisk(self) -> bool:
        os.chdir(self.runner.projectTestingDir)
        try:
            df = pd.DataFrame(
                [
                    self.timelineX,
                    self.timelineYFails,
                    self.timelineYPaths,
                    self.timelineYCrashes,
                    self.timelineYIterations,
                ]
            )
            df = df.transpose()
            df.columns = [
                "unix_time",
                "failures",
                "unique_paths",
                "crashes",
                "iterations",
            ]
            df.to_csv("python/data_list.csv")
            df2 = pd.DataFrame(
                list(self.timelineMutatorSel.values()),
                index=list(self.timelineMutatorSel.keys()),
            )
            # print(df2)
            df2.to_csv("python/mutation_sel.csv")
        except Exception as e:
            print(e)
            return False
        return True

    def dumpRunner(self, filename: str) -> bool:
        out: list = [
            self.runner.hashList,
            self.runner.seedQDict,
            self.runner.pathQDict,
            self.runner.pathFrequency,
            self.runner.failedPathHashLs,
            self.runner.crashPathHashLs,
            self.runner.seedQCov,
        ]
        os.chdir(self.pwd)
        try:
            with open(filename, "wb") as file:
                pickle.dump(out, file)
        except Exception as e:
            print(e)
            return False
        return True

    def loadRunner(self, filename: str) -> bool:
        os.chdir(self.pwd)
        try:
            with open(filename, "rb") as file:
                inputs: list = pickle.load(file)
                # print(inputs)
                self.runner.hashList = inputs[0]
                self.runner.seedQDict = inputs[1]
                self.runner.pathQDict = inputs[2]
                self.runner.pathFrequency = inputs[3]
                self.runner.failedPathHashLs = inputs[4]
                self.runner.successPathHashLs = inputs[5]
                self.runner.seedQCov = inputs[6]
                # print(self.runner.pathFrequency)
        except Exception as e:
            print(e)
            return False
        return True


def makeResultsDir(pwd:str)->bool:
    results =os.path.join(pwd,"python/results")
    success =os.path.join(pwd,"python/results/successQ")
    fail = os.path.join(pwd,"python/results/failQ")
    crash = os.path.join(pwd,"python/results/crashQ")
    if os.path.exists(results) != True:
        os.mkdir(results)
    if os.path.exists(success) != True:
        os.mkdir(success)
    if os.path.exists(fail) != True:
        os.mkdir(fail)
    if os.path.exists(crash) != True:
        os.mkdir(crash)

if __name__ == "__main__":
    pwd = os.path.dirname(os.path.abspath("LICENSE"))+"/project_testing"
    print(pwd)
    makeResultsDir(pwd)
    import sys

    orig_stdout = sys.stdout
    f = open("LOGGER.txt", "w")
    sys.stdout = f
    coreFuzzer = Fuzzer(
        pwd, seedFolder="./project_seed_q", defaultEpochs=2, runGetAesInput=True
    )
    # coreFuzzer.innerLoop(10)
    # print(coreFuzzer.runner.crashPathHashLs)
    # # coreFuzzer.decrChar(fuzzed_seed)
    # # coreFuzzer.insertchar(fuzzed_seed)
    # # coreFuzzer.flipRandChar(fuzzed_seed)
    # # coreFuzzer.incrChar(fuzzed_seed)
    # # coreFuzzer.decrChar(fuzzed_seed)
    # # coreFuzzer.pollute(fuzzed_seed)
    # seed = coreFuzzer.runner.hashList[0]
    # print(seed)
    # coreFuzzer.runner.writeSeedQ(isFail=False,isCrash=False,ids=seed)
    start = time.time()
    coreFuzzer.mainLoop(150)
    end = time.time()
    timetaken = end - start
    print("time taken: " + str(int(timetaken)) + "s")
    coreFuzzer.dumpRunner("150epochtestRun.pkl")
    print("exit")
    # run coverage and log if it is intereing. we also add it to failQ if it is failing
    # runner.runTest(fuzzed_seed)

    # Fuzzer.createSeedFile(
    #     "itzkbg2", "itzkbg2", "0123456789123456", "0123456789123456", "CBC",
    #     "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+-=~[];',./{}|:?<>\"123"
    # )
    # output = Fuzzer.runScriptUbuntu(pwd, "./python/seed.txt")
    # print("end of execution return value: "+str(output))
    # output = Fuzzer.runScriptUbuntu(pwd, "./aes_combined_seed/aes_combined_cbc.txt")
    # print("end of execution return value: "+str(output))

    # runner = Runner(pwd)
    # runner.getAesInputs("./aes_combined_seed")
    # print(runner.hashList)
    # print(runner.pathQDict.keys())
    # print(runner.seedQDict.keys())
    # print("FailedHashList")
    # pprint(runner.failedPathHashLs)
    # print("\nSuccessHashList")
    # pprint(runner.successPathHashLs)
    # print("\nSeedQ")
    # pprint(runner.seedQDict)
    # print("\nPathFreq")
    # pprint(runner.pathFrequency)

    # assert(len(runner.successPathHashLs)+len(runner.failedPathHashLs) == len(runner.hashList))
    # seed = runner.getSeed()
    # print(seed)
    # # fuzzing to get fuzzed input dict with fuzzer class
    # fuzzed_seed = {
    #     "key": "itzkbg2",
    #     "key2": "itzkbg2",
    #     "iv": "0123456789123456",
    #     "iv2": "0123456789123456",
    #     "algo": "CBC",
    #     "plain": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+-=~[];',./{}|:?<>\"123",
    # }
    f.close()
