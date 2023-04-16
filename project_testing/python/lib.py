import os
import subprocess
from pprint import pprint
import random
import uuid
import time
import datetime
import pandas as pd
import numpy as np
import pickle
import string
import mutatemethods as MnM
import threading

from datetime import datetime

# datetime object containing current date and time
now = datetime.now()
 
print("now =", now)

# dd/mm/YY H:M:S
dt_string = now.strftime("%d_%m_%Y_%H_%M_%S")

def getRandomString(length):
    # choose from all lowercase letter
    letters = string.printable
    result_str = "".join(random.choice(letters) for i in range(length))
    # print("Random string of length", length, "is:", result_str)
    return result_str


class Runner:
    mostRecentHash: str = None  # this is used to pass to the Fuzzer object to add new interesting hash to the mapping that count number of times a seed is chosen
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

    # for getSeed optimisation
    currentSeedHash: str = (
        None  # this is the hash of the seed last chosen from seedQ it updates each time getSeed() is called
    )
    seed2Interesting = {}

    ##hide
    crashExitCode: dict = None

    def __init__(self, pwd: str):
        self.projectTestingDir = pwd

    def getAesInputs(self, folder: str) -> bool:
        import glob

        print(self.projectTestingDir)
        os.chdir(self.projectTestingDir)

        os.chdir("./python/results")
        files = glob.glob("**/*.txt")
        for f in files:
            os.remove(f)
        os.chdir(self.projectTestingDir)
        fileList = os.listdir(folder)
        os.chdir(folder)
        # print(fileList)
        # populate the input
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
                self.runTest(inputDict, True)
            # except Exception as e:
            #     print(e)
            #     return False
        return True

    def createSeedFile(self, key: str, key2: str, IV: str, IV2: str, algo: str, plain: str) -> str:
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
        return path["375"] == 0

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
        compileStr = "gcc --coverage crypt_test.c -o crypt_test -lmbedcrypto -lmbedtls -w"
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
        targetMatches = len(keys1)  # we want all lines to match if it is not interesting
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

    def runTest(self, inputDict, isSetup: bool = False) -> int:
        # exit codes
        # -1 is not interesting
        # 0 is intersting not fail
        # 1 is interesting and fail or crash
        # 2 compiling error

        # arguments
        # inputDict this the fuzzed input
        # isSetup is flag, True means we are using prepared seedfiles from folder project_seed_q
        exitCodeRunTest: int = -1  # this variable is what we want to return at the end of the method
        exitCode: int = self.getPathCovFile(inputDict)
        isfail = False
        isCrash = False
        if exitCode == 2:
            print("gcc compiling issue or gcov execution issue")
            self.getSnapshot()
            self.writeDisk()
            self.dumpRunner()
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
        if isCrash:
            path: dict = self.crashNoPathCov(self.crashExitCode)
        else:
            covFilePath = self.coverageFile
            path: dict = self.parseFile(covFilePath)
        # print(path)
        interesting: bool = self.isInterestingOuter(path)
        ids = str(uuid.uuid4())
        if isSetup == True:
            # we have nothing in the seed Q at setup
            # we want to add the seed to the hashlist and to the seed2Interesting mapping
            # the first seed always is interesting.
            self.currentSeedHash = ids
            self.seed2Interesting[self.currentSeedHash] = 0
        if interesting:
            self.seedQDict[ids] = inputDict
            self.pathQDict[ids] = path
            self.hashList.append(ids)
            self.pathFrequency[ids] = 1
            self.mostRecentHash = ids
            self.seedQCov[ids] = self.currPathCov
            # we also want to add it the seed2Interesting.
            self.seed2Interesting[self.currentSeedHash] += 1
            # we also found a new seed so we add it to the seed2Interesting
            # if it is a new seed, if it is just the previous seed we dont want to overwrite it.
            if (ids != self.currentSeedHash):
                self.seed2Interesting[ids] = 0
            # print("interesting path found")
            if isfail:
                print("path is a failing path")
                self.failedPathHashLs.append(ids)
                exitCodeRunTest = 1
            elif isCrash:
                self.seedQCov[ids] = 0
                self.crashPathHashLs.append(ids)
                exitCodeRunTest = 1
            else:
                print("path is a successful path")
                exitCodeRunTest = 0
            print(self.seedQCov)
            self.writeDiskSeedQ(isfail, isCrash, ids)
        # print("path is not unique")
        return exitCodeRunTest

    def peachMinset(self, cost=None) -> dict:
        # return the sorted list based on value descendin
        if cost == None:
            seedQCov: dict = self.seedQCov
        else:
            seedQCov = cost
        sorted_dict = dict(sorted(seedQCov.items(), key=lambda x: x[1], reverse=True))
        return sorted_dict

    def getSeedOld(self, seedFreq: dict, timelineYCov: list) -> int:
        selected_hash = np.random.choice(self.hashList)
        print("selected hash "+str(selected_hash))
        print("random selection choice")
        return selected_hash

    def shannon_diversity(self, species):
        total = sum(species)
        output = 0
        for value in species:
            p = value / total
            if p != 0:
                output += np.log(p) * p
        return -output

    def getSeed(self, seedFreqDict: dict, timelineYCov: list) -> int:
        # get next seed based on the index of the number
        print("path freq")
        pprint(self.pathFrequency)
        print("seed freq")
        pprint(seedFreqDict)
        print("seed2interesting")
        pprint(self.seed2Interesting)
        seed2interestingProb = []
        interesting = self.seed2Interesting
        for hash in self.hashList:
            seed2interestingProb.append(interesting[hash] / len(self.hashList))
        print("interesting prob")
        print(seed2interestingProb)
        currDiversity = self.shannon_diversity(seed2interestingProb)
        print("curr diversity score " + str(currDiversity))
        possible_hash = {}
        for index, hash in enumerate(self.hashList):
            seed2interestingProb[index] = (interesting[hash] + 1) / (len(self.hashList) + 1)
            newDiversity = self.shannon_diversity(seed2interestingProb)
            if newDiversity >= currDiversity:
                diff = newDiversity - currDiversity
                possible_hash[hash] = diff
        maxIncrease = 0
        possible_choose = []
        for index, hash in enumerate(list(possible_hash.keys())):
            if possible_hash[hash] >= maxIncrease:
                maxIncrease = possible_hash[hash]
                possible_choose.append(hash)
        print("max increase score " + str(maxIncrease))
        selectedHash = np.random.choice(possible_choose)
        print("available choices " + str(possible_choose))
        # we have chosen a new seed.
        self.currentSeedHash = selectedHash
        print("selected hash " + selectedHash)
        return selectedHash

    def getSeedPonly(self, seedFreqDict: dict, timelineYCov: list) -> int:
        # get next seed based on the index of the number
        print("path freq")
        pprint(self.pathFrequency)
        print("seed freq")
        pprint(seedFreqDict)
        print("seed2interesting")
        pprint(self.seed2Interesting)
        seed2interestingProb = []
        interesting = self.seed2Interesting
        for hash in self.hashList:
            seed2interestingProb.append(interesting[hash] / len(self.hashList))
        print("interesting prob")
        print(seed2interestingProb)
        # normalise
        prob = []
        for v in seed2interestingProb:
            prob.append(v / sum(seed2interestingProb))
        selectedHash = np.random.choice(self.hashList, p=prob)
        self.currentSeedHash = selectedHash
        print("selected hash " + selectedHash)
        return selectedHash

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
    alpha_i = 15
    alpha_max = 2000
    pwd: str = None
    runner: Runner
    seedFreq: dict = {}  # number of times a seed has been selected in mainLoop for fuzzing
    currSeed: dict = None  # this is the dict containing all seed arguments

    mutationLs: list = [
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
    timelineYCodeCoverage = []
    timelineMutatorSel = {
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
    interestingMutatorSel = {
        "insertWhite": 0,
        "algo": 0,
        "delChar": 0,
        "insertChar": 0,
        "flipRandChar": 0,
        "incrChar": 0,
        "decrChar": 0,
        "pollute": 0,
    }
    crashinput = {
        "key": '\x08¢\x08`\x082L [\x0f\x1f  ¡   (()\x0bónN\x02\x03\x03    -    ;ó~~~#-\x8a\x83"äää333\xa06«xV \x1e \x13\x0f   \x86kr\x05\x06\x0622T\x86CCCU& Z `\x15\x15\x15\x8aj  c%6åÅå   )))\x17\x169<m$mÿ`A==  ! R\x1e!>\x0b0q m\x1dKL\x00LE\x89s\x7f\x7f\x7f ÔÔÔ4 ((!  Û;\r\x7f Z!\\Ó!!\x0b\x0b\x0c\x0b../.\x0f\x0f\x0f\x0f\x99 j²}ll\x91ë\'£\x00!\x7f \x83 \x01!!!jvA  ©\t)AA  \x99\x7f"""!=\x81"¤k\x84_wS    \x90\x1d\x1d\x1d\x81  øøQ! \x07Î\x87  \x84ssQ. .~   çh:ÑÑÑ\x0f  !\r_ð \x83\x83\x83\x83\x83  g½½!  %  \x01 \x1f   k kk --\\\\]',
        "key2": '^\x1ey\x1e\x13cabhRt\x98>\x9e \x91\x91 .\x12G(G1\x9bf# 2\x89\x8a\x88 \x056 9" (\x1a\x0b \x1f"p8\x9d\x9d\x9d\x1f]! /»gh glÃ\x04g z\x1cfF3\x0e\x0e§§9Y\x18O\x1f  \x01 !\x14g?\x88\x0b%\x1f %8êêêêêttt r#Êuv  !\x13 YW5DD+D //Û/ 3 "aS\x1f#^VRRR!EÖ×ÔÔÀ!!6¢MºT\x9aí>ÝÝÝé(ìê@]\x1fNf\x1e\x1f¾b[\'H\'h êz)!!¿@ \\ äZ¦{«zs\x0b1 !¤Ûßr  . "k®h qo  t\x1e1 \x9c+ ììì#( :$p1\n0   }\tIH]!|||nnnBAfA\x14\x15\x15ÛÚ :Û()^^   \x1f7éJnò±V ñòó!,I&%ãââ\x1f\x1f" \x1f\x1f < Hölllìé ºs\x7f+cúú}}l@ fg+zH  3   Ø\x1d]!Ç 6   !$ Í$$',
        "iv": '2 í  Z# \x00(#Y \'Y(`%))9)+IANäW8põ ok *` 5(¦ÃP\x049ð ¨   \x1f\x1f\x1f¥{?\x7f? ? -y\x1fppoEè èzzccc0 1006 ©©¹:"\x8d" \x1f  ---UU!! · > w_¼»uU¤  \x8d   !E\\\\\\5tEª,ÅÅÅ\x9bc#  #\x1f3\x0c!% #\x00  0 3be´  ¦ ¦v pwoGS \x06m\x1f\x1c\x1c\x1c\x9e\r\'\xad¬\xady!!!! ; \x1d\x86\x85\x0b\x0b2\x1f r«rr; @@@\x8c\x8c¡íî¶s!apÊ//\'/a6)*"     \x1f 4!¡¡¡j\tj99\t÷\x10aR\x1e\r/\t %o\x1d!  !5ðõ x ¬§Ää\x1fãp!# "\x7f@óK\x1b\x1c\x1a\t,,,,,\x1d( J  ª ªº`!@\x86ommm#"""fff $0`N \x1f.\x1fHH~~G\x1f\x1f\x1f',
        "iv2": '®®\xad !\x1f""\x1f- \'#\x04$\x8a\x1f$\x86|\x07d\x17$ M\x9a\x1f\\Å\x1f\x1f  µ   T T\x1e=.\x8a!ì%%%\xa0\xa0\xa0\xa0$& \x89   ¼\r\n\\z\xad\x9c op+0.\x0c0\x11ÚÛ$ÛK`     ·mP l\x0bª\\\\\\\x1f\x1f\x1f   \x93 g!\x1b%kÁÁ\\\x1c\\\\!t"    \x0b\x912 6.mù\x1f\x1f\x1f |||\x17mAOOx1 6?6\x1700 0!0`ae vE - z\x0b  ^\x1féò òÌòó!\x01!  \x1eHB\x10l{{S\x92&PQT^^N_\x0e  \x814 \x1f\x1fö(^L "q 0    Q ^Q^¥¥xy 9L!\x8a \x9at PÍ  |}T~}¬ L¶    \r¦cab!LL6T Á!\x0b$$\x1euax`8\x01\x01\x11   P   !p2****\t\t*',
        "algo": "CFB128",
        "plain": '\x9f\x9f\x9f\x0ed # N\x85~øü\x0fü5G\x1fOÓ\x998 4\x9f  b cb \x0c \t\x01\x02\x010!!\x06!!!"\x1f\x1f þ·ý àÆ\x0eWÍ°RE*$ \x1f\x02_e£c\x07  HHH0?!@!` \\  ÿÿ321j©\x1f2999\x9bL2 UkÆÎÞ!"! ~Avvv \x1f!\x1f     \x1fS\x1f{\x12F 9>nnn~!,\x7f! WUV\x1f"m)  a \x1c \x1e"# I\x02V!(^]<_ÖØ !\x17\x19E 4òYYY\x1b \x1f-&&   \x1e@i\x1c~    $o  ¡¡8xxx\x1f¯d\x02\x02\x01\x8e\x7f}\\Y!Ü\x1f G \x1d  @ \x99ýý\t\x0f.ðððõy[(%$\x1f\x1f\x1f\x1f\x0e\x0e\x1f  4 \x9b1`¥A¶¶\x96\x94!\x1f!D (\x02~~\x1e\x1f> ]  \x839 =xD}!4 WÏ h\x0c\x0c\x0cv fÌ,\x90Â\x0b}~weJJKô-11wB ÐÏÏ\x83\x85\x85\x85Ck!\x85!\x96)%\x93\x94  y !!  h \x1f  (((qqq\x1e\x0e !e~? .\x1f y>g\x90\x90°x\x17XXX\x80\r\x80ã CUXXX(Ò6+ààà$e=3q (n( L KKS7N¨?^!pppss ',
    }
    normalinput = {
        "key": "itzkbg2",
        "key2": "itzkbg2",
        "iv": "0123456789123456",
        "iv2": "0123456789123456",
        "algo": "CBC",
        "plain": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+-=~[];',./{}|:?<>\"123",
    }
    index = dt_string

    def __init__(
        self,
        pwd: str,
        seedFolder: str,
        isPSO = False,
        runGetAesInput=True,
        p=[1 / 8, 1 / 8, 1 / 8, 1 / 8, 1 / 8, 1 / 8, 1 / 8, 1 / 8],
    ) -> None:
        self.pwd = pwd
        self.selectorProbabilities: list = self.read_pso()
        if self.selectorProbabilities == None:
            self.selectorProbabilities: list = p
        print()
        print("mutator p-distribution: " + str(self.selectorProbabilities))
        print()
        if runGetAesInput == True:
            self.runner = Runner(pwd)
            self.runner.getAesInputs(seedFolder)
            print("Completed initialisation of prepared inputs")
        else:
            self.runner = Runner(pwd)
            print(
                "runnr object attribute is set to None, please use loadRunner() to load a serialised runner object instance"
                "any losses in results folder may be retrieved from runner dump"
            )
        print("isPSO "+str(isPSO))
        if isPSO:
            self.alpha_i = 2
            self.alpha_max = 100
        print("alpha initial "+str(self.alpha_i))
        print("alpha max "+str(self.alpha_max))

    def read_pso(self) -> list:
        # look for pso_results.txt in file
        os.chdir(self.pwd)
        try:
            with open("./python/PSO_results.txt", "r") as file:
                line = file.read()
        except:
            return None
        line = line[1:-1]
        line = line.split(",")
        # print(line)
        p = []
        for i in line:
            p.append(float(i))
        return p

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
        else:
            newKey = getRandomString(random.randint(0,32))
            output["key"] = output['key2'] = newKey
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

    mutationFunctions: list = [
        insertWhite,
        delChar,
        insertChar,
        flipRandChar,
        incrChar,
        decrChar,
        pollute,
    ]

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
            energy = min(
                int(self.alpha_i / currfraction * 2 ** (numTimesSeedChosen)),
                self.alpha_max,
            )
        else:
            # equals to alpha_i / times path executed
            print("> ave")
            energy = int(self.alpha_i / numTimesPathExecute) + 1
        energy = min(energy, self.alpha_max)
        # print(energy)
        return energy

    def getMutator(self) -> int:
        return np.random.choice([0, 1, 2, 3, 4, 5, 6, 7], p=self.selectorProbabilities)

    def fuzzInput(self) -> dict:
        # randomly choose mutation
        ind = self.getMutator()
        mutator = self.mutationLs[ind]
        self.currMutator = mutator
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
        print("Energy Assigned: " + str(energy))
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
                    self.interestingMutatorSel[self.currMutator] += 1

            except Exception as e:
                print("innerloop")
                print(e)
                self.getSnapshot()
                self.writeDisk()
                self.dumpRunner()
                print("Successfully saved run data.")
                exit(1)
            # count the iteration
            self.iterCount += 1

        return

    def mainLoop(self) -> None:
        currEpoch = 0
        self.initialiseSeedFreq()
        print("\n\n_______________________ new main loop")

        while True:
            print("\n------------------ epoch " + str(currEpoch))
            print("seed frequency")
            pprint(self.seedFreq)
            seedHash = self.runner.getSeed(self.seedFreq, self.timelineYCodeCoverage)
            self.updateSeedFreq(seedHash)  # update the record
            print(seedHash)
            self.currSeed = self.runner.seedQDict[seedHash]
            energy = self.assignEnergy(seedHash)
            print("energy " + str(energy))
            self.innerLoop(energy)
            currEpoch += 1
        return

    def pso_fuzz(self, epochs: int):
        currEpoch = 0
        print("Epoches in total: " + str(epochs))
        self.initialiseSeedFreq()
        print("\n\n_______________________ new pso fuzz loop")
        for i in range(epochs):
            print("\n------------------ epoch " + str(currEpoch))
            pprint(self.seedFreq)
            seedHash = self.runner.getSeed(self.seedFreq, self.timelineYCodeCoverage)
            self.updateSeedFreq(seedHash)  # update the record
            self.currSeed = self.runner.seedQDict[seedHash]
            energy = self.assignEnergy(seedHash)
            print("energy " + str(energy))
            self.innerLoop(energy)
            currEpoch += 1
        return

    def timeline(self):
        assert self.getSnapshot() == True
        assert self.writeDisk() == True  # comment out later
        assert self.dumpRunner() == True

    def getCodeCoverage(self, pathQDict: dict) -> float:
        # return the percentage of code coverage
        # pprint.pprint(pathQDict)

        # store the cumulative sum of values for each unique key
        cumul_dict = {}
        for val_dict in pathQDict.values():
            for key, value in val_dict.items():
                key = str(key)
                if key.isdigit() == False:
                    continue
                if key in cumul_dict:
                    cumul_dict[key] += value
                else:
                    cumul_dict[key] = value

        # pprint.pprint(cumul_dict)
        count_execute = 0
        for val_dict in cumul_dict.values():
            if val_dict > 0:
                count_execute += 1
        # for key, val_dict in pathQDict.items():
        #     if '81' in val_dict:
        #         print(f"{key} key 81 value is {val_dict['81']}")

        return round(count_execute / len(cumul_dict.items()), 5) * 100

    def getSnapshot(self) -> bool:
        successPaths = len(self.runner.successPathHashLs)
        crashPaths = len(self.runner.crashPathHashLs)
        failurePaths = len(self.runner.failedPathHashLs)
        totalPathsQ = len(self.runner.pathQDict.keys())
        codeCoverage = self.getCodeCoverage(self.runner.pathQDict)
        self.timelineYSuccess.append(successPaths)
        self.timelineYFails.append(failurePaths)
        self.timelineYPaths.append(totalPathsQ)
        self.timelineYIterations.append(self.iterCount)
        self.timelineYCrashes.append(crashPaths)
        self.timelineX.append(time.time())
        self.timelineYCodeCoverage.append(codeCoverage)
        return True

    def writeDisk(self) -> bool:
        os.chdir(self.runner.projectTestingDir)
        df = pd.DataFrame(
            [
                self.timelineX,
                self.timelineYFails,
                self.timelineYPaths,
                self.timelineYCrashes,
                self.timelineYIterations,
                self.timelineYCodeCoverage,
            ]
        )
        df = df.transpose()
        df.columns = ["unix_time", "failures", "unique_paths", "crashes", "iterations", "code_coverage"]
        df.to_csv(f"python/plot_data/{self.index}/data_list_{self.index}.csv")
        df2 = pd.DataFrame(
            list(self.timelineMutatorSel.values()),
            index=list(self.timelineMutatorSel.keys()),
        )
        df2.to_csv(f"python/plot_data/{self.index}/mutation_sel_{self.index}.csv")
        return True

    def dumpRunner(self) -> bool:
        # dump all th important attributes of runner obj and also seedFreq from fuzzer obj
        out: list = [
            self.runner.hashList,
            self.runner.seedQDict,
            self.runner.pathQDict,
            self.runner.pathFrequency,
            self.runner.failedPathHashLs,
            self.runner.crashPathHashLs,
            self.runner.seedQCov,
            self.seedFreq,
            self.runner.seed2Interesting
        ]
        os.chdir(self.pwd)
        try:
            with open(f"python/plot_data/{self.index}/dumpCrash_{self.index}.pkl", "wb") as file:
                pickle.dump(out, file)
        except Exception as e:
            print(e)
            return False
        return True

    def loadRunner(self, filename: str) -> bool:
        # load all th important attributes of runner obj and also seedFreq from fuzzer obj
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
                self.runner.crashPathHashLs = inputs[5]
                self.runner.seedQCov = inputs[6]
                self.seedFreq = inputs[7]
                self.runner.seed2Interesting = inputs[8]
                # print(self.runner.pathFrequency)
        except Exception as e:
            print(e)
            return False
        return True


def makeResultsDir(pwd: str) -> bool:
    results = os.path.join(pwd, "python/results")
    success = os.path.join(pwd, "python/results/successQ")
    fail = os.path.join(pwd, "python/results/failQ")
    crash = os.path.join(pwd, "python/results/crashQ")
    plot_data = os.path.join(pwd, "python/plot_data")
    subdir = os.path.join(pwd, f"python/plot_data/{dt_string}")

    try:
        if os.path.exists(results) != True:
            os.mkdir(results)
        if os.path.exists(success) != True:
            os.mkdir(success)
        if os.path.exists(fail) != True:
            os.mkdir(fail)
        if os.path.exists(crash) != True:
            os.mkdir(crash)
        if os.path.exists(plot_data) != True:
            os.mkdir(plot_data)
        os.mkdir(subdir)
    except:
        exit()
        return False
    return True


def getSnapshotCsv(dumpfile: str):
    os.chdir(pwd)
    with open(dumpfile, "rb") as f:
        inputs = pickle.load(f)
    hashList: list = inputs[0]
    seedQDict: dict = inputs[1]
    pathQDict: dict = inputs[2]
    pathFrequency: dict = inputs[3]
    failedPathHashLs: list = inputs[4]
    crashPathHashLs: list = inputs[5]
    seedQCov: dict = inputs[6]
    seedFreq: dict = inputs[7]
    pprint.pprint(pathQDict)
    seedQLs = []
    pathQLs = []
    pathFrequencyLs = []
    seedCovLs = []
    seedFreqLs = []
    isFail = []
    isCrash = []
    for i in hashList:
        seedQLs.append(seedQDict[i])
        pathQLs.append(pathQDict[i])
        pathFrequencyLs.append(pathFrequency[i])
        seedCovLs.append(seedQCov[i])
        seedFreqLs.append(seedFreq[i])
        if i in failedPathHashLs:
            isFail.append(True)
        else:
            isFail.append(False)
        if i in crashPathHashLs:
            isCrash.append(True)
        else:
            isCrash.append(False)
    df = pd.DataFrame([seedQLs, pathFrequencyLs, seedCovLs, seedFreqLs, isFail, isCrash])
    df = df.transpose()
    print(df.shape)
    df.columns = [
        "Seed Input",
        "Path Frequency",
        "Path Code Coverage",
        "Seed Frequency",
        "Fail Path",
        "Crash Path",
        "Total Code Coverage",
    ]
    df.index = hashList
    df.to_csv("python/dumpCrashBreakdown.csv")


def every(delay, task):
    next_time = time.time() + delay
    while True:
        time.sleep(max(0, next_time - time.time()))
        try:
            task()
        except Exception as e:
            print(e)
        # skip tasks if we are behind schedule:
        next_time += (time.time() - next_time) // delay * delay + delay


if __name__ == "__main__":
    pwd = os.path.dirname(os.path.abspath("LICENSE")) + "/project_testing"
    print(pwd)
    makeResultsDir(pwd)
    import sys
    orig_stdout = sys.stdout
    f = open(f"./project_testing/python/plot_data/{dt_string}/LOGGER_{dt_string}.txt", "w")
    sys.stdout = f

    coreFuzzer = Fuzzer(pwd, seedFolder="./project_seed_q", runGetAesInput=True)

    coreFuzzer.timeline()
    start = time.time()
    threading.Thread(target=lambda: every(5, coreFuzzer.timeline)).start()
    coreFuzzer.mainLoop()
    print("exit")

    f.close()
