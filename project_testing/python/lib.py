import os
import subprocess
from pprint import pprint
import random
import uuid
import time
import pandas as pd
import numpy as np

class Runner:
    hashList = []
    seedQDict = {}
    pathQDict = {}
    pathFrequency = {}
    failedPathHashLs = []
    successPathHashLs = []
    seedFile: str = "./python/seed.txt"
    projectTestingDir = None
    coverageFile: str = "crypt_test.c.gcov"

    def __init__(self, pwd: str):
        self.projectTestingDir = pwd

    def getAesInputs(self, folder: str) -> bool:
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

    def crashNoPathCov(self) -> dict:
        # we create a path where 375 is 0 this is the main method return success line
        return {375: 0}

    def runScriptUbuntu(self) -> int:
        # 0 no crash, path generated
        # -1 crash, no path generated
        # 1 crash, with path generated
        # 2 some execution failure not related to test script
        # we need to compile and then execute binary to be able to run coverage.
        print()
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
        if exitCode > 1:
            print("Program crash no path generated")
            return -1
        coverage = ["gcov", "crypt_test.c", "-m"]
        if subprocess.run(coverage, stdout=subprocess.DEVNULL).returncode != 0:
            print("coverage gcov failed")
            return 2
        deletenotes = "rm -rf crypt_test.gc*"
        os.system(deletenotes)
        print("completed one cycle")
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

    def runTest(self, inputDict) -> None:
        exitCode: int = self.getPathCovFile(inputDict)
        isfail = False
        if exitCode == 2:
            print("gcc compiling issue or gcov execution issue")
            return exit()
        elif exitCode == -1:
            isfail = True
            path: dict = self.crashNoPathCov()
        elif exitCode == 1:
            isfail = True
        elif exitCode == 0:
            isfail = False
        else:
            print("unknown exitcode crash")
            exit()
        covFilePath = self.coverageFile
        path: dict = self.parseFile(covFilePath)
        # print(path)
        interesting: bool = self.isInterestingOuter(path)
        if interesting:
            print("interesting path found")
            ids = uuid.uuid4()
            self.seedQDict[ids] = inputDict
            self.pathQDict[ids] = path
            self.hashList.append(ids)
            self.pathFrequency[ids] = 1
            if isfail:
                print("path is a failing path")
                self.failedPathHashLs.append(ids)
                return
            else:
                print("path is a successful path")
                self.successPathHashLs.append(ids)
                return
        print("path is not unique")

        return

    def getSeed(self)->dict:
        # get random seed
        hashind = random.randint(0,len(self.hashList)-1)
        return self.seedQDict[self.hashList[hashind]]

class Fuzzer:
    # TODO
    runner:Runner
    currSeed:str = None
    mutationLs:list = ["mutation0","mutation1","mutation2"]
    defaultEpochs:int = None
    iterCount:int = 0
    timelineYFails:list = []
    timelineYPaths:list = []
    timelineYIterations:list = []
    timelineX:list = []

    def __init__(self,pwd:str,seedFolder:str,defaultEpochs:int) -> None:
        self.defaultEpochs = defaultEpochs
        self.runner = Runner(pwd)
        try:
            self.runner.getAesInputs(seedFolder) 
        except Exception as e:
            print(e)
            print("failed to initialise prepared inputs")
            exit(1)
        print("Completed initialised of prepared inputs")

    def mutation0(self,input:dict)->dict:
        print("mutation0 selected")
        return input
    def mutation1(self,input:dict)->dict:
        print("mutation1 selected")
        return input
    def mutation2(self,input:dict)->dict:
        print("mutation2 selected")
        return input    
    
    def assignEnergy(self)->int:
        return 10
    
    def getMutator(self)->int:
        return random.randint(0,len(self.mutationLs)-1)

    def nextInput(self)->dict:
        # randomly choose mutation 
        ind = self.getMutator()
        mutator = self.mutationLs[ind]
        # return fuzzed seed
        if mutator == "mutation0":
            fuzzed = self.mutation0(self.currSeed)
        if mutator == "mutation1":
            fuzzed = self.mutation1(self.currSeed)
        if mutator == "mutation2":
            fuzzed = self.mutation2(self.currSeed)                        
        print("New Input Selected "+str(fuzzed))
        return fuzzed
    
    def innerLoop(self,energy:int)->None:
        # looping based on energy
        print("_______________________ new inner loop")
        for i in range(energy):
            print()
            print("------------------ iteration "+str(i))
            fuzzed_seed = self.nextInput()
            # run new fuzzed seed
            try:
                self.runner.runTest(fuzzed_seed)
            except Exception as e:
                print(e)
                self.getSnapshot()
                self.writeDisk()
                exit(1)
            # count the iteration
            self.iterCount += 1
        assert (self.getSnapshot()== True)
        assert (self.writeDisk() == True) # comment out later 
        return
    
    def mainLoop(self,epochs:int=None)->None:
        if epochs == None:
            epochs = self.defaultEpochs
        currEpoch = 0;
        print("\n\n_______________________ new main loop")
        while currEpoch < epochs:
            print("\n------------------ epoch "+str(currEpoch))
            self.currSeed = self.runner.getSeed()
            energy = self.assignEnergy()
            self.innerLoop(energy)
            currEpoch += 1
        return
    
    def getSnapshot(self)->bool:
        try:
            failurePaths = len(self.runner.failedPathHashLs)
            totalPathsQ = len(self.runner.pathQDict.keys())
            self.timelineYFails.append(failurePaths)
            self.timelineYPaths.append(totalPathsQ)
            self.timelineYIterations.append(self.iterCount)
            self.timelineX.append(time.time())
        except Exception as e:
            print(e)
            return False
        return True
    
    def writeDisk(self)->bool:
        os.chdir(self.runner.projectTestingDir)
        try:
            df = pd.DataFrame([self.timelineX,self.timelineYFails,self.timelineYPaths,self.timelineYIterations])
            df = df.transpose()
            df.columns = ["unix_time","failures","total_paths","iterations"]
            df.to_csv("python/data_list.csv")
        except Exception as e:
            print(e)
            return False
        return True

    

if __name__ == "__main__":
    pwd = "/home/lim/mbedtls/project_testing"

    # runner = Runner(pwd)
    # runner.getAesInputs("./aes_combined_seed")
    # # print(runner.hashList)
    # # print(runner.pathQDict.keys())
    # # print(runner.seedQDict.keys())
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

    coreFuzzer = Fuzzer(pwd,seedFolder="./aes_combined_seed",defaultEpochs=20)
    # coreFuzzer.innerLoop(10)
    coreFuzzer.mainLoop()


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
