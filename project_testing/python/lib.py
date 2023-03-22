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
    mostRecentHash: uuid = None
    hashList = []
    currPathCov:float = 0.0
    seedQCov = {}
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
        # print()
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
        import re
        coverage = ["gcov", "crypt_test.c", "-m"]
        p = subprocess.run(coverage, stdout=subprocess.PIPE)
        currPathCov = p.stdout.decode()
        regpattern = r"(?<=Lines executed:)(.*)(?=%)"
        self.currPathCov = float(re.search(regpattern,currPathCov).group(0))
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
        # 1 is interesting and fail
        # -1 is not interesting
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
            isfail = True
            path: dict = self.crashNoPathCov()
            # exit()
        covFilePath = self.coverageFile
        path: dict = self.parseFile(covFilePath)
        # print(path)
        interesting: bool = self.isInterestingOuter(path)
        if interesting:
            # print("interesting path found")
            ids = uuid.uuid4()
            self.seedQDict[ids] = inputDict
            self.pathQDict[ids] = path
            self.hashList.append(ids)
            self.pathFrequency[ids] = 1
            self.mostRecentHash = ids
            self.seedQCov[ids] = self.currPathCov
            print(self.seedQCov)
            if isfail:
                # print("path is a failing path")
                self.failedPathHashLs.append(ids)
                return 1
            else:
                # print("path is a successful path")
                self.successPathHashLs.append(ids)
                return 0
        # print("path is not unique")
        return -1

    def getSeed(self) -> int:
        # get random seed
        hashind = random.randint(0, len(self.hashList) - 1)
        return self.hashList[hashind]


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

    def __init__(
        self, pwd: str, seedFolder: str, defaultEpochs: int = 20, runGetAesInput=False
    ) -> None:
        self.pwd = pwd
        self.defaultEpochs = defaultEpochs
        if runGetAesInput == False:
            self.runner = Runner(pwd)
            try:
                self.runner.getAesInputs(seedFolder)
            except Exception as e:
                print(e)
                print("failed to initialise prepared inputs")
                exit(1)
            print("Completed initialised of prepared inputs")
        else:
            self.runner = Runner(pwd)
            print(
                "runenr object attribute is set to None, please use loadRunner() to load a serialised runner object instance"
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
            fuzzed_seed = self.fuzzInput()
            self.currSeed = fuzzed_seed
            # run new fuzzed seed
            try:
                exitCode = self.runner.runTest(fuzzed_seed)
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

    def writeDisk(self) -> bool:
        os.chdir(self.runner.projectTestingDir)
        try:
            df = pd.DataFrame(
                [
                    self.timelineX,
                    self.timelineYFails,
                    self.timelineYPaths,
                    self.timelineYIterations,
                ]
            )
            df = df.transpose()
            df.columns = ["unix_time", "failures", "total_paths", "iterations"]
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
            self.runner.successPathHashLs,
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
                # print(self.runner.pathFrequency)
        except Exception as e:
            print(e)
            return False
        return True


if __name__ == "__main__":
    pwd = "/home/lim/mbedtls-afl/project_testing"
    pwd = "/home/limjieshengubuntu/mbedtls-afl/project_testing"
    import sys

    # orig_stdout = sys.stdout
    # f = open("LOGGER.txt", "w")
    # sys.stdout = f
    # coreFuzzer = Fuzzer(
    #     pwd, seedFolder="./aes_combined_seed", defaultEpochs=2, runGetAesInput=False
    # )
    # coreFuzzer.dumpRunner("./python/runner.pkl")
    # coreFuzzer = Fuzzer(
    #     pwd, seedFolder="./aes_combined_seed", defaultEpochs=2, runGetAesInput=True
    # )
    # coreFuzzer.loadRunner("./python/runner.pkl")
    # # coreFuzzer.decrChar(fuzzed_seed)
    # # coreFuzzer.insertchar(fuzzed_seed)
    # # coreFuzzer.flipRandChar(fuzzed_seed)
    # # coreFuzzer.incrChar(fuzzed_seed)
    # # coreFuzzer.decrChar(fuzzed_seed)
    # # coreFuzzer.pollute(fuzzed_seed)

    # start = time.time()
    # coreFuzzer.mainLoop(5)
    # end = time.time()
    # timetaken = end - start
    # print("serial: " + str(int(timetaken)) + "s")
    # print("exit")
    # f.close()
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

    runner = Runner(pwd)
    runner.getAesInputs("./aes_combined_seed")
    print(runner.hashList)
    print(runner.pathQDict.keys())
    print(runner.seedQDict.keys())
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
