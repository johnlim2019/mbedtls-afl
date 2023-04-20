import os
import pickle
import pandas as pd
from pprint import pprint 
import lib
import time


def getSnapshotCsv(dumpfile:str):
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
    interestingFreq = inputs[8]
    pprint(len(list(pathQDict.values())[0]))
    seedQLs = []
    pathQLs = []
    pathFrequencyLs = []
    seedCovLs = []
    seedFreqLs = []
    isFail = [] 
    isCrash = []
    seedInteresting = []
    for i in hashList:
        seedQLs.append(seedQDict[i])
        pathQLs.append(pathQDict[i])
        pathFrequencyLs.append(pathFrequency[i])
        seedCovLs.append(seedQCov[i])
        seedFreqLs.append(seedFreq[i])
        seedInteresting.append(interestingFreq[i])
        if i in failedPathHashLs:
            isFail.append(True)
        else: 
            isFail.append(False)
        if i in crashPathHashLs:
            isCrash.append(True)
        else:
            isCrash.append(False)
    df = pd.DataFrame([
        seedQLs,pathFrequencyLs,seedCovLs,seedFreqLs,isFail,isCrash,seedInteresting
    ])
    df = df.transpose()
    # print(hashList)

    df.columns = [
        "Seed Input",
        "Path Frequency",
        "Path Code Coverage",
        "Seed Frequency",
        "Fail Path",
        "Crash Path",
        "Seed Interesting"
    ]
    df.index = hashList
    df.to_csv("python/dumpCrashBreakdown.csv")


pwd = os.path.dirname(os.path.abspath("LICENSE")) + "/project_testing"
print(pwd)
lib.makeResultsDir(pwd)

coreFuzzer = lib.Fuzzer(pwd, seedFolder="./project_seed_q", runGetAesInput=True)
hash = coreFuzzer.runner.hashList[0]
coreFuzzer.currSeed = coreFuzzer.runner.seedQDict[hash]
print(coreFuzzer.currSeed)
start = time.time()
for i in range(1000):
    coreFuzzer.fuzzInput()
end = time.time()
timetaken = end - start
print("time taken "+str(timetaken)+"s")
print("exit")