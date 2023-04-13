import os
import pickle
import pandas as pd


def getSnapshotCsv(dumpfile:str):
    pwd = os.path.dirname(os.path.abspath("LICENSE"))+"/project_testing"
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
    interestingFreq = inputs[8]
    # pprint.pprint(pathQDict)
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
    print(hashList)

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

getSnapshotCsv("python/dumpCrash.pkl")


# import lib
# cis = {'key': '4zkB]ÕcrrJl taPg !', 'key2': '!qrr j bcvtr - c jl!n¥vf ««', 'iv': '2~1 x32 5 u', 'iv2': '\x1f 1\x11~\x19f 5:[80eR\x893 95', 'algo': 'CFB128', 'plain': 'bbcde fgh hkdl+oÒpqsssuvw xy zABCD%EwGHIJ4 LNNPRRSTUVWXYZ1234567890jñ!@#$(\'^%*  \x8a()_---~[\\ \\\\\',./{~|:;<"""023'}
# os.chdir(pwd)
# # orig_stdout = sys.stdout
# # f = open("LOGGER.txt", "w")
# # sys.stdout = f
# coreFuzzer = lib.Fuzzer(
#     pwd, seedFolder="./project_seed_q", defaultEpochs=2, runGetAesInput=False
# )
# print(coreFuzzer.runner.runTest(cis))