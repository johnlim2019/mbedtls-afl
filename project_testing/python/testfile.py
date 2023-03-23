import subprocess
import pprint
import os
import pandas

pwd = os.path.dirname(os.path.abspath("LICENSE"))+"/project_testing"

# import re
# try:
#     os.chdir(pwd)
# except Exception as e:
#     print(e)
#     print("unable to change pwd")
# compileStr = "gcc --coverage crypt_test.c -o crypt_test -lmbedcrypto -lmbedtls"
# if os.system(compileStr) != 0:
#     print("did not compile")
# runTest = ["./crypt_test", "./aes_combined_seed/aes_combined_cbc.txt"]
# exitCode = subprocess.run(runTest, stdout=subprocess.DEVNULL).returncode
# if exitCode > 1:
#     print("Program crash no path generated")
# coverage = ["gcov", "crypt_test.c", "-m"]
# p = subprocess.run(coverage, stdout=subprocess.PIPE)
# currPathCov = p.stdout.decode()
# regpattern = r"(?<=Lines executed:)(.*)(?=%)"
# currPathCov = re.search(regpattern,currPathCov).group(0)
# print(currPathCov)
# if p.returncode != 0:
#     print("coverage gcov failed")
# deletenotes = "rm -rf crypt_test.gc*"
# os.system(deletenotes)
# # print("completed one cycle")

import pickle
import pandas as pd
import pprint

def getSnapshotCsv(dumpfile:str):
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
    df = pd.DataFrame([
        seedQLs,pathFrequencyLs,seedCovLs,seedFreqLs,isFail,isCrash
    ])
    df = df.transpose()
    print(df.shape)

    df.columns = [
        "Seed Input",
        "Path Frequency",
        "Path Code Coverage",
        "Seed Frequency",
        "Fail Path",
        "Crash Path"
    ]
    df.index = hashList
    df.to_csv("python/dumpCrashBreakdown.csv")

getSnapshotCsv("5epochtestRun.pkl")


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