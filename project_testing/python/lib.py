import os
import uuid

class Runner:
    hashList = []
    SeedQDict = {}
    pathQDict = {}
    seedFile:str = None
    projectTestingDir = None
    
    def __init__(self,pwd:str):
        self.projectTestingDir = pwd
    
    def createSeedFile(self,key: str, key2: str, IV: str, IV2: str, algo: str,
                    plain: str) -> str:
        os.chdir(self.projectTestingDir)
        fileStr = ""
        fileStr += plain + "\nendplain\n"
        fileStr += algo + "\n"
        fileStr += key + "\n"
        fileStr += key2 + "\n"
        fileStr += IV + "\n"
        fileStr += IV2
        with open('./python/seed.txt', 'w') as f:
            f.write(fileStr)
        return './python/seed.txt'


    def isCrash(self,path: dict) -> bool:
        return path[375] == 0


    def crashNoPathHandler(self)->dict:
        # we create a path where 375 is 0 this is the main method return success line
        return {375:0}

    def runScriptUbuntu(self,seedFilePath: str) -> int:
        # 0 no crash path generated
        # -1 crash no path generated
        # 1 crash with path generated
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
            return 1
        runTest = "./crypt_test " + seedFilePath
        exitCode = os.waitstatus_to_exitcode(os.system(runTest))
        if exitCode > 1: 
            print("Program crash no path generated")
            return -1
        coverage = "gcov crypt_test.c -m"
        if os.system(coverage) != 0:
            print("coverage gcov failed")
            return 2
        deletenotes = "rm -rf crypt_test.gc*"
        os.system(deletenotes)
        print("completed one cycle")
        return exitCode

    def getPathCovFile(self,input:dict)->str:
        # run the test and return 
        key = input["key"]
        key2 = input["key2"]
        iv = input["iv"]
        iv2 = input["iv2"]
        algo = input["algo"]
        plain = input["plain"]
        seedFilePath = self.createSeedFile(key,key2,iv,iv2,algo,plain)
        print("seed file path")
        print(seedFilePath)
        exitStatus = self.runScriptUbuntu(seedFilePath)
        if exitStatus == 0 or exitStatus == 1:
            return self.projectTestingDir+"/crypt_test.c.gcov"
        elif exitStatus == -1:
            return "No gcov file"
        elif exitStatus == 2:
            return None
        else:
            return None

    def parseFile(self,covFilePath:str)->dict:
        return {}
    
    def isInteresting(self,path:dict)->bool:
        return True
    
    def runTest(self,inputDict)->None:
        coverageFile:str = self.getPathCovFile(inputDict)
        path:dict = self.parseFile(covFilePath)
        interesting:bool = self.isInteresting(path)
        if interesting:
            ids = uuid.uuid4()
            self.SeedQDict[ids] = input_dict
            self.SeedQDict[ids] = path
            self.seedFile


if __name__ == "__main__":
    pwd = "/home/limjieshengubuntu/mbedtls-afl/project_testing"

    # fuzzing to get input dict 
    input_dict = {
        "key":"itzkbg2",
        "key2":"itzkbg2",
        "iv":"0123456789123456",
        "iv2":"0123456789123456",
        "algo":"CBC",
        "plain":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+-=~[];',./{}|:?<>\"123"
    }

    runner = Runner(pwd)
    # print(runner.projectTestingDir)
    covFilePath = runner.getPathCovFile(input_dict)
    print(covFilePath)
    # print(runner.runScriptUbuntu("aes_combined_seed/aes_combined_cbc_keynomatch.txt"));
    print(runner.runScriptUbuntu("aes_combined_seed/aes_combined_cbc.txt"));
    



    # Fuzzer.createSeedFile(
    #     "itzkbg2", "itzkbg2", "0123456789123456", "0123456789123456", "CBC",
    #     "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+-=~[];',./{}|:?<>\"123"
    # )
    # output = Fuzzer.runScriptUbuntu(pwd, "./python/seed.txt")
    # print("end of execution return value: "+str(output))
    # output = Fuzzer.runScriptUbuntu(pwd, "./aes_combined_seed/aes_combined_cbc.txt")
    # print("end of execution return value: "+str(output))

