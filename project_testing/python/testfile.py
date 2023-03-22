import subprocess
import os
pwd = "/home/limjieshengubuntu/mbedtls-afl/project_testing"

import re 
try:
    os.chdir(pwd)
except Exception as e:
    print(e)
    print("unable to change pwd")
compileStr = "gcc --coverage crypt_test.c -o crypt_test -lmbedcrypto -lmbedtls"
if os.system(compileStr) != 0:
    print("did not compile")
runTest = ["./crypt_test", "./aes_combined_seed/aes_combined_cbc.txt"]
exitCode = subprocess.run(runTest, stdout=subprocess.DEVNULL).returncode
if exitCode > 1:
    print("Program crash no path generated")
coverage = ["gcov", "crypt_test.c", "-m"]
p = subprocess.run(coverage, stdout=subprocess.PIPE)
currPathCov = p.stdout.decode()
regpattern = r"(?<=Lines executed:)(.*)(?=%)"
currPathCov = re.search(regpattern,currPathCov).group(0)
print(currPathCov)
if p.returncode != 0:
    print("coverage gcov failed")
deletenotes = "rm -rf crypt_test.gc*"
os.system(deletenotes)
# print("completed one cycle")