from lib import *
import glob
pwd = os.path.dirname(os.path.abspath("LICENSE")) + "/project_testing"

if __name__ == "__main__":
    os.chdir(pwd)
    filedir = glob.glob("python/plot_data/*/dumpCrash*.pkl")[0]
    print(filedir)
    getSnapshotCsv(filedir,pwd)
    