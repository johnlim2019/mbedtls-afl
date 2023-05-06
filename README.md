## Set up 
Install mbedtls library 

Ubuntu 
`sudo apt install libmbedtls-dev`

MacOS
`brew install mbedtls`

## Files
Main files are in `project_testing` folder. 

Input 

* `project_testing/project_seed_q` contains txt of our starting seed
* `project_testing/python/PSO_Results.txt` contains the pso results that we use in out mutator optimisation.
  
Output
* these folders are created on running the fuzzer script
* `project_testing/python/plot_data` contain the tracking data, counting the number of unique paths against iterations and time. 
  * It also contains our logger file 
  * dumpCrash pickle file which contains the state of fuzzer memory.
  * mutation_sel is the number of times each mutator is chosen. 
* `project_testing/python/results` contains all the seed input files that we find through fuzzing. 

Code 
* `project_testing/python/lib.py` fuzzer
* `project_testing/python/pso.py` this is the script used to run the pso 
* `project_testing/python/old.py` this is an older version of the fuzzer object that was used in the pso.
* `project_testing/crypt_test.c` the test driver.

Intermediate files
* These are created when we run the test driver script.
* `seed.txt` is generated to be the new fuzzed input
* `crypt_test.c.gc*` gcov related files used to find branch.
* `crypt_test` is the binary compiled and used in the fuzzer
  

Commands 
```shell
# in root folder
python3 project_testing/python/lib.py
python3 project_testing/python/pso.py
```

Note 
That when using MacOS and Ubuntu, the gcov is known generate different number of executable lines and result in different number total code coverage. 