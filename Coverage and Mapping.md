### Installing afl-cov manually
``` bash
# Install dependencies first
sudo apt install git python3 lcov -y
```
### Clone afl-cov from GitHub
``` bash
cd ~/Desktop
git clone https://github.com/mrash/afl-cov.git

# Verify it downloaded
ls afl-cov/

# Instrument bzip for coverage
gcc -O0 -g --coverage -fprofile-arcs -ftest-coverage bzip2.c -o bzip2_cov
``` 
### Run the commands
``` bash
# For decompression
python2 ~/Desktop/FuzzingProject/afl-cov/afl-cov \
        -d decompress/output_decompress \
        --coverage-cmd "./bzip2_cov -d AFL_FILE" \
        --code-dir . \
        --overwrite
        
# For compression
python2 ~/Desktop/FuzzingProject/afl-cov/afl-cov \
        -d compress/output_compress \
        --coverage-cmd "./bzip2_cov -z AFL_FILE" \
        --code-dir . \
        --overwrite
``` 
### To map coverage run each python script & make sure the file paths inside match
``` bash
python3 annotate_uncompressStream_cfg.py
python3 annotate_BZ2_bzWrite_cfg.py
``` 
