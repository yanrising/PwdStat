<h1 align="center">
PwdStat
 </h1>

CLI tool for identifying systemic password usage, creating password masks, and analyzing cracked password samples with human readable statistics to help defenders.

## Getting Started

-   [Usage](#usage)
-   [Install](#install)
-   [Output](#output)

## Usage
```sh
pwdstat.py -h

usage: pwdstat.py [-h] [-i INPUT] [-c COMPARE] [-o OUTPUT] [-f] [-q] [-v]

Tool for identifying systemic password usage, creating password masks, and analyzing cracked password samples with
human readable statistics

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Input list of passwords.
  -c COMPARE, --compare COMPARE
                        Directory of lists to compare against.
  -o OUTPUT, --output OUTPUT
                        Prints CSV files to directory. The default is cwd.
  -f, --filter          Filter subpar from results and bottom 0.01 percent of masks and tokens.
  -q, --quiet           Hides banner
  -v, --viz             Creates visuals of data in output directory.
```
Take a list of cracked passwords and analyze them.
```
pwdstat.py -i cracked_wordlist.txt

cat cracked_wordlist | pwdstat.py
```
Filter out passwords that do not meet minimum complexity requirements and the bottom 0.1% of tokens and masks.
```
cat cracked_wordlist | pwdstat.py -f
```
Compare input list against a directory of wordlists and mark ones that appear in them.
```
pwdstat.py -i cracked_wordlist.txt -c ./breach-data/
```
Input and compare but also output CSV files with data to a directory.
```
pwdstat.py -i cracked_wordlist.txt -c ./breach-data -o pwd_output
 __        __   __  ___      ___
|__) |  | |  \ /__`  |   /\   |
|    |/\| |__/ .__/  |  /~~\  |
[*] Password Stats:
[*] Reminder the sample is ONLY cracked passwords and data points should be reflected on as so
[*] Microsoft minimum password complexity requires 3 of the following criteria: 1 lowercase, 1 uppercase, 1 digit, and 1 special character.
There are 6443 passwords in the sample and the average complexity is 2.0/4 and the average length is 8.4
5181 passwords were considered subpar and did not meet minimum password requirements and had an average length of 7.9
46 passwords met the minimum complexity requirements and had an average length of 6.8
983 passwords met or exceeded minimum complexity requirements and had an average length of 9.2
143 passwords met or exceeded minimum complexity requirements and had a strong password length averaging 12.8
43 passwords met or exceeded minimum complexity requirements and had a very strong password length averaging 19.9
47 passwords well exceeded minimum complexity requirements and had a fortified password length averaging 23.0
[*] Password Lookup:
4384 passwords were also in HIBP-Top-7M.txt
2783 passwords were also in rockyou.txt
[*] Reused Passwords:
Fall2021 occurred 130 times
Password1 occurred 27 times
password occurred 13 times
Password$ occurred 4 times
Winter2021! occurred 4 times
Fall2021! occurred 4 times
zaq1!@#$ occurred 4 times
rj143 occurred 3 times
[*] Common Tokens and Words in Passwords:
The token fall2021 was used 136 times
The token $ was used 79 times
The token password1 was used 30 times
The token zaq1 was used 26 times
The token password was used 19 times
The token * was used 6 times
The token dcshoecousa was used 6 times
The token winter2021 was used 6 times
[*] Common Password Masks:
342 passwords used the mask ?d?d?d?d?d?d
For example: 640512, 118217, and 770884
325 passwords used the mask ?l?l?l?l?l?l?d?d
For example: jelena15, memory66, and jelena15
299 passwords used the mask ?l?l?l?l?l?l
For example: rizqie, rizqie, and dcshew
259 passwords used the mask ?l?l?l?l?l?l?l?l
For example: dcsgjskg, dcrowdie, and dcrooter
251 passwords used the mask ?l?l?l?l?l?d?d?d?d?d
For example: frame12175, glass80034, and shark57315
233 passwords used the mask ?l?l?l?l?l?l?l
For example: chogori, chogori, and dcshete
184 passwords used the mask ?l?l?l?l?l?l?l?d?d
For example: dcshoes21, dcshoes13, and dcshoes01
165 passwords used the mask ?l?l?l?l?l?d?d
For example: jessi03, jessi03, and dcsan13
```


## Install
**PwdStat** works on Windows and *Nix systems and requires Python.
```
git clone 
```
```
pip install -r requirements.txt
```
## Output
The `-o` flag is used to direct the CSV output files to a directory by default **PwdStat** does not print output files. 
The files are **tab** seperated for easy parsing without quoting issues.
```
cat passwords.csv | awk -F '\t' '{print $1}'
```

Graphs can also be created with `-v` and created visuals are in PDF format and are printed to the same output directory:

- Common Password Tokens
- Password Classes of Cracked Passwords
- Average Length of Cracked Passwords
- Common Password Masks

***

### passwords.csv
All of the passwords from the set tagged
|Password|Class|Complexity|Length|Mask|Is In *|
|---|---|--|--|--|--|
|Password|Rating given to password based on criteria|Complexity rating out of four|Length of password|Password mask in Hashcat format|Is the password in this file (repeated for all files in directory)|

### passwords_agg.csv
All of the passwords from the set aggregated by password to remove duplicates
|Password|Count|Complexity|Length|
|---|---|--|--|
|Password|Occurrences in list|Average complexity rating|Average length of password

### common_tokens.csv
Words and tokens from the passwords sorted by count. Passwords are passed to NLTK for parsing.
|Tokens|Count|
|---|---|
|Password token|Count of token in all passwords|

### password_classes.csv
All of the passwords from the set aggregated by class
|Class|Count|Complexity|Length|
|---|---|--|--|
|Password class|Occurrences in list|Average complexity rating|Average length of password

### password_masks.csv
All of the passwords from the set aggregated by mask
|Class|Count|Complexity|Length|
|---|---|--|--|
|Password mask|Occurrences in list|Average complexity rating|Average length of password
