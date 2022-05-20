from email import policy
from email.parser import BytesParser
from glob import glob
import sys
import os.path
import re


def test_files(files, check_part):
    while files:
        file = files.pop(0)
        if os.path.isdir(file):
            files = files + glob(file + '/*')
            continue
        if not os.path.isfile(file):
            continue

        with open(file,'rb') as fp:
            msg = BytesParser(policy=policy.default).parse(fp)
        subj = re.match(r'\[\d\] \S+', msg['subject']).group(0)

        found = 0
        for part in msg.walk():
            name = part.get_filename()
            if not name:
                continue
            try:
                content = part.get_content()
            except:
                continue
            if check_part(name,content):
                found +=1 

        if found:
            print(subj)
        else:
            print("NOT " + subj, file=sys.stderr)
        if msg.defects:
            print("ERR " + str(msg.defects))


eicar = b'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
def _check_part_eicartxt(name,content):
    if isinstance(content,str):
        content=str.encode(content)
    if re.search(r'\.txt$',name) and eicar in content:
        return True
    return False

def _check_part_zipname(name,content):
    return True if re.search(r'\.zip$',name) else False

# comment out the test we want to run
test_files(sys.argv[1:], _check_part_eicartxt)
## test_files(sys.argv[1:], _check_part_zipname)
