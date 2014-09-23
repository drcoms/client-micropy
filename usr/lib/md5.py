import os

def md5(s):
    os.system("echo %s | md5sum " % s + r"| awk '{print $1}' | sed 's/\(..\)/\\x\1/g'" + '> /tmp/drcom_md5')
    with open('/tmp/drcom_md5', 'r') as f:
        foo = f.read().strip()
    return eval('"%s"' % foo)
