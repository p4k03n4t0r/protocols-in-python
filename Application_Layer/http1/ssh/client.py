import base64
import paramiko
import os

USER = os.environ.get('USER')
key = paramiko.RSAKey.from_private_key_file("/home/{}/.ssh/azure".format(USER))
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect('13.95.7.28', username=USER, pkey=key)
stdin, stdout, stderr = client.exec_command('ls')
for line in stdout:
    print('... ' + line.strip('\n'))
client.close()