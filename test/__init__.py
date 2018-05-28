import os
import subprocess


def setup():
    print "Module setup"
    test_dir = os.path.dirname(os.path.abspath(__file__))
    os.environ['CONFIG'] = test_dir + '/config.yaml'
    caf = './cacert'
    if not os.path.exists(caf):
        print "Generate a key pair using ssh-keygen -f cacert -N \'\'"
        raise OSError("Missing CA cert")
