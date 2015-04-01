import nose
import os
from tests.integration import SUBSCRIPTION, ONDEMAND

testfiles = [file for file in os.listdir('.')
             if file.startswith("test") and file.endswith(".py")]
try:
    for service in (SUBSCRIPTION, ONDEMAND):
        for test in testfiles:
            result = nose.run(
                argv=['-x', '-v', '-s', '--tc={0}:'.format(service), test])
            if not result:
                raise RuntimeError("Test failed")
except RuntimeError as e:
    print e
