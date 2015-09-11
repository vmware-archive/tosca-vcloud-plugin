# Copyright (c) 2014 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
