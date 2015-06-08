tosca-vcloud-plugin
=====================


## Running Integration Tests

Create virtual environment and install plugin in dev-mode
```
virtualenv venv && source venv/bin/activate
pip install -r tosca-vcloud-plugin/dev-requirements.txt
pip install -r tosca-vcloud-plugin/test-requirements.txt
pip install -e tosca-vcloud-plugin
```
Copy configuration files from `examples` folder, fill them with relevant data
```
cp tosca-vcloud-plugin/examples/vcloud_config.yaml.example vcloud_config.yaml
cp tosca-vcloud-plugin/examples/vcloud_integration_test_config.yaml.example vcloud_integration_test_config.yaml
```
Export config files with environment variables
```
export VCLOUD_CONFIG_PATH="~/vcloud_config.yaml"
export VCLOUD_INTEGRATION_TEST_CONFIG_PATH="~/vcloud_intergation_test_config.yaml"
```
Run tests using nosetests. For subscription account use the following command
```
nosetests --tc=subscription: tosca-vcloud-plugin/tests/integration
```
For OnDemand
```
nosetests --tc=ondemand: tosca-vcloud-plugin/tests/integration
```
Run tests using tox. For subscription account use the following command
```
tox -e py27-subscription
```
For OnDemand
```
tox -e py27-ondemand
```
For all accounts
```
tox
```
For specify particular test, you can add full test name after '--'. 
For example 
```
tox -e ondemand -- \test_network_plugin.py
tox -e ondemand -- \test_network_plugin.py:ValidationOperationsTestCase
tox -e ondemand -- \test_network_plugin.py:ValidationOperationsTestCase.test_validation

```