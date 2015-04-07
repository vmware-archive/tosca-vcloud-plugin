# Simple syntax check for blueprints and json examples

import yaml
import json

yaml_files = ['../examples/blueprint.yaml',
              '../manager_blueprint/vcloud-manager-blueprint.yaml',
              '../plugin.yaml']

json_files = ['../examples/vcloud_config.json.example',
              '../examples/vcloud_config_ondemand.json.example',
              '../examples/vcloud_integration_test_config.json.example',
              '../manager_blueprint/inputs.json.example']

for filename in yaml_files:
    try:
        yaml.load(open(filename))
    except yaml.scanner.ScannerError as e:
        print e
    except IOError as e:
        print e

for filename in json_files:
    try:
        json.load(open(filename))
    except ValueError as e:
        print filename, e
    except IOError as e:
        print e
