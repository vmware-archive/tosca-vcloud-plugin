# Simple syntax check for blueprints and json examples
import yaml

yaml_files = ['../examples/blueprint.yaml',
              '../manager_blueprint/vcloud-manager-blueprint.yaml',
              '../plugin.yaml']


for filename in yaml_files:
    try:
        yaml.load(open(filename))
    except yaml.scanner.ScannerError as e:
        print e
    except IOError as e:
        print e
