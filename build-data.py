
import os
import yaml
import json

def main():
    inventory_dir = 'inventory'
    keys = []
    for filename in os.listdir(inventory_dir):
        if filename.endswith('.yaml'):
            filepath = os.path.join(inventory_dir, filename)
            with open(filepath, 'r') as f:
                try:
                    key_data = yaml.safe_load(f)
                    if key_data:
                        keys.append(key_data)
                except yaml.YAMLError as e:
                    print(f"Error parsing YAML file {filename}: {e}")

    with open('docs/keys.json', 'w') as f:
        json.dump(keys, f, indent=2)

if __name__ == '__main__':
    main()
