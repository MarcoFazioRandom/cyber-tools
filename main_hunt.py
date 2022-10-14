import os
import csv
import scan_tools

def get_file_path(filename):
    return os.path.dirname(os.path.abspath(__file__)) + '\\' + filename

def open_input_file():
    complete_filepath = get_file_path('input.txt')
    lines = ''
    with open(complete_filepath, 'r') as f:
        lines = f.read().splitlines()
    return lines

def clear_file(filename):
    complete_filepath = get_file_path(filename)
    with open(complete_filepath, 'r+') as file:
        file.truncate(0)

def hunt():
    print('start scanning: ')
    clear_file('output.csv')
    target_list = open_input_file()
    # Delete duplicates 
    target_list = list(set(target_list))
    tot = len(target_list)
    found_count = 0
    complete_filepath = get_file_path('output.csv')
    with open(complete_filepath, 'a', newline='') as file:
        for i in range(tot):
            target = target_list[i]
            print(f'hunting for {target}... ')
            result = {'target': target}
            scan_result = scan_tools.hunt(target)
            is_empty = not any(scan_result.values())
            if is_empty:
                print('- not found')
            else:
                print('- found')
                result.update(scan_result)
                found_count += 1
                writer = csv.DictWriter(file, fieldnames=result.keys())
                if found_count == 1:
                    writer.writeheader()
                writer.writerow(result)
    print(f'found {found_count} matches out of {tot}')
    return found_count

found_count = hunt()
