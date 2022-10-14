import os
import csv

def get_file_path(filename):
    return os.path.dirname(os.path.abspath(__file__)) + '\\' + filename

def open_input_file():
    complete_filepath = get_file_path('input.txt')
    lines = ''
    with open(complete_filepath, 'r') as f:
        lines = f.read().splitlines()
    for l in lines:
        print(l)

def create_csv_result(dictionary: dict):
    complete_filepath = get_file_path('output.csv')
    with open(complete_filepath, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=dictionary.keys())
        writer.writeheader()
        writer.writerow(dictionary)

def update_csv_result(dictionary: dict):
    complete_filepath = get_file_path('output.csv')
    with open(complete_filepath, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=dictionary.keys())
        # writer.writeheader()
        writer.writerow(dictionary)

