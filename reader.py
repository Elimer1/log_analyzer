from pathlib import Path

def file_to_list(file_path)->list[list[str]]:
    with open(file_path,"r") as file:
        return [packet.strip().split(",") for packet in file.readlines()]

def port_to_protocol(data):
    return {list[3]:list[4] for list in data}

print(file_to_list("test.log"))