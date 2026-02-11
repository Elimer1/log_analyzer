from checks import *

suspicion_checks = {
    "EXTERNAL_IP": lambda line: check_external_ips(line),
    "LARGE_PACKET": lambda line: filter_by_size(line),
    "NIGHT_ACTIVITY": lambda line: check_night_activity(line),
    "SENSITIVE_PORT": lambda line: filter_by_sensitive_port(line)
}

def count_ip_occurrences(data):
    ip_list = [line[1] for line in set(data)]
    return {ip:ip_list.count(ip) for ip in ip_list }

def identify_suspicion_types(data):
    suspicious_dict = {}
    for line in data:
        ip = line[1]
        if ip not in suspicious_dict:
            suspicious_dict[ip] = set()

        if check_external_ips(line):
            suspicious_dict[ip].add("EXTERNAL_IP")
        if filter_by_sensitive_port(line):
            suspicious_dict[ip].add("SENSITIVE_PORT")
        if filter_by_size(line):
            suspicious_dict[ip].add("LARGE_PACKET")
        if check_night_activity(line):
            suspicious_dict[ip].add("NIGHT_ACTIVITY")

    for ip in suspicious_dict:
        suspicious_dict[ip] = list(suspicious_dict[ip])
    return suspicious_dict

def filter_high_threat_ips(suspicious_dict):
    return {ip: suspicious_dict[ip] for ip in suspicious_dict if len(suspicious_dict[ip]) >= 2}

def get_hour(time_list):
    return list(map(lambda timestamp:datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S").hour,time_list ))

def b_to_kb(size_list):
    return list(map(lambda byte: byte / 1024,size_list))

def filter_by_port(data):
    return list(filter(lambda line: line[3] in SENSITIVE_PORTS,data))

def filter_by_night(data):
    return list(filter(lambda line: NIGHT_START <= datetime.strptime(line[0], "%Y-%m-%d %H:%M:%S").hour < NIGHT_END, data))

def inspector(line,lambda_dict):
    return list(filter(lambda key: lambda_dict[key](line),lambda_dict))

def process_all_logs(data):
    return list(filter(lambda suspicions: len(suspicions) > 0, map(lambda row: inspector(row, suspicion_checks), data)))

