from checks import *

def count_ip_occurrences(data):
    ip_list = [line[1] for line in data]
    return {ip:ip_list.count(ip) for ip in set(ip_list) }

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

def filter_high_threat_ips(suspicious_dict)