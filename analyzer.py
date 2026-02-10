def count_ip_occurrences(data):
    ip_list = [line[1] for line in data]
    return {ip:ip_list.count(ip) for ip in set(ip_list) }

