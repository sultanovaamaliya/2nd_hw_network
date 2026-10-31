import random
import struct
import socket

A_ROOT = "198.41.0.4"


def dns_server():
    dom = input("Введите домен: ")
    server_ip = A_ROOT

    if ".multiply." in dom:
        index = dom.find(".multiply.")
        new_dom = dom[:index]
        arr = new_dom.split(".")
        mult = 1
        for x in arr:
            mult *= int(x)
        print(f"127.0.0.{mult % 256}")
        return

    while True:
        header = struct.pack("!HHHHHH", random.randint(1, 65535), 0, 1, 0, 0, 0)

        quest_body = b""
        for part in dom.split('.'):
            l = bytes([len(part)])
            encod = part.encode()
            quest_body += bytes(l) + encod
        quest_body += b'\x00'

        qtype_qclass = struct.pack("!HH", 1, 1)

        query = header + quest_body + qtype_qclass #ручное формирование запроса
        print(f"\nЗапрос к {server_ip}: {dom}")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(query, (server_ip, 53))
        data, _ = sock.recvfrom(4096)
        print(data)
        sock.close()

        id_, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", data, 0)
        print(f"ID: {id_}, Флаги: {flags}")
        print(f"Вопросов (qd): {qd}")
        print(f"Ответов с IP (an): {an}")
        print(f"Серверов делегатов (ns): {ns}")
        print(f"Доп. записей с IP серверов (ar): {ar}")

        offset = 12
        for _ in range(qd):
            _, offset = readname(data, offset)
            offset += 4

        answers = []
        for _ in range(an):
            rr, offset = parse_rr(data, offset)
            answers.append(rr)

        for rr in answers:
            if rr["type"] == 1 and rr["name"].rstrip('.') == dom.rstrip('.'):
                ip = socket.inet_ntoa(
                    data[rr["rdata_offset"]:rr["rdata_offset"] + 4]
                )
                print(f"\nУСПЕХ: {dom} -> {ip}")
                return

        zone_name = []
        name_ip = {}

        for _ in range(ns):
            rr, offset = parse_rr(data, offset)
            if rr["type"] == 2:
                zone = rr["name"]
                host, _ = readname(data, rr["rdata_offset"])
                zone_name.append((zone, host))

        for _ in range(ar):
            rr, offset = parse_rr(data, offset)
            if rr["type"] == 1:
                ip = socket.inet_ntoa(data[rr["rdata_offset"]:rr["rdata_offset"] + 4])
                name_ip[rr['name']] = ip

        next_ip = None
        for zone, host in zone_name:
            if host in name_ip:
                next_ip = name_ip[host]
                break

        if not next_ip:
            print("\nНет glue-записей для NS, дальше идти не можем.")
            return

        server_ip = next_ip


def readname(data, offset):
    parts_dom = []
    jump = False
    orig_offset = offset

    while True:
        length = data[offset]
        if length & 0xC0 == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            offset = ptr
            if not jump:
                orig_offset += 2
                jump = True
            continue

        if length == 0:
            if not jump:
                orig_offset = offset + 1
            break

        offset += 1
        parts_dom.append(data[offset:offset + length].decode())
        offset += length

    name = ".".join(parts_dom)
    return name or ".", orig_offset


def parse_rr(data, offset):
    '''Разбop Resource Record, возвращает (rr_dict, новый_offset).
    rr_dict: {name, type, cls, ttl, rdlength, rdata_offset}'''
    name, offset = readname(data, offset)
    rtype, rcls, rttl, rdlength = struct.unpack_from("!HHIH", data, offset)
    offset += 10
    rdataoffset = offset
    offset += rdlength

    return {
        "name" : name,
        "type" : rtype,
        "cls" : rcls,
        "ttl" : rttl,
        "rdlength" : rdlength,
        "rdata_offset" : rdataoffset
    }, offset


if __name__ == '__main__':
    dns_server()
