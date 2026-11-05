import random
import struct
import socket

A_ROOT = "198.41.0.4"


def normalize_name(name):
    name = name.rstrip(".")
    try:
        return name.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return name.lower()

def is_in_zone(name, zone):
    name = normalize_name(name)
    zone = normalize_name(zone)

    return not zone or name == zone or name.endswith("." + zone)

def recv_exact(sock, size):
    result = b""

    while len(result) < size:
        part = sock.recv(size - len(result))
        if not part:
            raise OSError("DNS-соединение закрыто до получения полного ответа.")
        result += part

    return result

def send_dns_query(server_ip, query):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(4)
        sock.sendto(query, (server_ip, 53))
        data, _ = sock.recvfrom(4096)

    if len(data) < 12:
        raise OSError("Получен слишком короткий DNS-ответ.")

    flags = struct.unpack_from("!H", data, 2)[0]

    if flags & 0x0200:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            sock.connect((server_ip, 53))
            sock.sendall(struct.pack("!H", len(query)) + query)

            response_len = struct.unpack("!H", recv_exact(sock, 2))[0]
            data = recv_exact(sock, response_len)

    return data


def dns_server():
    dom = input("Введите домен: ").strip().rstrip(".")
    type_dom = input("Тип записи: ").strip().upper()
    server_ips = [A_ROOT]

    index = dom.lower().find(".multiply.")

    if index != -1:
        new_dom = dom[:index]
        arr = new_dom.split(".")

        if any(not x.isascii() or not x.isdigit() for x in arr):
            print("Перед .multiply. должны быть числа.")
            return

        mult = 1
        for x in arr:
            mult = (mult * int(x)) % 256
        print(f"127.0.0.{mult}")
        return

    QTYPE_MAP = {
        "A": 1,
        "AAAA": 28,
        "CNAME": 5,
        "MX": 15,
        "NS": 2,
        "SOA": 6,
        "ANY": 255
    }
    qtype = QTYPE_MAP.get(type_dom, 1)  # по умолчанию A
    seen_cnames = {normalize_name(dom)}
    cname_hops = 0

    while True:
        header = struct.pack("!HHHHHH", random.randint(1, 65535), 0, 1, 0, 0, 0)

        quest_body = b""
        for part in dom.split('.'):
            encod = part.encode("idna")
            l = bytes([len(encod)])
            quest_body += l + encod
        quest_body += b'\x00'

        qtype_qclass = struct.pack("!HH", qtype, 1)
        query = header + quest_body + qtype_qclass #ручное формирование запроса
        data = None

        for server_ip in server_ips:
            print(f"\nЗапрос к {server_ip}: {dom}")

            try:
                data = send_dns_query(server_ip, query)
                break
            except OSError as error:
                print(f"Ошибка от {server_ip}: {error}")

        if data is None:
            print("Ни один из DNS-серверов не ответил.")
            return

        print(data)

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

        #if для A/AAAA/MX и т.д. пришёл CNAME — поиск уже для имени, на которое он указывает
        if qtype not in (5, 255):
            cname_target = None

            for rr in answers:
                if (rr["type"] == 5 and normalize_name(rr["name"]) == normalize_name(dom)):
                    cname_target, _ = readname(data, rr["rdata_offset"])
                    break

            if cname_target is not None:
                target_norm = normalize_name(cname_target)

                if target_norm in seen_cnames or cname_hops >= 10:
                    print("Обнаружен цикл CNAME или слишком длинная цепочка.")
                    return

                print(f"CNAME: {dom} -> {cname_target}")

                seen_cnames.add(target_norm)
                cname_hops += 1
                dom = cname_target.rstrip(".")
                server_ips = [A_ROOT]
                continue


        for rr in answers:
            if normalize_name(rr["name"]) != normalize_name(dom):
                continue

            #если запрос не ANY, фильтруем по типу
            if qtype != 255 and rr["type"] != qtype:
                continue

            off = rr["rdata_offset"]
            length = rr["rdlength"]
            rdata = data[off:off + length]
            t = rr["type"]

            if t == 1: #A
                ip = socket.inet_ntoa(rdata)
                print(f"\nУСПЕХ A: {dom} -> {ip}")
                return

            elif t == 28: #AAAA
                ip6 = socket.inet_ntop(socket.AF_INET6, rdata)
                print(f"\nУСПЕХ AAAA: {dom} -> {ip6}")
                return

            elif t in (2, 5): #NS/CNAME
                target, _ = readname(data, off)
                tname = "NS" if t == 2 else "CNAME"
                print(f"\nУСПЕХ {tname}: {dom} -> {target}")
                return

            elif t == 15: #MX
                pref = struct.unpack_from("!H", data, off)[0]
                exch, _ = readname(data, off + 2)
                print(f"\nУСПЕХ MX: {dom} -> {pref} {exch}")
                return

            elif t == 6: #SOA
                mname, o2 = readname(data, off)
                rname, o3 = readname(data, o2)
                serial, refresh, retry, expire, minimum = struct.unpack_from("!IIIII", data, o3)
                print(f"\nУСПЕХ SOA: {dom} -> {mname} {rname} {serial} {refresh} {retry} {expire} {minimum}")
                return

            else:
                # для редких
                print(f"\nУСПЕХ TYPE {t}: RDATA = {rdata.hex()}")
                return

        if flags & 0x0400:  # AA: ответ авторитетного сервера
            print(f"\nАвторитетный ответ получен, записи типа {type_dom} нет.")
            return

        zone_name = []
        name_ip = {}

        for _ in range(ns):
            rr, offset = parse_rr(data, offset)
            if rr["type"] == 2: # NS
                zone = rr["name"]
                host, _ = readname(data, rr["rdata_offset"])
                zone_name.append((zone, host))

        for _ in range(ar):
            rr, offset = parse_rr(data, offset)
            if rr["type"] == 1:
                ip = socket.inet_ntoa(data[rr["rdata_offset"]:rr["rdata_offset"] + 4])
                name_ip[normalize_name(rr["name"])] = ip

        referrals = [
            (zone, host)
            for zone, host in zone_name
            if is_in_zone(dom, zone)
        ]

        next_ips = []

        for zone, host in referrals:
            ip = name_ip.get(normalize_name(host))
            # Если glue-записи нет, отдельно ищем A-запись для NS
            if ip is None:
                ip = resolve_a_iteratively(host)

            if ip and ip not in next_ips:
                next_ips.append(ip)

        if not next_ips:
            print("\nНе удалось получить IPv4-адреса NS-серверов.")
            return

        server_ips = next_ips


def readname(data, offset):
    parts_dom = []
    jump = False
    orig_offset = offset

    while True:
        length = data[offset]
        if length & 0xC0 == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[offset + 1]

            if not jump:
                orig_offset = offset + 2
                jump = True
            offset = ptr
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


def resolve_a_iteratively(name, resolving=None, depth=0):
    if resolving is None:
        resolving = set()

    name = name.rstrip(".")
    name_norm = normalize_name(name)
    resolving.add(name_norm)

    try:
        servers = [A_ROOT]
        visited = set()

        while servers:
            state = (name_norm, tuple(servers))
            if state in visited:
                return None
            visited.add(state)

            quest_body = b""
            for part in name.split("."):
                encoded = part.encode("idna")
                l = bytes([len(encoded)])
                quest_body += l + encoded
            quest_body += b"\x00"

            request_id = random.randint(0, 65535)
            header = struct.pack("!HHHHHH", request_id, 0, 1, 0, 0, 0)
            query = header + quest_body + struct.pack("!HH", 1, 1)

            data = None

            # Пробуем все известные адреса DNS-серверов
            for server_ip in servers:
                try:
                    data = send_dns_query(server_ip, query)
                    break
                except OSError:
                    continue

            _, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", data, 0)

            if flags & 0x000F:  # RCODE
                return None

            offset = 12

            for _ in range(qd):
                _, offset = readname(data, offset)
                offset += 4

            answers = []

            for _ in range(an):
                rr, offset = parse_rr(data, offset)
                answers.append(rr)

            # Ищем A-запись для нужного имени
            for rr in answers:
                if (
                    rr["type"] == 1
                    and normalize_name(rr["name"]) == name_norm
                    and rr["rdlength"] == 4
                ):
                    return socket.inet_ntoa(
                        data[rr["rdata_offset"]:rr["rdata_offset"] + 4]
                    )

            # Если имя является CNAME, ищем адрес его цели
            for rr in answers:
                if (
                    rr["type"] == 5
                    and normalize_name(rr["name"]) == name_norm
                ):
                    target, _ = readname(data, rr["rdata_offset"])
                    return resolve_a_iteratively(
                        target, resolving, depth + 1
                    )

            # Авторитетный ответ без A-записи — дальше делегации нет
            if flags & 0x0400:
                return None

            zone_name = []
            name_ip = {}

            for _ in range(ns):
                rr, offset = parse_rr(data, offset)

                if rr["type"] == 2:
                    host, _ = readname(data, rr["rdata_offset"])
                    zone_name.append((rr["name"], host))

            for _ in range(ar):
                rr, offset = parse_rr(data, offset)

                if rr["type"] == 1 and rr["rdlength"] == 4:
                    ip = socket.inet_ntoa(
                        data[rr["rdata_offset"]:rr["rdata_offset"] + 4]
                    )
                    name_ip[normalize_name(rr["name"])] = ip

            referrals = [
                (zone, host)
                for zone, host in zone_name
                if is_in_zone(name, zone)
            ]

            # Если есть glue-записи, используем их
            next_servers = []

            for _, host in referrals:
                ip = name_ip.get(normalize_name(host))
                if ip and ip not in next_servers:
                    next_servers.append(ip)

            # Если glue нет, отдельно разрешаем имена NS-серверов
            if not next_servers:
                for _, host in referrals:
                    ip = resolve_a_iteratively(host, resolving, depth + 1)
                    if ip and ip not in next_servers:
                        next_servers.append(ip)

            servers = next_servers
        return None

    finally:
        resolving.discard(name_norm)


if __name__ == '__main__':
    dns_server()
