#!/usr/bin/env python3
"""Ступень 2 (extract): pcap -> per-session CSV записей TLS.

Работает ТОЛЬКО с проводным слоем — размеры TLS-записей, тайминг, направление.
Расшифровки нет (TLS 1.3), и она не нужна: цензор её тоже не делает.

Направление ("up"=клиент->сервер, "down"=сервер->клиент) определяется по
--server-port. Сессия = TCP-поток (tcp.stream), чтобы несколько коннектов в
одном pcap не смешивались.

Выход (stdout или -o): CSV  session,ts,dir,record_len,content_type
"""
import argparse, csv, subprocess, sys

FIELDS = ["frame.time_epoch", "tcp.stream", "tcp.dstport",
          "tls.record.length", "tls.record.content_type"]

def run_tshark(pcap, server_port):
    # -Y tls.record: только кадры с TLS-записями. Одна строка на кадр; в кадре
    # может быть несколько записей -> поля приходят как "a,b,c".
    cmd = ["tshark", "-r", pcap, "-Y", "tls.record.length",
           "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a"]
    for f in FIELDS:
        cmd += ["-e", f]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(f"tshark failed on {pcap}")
    return proc.stdout

def parse(out, pcap_tag, server_port):
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        ts, stream, dstport, lens, ctypes = parts[:5]
        try:
            ts = float(ts)
        except ValueError:
            continue
        # up = клиент -> сервер (dst == server_port)
        dports = dstport.split(",")
        lengths = [x for x in lens.split(",") if x]
        types = ctypes.split(",")
        for i, ln in enumerate(lengths):
            dp = dports[i] if i < len(dports) else dports[-1]
            ct = types[i] if i < len(types) else (types[-1] if types else "")
            direction = "up" if dp == str(server_port) else "down"
            rows.append({
                "session": f"{pcap_tag}#{stream}",
                "ts": ts, "dir": direction,
                "record_len": int(ln), "content_type": ct,
            })
    return rows

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--server-port", type=int, default=443,
                    help="порт relay/сайта (divany=443, nearsky relay=8443 если снимаем за nginx)")
    ap.add_argument("--tag", help="метка класса, префикс session (напр. veil-active)")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()
    tag = a.tag or a.pcap.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    rows = parse(run_tshark(a.pcap, a.server_port), tag, a.server_port)
    fh = open(a.out, "w", newline="") if a.out else sys.stdout
    w = csv.DictWriter(fh, fieldnames=["session", "ts", "dir", "record_len", "content_type"])
    w.writeheader()
    w.writerows(rows)
    if a.out:
        fh.close()
    sys.stderr.write(f"{tag}: {len(rows)} records, "
                     f"{len(set(r['session'] for r in rows))} sessions\n")

if __name__ == "__main__":
    main()
