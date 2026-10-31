#!/usr/bin/env python3
"""Minimal cleartext FTP server for UC-12 (LAB NDR).

Replaces pyftpdlib (incompatible with Python 3.12: it imports asynchat/asyncore).
Speaks just enough RFC 959 for the Windows ftp.exe client to complete a
USER/PASS/QUIT login so Suricata's FTP app-layer parser sees the credentials.

Usage: sudo python3 mini_ftpd.py            # binds 0.0.0.0:21
"""
import socket
import threading

HOST = "0.0.0.0"
PORT = 21


def handle(conn, addr):
    try:
        conn.sendall(b"220 LAB FTP ready\r\n")
        user = None
        while True:
            data = conn.recv(4096)
            if not data:
                break
            line = data.decode("utf-8", "replace").strip()
            cmd = line.split(" ", 1)[0].upper() if line else ""
            arg = line.split(" ", 1)[1] if " " in line else ""
            if cmd == "USER":
                user = arg
                conn.sendall(b"331 Password required\r\n")
            elif cmd == "PASS":
                conn.sendall(b"230 Login successful\r\n")
            elif cmd == "QUIT":
                conn.sendall(b"221 Goodbye\r\n")
                break
            elif cmd in ("SYST",):
                conn.sendall(b"215 UNIX Type: L8\r\n")
            elif cmd in ("TYPE", "PWD", "CWD", "PORT", "PASV", "OPTS"):
                conn.sendall(b"200 OK\r\n")
            else:
                conn.sendall(b"500 Unknown command\r\n")
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(5)
    print(f"[*] mini_ftpd listening on {HOST}:{PORT}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
