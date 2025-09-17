#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hashlib
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs

# --- Bencode/Bdecode 编码逻辑 ---
def bencode(data):
    """将Python对象编码为Bencode格式。"""
    if isinstance(data, bytes):
        return str(len(data)).encode() + b':' + data
    elif isinstance(data, str):
        return bencode(data.encode('utf-8'))
    elif isinstance(data, int):
        return b'i' + str(data).encode() + b'e'
    elif isinstance(data, list):
        return b'l' + b''.join(bencode(item) for item in data) + b'e'
    elif isinstance(data, dict):
        sorted_items = sorted(data.items())
        encoded_items = b''
        for k, v in sorted_items:
            key = k if isinstance(k, bytes) else k.encode('utf-8')
            encoded_items += bencode(key) + bencode(v)
        return b'd' + encoded_items + b'e'
    raise TypeError(f"无法编码的类型: {type(data)}")

# --- 种子文件创建逻辑 ---
def create_torrent_file(file_path, tracker_announce_url, web_seed_url, piece_size=262144):
    """
    为一个指定文件创建 .torrent 种子。
    种子将包含Tracker URL和一个Web Seed URL（指向内置HTTP服务器）。
    返回新创建的 .torrent 文件的路径和info_hash。
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError("指定的路径不是一个有效的文件。")

    # 构造种子的元数据字典
    torrent_data = {
        b'announce': tracker_announce_url,
        b'info': {
            b'name': os.path.basename(file_path),
            b'piece length': piece_size,
            b'pieces': b'',
            b'length': os.path.getsize(file_path)
        },
        b'url-list': [web_seed_url] # Web Seed URL, 关键功能
    }

    # 计算所有文件块的SHA1哈希值
    pieces = []
    with open(file_path, 'rb') as f:
        while True:
            piece = f.read(piece_size)
            if not piece:
                break
            pieces.append(hashlib.sha1(piece).digest())

    torrent_data[b'info'][b'pieces'] = b''.join(pieces)

    # 对 'info' 字典进行Bencode编码以计算info_hash
    info_bencoded = bencode(torrent_data[b'info'])
    info_hash = hashlib.sha1(info_bencoded).hexdigest()

    # 在源文件相同目录下生成 .torrent 文件
    torrent_filename = f"{os.path.splitext(os.path.basename(file_path))[0]}.torrent"
    save_path = os.path.join(os.path.dirname(file_path), torrent_filename)

    with open(save_path, 'wb') as f:
        f.write(bencode(torrent_data))

    return save_path, info_hash

# --- Tracker 服务器逻辑 ---
_tracker_instance = None
_tracker_lock = threading.Lock()

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """支持多线程处理请求的HTTPServer。"""
    daemon_threads = True

class TrackerRequestHandler(BaseHTTPRequestHandler):
    """处理来自BT客户端的HTTP Announce请求。"""
    # 共享的torrents字典: {info_hash: {peer_id: {'ip', 'port', 'timestamp'}}}
    torrents = {}

    def do_GET(self):
        if not self.path.startswith('/announce'):
            self.send_error(404, "Not Found")
            return

        try:
            query = parse_qs(self.path.split('?', 1)[1])
            info_hash = query['info_hash'][0].encode('latin-1')
            peer_id = query['peer_id'][0].encode('latin-1')
            port = int(query['port'][0])
        except (KeyError, ValueError, IndexError):
            self.send_failure_response("请求参数缺失或无效")
            return

        # 更新或添加客户端到peer列表
        if info_hash not in self.torrents:
            self.torrents[info_hash] = {}
        
        peer_list = self.torrents[info_hash]
        peer_list[peer_id] = {'ip': self.client_address[0], 'port': port, 'timestamp': time.time()}

        # 清理超时的旧peers (例如超过30分钟)
        now = time.time()
        stale_peers = [pid for pid, data in peer_list.items() if now - data['timestamp'] > 1800]
        for pid in stale_peers:
            del peer_list[pid]
        
        # 构造响应，返回其他peers的列表
        peers_for_response = [
            {b'peer id': pid, b'ip': data['ip'], b'port': data['port']}
            for pid, data in peer_list.items() if pid != peer_id
        ]
        
        response_dict = {b'interval': 900, b'peers': peers_for_response}
        
        self.send_response(200)
        self.end_headers()
        self.wfile.write(bencode(response_dict))

    def send_failure_response(self, reason):
        response = bencode({b'failure reason': reason})
        self.send_response(400)
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format, *args):
        # 屏蔽默认的日志输出到控制台
        return

def _run_tracker_server(server_instance):
    """在线程中运行HTTP服务器的函数。"""
    try:
        server_instance.serve_forever()
    except Exception:
        pass # 服务器关闭时会抛出异常

def start_tracker(host='0.0.0.0', port=6969):
    """启动Tracker服务器并返回其实例。如果已在运行则直接返回。"""
    global _tracker_instance
    with _tracker_lock:
        if _tracker_instance and _tracker_instance['thread'].is_alive():
            return _tracker_instance

        try:
            server = ThreadedHTTPServer((host, port), TrackerRequestHandler)
            thread = threading.Thread(target=_run_tracker_server, args=(server,), daemon=True)
            thread.start()
            
            _tracker_instance = {'server': server, 'thread': thread, 'host': host, 'port': port}
            return _tracker_instance
        except Exception as e:
            # 在主程序中通过logger记录错误
            return None

def stop_tracker():
    """停止正在运行的Tracker服务器。"""
    global _tracker_instance
    with _tracker_lock:
        if _tracker_instance:
            try:
                _tracker_instance['server'].shutdown()
                _tracker_instance['server'].server_close()
                _tracker_instance['thread'].join(timeout=2)
            finally:
                _tracker_instance = None