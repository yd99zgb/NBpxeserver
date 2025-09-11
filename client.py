### 文件: client.py (已修复UI显示问题的最终版本)

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import configparser
import os
import subprocess
import shlex 
import socket
import time
import re
from tkinter.scrolledtext import ScrolledText

# --- 文件名常量 ---
CONFIG_INI_FILENAME = 'ipxefm_cli.ini'
IPXEBOOT_TXT_PATH = 'ipxeboot.txt'
INIT_IPXE_PATH = 'Boot/ipxefm/init.ipxe'
# --- 服务端探测客户端的特殊MAC地址 ---
PROBE_MAC = '00-11-22-33-44-55'

# ################################################################# #
# #################### iPXE 文件管理器 (新功能) #################### #
# ################################################################# #

# =======================[ 核心修复点 1: 替换为更稳定的滚动框架 ]=======================
class ScrolledFrame(ttk.Frame):
    """
    一个稳定可靠、带垂直滚动条的 ttk.Frame 容器。
    所有内容都应被添加到 .viewPort 属性中。
    """
    def __init__(self, parent, *args, **kw):
        super().__init__(parent, *args, **kw)

        # 创建一个 canvas 和一个垂直滚动条
        self.canvas = tk.Canvas(self, borderwidth=0, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        # 将滚动条和 canvas 放置到主 Frame 中
        self.scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)

        # 这个内部 Frame 将容纳所有子控件，并且它本身是可以滚动的
        self.viewPort = ttk.Frame(self.canvas)
        
        # 将内部 Frame 放入 canvas
        self.canvas_window = self.canvas.create_window((0, 0), window=self.viewPort, anchor="nw")

        # 绑定事件以实现滚动功能
        self.viewPort.bind("<Configure>", self._on_frame_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)
        
        # 绑定鼠标滚轮事件
        self.bind_all("<MouseWheel>", self._on_mousewheel, add=True)

    def _on_frame_configure(self, event):
        # 当内部 Frame 的大小改变时，更新 canvas 的滚动区域
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        # 当 canvas 的大小改变时，调整内部 Frame 的宽度以匹配
        self.canvas.itemconfig(self.canvas_window, width=event.width)

    def _on_mousewheel(self, event):
        # 仅当鼠标悬停在此控件上时才响应滚轮事件
        if self.winfo_containing(event.x_root, event.y_root) is not self:
             # 如果不是直接在滚动条或画布上，检查是否在子控件上
            widget_under_mouse = self.winfo_containing(event.x_root, event.y_root)
            if not widget_under_mouse or not str(widget_under_mouse).startswith(str(self)):
                return

        # 跨平台滚轮支持
        if event.delta:
            self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        else:
            if event.num == 5:
                self.canvas.yview_scroll(1, "units")
            elif event.num == 4:
                self.canvas.yview_scroll(-1, "units")

# =======================[ 修复结束 ]=======================


class IPXEFileManager(tk.Toplevel):
    """
    用于智能管理 ipxeboot.txt 和 init.ipxe 文件的图形化界面。
    """
    def __init__(self, parent):
        super().__init__(parent)
        self.title("iPXEFM 管理器")
        self.geometry("900x700")
        self.transient(parent)
        self.grab_set()

        self.ipxeboot_vars = {}
        self.init_ipxe_vars = {}
        self.ipxeboot_lines = []
        self.init_ipxe_lines = []
        self.var_pattern = re.compile(r'^\s*set\s+([a-zA-Z0-9_-]+)\s+(.*)')

        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill="both", expand=True)
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill="both", expand=True)

        if not self._load_data():
            self.destroy()
            return

        boot_files_frame = ttk.Frame(notebook, padding=5)
        # =======================[ 核心修复点 2: 正确创建和添加第二个选项卡 ]=======================
        global_settings_scrolled_frame = ScrolledFrame(notebook)
        
        notebook.add(boot_files_frame, text="启动项管理 (ipxeboot.txt)")
        notebook.add(global_settings_scrolled_frame, text="全局参数配置 (init.ipxe)")

        self._create_boot_files_ui(boot_files_frame)
        self._create_global_settings_ui(global_settings_scrolled_frame.viewPort)
        # =======================[ 修复结束 ]=======================

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill="x", pady=(10, 0))
        ttk.Button(button_frame, text="保存并关闭", command=self._save_and_close).pack(side="right", padx=5)
        ttk.Button(button_frame, text="取消", command=self.destroy).pack(side="right")

    def _read_file_with_fallback(self, filepath):
        """尝试使用 UTF-8 读取文件，如果失败，则回退到 GBK 编码。"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return f.readlines()
        except UnicodeDecodeError:
            try:
                with open(filepath, 'r', encoding='gbk') as f:
                    return f.readlines()
            except Exception as e:
                raise IOError(f"无法使用 UTF-8 或 GBK 解码文件 '{filepath}'。") from e

    def _load_data(self):
        """加载并解析两个iPXE配置文件。"""
        try:
            self.ipxeboot_lines = self._read_file_with_fallback(IPXEBOOT_TXT_PATH)
            self.init_ipxe_lines = self._read_file_with_fallback(INIT_IPXE_PATH)
        except (FileNotFoundError, IOError) as e:
            messagebox.showerror("文件读取错误", f"无法加载配置文件: {e}", parent=self)
            return False
        
        for line in self.ipxeboot_lines:
            match = self.var_pattern.match(line)
            if match:
                key, value = match.groups()
                self.ipxeboot_vars[key] = tk.StringVar(value=value.strip())
        
        for line in self.init_ipxe_lines:
            match = self.var_pattern.match(line)
            if match:
                key, value = match.groups()
                self.init_ipxe_vars[key] = tk.StringVar(value=value.strip())
        return True

    def _create_boot_files_ui(self, parent):
        """创建用于管理ipxeboot.txt中启动项的UI。"""
        notebook = ttk.Notebook(parent)
        notebook.pack(fill="both", expand=True)

        boot_types = {
            "WIM": {'prefix': 'wim', 'keys': list(map(str, range(1, 10))) + ['0'] + list('abcdefg')},
            "ISO": {'prefix': 'iso', 'keys': list(map(str, range(1, 10))) + ['0'] + list('abcdefg')},
            "IMG": {'prefix': 'img', 'keys': list(map(str, range(1, 10))) + ['0'] + list('abcdefg')},
            "VHD": {'prefix': 'vhd', 'keys': list(map(str, range(1, 10))) + ['0'] + list('abcdefg')},
            "RAMOS": {'prefix': 'ramos', 'keys': list(map(str, range(1, 10))) + ['0'] + list('abcdefg')},
            "IQN": {'prefix': 'iqn', 'keys': list(map(str, range(1, 10))) + ['0'] + list('abcdefg')},
        }

        for type_name, config in boot_types.items():
            scrolled_frame = ScrolledFrame(notebook)
            notebook.add(scrolled_frame, text=type_name)
            container = scrolled_frame.viewPort
            
            headers = ["#", "文件/资源路径", "显示名称", "任务(Job)", "注入目录", "参数2"]
            for i, header in enumerate(headers):
                ttk.Label(container, text=header, font=('Helvetica', 9, 'bold')).grid(row=0, column=i, padx=5, pady=5, sticky='w')

            row_idx = 1
            for key_suffix in config['keys']:
                prefix = config['prefix']
                
                ttk.Label(container, text=key_suffix.upper()).grid(row=row_idx, column=0, padx=5)
                self._create_entry_for_var(container, f"{prefix}{key_suffix}", row_idx, 1, 40)
                self._create_entry_for_var(container, f"{prefix}{key_suffix}name", row_idx, 2, 25)
                if type_name == "WIM":
                    self._create_entry_for_var(container, f"{prefix}{key_suffix}job", row_idx, 3, 10)
                    self._create_entry_for_var(container, f"{prefix}{key_suffix}injectdir", row_idx, 4, 10)
                    self._create_entry_for_var(container, f"{prefix}{key_suffix}args2", row_idx, 5, 10)
                row_idx += 1

    def _create_global_settings_ui(self, parent):
        """创建用于管理init.ipxe全局参数的UI。"""
        ttk.Label(parent, text="高级用户设置 (init.ipxe)", font=('Helvetica', 12, 'bold')).grid(row=0, column=0, columnspan=2, pady=10, sticky='w')
        
        row_idx = 1
        settings_map = [
            ("iSCSI 服务器地址:", "iscsiurl"),
            ("主菜单脚本名:", "scriptfile"),
            ("默认启动类型 (wim/iso...):", "ext-default"),
            ("WIM 默认启动项 (0-9):", "wimbootfile-default"),
            ("ISO 默认启动项 (0-9):", "isobootfile-default"),
            ("IMG 默认启动项 (0-9):", "imgbootfile-default"),
            ("VHD 默认启动项 (0-9):", "vhdbootfile-default"),
            ("IQN 默认启动项 (0-9):", "iqnbootfile-default"),
            ("RAMOS 默认启动项 (0-9):", "ramosbootfile-default"),
            ("BIOS WIM 启动模式:", "pcbioswimbootmode"),
            ("UEFI WIM 启动模式:", "efiwimbootmode"),
            ("BIOS ISO 启动模式:", "pcbiosisobootmode"),
            ("UEFI ISO 启动模式:", "efiisobootmode"),
            ("BIOS IMG 启动模式:", "pcbiosimgbootmode"),
            ("UEFI IMG 启动模式:", "efiimgbootmode"),
            ("BIOS VHD 启动模式:", "pcbiosvhdbootmode"),
            ("UEFI VHD 启动模式:", "efivhdbootmode"),
            ("BIOS IQN 启动模式:", "pcbiosiqnbootmode"),
            ("UEFI IQN 启动模式:", "efiiqnbootmode"),
            ("BIOS RAMOS 启动模式:", "pcbiosramosbootmode"),
            ("UEFI RAMOS 启动模式:", "efiramosbootmode"),
            ("主菜单超时 (ms):", "ext-timeout"),
            ("文件选择菜单超时 (ms):", "bootfile-timeout"),
        ]

        for label_text, var_key in settings_map:
            ttk.Label(parent, text=label_text).grid(row=row_idx, column=0, sticky='w', padx=5, pady=2)
            self._create_entry_for_var(parent, var_key, row_idx, 1, 50, var_dict=self.init_ipxe_vars)
            row_idx += 1

    def _create_entry_for_var(self, parent, key, row, col, width, var_dict=None):
        """辅助函数，用于创建 Entry 并链接到 StringVar。"""
        target_dict = self.ipxeboot_vars if var_dict is None else var_dict
        if key not in target_dict:
            target_dict[key] = tk.StringVar()
        
        entry = ttk.Entry(parent, textvariable=target_dict[key], width=width)
        entry.grid(row=row, column=col, sticky='ew', padx=5, pady=2)
        return entry

    def _save_and_close(self):
        """保存所有更改到文件并关闭窗口。"""
        try:
            self._save_file(IPXEBOOT_TXT_PATH, self.ipxeboot_lines, self.ipxeboot_vars)
            self._save_file(INIT_IPXE_PATH, self.init_ipxe_lines, self.init_ipxe_vars)
            messagebox.showinfo("保存成功", f"配置文件 '{IPXEBOOT_TXT_PATH}' 和 '{INIT_IPXE_PATH}' 已成功更新。", parent=self)
            self.destroy()
        except Exception as e:
            messagebox.showerror("保存失败", f"写入文件时发生错误: {e}", parent=self)

    def _save_file(self, path, original_lines, data_vars):
        """核心保存逻辑，替换变量值同时保留文件结构。"""
        new_lines = []
        processed_keys = set()

        for line in original_lines:
            match = self.var_pattern.match(line)
            if match:
                key = match.group(1)
                if key in data_vars:
                    new_value = data_vars[key].get().strip()
                    if not new_value:
                        new_lines.append(f"set {key} \n")
                    else:
                        new_lines.append(f"set {key} {new_value}\n")
                    processed_keys.add(key)
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)

        for key, var in data_vars.items():
            if key not in processed_keys and var.get().strip():
                new_lines.append(f"set {key} {var.get().strip()}\n")

        with open(path, 'w', encoding='utf-8', newline='\n') as f:
            f.writelines(new_lines)

# ############################################################### #
# #################### 右键菜单与客户端管理 #################### #
# ############################################################### #

class MenuEditDialog(tk.Toplevel):
    def __init__(self, parent, title, item_data=None):
        super().__init__(parent)
        self.title(title)
        self.transient(parent)
        self.grab_set()
        self.result = None
        item_data = item_data or {'name': '', 'path': '', 'args': ''}
        self.name_var = tk.StringVar(value=item_data['name'])
        self.path_var = tk.StringVar(value=item_data['path'])
        self.args_var = tk.StringVar(value=item_data['args'])
        ttk.Label(self, text="菜单名称:").grid(row=0, column=0, sticky="w", padx=10, pady=5)
        ttk.Entry(self, textvariable=self.name_var, width=40).grid(row=0, column=1, padx=10, pady=5)
        ttk.Label(self, text="执行路径:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        ttk.Entry(self, textvariable=self.path_var, width=40).grid(row=1, column=1, padx=10, pady=5)
        ttk.Label(self, text="命令参数:").grid(row=2, column=0, sticky="w", padx=10, pady=5)
        ttk.Entry(self, textvariable=self.args_var, width=40).grid(row=2, column=1, padx=10, pady=5)
        ttk.Label(self, text="占位符: %IP%, %MAC%, %NAME%, %STATUS%, %FIRMWARE%", foreground="grey").grid(row=3, column=1, sticky="w", padx=10)
        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=10)
        ttk.Button(btn_frame, text="确定", command=self.on_ok).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="取消", command=self.destroy).pack(side="left", padx=5)
        self.wait_window(self)

    def on_ok(self):
        name = self.name_var.get().strip()
        path = self.path_var.get().strip()
        if not name or not path:
            messagebox.showwarning("输入错误", "菜单名称和执行路径不能为空。", parent=self)
            return
        self.result = {'name': name, 'path': path, 'args': self.args_var.get()}
        self.destroy()

class MenuConfigWindow(tk.Toplevel):
    def __init__(self, parent, client_manager, menu_config):
        super().__init__(parent)
        self.title("右键菜单配置")
        self.transient(parent)
        self.grab_set()
        self.client_manager = client_manager
        self.local_menu_config = [dict(item) for item in menu_config]
        tree_frame = ttk.Frame(self, padding=10)
        tree_frame.pack(fill="both", expand=True)
        columns = ('name', 'path', 'args')
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='headings')
        self.tree.heading('name', text='菜单名称'); self.tree.heading('path', text='执行路径'); self.tree.heading('args', text='命令参数')
        self.tree.column('name', width=120); self.tree.column('path', width=200); self.tree.column('args', width=200)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self._populate_tree()
        btn_frame = ttk.Frame(self, padding=10); btn_frame.pack(fill="x")
        ttk.Button(btn_frame, text="添加...", command=self.add_item).pack(side="left")
        ttk.Button(btn_frame, text="编辑...", command=self.edit_item).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="删除", command=self.delete_item).pack(side="left")
        ttk.Button(btn_frame, text="上移", command=self.move_up).pack(side="left", padx=(15, 5))
        ttk.Button(btn_frame, text="下移", command=self.move_down).pack(side="left")
        action_frame = ttk.Frame(self, padding=(10,0,10,10)); action_frame.pack(fill="x")
        ttk.Button(action_frame, text="保存并关闭", command=self.save_and_close).pack(side="right")
        ttk.Button(action_frame, text="取消", command=self.destroy).pack(side="right", padx=10)

    def _populate_tree(self):
        for item in self.tree.get_children(): self.tree.delete(item)
        for item_data in self.local_menu_config: self.tree.insert('', 'end', values=(item_data['name'], item_data['path'], item_data['args']))
            
    def get_selected_iid(self):
        selection = self.tree.selection()
        if not selection: messagebox.showwarning("没有选择", "请先选择一个菜单项。", parent=self); return None
        return selection[0]

    def add_item(self):
        dialog = MenuEditDialog(self, "添加新菜单项")
        if dialog.result: self.local_menu_config.append(dialog.result); self._populate_tree()
            
    def edit_item(self):
        iid = self.get_selected_iid();
        if not iid: return
        index = self.tree.index(iid)
        dialog = MenuEditDialog(self, "编辑菜单项", self.local_menu_config[index])
        if dialog.result: self.local_menu_config[index] = dialog.result; self._populate_tree()
            
    def delete_item(self):
        iid = self.get_selected_iid();
        if not iid: return
        index = self.tree.index(iid)
        if messagebox.askyesno("确认删除", f"确定要删除菜单项 '{self.local_menu_config[index]['name']}' 吗?", parent=self):
            del self.local_menu_config[index]; self._populate_tree()
            
    def move_up(self):
        iid = self.get_selected_iid();
        if not iid: return
        index = self.tree.index(iid)
        if index > 0:
            self.local_menu_config.insert(index - 1, self.local_menu_config.pop(index)); self._populate_tree()
            new_iid = self.tree.get_children()[index - 1]; self.tree.selection_set(new_iid)
            
    def move_down(self):
        iid = self.get_selected_iid();
        if not iid: return
        index = self.tree.index(iid)
        if index < len(self.local_menu_config) - 1:
            self.local_menu_config.insert(index + 1, self.local_menu_config.pop(index)); self._populate_tree()
            new_iid = self.tree.get_children()[index + 1]; self.tree.selection_set(new_iid)

    def save_and_close(self):
        self.client_manager.update_menu_config(self.local_menu_config); self.destroy()

class ClientManager:
    CLIENT_SYMBOL = "\U0001F4BB" 

    def __init__(self, parent_frame, logger=None):
        self.root = parent_frame.winfo_toplevel()
        self.frame = ttk.Frame(parent_frame)
        self.client_counter = 0; self.mac_to_iid = {}; self.ip_to_mac = {}; self.map_lock = threading.Lock()
        self.logger = logger
        self.mac_to_last_wim = {}
        self.last_checked_index = 0
        self.CLIENTS_TO_CHECK_PER_CYCLE = 5
        self.STATUS_MAP = {'pxe': 'PXE', 'pxemenu': 'PXE菜单', 'ipxe': 'iPXE', 'online': '在线', 'transfer_pe': '传输PE', 'booting_pe': '启动PE', 'get_ip': '获取IP', 'msft_online': '在线', 'offline': '离线'}
        self.selection_order = []
        self._last_selection_state = set()
        columns = ('#', 'firmware', 'name', 'ip', 'mac', 'status')
        self.tree = ttk.Treeview(self.frame, columns=columns, show='headings', selectmode='extended')
        self._setup_treeview_columns()
        self.tree.tag_configure('online_status', background='#e6ffed', font=('Helvetica', 9, 'bold'))
        self.tree.tag_configure('offline_status', foreground='grey')
        self.tree.tag_configure('intermediate_status', font=('Helvetica', 9, 'bold'))
        scrollbar = ttk.Scrollbar(self.frame, orient=tk.VERTICAL, command=self.tree.yview); self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        self._load_config_from_ini()
        self._setup_bindings()
        self.stop_heartbeat = threading.Event()
        self.heartbeat_thread = threading.Thread(target=self._heartbeat_worker, daemon=True)
        self.heartbeat_thread.start()

    def _normalize_mac(self, mac_string):
        if not isinstance(mac_string, str): return ""
        cleaned = re.sub(r'[^a-fA-F0-9]', '', mac_string).upper()
        if len(cleaned) != 12: return mac_string
        return '-'.join(cleaned[i:i+2] for i in range(0, 12, 2))

    def stop_monitoring(self):
        self.stop_heartbeat.set()

    def _heartbeat_worker(self):
        time.sleep(10)
        while not self.stop_heartbeat.is_set():
            try: self._check_clients_liveness()
            except Exception as e:
                if self.logger: self.logger(f"心跳检测线程出错: {e}", "ERROR")
            self.stop_heartbeat.wait(20)

    def _ping_ip(self, ip):
        if not ip or ip == '未知': return False
        try:
            param = '-n' if os.name == 'nt' else '-c'
            timeout_param = '-w' if os.name == 'nt' else '-W'
            command = ['ping', param, '1', timeout_param, '1000' if os.name == 'nt' else '1', ip]
            startupinfo = subprocess.STARTUPINFO() if os.name == 'nt' else None
            if startupinfo: startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            result = subprocess.run(command, capture_output=True, text=True, timeout=1.5, startupinfo=startupinfo)
            return result.returncode == 0
        except: return False

    def _get_ip_from_hostname(self, hostname):
        if not hostname or hostname == '未知': return None
        try:
            param = '-n' if os.name == 'nt' else '-c'
            command = ['ping', param, '1', hostname]
            startupinfo = subprocess.STARTUPINFO() if os.name == 'nt' else None
            if startupinfo: startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            result = subprocess.run(command, capture_output=True, text=True, timeout=2, startupinfo=startupinfo, encoding='utf-8', errors='ignore')
            if result.returncode == 0:
                match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", result.stdout)
                if match: return match.group(1)
            return None
        except: return None

    def _check_clients_liveness(self):
        updates_to_perform = []
        all_iids = list(self.tree.get_children(''))
        if not all_iids: self.last_checked_index = 0; return
        if self.last_checked_index >= len(all_iids): self.last_checked_index = 0
        checked_count, current_scan_index = 0, self.last_checked_index
        for _ in range(len(all_iids)):
            if checked_count >= self.CLIENTS_TO_CHECK_PER_CYCLE: break
            iid = all_iids[current_scan_index]
            try:
                if not self.tree.exists(iid): continue
                current_values = self.tree.item(iid, 'values')
                if not current_values or len(current_values) < 6: continue
                _, _, name_with_symbol, current_ip, mac, current_status = current_values
            except tk.TclError: current_scan_index = (current_scan_index + 1) % len(all_iids); continue
            if "在线" not in current_status and "离线" not in current_status: current_scan_index = (current_scan_index + 1) % len(all_iids); continue
            checked_count += 1
            mac_norm = self._normalize_mac(mac)
            if mac_norm == PROBE_MAC: current_scan_index = (current_scan_index + 1) % len(all_iids); continue
            last_wim, clean_name = self.mac_to_last_wim.get(mac_norm, ''), name_with_symbol.lstrip(self.CLIENT_SYMBOL).strip()
            is_online, final_ip = False, current_ip
            if current_ip != '未知': is_online = self._ping_ip(current_ip)
            elif clean_name and clean_name != '未知':
                resolved_ip = self._get_ip_from_hostname(clean_name)
                if resolved_ip: is_online, final_ip = True, resolved_ip
            update_data = {}
            online_status_text = f"{self.STATUS_MAP['online']}" + (f" [{last_wim}]" if last_wim else "")
            offline_status_text = f"{self.STATUS_MAP['offline']}" + (f" [{last_wim}]" if last_wim else "")
            if is_online:
                if online_status_text != current_status or final_ip != current_ip: update_data.update({'status': online_status_text, 'ip': final_ip})
            elif offline_status_text != current_status: update_data['status'] = offline_status_text
            if update_data: update_data['mac'] = mac_norm; updates_to_perform.append(update_data)
            current_scan_index = (current_scan_index + 1) % len(all_iids)
        self.last_checked_index = current_scan_index
        if updates_to_perform: self.root.after(0, self._apply_ui_updates, updates_to_perform)

    def _apply_ui_updates(self, updates):
        final_updates = {}
        for data in updates:
            mac_norm = self._normalize_mac(data['mac'])
            if mac_norm not in final_updates: final_updates[mac_norm] = {}
            final_updates[mac_norm].update(data)
        for mac, data in final_updates.items(): self._update_ui(mac, data)

    def _setup_bindings(self):
        self.tree.bind('<<TreeviewSelect>>', self._on_selection_change)
        self.tree.bind("<Button-3>", self._show_context_menu)
        self.tree.bind("<Button-1>", self._on_tree_click)

    def _on_tree_click(self, event):
        if not self.tree.identify_row(event.y): self.tree.selection_set()

    def pack(self, *args, **kwargs): self.frame.pack(*args, **kwargs)
    
    def _setup_treeview_columns(self):
        headings = {'#': '序号', 'firmware': '固件', 'name': '计算机名', 'ip': 'IP地址', 'mac': 'MAC地址', 'status': '状态'}
        widths = {'#': 40, 'firmware': 60, 'name': 190, 'ip': 120, 'mac': 130, 'status': 160}
        for col, text in headings.items(): self.tree.heading(col, text=text)
        for col, width in widths.items(): self.tree.column(col, width=width, anchor=tk.W if col not in ['#', 'firmware'] else tk.CENTER, stretch=col not in ['#', 'firmware'])

    def _update_ui(self, mac, data_to_update):
        mac_norm = self._normalize_mac(mac)
        if not mac_norm: return
        def update_action():
            is_probe_client = (mac_norm == PROBE_MAC)
            final_status, tags = data_to_update.get('status', None), ()
            if not is_probe_client and final_status: tags = ('online_status',) if '在线' in final_status else ('offline_status',) if '离线' in final_status else ('intermediate_status',)
            if mac_norm in self.mac_to_iid and self.tree.exists(self.mac_to_iid[mac_norm]):
                iid = self.mac_to_iid[mac_norm]; current_values = list(self.tree.item(iid, 'values'))
                if data_to_update.get('firmware', '未知') != '未知': current_values[1] = data_to_update['firmware']
                if 'name' in data_to_update: current_values[2] = f"{self.CLIENT_SYMBOL} {data_to_update['name']}".strip()
                if 'ip' in data_to_update: current_values[3] = data_to_update['ip']
                current_values[4] = mac_norm
                if final_status: current_values[5] = final_status
                self.tree.item(iid, values=tuple(current_values), tags=tags)
            else:
                seq = '*' if is_probe_client else self.client_counter + 1
                hostname, display_name = data_to_update.get('name', '未知'), 'DHCP探测' if is_probe_client else f"{self.CLIENT_SYMBOL} {data_to_update.get('name', '未知')}".strip()
                vals = ('*', '*', 'DHCP探测', data_to_update.get('ip', '未知'), mac_norm, '*') if is_probe_client else (seq, data_to_update.get('firmware', '未知'), display_name, data_to_update.get('ip', '未知'), mac_norm, final_status or "未知")
                if not is_probe_client: self.client_counter += 1
                iid = self.tree.insert('', 0, values=vals, tags=tags); self.mac_to_iid[mac_norm] = iid
            if not is_probe_client: self._save_config_to_ini()
        self.root.after(0, update_action)

    def _on_selection_change(self, event):
        current, added = set(self.tree.selection()), set()
        added = current - self._last_selection_state
        if added:
            for item in self.tree.get_children(''):
                if item in added and item not in self.selection_order: self.selection_order.append(item)
        removed = self._last_selection_state - current
        if removed: self.selection_order = [item for item in self.selection_order if item not in removed]
        self._last_selection_state = current

    def _load_config_from_ini(self):
        self.menu_config = []
        if not os.path.exists(CONFIG_INI_FILENAME):
            self.menu_config.extend([
                {'name': '远程', 'path': 'bin\\tvnviewer.exe', 'args': '%IP%'},
                {'name': 'NetCopy网络同传', 'path': 'cmd', 'args': '/c echo startup.bat netcopy| bin\\\\nc64.exe -t %IP% 6086'},
                {'name': '重启客户机', 'path': 'cmd', 'args': '/c echo wpeutil reboot| bin\\\\nc64.exe -t %IP% 6086'},
                {'name': '关闭客户机', 'path': 'cmd', 'args': '/c echo wpeutil shutdown| bin\\\\nc64.exe -t %IP% 6086'}
            ]); self._save_config_to_ini(); return
        config = configparser.ConfigParser(interpolation=None)
        try:
            config.read(CONFIG_INI_FILENAME, encoding='utf-8')
            if config.has_section('Menu_Order'):
                order = [k.strip() for k in config['Menu_Order'].get('order', '').split(',') if k.strip()]
                for item_key in order:
                    if config.has_section(item_key): self.menu_config.append(dict(config[item_key]))
            client_sections, max_seq, loaded_macs = [s for s in config.sections() if not s.startswith('Menu_')], 0, set()
            sorted_clients = sorted(client_sections, key=lambda s: int(config[s].get('seq', 0)), reverse=True)
            for section_name in sorted_clients:
                mac_norm = self._normalize_mac(section_name)
                if not mac_norm or mac_norm in loaded_macs: continue
                loaded_macs.add(mac_norm)
                client_data = config[section_name]
                seq = int(client_data.get('seq', 0)); max_seq = max(max_seq, seq)
                status, hostname = client_data.get('status', '未知'), client_data.get('name', '未知')
                tags = ('online_status',) if '在线' in status else ('offline_status',) if '离线' in status else ('intermediate_status',)
                values = (seq, client_data.get('firmware', '未知'), f"{self.CLIENT_SYMBOL} {hostname}".strip(), client_data.get('ip', '未知'), mac_norm, status)
                iid = self.tree.insert('', 0, values=values, tags=tags); self.mac_to_iid[mac_norm] = iid
                self.mac_to_last_wim[mac_norm] = client_data.get('last_wim', '')
            self.client_counter = max_seq
        except Exception as e: 
            if self.logger: self.logger(f"加载 {CONFIG_INI_FILENAME} 出错: {e}", "ERROR")

    def _save_config_to_ini(self):
        config = configparser.ConfigParser(interpolation=None)
        order = []
        for i, item_data in enumerate(self.menu_config):
            item_key = f'Menu_Item_{i+1}'; order.append(item_key); config[item_key] = item_data
        config['Menu_Order'] = {'order': ','.join(order)}
        saved_macs = set()
        for iid in self.tree.get_children(''):
            vals = self.tree.item(iid, 'values')
            if len(vals) == 6:
                seq, firmware, name_with_symbol, ip, mac, status = vals
                mac_norm = self._normalize_mac(mac)
                if not mac_norm or mac_norm == PROBE_MAC or mac_norm in saved_macs: continue
                saved_macs.add(mac_norm)
                clean_name = name_with_symbol.lstrip(f"{self.CLIENT_SYMBOL} ").strip()
                last_wim = self.mac_to_last_wim.get(mac_norm, '')
                config[mac_norm] = {'seq': str(seq), 'firmware': str(firmware), 'name': clean_name, 'ip': str(ip), 'status': str(status), 'last_wim': last_wim}
        try:
            with open(CONFIG_INI_FILENAME, 'w', encoding='utf-8') as f: config.write(f)
        except Exception as e: 
            if self.logger: self.logger(f"保存到 {CONFIG_INI_FILENAME} 出错: {e}", "ERROR")

    def _show_context_menu(self, event):
        iid = self.tree.identify_row(event.y)
        if iid and iid not in self.tree.selection():
            if not (event.state & 0x0004) and not (event.state & 0x0001): self.tree.selection_set(iid)
        selection_count, has_any_clients = len(self.tree.selection()), bool(self.tree.get_children())
        menu, item_state = tk.Menu(self.root, tearoff=0), 'normal' if selection_count > 0 else 'disabled'
        menu.add_command(label="唤醒 (WOL)", command=self._wake_on_lan_command, state=item_state)
        menu.add_separator()
        for item in self.menu_config:
            cmd = lambda p=item['path'], a=item['args']: self._execute_custom_command(p, a)
            menu.add_command(label=item['name'], command=cmd, state=item_state)
        if self.menu_config: menu.add_separator()
        menu.add_command(label="iPXEFM管理", command=self._open_ipxefm_manager, state='normal')
        menu.add_separator()
        select_state = 'normal' if has_any_clients else 'disabled'
        menu.add_command(label="全选", command=self._select_all, state=select_state)
        menu.add_command(label="反选", command=self._invert_selection, state=select_state)
        menu.add_command(label="导出选中项...", command=self._export_selection, state=item_state)
        menu.add_separator()
        delete_label = f"删除选中的客户机 ({selection_count})" if selection_count > 1 else "删除这台客户机"
        menu.add_command(label=delete_label, command=self._delete_selected_client, state=item_state)
        menu.add_command(label="配置菜单...", command=self._open_menu_config_window, state='normal')
        menu.add_separator()
        menu.add_command(label="清空全部客户机", command=self._clear_all_clients, state='normal' if has_any_clients else 'disabled')
        menu.post(event.x_root, event.y_root)

    def _open_ipxefm_manager(self): IPXEFileManager(self.root)
    def _select_all(self): self.tree.selection_set(self.tree.get_children(''))
    def _invert_selection(self):
        all_items, selected_items = set(self.tree.get_children('')), set(self.tree.selection())
        self.tree.selection_set(list(all_items.difference(selected_items)))

    def _export_selection(self):
        ordered_selection = [item for item in self.selection_order if item in self.tree.selection()]
        if not ordered_selection: return
        filepath = filedialog.asksaveasfilename(title="导出选中项", initialfile="exported_clients.txt", defaultextension=".txt", filetypes=[("Text Documents", "*.txt"), ("All Files", "*.*")])
        if not filepath: return
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                for iid in ordered_selection: _, _, _, ip, mac, _ = self.tree.item(iid, 'values'); f.write(f"{ip}\t{mac}\n")
            messagebox.showinfo("导出成功", f"成功导出 {len(ordered_selection)} 条记录到\n{filepath}", parent=self.root)
        except Exception as e: messagebox.showerror("导出失败", f"无法写入文件: {e}", parent=self.root)

    def _execute_custom_command(self, path, args):
        ordered_selection = [item for item in self.selection_order if item in self.tree.selection()]
        if not ordered_selection: return
        for iid in ordered_selection:
            _, firmware, name_with_symbol, ip, mac, status = self.tree.item(iid, 'values')
            clean_name = name_with_symbol.lstrip(f"{self.CLIENT_SYMBOL} ").strip()
            final_args = args.replace('%IP%', ip).replace('%MAC%', mac).replace('%NAME%', clean_name).replace('%STATUS%', status).replace('%FIRMWARE%', firmware)
            if '%IP%' in final_args and ip == '未知': messagebox.showwarning("执行失败", f"客户机 {mac} 没有有效的IP地址，已跳过。", parent=self.root); continue
            try: subprocess.Popen([path] + shlex.split(final_args))
            except FileNotFoundError: messagebox.showerror("执行失败", f"无法找到程序: '{path}'", parent=self.root); return
            except Exception as e: messagebox.showerror("执行失败", f"为客户机 {mac} 执行命令时出错: {e}", parent=self.root); return

    def _open_menu_config_window(self): MenuConfigWindow(self.root, self, self.menu_config)
    def update_menu_config(self, new_config): self.menu_config = new_config; self._save_config_to_ini(); messagebox.showinfo("配置已保存", "菜单配置已更新。", parent=self.root)

    def _delete_selected_client(self):
        sel_iids = self.tree.selection(); count = len(sel_iids)
        if not sel_iids: return
        msg = f"确定要从列表中永久删除这 {count} 台客户机吗?" if count > 1 else f"确定要从列表中永久删除客户机 {self.tree.item(sel_iids[0], 'values')[4]} 吗?"
        if messagebox.askyesno("确认删除", msg, parent=self.root):
            for iid in sel_iids:
                mac_norm = self._normalize_mac(self.tree.item(iid, 'values')[4])
                if mac_norm in self.mac_to_iid: del self.mac_to_iid[mac_norm]
                if mac_norm in self.mac_to_last_wim: del self.mac_to_last_wim[mac_norm]
                self.tree.delete(iid)
            self._save_config_to_ini()

    def _clear_all_clients(self):
        if not self.tree.get_children(): return
        if messagebox.askyesno("确认清空", "警告：这将从列表和配置文件中永久删除所有客户机记录！\n菜单配置将保留。\n\n您确定要继续吗?", icon='warning', parent=self.root):
            self.mac_to_iid.clear(); self.mac_to_last_wim.clear()
            for iid in self.tree.get_children(''): self.tree.delete(iid)
            self.client_counter = 0; self._save_config_to_ini()
    
    def _send_wol_packet(self, mac_address):
        try:
            mac_bytes = bytes.fromhex(self._normalize_mac(mac_address).replace('-', ''))
            if len(mac_bytes) != 6: raise ValueError("无效的MAC地址格式")
            magic_packet = b'\xff' * 6 + mac_bytes * 16
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1); sock.sendto(magic_packet, ('255.255.255.255', 9))
            return True, None
        except Exception as e: return False, str(e)

    def _wake_on_lan_command(self):
        ordered_selection = [item for item in self.selection_order if item in self.tree.selection()]
        if not ordered_selection: return
        success_count, failed_macs = 0, []
        for iid in ordered_selection:
            mac = self.tree.item(iid, 'values')[4]
            success, _ = self._send_wol_packet(mac)
            if success: success_count += 1
            else: failed_macs.append(mac)
        if success_count > 0:
            message = f"已向 {success_count} 台客户机发送唤醒指令。" + (f"\n\n失败 {len(failed_macs)} 台。" if failed_macs else "")
            messagebox.showinfo("操作完成", message, parent=self.root)
        else: messagebox.showerror("操作失败", "未能向任何选定的客户机发送唤醒指令。", parent=self.root)

    def handle_dhcp_request(self, mac, ip, state_hint, firmware_type=None, hostname=None):
        mac_norm = self._normalize_mac(mac)
        if not mac_norm: return
        with self.map_lock:
            if ip and ip != '0.0.0.0': self.ip_to_mac[ip] = mac_norm
        status = self.STATUS_MAP.get(state_hint, state_hint)
        if state_hint == 'msft_online':
            last_wim = self.mac_to_last_wim.get(mac_norm)
            status = f"{self.STATUS_MAP['online']}" + (f" [{last_wim}]" if last_wim else "")
        update_data = {'status': status}
        if ip and ip != '0.0.0.0': update_data['ip'] = ip
        elif hostname:
            resolved_ip = self._get_ip_from_hostname(hostname)
            if resolved_ip: update_data['ip'] = resolved_ip; self.ip_to_mac[resolved_ip] = mac_norm
        if hostname: update_data['name'] = hostname
        if firmware_type and state_hint != 'get_ip': update_data['firmware'] = firmware_type
        self._update_ui(mac_norm, update_data)

    def _get_mac_from_ip(self, ip):
        with self.map_lock: return self.ip_to_mac.get(ip)

    def handle_file_transfer_start(self, client_ip, filename):
        mac = self._get_mac_from_ip(client_ip)
        if mac and filename.lower().endswith('.wim'): self._update_ui(mac, {'status': f"{self.STATUS_MAP['transfer_pe']} [{os.path.basename(filename)}]"})

    def handle_file_transfer_complete(self, client_ip, filename):
        mac = self._get_mac_from_ip(client_ip)
        if mac and filename.lower().endswith('.wim'):
            basename = os.path.basename(filename)
            self.mac_to_last_wim[mac] = basename
            self._update_ui(mac, {'status': f"{self.STATUS_MAP['booting_pe']} [{basename}]"})

    def handle_file_upload_complete(self, client_ip, filename):
        mac = self._get_mac_from_ip(client_ip)
        if mac:
            last_wim = self.mac_to_last_wim.get(mac)
            self._update_ui(mac, {'status': f"{self.STATUS_MAP['online']}" + (f" [{last_wim}]" if last_wim else "")})
    
    def remove_probe_client(self):
        def _remove_action():
            probe_mac_norm = self._normalize_mac(PROBE_MAC)
            if probe_mac_norm in self.mac_to_iid:
                iid = self.mac_to_iid[probe_mac_norm]
                if self.tree.exists(iid): self.tree.delete(iid)
                del self.mac_to_iid[probe_mac_norm]
        self.root.after(100, _remove_action)

    def set_all_clients_offline_in_ini(self):
        if not os.path.exists(CONFIG_INI_FILENAME): return
        if self.logger: self.logger("正在将配置文件中所有客户端的状态更新为“离线”...", "INFO")
        config = configparser.ConfigParser(interpolation=None)
        try:
            config.read(CONFIG_INI_FILENAME, encoding='utf-8')
            offline_text = self.STATUS_MAP.get('offline', '离线')
            for section in config.sections():
                if not section.startswith('Menu_'):
                    last_wim = config.get(section, 'last_wim', fallback='')
                    final_status = f"{offline_text} [{last_wim}]" if last_wim else offline_text
                    config.set(section, 'status', final_status)
            with open(CONFIG_INI_FILENAME, 'w', encoding='utf-8') as f: config.write(f)
        except Exception as e:
            if self.logger: self.logger(f"更新客户端状态到INI文件时出错: {e}", "ERROR")