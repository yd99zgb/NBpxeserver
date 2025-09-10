### 文件 2: `client.py` (完整最终版)

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import configparser
import os
import subprocess
import shlex # 用于安全地拆分命令行参数
import socket
import time
import re

# --- 文件名常量 ---
CONFIG_INI_FILENAME = 'ipxefm_cli.ini'
# --- 新增: 服务端探测客户端的特殊MAC地址 ---
PROBE_MAC = '00-11-22-33-44-55'


class MenuEditDialog(tk.Toplevel):
    """一个用于添加或编辑菜单项的模態对话框。"""
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
    """一个用于管理右键菜单项的配置窗口。"""
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
        if not selection:
            messagebox.showwarning("没有选择", "请先选择一个菜单项。", parent=self)
            return None
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
        iid = self.get_selected_iid()
        if not iid: return
        index = self.tree.index(iid)
        if messagebox.askyesno("确认删除", f"确定要删除菜单项 '{self.local_menu_config[index]['name']}' 吗?", parent=self):
            del self.local_menu_config[index]; self._populate_tree()
            
    def move_up(self):
        iid = self.get_selected_iid()
        if not iid: return
        index = self.tree.index(iid)
        if index > 0:
            self.local_menu_config.insert(index - 1, self.local_menu_config.pop(index)); self._populate_tree()
            new_iid = self.tree.get_children()[index - 1]; self.tree.selection_set(new_iid)
            
    def move_down(self):
        iid = self.get_selected_iid()
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

        self.STATUS_MAP = {
            'pxe': 'PXE', 'pxemenu': 'PXE菜单', 'ipxe': 'iPXE', 
            'online': '在线', 'transfer_pe': '传输PE',
            'booting_pe': '启动PE',
            'get_ip': '获取IP', 
            'msft_online': '在线',
            'offline': '离线'
        }

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

    def stop_monitoring(self):
        self.stop_heartbeat.set()

    def _heartbeat_worker(self):
        time.sleep(10)
        while not self.stop_heartbeat.is_set():
            try:
                self._check_clients_liveness()
            except Exception as e:
                if self.logger: self.logger(f"心跳检测线程出错: {e}", "ERROR")
                else: print(f"心跳检测线程出错: {e}")
            self.stop_heartbeat.wait(20)

    def _ping_ip(self, ip):
        if not ip or ip == '未知':
            return False
        try:
            param = '-n' if os.name == 'nt' else '-c'
            timeout_param = '-w' if os.name == 'nt' else '-W'
            command = ['ping', param, '1', timeout_param, '1000' if os.name == 'nt' else '1', ip]
            
            startupinfo = None
            if os.name == 'nt':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                
            result = subprocess.run(command, capture_output=True, text=True, timeout=1.5, startupinfo=startupinfo)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
        except Exception as e:
            if self.logger: self.logger(f"Ping {ip} 时发生错误: {e}", "ERROR")
            else: print(f"Ping {ip} 时发生错误: {e}")
            return False

    def _get_ip_from_hostname(self, hostname):
        """尝试通过ping主机名来解析其IP地址。"""
        if not hostname or hostname == '未知':
            return None
        try:
            param = '-n' if os.name == 'nt' else '-c'
            command = ['ping', param, '1', hostname]
            
            startupinfo = None
            if os.name == 'nt':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                
            result = subprocess.run(command, capture_output=True, text=True, timeout=2, startupinfo=startupinfo, encoding='utf-8', errors='ignore')

            if result.returncode == 0:
                match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", result.stdout)
                if match:
                    ip = match.group(1)
                    return ip
            return None
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None
        except Exception as e:
            if self.logger: self.logger(f"通过主机名 {hostname} 解析IP时出错: {e}", "ERROR")
            else: print(f"通过主机名 {hostname} 解析IP时出错: {e}")
            return None

    def _check_clients_liveness(self):
        updates_to_perform = []
        all_iids = list(self.tree.get_children(''))
        
        if not all_iids:
            self.last_checked_index = 0
            return

        if self.last_checked_index >= len(all_iids):
            self.last_checked_index = 0

        # if self.logger:
        #     self.logger(f"心跳服务: 开始轮流 PING 检测 (从索引 {self.last_checked_index} 开始, 最多 {self.CLIENTS_TO_CHECK_PER_CYCLE} 个)", "DEBUG")

        checked_count = 0
        current_scan_index = self.last_checked_index
        
        for _ in range(len(all_iids)):
            if checked_count >= self.CLIENTS_TO_CHECK_PER_CYCLE:
                break
            
            iid = all_iids[current_scan_index]

            try:
                current_values = self.tree.item(iid, 'values')
                if not current_values or len(current_values) < 6: continue
                _, _, name_with_symbol, current_ip, mac_upper, current_status = current_values
            except tk.TclError:
                current_scan_index = (current_scan_index + 1) % len(all_iids)
                continue

            if "在线" not in current_status and "离线" not in current_status:
                current_scan_index = (current_scan_index + 1) % len(all_iids)
                continue

            checked_count += 1
            
            if mac_upper == PROBE_MAC:
                current_scan_index = (current_scan_index + 1) % len(all_iids)
                continue
            
            last_wim = self.mac_to_last_wim.get(mac_upper, '')
            clean_name = name_with_symbol.lstrip(self.CLIENT_SYMBOL).strip()
            
            is_online = False
            final_ip = current_ip

            if current_ip != '未知':
                # if self.logger: self.logger(f"心跳服务: -> PING IP [{current_ip}] for MAC [{mac_upper}]...", "DEBUG")
                is_online = self._ping_ip(current_ip)
            elif clean_name and clean_name != '未知':
                # if self.logger: self.logger(f"心跳服务: -> PING Hostname [{clean_name}] for MAC [{mac_upper}]...", "DEBUG")
                resolved_ip = self._get_ip_from_hostname(clean_name)
                if resolved_ip:
                    is_online = True
                    final_ip = resolved_ip

            update_data = {}
            online_status_text = f"{self.STATUS_MAP['online']}" + (f" [{last_wim}]" if last_wim else "")
            offline_status_text = f"{self.STATUS_MAP['offline']}" + (f" [{last_wim}]" if last_wim else "")

            if is_online:
                if online_status_text != current_status or final_ip != current_ip:
                    update_data['status'] = online_status_text
                    update_data['ip'] = final_ip
            else:
                if offline_status_text != current_status:
                    update_data['status'] = offline_status_text
            
            if update_data:
                update_data['mac'] = mac_upper
                updates_to_perform.append(update_data)
            
            current_scan_index = (current_scan_index + 1) % len(all_iids)
        
        self.last_checked_index = current_scan_index

        if updates_to_perform:
            self.root.after(0, self._apply_ui_updates, updates_to_perform)

    def _apply_ui_updates(self, updates):
        final_updates = {}
        for data in updates:
            mac = data['mac']
            if mac not in final_updates:
                final_updates[mac] = {}
            final_updates[mac].update(data)
        
        for mac, data in final_updates.items():
            self._update_ui(mac, data)

    def _get_arp_table(self):
        pass
        
    def _setup_bindings(self):
        self.tree.bind('<<TreeviewSelect>>', self._on_selection_change)
        self.tree.bind("<Button-3>", self._show_context_menu)
        self.tree.bind("<Button-1>", self._on_tree_click)

    def _on_tree_click(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            self.tree.selection_set()

    def pack(self, *args, **kwargs): self.frame.pack(*args, **kwargs)
    
    def _setup_treeview_columns(self):
        self.tree.heading('#', text='序号'); self.tree.heading('firmware', text='固件'); self.tree.heading('name', text='计算机名'); self.tree.heading('ip', text='IP地址'); self.tree.heading('mac', text='MAC地址'); self.tree.heading('status', text='状态')
        self.tree.column('#', width=40, anchor=tk.CENTER, stretch=False)
        self.tree.column('firmware', width=60, anchor=tk.CENTER, stretch=False)
        self.tree.column('name', width=190, anchor=tk.W)
        self.tree.column('ip', width=120, anchor=tk.W)
        self.tree.column('mac', width=130, anchor=tk.W)
        self.tree.column('status', width=160, anchor=tk.W)

    def _update_ui(self, mac, data_to_update):
        def update_action():
            is_probe_client = (mac.upper() == PROBE_MAC)
            final_status = data_to_update.get('status', None)
            
            tags = () 
            if not is_probe_client and final_status:
                if '在线' in final_status:
                    tags = ('online_status',)
                elif '离线' in final_status:
                    tags = ('offline_status',)
                else: 
                    tags = ('intermediate_status',)
            
            if mac in self.mac_to_iid:
                iid = self.mac_to_iid[mac]
                if not self.tree.exists(iid):
                    if mac in self.mac_to_iid: del self.mac_to_iid[mac]
                    return

                vals = list(self.tree.item(iid, 'values'))
                
                current_display_name = vals[2]
                clean_name = current_display_name.lstrip(f"{self.CLIENT_SYMBOL} ").strip()
                hostname = clean_name
                
                if 'name' in data_to_update:
                    hostname = data_to_update['name']

                if 'firmware' in data_to_update: vals[1] = data_to_update['firmware']
                if 'ip' in data_to_update: vals[3] = data_to_update['ip']
                if final_status: vals[5] = final_status
                vals[4] = mac.upper()

                if is_probe_client:
                    vals[0] = '*'; vals[1] = '*'; vals[2] = 'DHCP探测'; vals[5] = '*'
                else:
                    vals[2] = f"{self.CLIENT_SYMBOL} {hostname}".strip()
                
                self.tree.item(iid, values=tuple(vals), tags=tags)
            else:
                seq = '*' if is_probe_client else self.client_counter + 1
                hostname = data_to_update.get('name', '未知')
                
                display_name = 'DHCP探测'
                if not is_probe_client:
                    display_name = f"{self.CLIENT_SYMBOL} {hostname}".strip()
                
                vals = (
                    seq, 
                    '*' if is_probe_client else data_to_update.get('firmware', '未知'),
                    display_name, 
                    data_to_update.get('ip', '未知'), 
                    mac.upper(), 
                    '*' if is_probe_client else (final_status or "未知")
                )

                if not is_probe_client:
                    self.client_counter += 1

                iid = self.tree.insert('', 0, values=vals, tags=tags)
                self.mac_to_iid[mac] = iid
            
            if not is_probe_client:
                self._save_config_to_ini()
                
        self.root.after(0, update_action)

    def _on_selection_change(self, event):
        current_selection_set = set(self.tree.selection())
        added_items = current_selection_set - self._last_selection_state
        if added_items:
            for item in self.tree.get_children(''):
                if item in added_items and item not in self.selection_order:
                    self.selection_order.append(item)
        removed_items = self._last_selection_state - current_selection_set
        if removed_items:
            self.selection_order = [item for item in self.selection_order if item not in removed_items]
        self._last_selection_state = current_selection_set

    def _load_config_from_ini(self):
        self.menu_config = []
        if not os.path.exists(CONFIG_INI_FILENAME):
            self.menu_config.append({'name': '远程', 'path': 'bin\\tvnviewer.exe', 'args': '%IP%'})
            self.menu_config.append({'name': 'NetCopy网络同传', 'path': 'cmd', 'args': '/c echo startup.bat netcopy| bin\\\\nc64.exe -t %IP% 6086'})
            self._save_config_to_ini() 
            return

        config = configparser.ConfigParser(interpolation=None)
        try:
            config.read(CONFIG_INI_FILENAME, encoding='utf-8')
            if 'Menu_Order' in config and 'order' in config['Menu_Order']:
                order = [key.strip() for key in config['Menu_Order']['order'].split(',')]
                for item_key in order:
                    if item_key in config: self.menu_config.append(dict(config[item_key]))
            
            client_sections = [s for s in config.sections() if not s.startswith('Menu_')]
            if client_sections:
                max_seq = 0
                sorted_clients = sorted(client_sections, key=lambda mac: int(config[mac].get('seq', 0)), reverse=True)
                for mac in sorted_clients:
                    mac_formatted = mac.replace(":", "-").upper()
                    client_data = config[mac]; seq = int(client_data.get('seq', 0))
                    if seq > max_seq: max_seq = seq
                    status = client_data.get('status', '未知')
                    hostname = client_data.get('name', '未知')
                    
                    tags = ()
                    if '在线' in status:
                        tags = ('online_status',)
                    elif '离线' in status:
                        tags = ('offline_status',)
                    elif status and status != '未知':
                        tags = ('intermediate_status',)
                    
                    display_name = f"{self.CLIENT_SYMBOL} {hostname}".strip()
                    
                    values = (
                        seq, 
                        client_data.get('firmware', '未知'),
                        display_name, 
                        client_data.get('ip', '未知'), 
                        mac_formatted, 
                        status
                    )
                    
                    iid = self.tree.insert('', 0, values=values, tags=tags)
                    self.mac_to_iid[mac_formatted] = iid
                    
                    last_wim = client_data.get('last_wim', '')
                    if last_wim:
                        self.mac_to_last_wim[mac_formatted] = last_wim

                self.client_counter = max_seq
        except Exception as e: 
            if self.logger: self.logger(f"Error loading {CONFIG_INI_FILENAME}: {e}", "ERROR")
            else: print(f"Error loading {CONFIG_INI_FILENAME}: {e}")

    def _save_config_to_ini(self):
        config = configparser.ConfigParser(interpolation=None)
        order = []
        for i, item_data in enumerate(self.menu_config):
            item_key = f'Menu_Item_{i+1}'; order.append(item_key)
            config[item_key] = item_data
        config['Menu_Order'] = {'order': ','.join(order)}
        for iid in self.tree.get_children(''):
            vals = self.tree.item(iid, 'values')
            if len(vals) == 6:
                seq, firmware, name_with_symbol, ip, mac, status = vals
                if mac.upper() == PROBE_MAC:
                    continue
                
                clean_name = name_with_symbol.lstrip(f"{self.CLIENT_SYMBOL} ").strip()

                last_wim = self.mac_to_last_wim.get(mac, '')
                config[mac] = {
                    'seq': str(seq), 
                    'firmware': str(firmware),
                    'name': str(clean_name), 
                    'ip': str(ip), 
                    'status': str(status),
                    'last_wim': last_wim
                }
        try:
            with open(CONFIG_INI_FILENAME, 'w', encoding='utf-8') as f: config.write(f)
        except Exception as e: 
            if self.logger: self.logger(f"Error saving to {CONFIG_INI_FILENAME}: {e}", "ERROR")
            else: print(f"Error saving to {CONFIG_INI_FILENAME}: {e}")

    def _show_context_menu(self, event):
        iid = self.tree.identify_row(event.y)
        if iid and iid not in self.tree.selection():
            if not (event.state & 0x0004) and not (event.state & 0x0001):
                self.tree.selection_set(iid)
        
        selection_count = len(self.tree.selection())
        has_any_clients = bool(self.tree.get_children())
        menu = tk.Menu(self.root, tearoff=0)
        item_state = 'normal' if selection_count > 0 else 'disabled'
        
        menu.add_command(label="唤醒 (WOL)", command=self._wake_on_lan_command, state=item_state)
        menu.add_separator()

        for item in self.menu_config:
            cmd = lambda p=item['path'], a=item['args']: self._execute_custom_command(p, a)
            menu.add_command(label=item['name'], command=cmd, state=item_state)
        
        if self.menu_config: menu.add_separator()

        select_state = 'normal' if has_any_clients else 'disabled'
        menu.add_command(label="全选", command=self._select_all, state=select_state)
        menu.add_command(label="反选", command=self._invert_selection, state=select_state)
        menu.add_command(label="导出选中项...", command=self._export_selection, state=item_state)
        menu.add_separator()
        
        delete_label = f"删除选中的客户机 ({selection_count})" if selection_count > 1 else "删除这台客户机"
        menu.add_command(label=delete_label, command=self._delete_selected_client, state=item_state)
        menu.add_command(label="配置菜单...", command=self._open_menu_config_window, state='normal')
        menu.add_separator()
        clear_state = 'normal' if has_any_clients else 'disabled'
        menu.add_command(label="清空全部客户机", command=self._clear_all_clients, state=clear_state)
        menu.post(event.x_root, event.y_root)

    def _select_all(self):
        self.tree.selection_set(self.tree.get_children(''))

    def _invert_selection(self):
        all_items = set(self.tree.get_children(''))
        selected_items = set(self.tree.selection())
        items_to_select = all_items.difference(selected_items)
        self.tree.selection_set(list(items_to_select))

    def _export_selection(self):
        ordered_selection = [item for item in self.selection_order if item in self.tree.selection()]
        if not ordered_selection: return

        filepath = filedialog.asksaveasfilename(
            title="导出选中项",
            initialfile="exported_clients.txt",
            defaultextension=".txt",
            filetypes=[("Text Documents", "*.txt"), ("All Files", "*.*")]
        )
        if not filepath: return
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                for iid in ordered_selection:
                    vals = self.tree.item(iid, 'values')
                    _, _, _, ip, mac, _ = vals
                    f.write(f"{ip}\t{mac}\n")
            messagebox.showinfo("导出成功", f"成功导出 {len(ordered_selection)} 条记录到\n{filepath}", parent=self.root)
        except Exception as e:
            messagebox.showerror("导出失败", f"无法写入文件: {e}", parent=self.root)

    def _execute_custom_command(self, path, args):
        ordered_selection = [item for item in self.selection_order if item in self.tree.selection()]
        if not ordered_selection: return

        for iid in ordered_selection:
            vals = self.tree.item(iid, 'values')
            _, firmware, name_with_symbol, ip, mac, status = vals
            clean_name = name_with_symbol.lstrip(f"{self.CLIENT_SYMBOL} ").strip()
            
            final_args = args.replace('%IP%', ip).replace('%MAC%', mac).replace('%NAME%', clean_name).replace('%STATUS%', status).replace('%FIRMWARE%', firmware)
            if '%IP%' in final_args and ip == '未知':
                messagebox.showwarning("执行失败", f"客户机 {mac} 没有有效的IP地址，已跳过。", parent=self.root)
                continue
            try:
                subprocess.Popen([path] + shlex.split(final_args))
            except FileNotFoundError: messagebox.showerror("执行失败", f"无法找到程序: '{path}'", parent=self.root); return
            except Exception as e: messagebox.showerror("执行失败", f"为客户机 {mac} 执行命令时出错: {e}", parent=self.root); return

    def _open_menu_config_window(self): MenuConfigWindow(self.root, self, self.menu_config)
    def update_menu_config(self, new_config):
        self.menu_config = new_config; self._save_config_to_ini()
        messagebox.showinfo("配置已保存", "菜单配置已更新。", parent=self.root)

    def _delete_selected_client(self):
        sel_iids = self.tree.selection()
        if not sel_iids: return
        count = len(sel_iids)
        msg = f"确定要从列表中永久删除这 {count} 台客户机吗?" if count > 1 else f"确定要从列表中永久删除客户机 {self.tree.item(sel_iids[0], 'values')[4]} 吗?"
        if messagebox.askyesno("确认删除", msg, parent=self.root):
            for iid in sel_iids:
                mac = self.tree.item(iid, 'values')[4]
                if mac in self.mac_to_iid: del self.mac_to_iid[mac]
                if mac in self.mac_to_last_wim: del self.mac_to_last_wim[mac]
                self.tree.delete(iid)
            self._save_config_to_ini()

    def _clear_all_clients(self):
        if not self.tree.get_children(): return
        if messagebox.askyesno("确认清空", "警告：这将从列表和配置文件中永久删除所有客户机记录！\n菜单配置将保留。\n\n您确定要继续吗?", icon='warning', parent=self.root):
            self.mac_to_iid.clear()
            self.mac_to_last_wim.clear()
            for iid in self.tree.get_children(''): self.tree.delete(iid)
            self.client_counter = 0
            self._save_config_to_ini()
    
    def _send_wol_packet(self, mac_address):
        try:
            mac_bytes = bytes.fromhex(mac_address.replace(':', '').replace('-', ''))
            if len(mac_bytes) != 6:
                raise ValueError("无效的MAC地址格式")
            
            magic_packet = b'\xff' * 6 + mac_bytes * 16
            
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.sendto(magic_packet, ('255.255.255.255', 9))
            return True, None
        except Exception as e:
            return False, str(e)

    def _wake_on_lan_command(self):
        ordered_selection = [item for item in self.selection_order if item in self.tree.selection()]
        if not ordered_selection:
            return

        success_count = 0
        failed_macs = []

        for iid in ordered_selection:
            vals = self.tree.item(iid, 'values')
            mac = vals[4]
            success, error_msg = self._send_wol_packet(mac)
            if success:
                success_count += 1
            else:
                failed_macs.append(mac)
                if self.logger: self.logger(f"发送WOL包到 {mac} 失败: {error_msg}", "WARNING")
                else: print(f"发送WOL包到 {mac} 失败: {error_msg}")

        if success_count > 0:
            message = f"已向 {success_count} 台客户机发送唤醒指令。"
            if failed_macs:
                message += f"\n\n失败 {len(failed_macs)} 台 (MAC地址可能无效)。"
            messagebox.showinfo("操作完成", message, parent=self.root)
        else:
            messagebox.showerror("操作失败", f"未能向任何选定的客户机发送唤醒指令。\n请检查MAC地址格式。", parent=self.root)

    def handle_dhcp_request(self, mac, ip, state_hint, firmware_type=None, hostname=None):
        mac_formatted = mac.replace(":", "-").upper()
        
        with self.map_lock:
            if ip and ip != '0.0.0.0': self.ip_to_mac[ip] = mac_formatted
        
        status = self.STATUS_MAP.get(state_hint, state_hint)
        
        if state_hint == 'msft_online':
            last_wim = self.mac_to_last_wim.get(mac_formatted)
            status = f"{self.STATUS_MAP['online']}" + (f" [{last_wim}]" if last_wim else "")
                
        update_data = {'status': status}

        if ip and ip != '0.0.0.0':
            update_data['ip'] = ip
        elif hostname:
            if self.logger: self.logger(f"DHCP: 客户机 {mac_formatted} 报告主机名 '{hostname}' 但无IP，尝试主动解析...", "DEBUG")
            resolved_ip = self._get_ip_from_hostname(hostname)
            if resolved_ip:
                if self.logger: self.logger(f"DHCP: 成功将 '{hostname}' 解析为 {resolved_ip} (MAC: {mac_formatted})", "INFO")
                update_data['ip'] = resolved_ip
                with self.map_lock:
                    self.ip_to_mac[resolved_ip] = mac_formatted
        
        if hostname:
            update_data['name'] = hostname

        if firmware_type and state_hint != 'get_ip':
            update_data['firmware'] = firmware_type
        
        self._update_ui(mac_formatted, update_data)

    def _get_mac_from_ip(self, ip):
        with self.map_lock: return self.ip_to_mac.get(ip)

    def handle_file_transfer_start(self, client_ip, filename):
        mac = self._get_mac_from_ip(client_ip)
        if mac and filename.lower().endswith('.wim'):
            status_text = f"{self.STATUS_MAP['transfer_pe']} [{os.path.basename(filename)}]"
            self._update_ui(mac, {'status': status_text})

    def handle_file_transfer_complete(self, client_ip, filename):
        mac = self._get_mac_from_ip(client_ip)
        if mac and filename.lower().endswith('.wim'):
            basename = os.path.basename(filename)
            self.mac_to_last_wim[mac] = basename
            status_text = f"{self.STATUS_MAP['booting_pe']} [{basename}]"
            self._update_ui(mac, {'status': status_text})

    def handle_file_upload_complete(self, client_ip, filename):
        mac = self._get_mac_from_ip(client_ip)
        if mac:
            last_wim = self.mac_to_last_wim.get(mac)
            status_text = f"{self.STATUS_MAP['online']}" + (f" [{last_wim}]" if last_wim else "")
            self._update_ui(mac, {'status': status_text})
    
    def remove_probe_client(self):
        def _remove_action():
            probe_mac_upper = PROBE_MAC.upper()
            if probe_mac_upper in self.mac_to_iid:
                iid = self.mac_to_iid[probe_mac_upper]
                if self.tree.exists(iid):
                    self.tree.delete(iid)
                del self.mac_to_iid[probe_mac_upper]
        
        self.root.after(100, _remove_action)
