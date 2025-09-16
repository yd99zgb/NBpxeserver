
### 文件 3: `option.py` (完整最终版)

#!/usr/bin/env python
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, scrolledtext
import ipaddress
import struct
import binascii

# ================================================================= #
# ================= 预设模板与示例 (Preset Templates) ================ #
# ================================================================= #

# 为用户提供一个简短的默认内容
EXAMPLE_OPTIONS = """# --------------------------------------------------------------------
# DHCP 自定义选项配置
# --------------------------------------------------------------------
# 格式: 选项代码, 类型, 值
# - 以 '#' 或 ';' 开头的行将被忽略。
# - 您可以使用上方的“预设模板”功能快速插入常用配置。
# - 移除行首的 '#' 来启用一个选项。
# --------------------------------------------------------------------
"""

# 定义一个巨大的字典，存储所有预设模板
PRESET_SNIPPETS = {
    # --- iPXE 分类 ---
    "iPXE: 引导至 iSCSI Target (完整示例)": """
# --- iPXE: Boot to iSCSI Target (Full Example) ---
# 这是一个完整的iSCSI启动示例。请根据您的环境修改IP地址和IQN。
#
# [17] Root Path: 定义iSCSI目标的URI (iSCSI Target URI)
# 格式: iscsi:<server_ip>:<protocol>:<port>:<lun>:<target_iqn>
# 17, string, iscsi:192.168.1.108::3260:1:iqn.2010-04.org.ipxe.dolphin:storage
#
# [175] iPXE - Encapsulated Options - No Disconnect (保持SAN连接)
# 子选项8=1告诉iPXE在引导操作系统后不要断开iSCSI连接，这对于Windows安装至关重要。
# 175, hex, 080101
#
# [203] iSCSI Initiator Name (可选)
# 如果需要，可以为客户端指定一个iSCSI发起端名称
# 203, string, iqn.2024-01.com.example:client01
""",
    "iPXE: 从 HTTP URL 加载脚本": """
# --- iPXE: Load Script from HTTP URL ---
# 推荐使用HTTP方式加载iPXE脚本，因为它比TFTP更快更可靠。
# ${next-server} 和 ${http-port} 是会自动替换的变量。
#
# [17] Root Path: iPXE脚本的URL
# 17, string, http://${next-server}:${http-port}/menu.ipxe
""",
    "iPXE: 为不同架构加载不同脚本": """
# --- iPXE: Scripting with Architecture detection ---
# 使用iPXE的内置变量，根据客户端架构（BIOS, EFI32, EFI64）加载不同的脚本
#
# [17] Root Path
# 17, string, http://${next-server}:${http-port}/bootstrap.ipxe?arch=${buildarch}
""",
    "iPXE: 配置VLAN网络": """
# --- iPXE: Configure VLAN ---
# 强制iPXE客户端在指定的VLAN中获取IP地址。
#
# [175] iPXE - Encapsulated Options - VLAN ID
# 子选项178=VLAN ID (例如100)。格式为: 178(b2), 长度(02), VLAN ID (uint16)
# 175, hex, b2020064
""",
    "iPXE: 链式加载另一个PXE服务器(如WDS)": """
# --- iPXE: Chainload to another PXE server (e.g., WDS/MDT) ---
# 如果您想让iPXE去加载另一个PXE/TFTP服务器上的文件。
#
# [210] PXE Path Prefix (iPXE扩展)
# 告诉iPXE后续TFTP请求的路径前缀
# 210, string, tftp://192.168.1.200/smsboot/x64/
#
# [67] Bootfile Name (覆盖默认)
# 告诉iPXE要加载的文件名
# 67, string, wdsnbp.com
""",
    # --- Windows 部署分类 ---
    "Windows (WDS/MDT): 基础配置": """
# --- Windows Deployment Services (WDS/MDT) Basic Options ---
# 这是将标准PXE客户端（非iPXE）导向WDS/MDT服务器的经典配置。
#
# [60] Vendor Class Identifier: 必须为 "PXEClient"
# 注意: 仅当DHCP服务器与WDS在不同服务器上时才需要此选项。
# 60, string, PXEClient
#
# [66] TFTP Server Name: WDS/MDT服务器的IP地址或主机名
# 66, string, 192.168.1.200
#
# [67] Bootfile Name: 要加载的启动文件名
# 67, string, boot\\x64\\wdsnbp.com
""",
    "Windows (WDS/MDT): UEFI与BIOS共存": """
# --- Windows Deployment (WDS/MDT) for both UEFI and BIOS ---
# 此为高级用法，通常需要DHCP服务器支持策略。本处仅为示例。
# 实际应用中，您需要为BIOS和UEFI客户端分别设置Option 67。
# 这里我们只展示不同架构对应的文件名。
#
# [67] Bootfile for BIOS x86/x64
# 67, string, boot\\x64\\wdsnbp.com
#
# [67] Bootfile for UEFI x64
# 67, string, boot\\x64\\wdsmgfw.efi
#
# [67] Bootfile for UEFI x86 (32-bit)
# 67, string, boot\\x86\\wdsmgfw.efi
""",
    # --- Linux 自动安装分类 ---
    "Linux: Kickstart/Preseed 自动安装": """
# --- Linux Auto-Install (Kickstart/Preseed) ---
# 通过DHCP向Linux安装程序传递自动化配置文件的位置。
#
# [17] Root Path (for NFS root, 可选)
# 如果您的根文件系统在NFS上。
# 17, string, nfs:192.168.1.110:/path/to/nfsroot
#
# [11] Resource Location Server (通用)
# 传递Kickstart(CentOS/RHEL)或Preseed(Debian/Ubuntu)文件的URL
# 11, string, http://192.168.1.100/ks/centos8.cfg
""",
    # --- 标准网络选项分类 ---
    "标准网络: 设置NTP时间服务器 (Opt 42)": """
# --- Standard: NTP Time Servers (Option 42) ---
# 为客户端指定一个或多个NTP服务器，以同步时间。
#
# 42, ip-list, 192.168.1.1, 210.72.145.44
""",
    "标准网络: 设置Syslog服务器 (Opt 7)": """
# --- Standard: Syslog Servers (Option 7) ---
# 告诉客户端将系统日志发送到指定的服务器。
#
# 7, ip-list, 192.168.1.50
""",
    "标准网络: 设置客户端主机名 (Opt 12)": """
# --- Standard: Set Client Hostname (Option 12) ---
# 建议客户端使用的主机名。
#
# 12, string, workstation-01
""",
    "标准网络: 设置域名 (Opt 15)": """
# --- Standard: Set Domain Name (Option 15) ---
# 为客户端设置DNS域名。
#
# 15, string, mycorp.local
""",
    "标准网络: 设置静态路由 (Opt 33 & 121)": """
# --- Standard: Static Routes (Option 33 & 121) ---
#
# [33] Static Route (旧格式, Classful)
# 为客户端添加一条静态路由。格式为: 目标网络IP,网关IP
# 33, ip-list, 10.0.0.0, 192.168.1.254
#
# [121] Classless Static Routes (新格式, 推荐)
# 更灵活的无类路由。格式为: 掩码位数,目标网络(补零),网关IP。需要用hex类型。
# 示例: 路由到 10.20.30.0/24 via 192.168.1.254
# 24 -> 18 (hex)
# 10.20.30 -> 0a141e (hex)
# 192.168.1.254 -> c0a801fe (hex)
# 121, hex, 180a141ec0a801fe
""",
    # --- VoIP 分类 ---
    "VoIP: 设置SIP服务器 (Opt 120)": """
# --- VoIP: SIP Servers (RFC 3361, Option 120) ---
# 为SIP客户端（如IP电话）指定SIP服务器的地址。
# 格式编码比较复杂，通常是域名编码。
# 示例: sip.example.com
# 03 -> 'sip'长度, 736970 -> 'sip'
# 07 -> 'example'长度, 6578616d706c65 -> 'example'
# 03 -> 'com'长度, 636f6d -> 'com'
# 00 -> 结束
#
# 120, hex, 03736970076578616d706c6503636f6d00
""",
    "VoIP: 设置TFTP服务器和配置文件名 (Opt 66/67)": """
# --- VoIP: Phone Firmware/Config via TFTP ---
# 很多IP电话使用Option 66和67来寻找固件和配置文件。
#
# [66] TFTP Server Name: 电话配置服务器的IP
# 66, string, 192.168.1.80
#
# [67] Bootfile Name: 配置文件名, 有时包含路径
# 67, string, /configs/SEP00112233AABB.cnf.xml
""",
    # --- 高级与特定厂商分类 ---
    "高级: WPAD代理自动发现 (Opt 252)": """
# --- Advanced: WPAD Proxy Auto-Discovery (Option 252) ---
# 告诉浏览器在哪里可以找到 wpad.dat 代理配置文件。
#
# 252, string, http://proxy.mycorp.local/wpad.dat
""",
    "高级: 配置原生PXE菜单 (Opt 43)": """
# --- Advanced: Native PXE Menu via DHCP Option 43 ---
# 这是使用DHCP原生方式创建PXE菜单的复杂示例，用于不支持iPXE的高级场景。
#
# Option 43 是一个容器，内部包含多个子选项。
# Sub-option 6:  PXE Discovery Control (值: 0x03 表示同时监听广播和多播)
# Sub-option 8:  PXE Boot Servers (服务器列表)
# Sub-option 9:  PXE Boot Menu (菜单项定义)
# Sub-option 10: PXE Menu Prompt (菜单提示和超时)
#
# 以下是一个完整的十六进制(hex)值示例:
# 060103 -> Sub-option 6, length 1, value 03
# 0807800001C0A80164 -> Sub-option 8, length 7, type 8000(BIOS), count 1, IP 192.168.1.100
# 090B80000A4D79204D656E75 -> Sub-option 9, length 11, type 8000, desc_len 10, desc "My Menu"
# 0A0D0A426F6F74204D656E7500 -> Sub-option 10, length 13, timeout 10s, prompt "Boot Menu" + null
# FF -> End of options
#
# 43, hex, 0601030807800001C0A80164090B80000A4D79204D656E750A0D0A426F6F74204D656E7500FF
""",
}


def create_dhcp_options_tab(parent, settings_vars, all_settings):
    """
    在指定的父控件(parent)中创建"DHCP自定义选项"的GUI界面 (新版，带模板功能)。
    """
    parent.columnconfigure(1, weight=1)

    # 1. 启用/禁用功能的复选框
    enabled_key = 'dhcp_options_enabled'
    settings_vars[enabled_key] = tk.BooleanVar(value=all_settings.get(enabled_key, False))
    enabled_check = ttk.Checkbutton(parent, text="启用 DHCP 自定义选项", variable=settings_vars[enabled_key])
    enabled_check.grid(row=0, column=0, columnspan=3, sticky="w", pady=(5, 10), padx=5)

    # 2. 创建模板选择区域
    preset_frame = ttk.Frame(parent)
    preset_frame.grid(row=1, column=0, columnspan=3, sticky="ew", padx=5)
    preset_frame.columnconfigure(1, weight=1)

    ttk.Label(preset_frame, text="预设模板:").grid(row=0, column=0, sticky="w", padx=(0, 5))

    preset_var = tk.StringVar()
    preset_combo = ttk.Combobox(preset_frame, textvariable=preset_var, state="readonly",
                                values=list(PRESET_SNIPPETS.keys()), width=45)
    preset_combo.grid(row=0, column=1, sticky="ew")
    preset_combo.set("选择一个预设模板以插入...")

    # 3. 创建可滚动的文本框用于输入选项
    options_frame = ttk.LabelFrame(parent, text="选项定义 (格式: 代码, 类型, 值)", padding="10")
    options_frame.grid(row=2, column=0, columnspan=3, sticky="nsew", pady=10, padx=5)
    options_frame.columnconfigure(0, weight=1)
    options_frame.rowconfigure(0, weight=1)
    parent.rowconfigure(2, weight=1) # 让该行可伸展

    options_text_key = 'dhcp_options_text'
    text_widget_key = options_text_key + '_widget'

    options_text_widget = scrolledtext.ScrolledText(options_frame, wrap=tk.WORD, height=15, width=70)
    options_text_widget.pack(fill="both", expand=True)

    initial_text = all_settings.get(options_text_key, '').strip()
    if not initial_text:
        initial_text = EXAMPLE_OPTIONS.strip()
    options_text_widget.insert(tk.END, initial_text)
    settings_vars[text_widget_key] = options_text_widget

    # 4. "插入模板"按钮的逻辑
    def insert_preset():
        selected_preset = preset_var.get()
        if selected_preset in PRESET_SNIPPETS:
            snippet = PRESET_SNIPPETS[selected_preset].strip()
            options_text_widget.insert(tk.INSERT, f"\n\n{snippet}\n")
            preset_combo.set("选择一个预设模板以插入...")

    insert_button = ttk.Button(preset_frame, text="插入模板", command=insert_preset)
    insert_button.grid(row=0, column=2, sticky="e", padx=(5, 0))


def parse_and_build_dhcp_options(options_text):
    """
    解析用户输入的选项文本，并将其转换为DHCP协议所需的二进制格式。
    """
    all_options_bytes = bytearray()
    
    for line in options_text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith(';'):
            continue
        
        try:
            parts = [p.strip() for p in line.split(',', 2)]
            if len(parts) != 3:
                continue
            
            code_str, type_str, val_str = parts
            code = int(code_str)
            
            if not (0 < code < 255):
                continue

            value_bytes = b''
            type_str_lower = type_str.lower()

            if type_str_lower == 'string':
                val_str = val_str.replace('${next-server}', SETTINGS.get('server_ip', '0.0.0.0'))
                val_str = val_str.replace('${http-port}', str(SETTINGS.get('http_port', '80')))
                value_bytes = val_str.encode('utf-8')
            elif type_str_lower == 'hex':
                value_bytes = binascii.unhexlify(val_str.replace(' ', ''))
            elif type_str_lower == 'ip':
                value_bytes = ipaddress.ip_address(val_str).packed
            elif type_str_lower == 'ip-list':
                ip_list = [ip.strip() for ip in val_str.split(',')]
                value_bytes = b''.join([ipaddress.ip_address(ip).packed for ip in ip_list])
            elif type_str_lower == 'uint8':
                value_bytes = struct.pack('!B', int(val_str))
            elif type_str_lower == 'uint16':
                value_bytes = struct.pack('!H', int(val_str))
            elif type_str_lower == 'uint32':
                value_bytes = struct.pack('!I', int(val_str))
            elif type_str_lower == 'sint8':
                value_bytes = struct.pack('!b', int(val_str))
            elif type_str_lower == 'sint16':
                value_bytes = struct.pack('!h', int(val_str))
            elif type_str_lower == 'sint32':
                value_bytes = struct.pack('!i', int(val_str))
            else:
                continue
            
            if len(value_bytes) > 255:
                continue
            
            all_options_bytes += bytes([code, len(value_bytes)]) + value_bytes

        except (ValueError, TypeError, binascii.Error, ipaddress.AddressValueError, struct.error):
            continue
            
    return bytes(all_options_bytes)

SETTINGS = {}
def set_global_settings(settings_dict):
    global SETTINGS
    SETTINGS = settings_dict
