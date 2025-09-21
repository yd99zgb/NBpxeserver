#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from urllib.parse import unquote
import configparser

# 模块配置，由主程序初始化
_SERVER_CONFIG = {}
_CLIENT_MANAGER = None

# 定义所有支持扫描的启动文件扩展名
SUPPORTED_EXTENSIONS = {'.wim', '.iso', '.efi', '.vhd', '.ima', '.img'}

def initialize_dynamic_scripting(settings: dict, client_manager_instance=None):
    """
    从主服务器接收配置和 ClientManager 实例并初始化本模块。
    """
    global _SERVER_CONFIG, _CLIENT_MANAGER
    _SERVER_CONFIG['server_ip'] = settings.get('server_ip', '127.0.0.1')
    _SERVER_CONFIG['http_port'] = settings.get('http_port', 80)
    _SERVER_CONFIG['http_root'] = settings.get('http_root', '.') 
    _SERVER_CONFIG['subnet_mask'] = settings.get('subnet_mask', '')
    _SERVER_CONFIG['router_ip'] = settings.get('router_ip', '')
    _SERVER_CONFIG['dns_server_ip'] = settings.get('dns_server_ip', '')
    _SERVER_CONFIG['http_uri'] = f"http://{_SERVER_CONFIG['server_ip']}:{_SERVER_CONFIG['http_port']}"
    _CLIENT_MANAGER = client_manager_instance
    
    log_msg = f"Dynamic scripting module updated. HTTP URI: {_SERVER_CONFIG['http_uri']}"
    if _CLIENT_MANAGER:
        log_msg += " | ClientManager instance linked."
    print(log_msg)


def _generate_wim_boot_script(bootfile_path: str, http_uri: str) -> str:
    """生成 WIM 文件的启动脚本。"""
    if not bootfile_path.startswith('/'):
        bootfile_path = '/' + bootfile_path

    return f"""#!ipxe
# --- Dynamic WIM Boot Script ---
set booturl {http_uri}
set bootfile {bootfile_path}
echo Booting Windows Image File...
kernel ${{booturl}}/app/wimboot/wimboot gui || goto failed
iseq ${{platform}} pcbios  && initrd ${{booturl}}/app/wimboot/bootmgr  bootmgr ||
iseq ${{platform}} efi  && initrd -n bootx64.efi ${{booturl}}/app/wimboot/bootmgfw.efi bootx64.efi ||
initrd ${{booturl}}/app/wimboot/BCD BCD ||
initrd ${{booturl}}/app/wimboot/boot.sdi  boot.sdi ||
initrd -n boot.wim ${{booturl}}${{bootfile}} boot.wim ||
echo Starting Windows PE...
boot || goto failed
:failed
echo Boot failed! Returning to menu in 5 seconds...
sleep 5
chain ${{booturl}}/dynamic.ipxe?bootfile=ipxefm
"""

def _generate_iso_boot_script(bootfile_path: str, http_uri: str) -> str:
    """[已恢复] 生成 ISO 文件的 imgboot 启动脚本。"""
    if not bootfile_path.startswith('/'):
        bootfile_path = '/' + bootfile_path
        
    return f"""#!ipxe
# --- Dynamic ISO Boot Script ---
set booturl {http_uri}
set bootfile {bootfile_path}
echo Booting ISO via imgboot...
goto ${{platform}}
:efi
initrd -n boot.iso ${{booturl}}${{bootfile}} ||
chain ${{booturl}}/app/efi/imgboot.efi || goto failed
:pcbios
kernel ${{booturl}}/app/pcbios/memdisk iso raw ||
initrd ${{booturl}}${{bootfile}} || goto failed
boot
:failed
echo Boot failed! Returning to menu in 5 seconds...
sleep 5
chain ${{booturl}}/dynamic.ipxe?bootfile=ipxefm
"""

def _generate_disk_image_boot_script(bootfile_path: str, http_uri: str) -> str:
    """为 VHD, IMG, IMA 等生成通用的 imgboot/memdisk 启动脚本。"""
    if not bootfile_path.startswith('/'):
        bootfile_path = '/' + bootfile_path

    return f"""#!ipxe
# --- Dynamic Disk Image Boot Script ---
set booturl {http_uri}
set bootfile {bootfile_path}
echo Booting Disk Image via imgboot...
goto ${{platform}}
:efi
initrd -n boot.img ${{booturl}}${{bootfile}} ||
chain ${{booturl}}/app/efi/imgboot.efi || goto failed
:pcbios
kernel ${{booturl}}/app/pcbios/memdisk raw ||
initrd ${{booturl}}${{bootfile}} || goto failed
boot
:failed
echo Boot failed! Returning to menu in 5 seconds...
sleep 5
chain ${{booturl}}/dynamic.ipxe?bootfile=ipxefm
"""

def _generate_efi_boot_script(bootfile_path: str, http_uri: str) -> str:
    """[已恢复] 生成 EFI 文件的 chainload 启动脚本，并附加参数。"""
    if not bootfile_path.startswith('/'):
        bootfile_path = '/' + bootfile_path
        
    return f"""#!ipxe
# --- Dynamic EFI Boot Script ---
set booturl {http_uri}
set bootfile {bootfile_path}
echo Launching EFI application with proxydhcp parameter...
chain ${{booturl}}${{bootfile}} proxydhcp=${{pxebs/next-server}} || goto failed
:failed
echo Boot failed! Returning to menu in 5 seconds...
sleep 5
chain ${{booturl}}/dynamic.ipxe?bootfile=ipxefm
"""

def _generate_whoami_menu(http_uri: str) -> str:
    """生成一个菜单，列出所有待分配MAC地址的客户端。"""
    if not _CLIENT_MANAGER:
        return "#!ipxe\necho Server Error: ClientManager not initialized.\nshell"

    unassigned_clients = _CLIENT_MANAGER.get_unassigned_clients()

    if not unassigned_clients:
        return "#!ipxe\necho No unassigned clients found to claim.\nsleep 3\nsanboot --no-describe --drive 0x80"
    
    script = [
        "#!ipxe",
        "",
        "menu Please identify this machine",
    ]
    
    for client in unassigned_clients:
        script.append(f"item {client['ip']} {client['name']} --- {client['ip']}")
    
    script.extend([
        "",
        "choose --timeout 30000 selected || exit",
        f"chain {http_uri}/dynamic.ipxe?myip=${{selected}}&mymac=${{net0/mac}}",
        "exit"
    ])
    
    return "\n".join(script)

def _perform_mac_binding(ip: str, mac: str) -> str:
    """执行MAC地址和IP的绑定操作。"""
    if not _CLIENT_MANAGER:
        return "#!ipxe\necho Server Error: ClientManager not initialized.\nshell"

    mac_norm = mac.upper().replace(':', '-')
    success = _CLIENT_MANAGER.assign_mac_to_ip(ip, mac_norm)

    if success:
        return (
            "#!ipxe\n"
            f"echo Successfully bound this machine ({mac_norm}) to IP {ip}.\n"
            "echo Rebooting in 5 seconds...\n"
            "sleep 5\n"
            "reboot"
        )
    else:
        return (
            "#!ipxe\n"
            f"echo ERROR: Failed to bind MAC {mac_norm} to IP {ip}.\n"
            "echo Please check server logs.\n"
            "sleep 10\n"
            "shell"
        )

def _generate_all_files_menu(http_uri: str) -> str:
    """扫描HTTP目录并生成一个包含所有可启动文件的菜单。"""
    http_root = _SERVER_CONFIG.get('http_root')
    if not http_root or not os.path.isdir(http_root):
        return "#!ipxe\necho Server Error: HTTP root directory not configured or not found.\nshell"

    boot_files = []
    for root, _, files in os.walk(http_root):
        for file in files:
            if os.path.splitext(file)[1].lower() in SUPPORTED_EXTENSIONS:
                full_path = os.path.join(root, file)
                relative_path = os.path.relpath(full_path, http_root)
                web_path = relative_path.replace(os.sep, '/')
                boot_files.append(web_path)
    
    if not boot_files:
        return "#!ipxe\necho No bootable files (.wim, .iso, .efi, etc.) found in the HTTP directory.\nsleep 5\nsanboot --no-describe --drive 0x80"

    script = [
        "#!ipxe",
        "",
        "menu All Bootable Files",
        "item --gap -- Select a file to boot",
    ]

    boot_files.sort()
    for path in boot_files:
        script.append(f"item \"{path}\" \"{path}\"")

    script.extend([
        "",
        "choose --timeout 30000 selected || exit",
        f"chain {http_uri}/dynamic.ipxe?bootfile=${{selected}}",
        "exit"
    ])

    return "\n".join(script)

def _generate_client_info_script(client_ip: str) -> str:
    """
    生成一个有效的 iPXE 脚本，该脚本使用客户端的网络和身份信息设置变量。
    如果某个值找不到，则将其留空。
    """
    info = {
        'pcname': '',
        'ip': client_ip,
        'mask': _SERVER_CONFIG.get('subnet_mask', ''),
        'gateway': _SERVER_CONFIG.get('router_ip', ''),
        'dns1': '',
        'dns2': '',
        'mac': ''
    }

    # 解析DNS服务器 (可以是逗号分隔的)
    dns_servers = _SERVER_CONFIG.get('dns_server_ip', '').replace(' ', '').split(',')
    if len(dns_servers) > 0 and dns_servers[0]:
        info['dns1'] = dns_servers[0]
    if len(dns_servers) > 1 and dns_servers[1]:
        info['dns2'] = dns_servers[1]

    # 从实时的 ClientManager 映射中获取 MAC 地址
    mac_address = None
    if _CLIENT_MANAGER and hasattr(_CLIENT_MANAGER, 'ip_to_mac'):
        mac_address = _CLIENT_MANAGER.ip_to_mac.get(client_ip)
    
    # 如果找到 MAC 地址，用它从 INI 配置文件中查找计算机名
    if mac_address:
        mac_norm = mac_address.upper().replace(':', '-')
        info['mac'] = mac_norm
        
        CONFIG_INI_FILENAME = 'ipxefm_cli.ini'
        if os.path.exists(CONFIG_INI_FILENAME):
            config = configparser.ConfigParser(interpolation=None)
            try:
                config.read(CONFIG_INI_FILENAME, encoding='utf-8')
                if config.has_section(mac_norm):
                    info['pcname'] = config.get(mac_norm, 'name', fallback='')
            except Exception:
                pass # 如果配置文件读取失败，则静默处理

    # 使用正确的 'set key value' 语法构建 iPXE 脚本
    script = [
        "#!ipxe",
        "rem Predefined information about this machine",
        f"set pcname {info['pcname']}",
        f"set ip {info['ip']}",
        f"set mask {info['mask']}",
        f"set gateway {info['gateway']}",
        f"set dns1 {info['dns1']}",
        f"set dns2 {info['dns2']}",
        f"set mac {info['mac']}",
    ]
    
    return "\n".join(script)

def _generate_unattend_xml(client_ip: str) -> str:
    """
    根据客户端IP从客户列表中获取计算机名，生成一个简单的unattend.xml文件内容。
    """
    computer_name = ""  # 如果未找到，默认为空

    # 从实时的 ClientManager 映射中获取 MAC 地址
    mac_address = None
    if _CLIENT_MANAGER and hasattr(_CLIENT_MANAGER, 'ip_to_mac'):
        mac_address = _CLIENT_MANAGER.ip_to_mac.get(client_ip)

    # 如果找到 MAC 地址，则从 INI 配置文件中查找计算机名
    if mac_address:
        mac_norm = mac_address.upper().replace(':', '-')
        
        CONFIG_INI_FILENAME = 'ipxefm_cli.ini'
        if os.path.exists(CONFIG_INI_FILENAME):
            config = configparser.ConfigParser(interpolation=None)
            try:
                config.read(CONFIG_INI_FILENAME, encoding='utf-8')
                if config.has_section(mac_norm):
                    computer_name = config.get(mac_norm, 'name', fallback='')
            except Exception as e:
                # 如有需要，可打印错误用于调试
                print(f"为 {mac_norm} 读取 {CONFIG_INI_FILENAME} 时出错: {e}")
                pass  # 静默失败，computer_name 保持为 ""

    # 构建 XML 字符串
    xml_content = f"""<?xml version="1.0" encoding="utf-8"?>    
<unattend xmlns="urn:schemas-microsoft-com:unattend">    
    <settings pass="windowsPE">    
        <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">    
            <ComputerName>{computer_name}</ComputerName> 
            <EnableNetwork>true</EnableNetwork>    
            <EnableFirewall>false</EnableFirewall>    
        </component>    
    </settings>    
</unattend>
"""

    return xml_content

def generate_dynamic_script(params: dict, client_ip: str) -> str:
    """
    主生成函数。根据 URL 参数决定生成哪种脚本。
    """
    http_uri = _SERVER_CONFIG.get('http_uri', 'http://127.0.0.1')
    
    # 1. 优先处理绑定请求
    if 'myip' in params and 'mymac' in params:
        ip_to_bind = params['myip'][0]
        mac_to_bind = params['mymac'][0]
        print(f"Dynamic script request to bind MAC {mac_to_bind} to IP {ip_to_bind}")
        return _perform_mac_binding(ip_to_bind, mac_to_bind)

    # 2. 其次处理 bootfile 参数
    bootfile = params.get('bootfile', [None])[0]
    if bootfile:
        bootfile = unquote(bootfile)
        bootfile = bootfile.strip('"')
        
        # 2a. 处理 'getmyxml' 生成 unattend.xml
        if bootfile.lower() == 'getmyxml':
            print(f"Dynamic script request for unattend.xml ('getmyxml') from {client_ip}")
            return _generate_unattend_xml(client_ip)
        
        # 2b. 处理 'getmyip' 获取客户端信息
        if bootfile.lower() == 'getmyip':
            print(f"Dynamic script request for client info ('getmyip') from {client_ip}")
            return _generate_client_info_script(client_ip)
        
        # 2c. 处理 'whoami' 请求
        if bootfile.lower() == 'whoami':
            print(f"Dynamic script request for client identification ('whoami') from {client_ip}")
            return _generate_whoami_menu(http_uri)
        
        # 2d. 处理 'ipxefm' 请求
        if bootfile.lower() == 'ipxefm':
            print(f"Dynamic script request to list all bootable files ('ipxefm') from {client_ip}")
            return _generate_all_files_menu(http_uri)
        
        # 2e. 处理常规文件引导
        print(f"Dynamic script request for direct boot: '{bootfile}' from {client_ip}")
        file_ext = os.path.splitext(bootfile)[1].lower()

        if file_ext == '.wim':
            return _generate_wim_boot_script(bootfile, http_uri)
        elif file_ext == '.iso':
            return _generate_iso_boot_script(bootfile, http_uri)
        elif file_ext == '.efi':
            return _generate_efi_boot_script(bootfile, http_uri)
        elif file_ext in ('.vhd', '.img', '.ima'):
            return _generate_disk_image_boot_script(bootfile, http_uri)
        else:
            return f"#!ipxe\necho Unsupported file type: {bootfile}\nsleep 5\nchain {http_uri}/dynamic.ipxe?bootfile=ipxefm"
    
    # 3. 如果没有 bootfile 参数，默认显示 'ipxefm' 菜单
    print(f"Default dynamic script request from {client_ip}, showing 'ipxefm' menu.")
    return _generate_all_files_menu(http_uri)