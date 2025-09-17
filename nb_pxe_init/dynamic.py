#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from urllib.parse import unquote

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
initrd ${{booturl}}${{bootfile}} boot.wim ||
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
        
        # 2a. 处理 'whoami' 请求
        if bootfile.lower() == 'whoami':
            print(f"Dynamic script request for client identification ('whoami') from {client_ip}")
            return _generate_whoami_menu(http_uri)
        
        # 2b. 处理 'ipxefm' 请求
        if bootfile.lower() == 'ipxefm':
            print(f"Dynamic script request to list all bootable files ('ipxefm') from {client_ip}")
            return _generate_all_files_menu(http_uri)
        
        # 2c. 处理常规文件引导
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