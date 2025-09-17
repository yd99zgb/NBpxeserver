#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from urllib.parse import unquote

# 模块配置，由主程序初始化
_SERVER_CONFIG = {}
# [新] 增加一个全局变量来持有 ClientManager 的实例
_CLIENT_MANAGER = None

def initialize_dynamic_scripting(settings: dict, client_manager_instance=None):
    """
    从主服务器接收配置和 ClientManager 实例并初始化本模块。
    """
    global _SERVER_CONFIG, _CLIENT_MANAGER
    _SERVER_CONFIG['server_ip'] = settings.get('server_ip', '127.0.0.1')
    _SERVER_CONFIG['http_port'] = settings.get('http_port', 80)
    _SERVER_CONFIG['http_uri'] = f"http://{_SERVER_CONFIG['server_ip']}:{_SERVER_CONFIG['http_port']}"
    _CLIENT_MANAGER = client_manager_instance
    
    log_msg = f"Dynamic scripting module updated. HTTP URI: {_SERVER_CONFIG['http_uri']}"
    if _CLIENT_MANAGER:
        log_msg += " | ClientManager instance linked."
    print(log_msg)


def _generate_wim_boot_script(bootfile_path: str, http_uri: str) -> str:
    """根据用户提供的模板生成 WIM 文件的启动脚本。"""
    if not bootfile_path.startswith('/'):
        bootfile_path = '/' + bootfile_path

    return f"""#!ipxe

# --- Dynamic WIM Boot Script ---
# Booting: {bootfile_path}

set booturl {http_uri}
set bootfile {bootfile_path}

echo Booting Windows Image File...

kernel ${{booturl}}/app/wimboot/wimboot gui || goto failed
# 在bios和efi不同环境取相应的文件
iseq ${{platform}} pcbios  && initrd ${{booturl}}/app/wimboot/bootmgr  bootmgr ||
iseq ${{platform}} efi  && initrd -n bootx64.efi ${{booturl}}/app/wimboot/bootmgfw.efi bootx64.efi ||
initrd ${{booturl}}/app/wimboot/BCD BCD ||
initrd ${{booturl}}/app/wimboot/boot.sdi  boot.sdi ||
initrd ${{booturl}}/app/wimboot/segoen_slboot.ttf segoen_slboot.ttf ||
initrd ${{booturl}}/app/wimboot/segoe_slboot.ttf segoe_slboot.ttf ||
initrd ${{booturl}}/app/wimboot/segmono_boot.ttf segmono_boot.ttf ||
initrd ${{booturl}}/app/wimboot/wgl4_boot.ttf wgl4_boot.ttf ||
initrd ${{booturl}}/app/wimboot/bootres.dll bootres.dll ||

# 下面这行initrd是核心，用于加载指定的WIM文件
iseq ${{platform}} pcbios  && initrd ${{booturl}}${{bootfile}} boot.wim ||
iseq ${{platform}} efi && initrd -n boot.wim ${{booturl}}${{bootfile}} boot.wim ||

echo Starting Windows PE...
boot || goto failed

:failed
echo Boot failed! Returning to menu in 5 seconds...
sleep 5
chain http://${{booturl}}/dynamic.ipxe
"""

def _generate_iso_boot_script(bootfile_path: str, http_uri: str) -> str:
    """生成 ISO 文件的 sanboot 启动脚本。"""
    if not bootfile_path.startswith('/'):
        bootfile_path = '/' + bootfile_path
        
    return f"""#!ipxe

# --- Dynamic ISO Boot Script ---
# Booting: {bootfile_path}

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
chain ${{booturl}}/dynamic.ipxe
"""

def _generate_efi_boot_script(bootfile_path: str, http_uri: str) -> str:
    """生成 EFI 文件的 chainload 启动脚本，并附加指定参数。"""
    if not bootfile_path.startswith('/'):
        bootfile_path = '/' + bootfile_path
        
    return f"""#!ipxe

# --- Dynamic EFI Boot Script ---
# Booting: {bootfile_path}

set booturl {http_uri}
set bootfile {bootfile_path}

echo Booting EFI Application...
# 附加 proxydhcp 参数并 chain aunching EFI application with proxydhcp parameter...
chain ${{booturl}}${{bootfile}} proxydhcp=${{pxebs/next-server}} || goto failed

:failed
echo Boot failed! Returning to menu in 5 seconds...
sleep 5
chain ${{booturl}}/dynamic.ipxe
"""

def _generate_whoami_menu(http_uri: str) -> str:
    """
    [新] 生成一个菜单，列出所有待分配MAC地址的客户端。
    """
    if not _CLIENT_MANAGER:
        return "#!ipxe\necho Server Error: ClientManager not initialized.\nshell"

    unassigned_clients = _CLIENT_MANAGER.get_unassigned_clients()

    if not unassigned_clients:
        return "#!ipxe\necho No unassigned clients found in the list to claim.\necho Booting from local disk...\nsleep 3\nsanboot --no-describe --drive 0x80"
    
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
    """
    [新] 执行MAC地址和IP的绑定操作。
    """
    if not _CLIENT_MANAGER:
        return "#!ipxe\necho Server Error: ClientManager not initialized.\nshell"

    mac_norm = mac.upper().replace(':', '-')
    success = _CLIENT_MANAGER.assign_mac_to_ip(ip, mac_norm)

    if success:
        return (
            "#!ipxe\n"
            f"echo Successfully bound this machine ({mac_norm}) to IP {ip}.\n"
            "echo The server configuration has been updated.\n"
            "echo Rebooting in 5 seconds to apply changes...\n"
            "sleep 5\n"
            "reboot"
        )
    else:
        return (
            "#!ipxe\n"
            f"echo ERROR: Failed to bind MAC {mac_norm} to IP {ip}.\n"
            "echo The IP may no longer be available for assignment.\n"
            "echo Please check server logs and restart.\n"
            "echo Halting in 10 seconds.\n"
            "sleep 10\n"
            "shell"
        )

def generate_dynamic_script(params: dict, client_ip: str) -> str:
    """
    主生成函数。根据 URL 参数决定生成哪种脚本。
    """
    http_uri = _SERVER_CONFIG.get('http_uri', 'http://127.0.0.1')
    
    # --- [全新路由逻辑] ---
    
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
        
        # 2a. 处理 whoami 请求
        if bootfile.lower() == 'whoami':
            print(f"Dynamic script request for client identification ('whoami') from {client_ip}")
            return _generate_whoami_menu(http_uri)
        
        # 2b. 处理常规文件引导
        print(f"Dynamic script request for direct boot: '{bootfile}' from {client_ip}")
        if bootfile.lower().endswith('.wim'):
            return _generate_wim_boot_script(bootfile, http_uri)
        elif bootfile.lower().endswith('.iso'):
            return _generate_iso_boot_script(bootfile, http_uri)
        elif bootfile.lower().endswith('.efi'):
            return _generate_efi_boot_script(bootfile, http_uri)
        else:
            return f"#!ipxe\necho Unsupported file type: {bootfile}\nsleep 5\nexit"
    
    # 3. 如果以上都不是，返回一个错误或默认行为
    return "#!ipxe\necho Invalid dynamic script request.\nsleep 5\nsanboot --no-describe --drive 0x80"