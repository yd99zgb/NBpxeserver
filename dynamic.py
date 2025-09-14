#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from urllib.parse import unquote

# 模块配置，由主程序初始化
_SERVER_CONFIG = {}

# 模拟客户端数据库 (用于回退逻辑)
KNOWN_CLIENTS = {
    '08-00-27-1A-2B-3C': {'hostname': 'WebServer-01', 'assigned_os': 'Boot/wim/WinPE_Admin.wim'},
    '00-50-56-A1-B2-C3': {'hostname': 'GraphicsWorkstation', 'assigned_os': 'Boot/iso/ubuntu-desktop.iso'},
}

def initialize_dynamic_scripting(settings: dict):
    """从主服务器接收配置并初始化本模块。"""
    global _SERVER_CONFIG
    _SERVER_CONFIG['server_ip'] = settings.get('server_ip', '127.0.0.1')
    _SERVER_CONFIG['http_port'] = settings.get('http_port', 80)
    _SERVER_CONFIG['http_uri'] = f"http://{_SERVER_CONFIG['server_ip']}:{_SERVER_CONFIG['http_port']}"
    print(f"Dynamic scripting module updated. HTTP URI: {_SERVER_CONFIG['http_uri']}")

def _generate_wim_boot_script(bootfile_path: str, http_uri: str) -> str:
    """根据用户提供的模板生成 WIM 文件的启动脚本。"""
    
    # 确保 bootfile 路径以 / 开头，符合 URL 规范
    if not bootfile_path.startswith('/'):
        bootfile_path = '/' + bootfile_path

    # 使用 f-string 和三引号来精确构建多行 iPXE 脚本
    # 注意：iPXE 变量 ${...} 在 f-string 中需要写为 ${{...}} 来转义
    # 但由于我们的Python变量名和iPXE变量名不冲突，可以直接写
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

echo Booting ISO via SANBOOT...
sanboot --no-describe ${{booturl}}${{bootfile}} || goto failed

:failed
echo Boot failed! Returning to menu in 5 seconds...
sleep 5
chain ${{booturl}}/dynamic.ipxe
"""

def _generate_mac_based_menu(params: dict) -> str:
    """
    当没有 bootfile 参数时，执行原始的、基于 MAC 地址的菜单逻辑。
    """
    mac = params.get('mac', ['unknown'])[0].upper().replace(':', '-')
    http_uri = _SERVER_CONFIG.get('http_uri', 'http://127.0.0.1')
    client_info = KNOWN_CLIENTS.get(mac)
    
    script_lines = [
        "#!ipxe",
        "",
        f"set http_uri {http_uri}",
        "set menu-timeout 5000",
        ""
    ]
    
    if client_info:
        # 已知客户端逻辑...
        hostname = client_info['hostname']
        script_lines.extend([
            f"menu Welcome, {hostname} ({mac})",
            "item --gap -- Assigned Task",
            f"item osboot Boot {os.path.basename(client_info['assigned_os'])}",
            "item localboot Boot from Local Disk",
            "choose --timeout ${menu-timeout} selected || goto localboot",
            "goto ${selected}",
            ":osboot",
            f"chain ${{http_uri}}/dynamic.ipxe?bootfile={client_info['assigned_os']}" # 巧妙地调用自己！
        ])
    else:
        # 未知客户端逻辑...
        script_lines.extend([
            f"menu General Boot Menu for {mac}",
            "item winpe Boot Windows PE (General Purpose)",
            "item localboot Boot from Local Disk (Default)",
            "choose --timeout ${menu-timeout} selected || goto localboot",
            "goto ${selected}",
            ":winpe",
            "chain ${http_uri}/dynamic.ipxe?bootfile=/Boot/wim/WinPE_common.wim" # 调用自己
        ])
        
    script_lines.extend(["", ":localboot", "sanboot --no-describe --drive 0x80 || exit"])
    return "\n".join(script_lines)


def generate_dynamic_script(params: dict, client_ip: str) -> str:
    """
    主生成函数。根据 URL 参数决定生成哪种脚本。
    :param params: 从 URL 查询字符串解析出的参数字典。
    :param client_ip: 发起请求的客户端 IP 地址。
    :return: 完整的 iPXE 脚本字符串。
    """
    http_uri = _SERVER_CONFIG.get('http_uri', 'http://127.0.0.1')
    
    # 优先检查 'bootfile' 参数
    # parse_qs 的结果是列表，所以我们取第一个元素
    bootfile = params.get('bootfile', [None])[0]

    if bootfile:
        # 对文件名进行 URL 解码，以处理像 %20 (空格) 这样的字符
        bootfile = unquote(bootfile)
        
        print(f"Dynamic script request for direct boot: '{bootfile}' from {client_ip}")

        if bootfile.lower().endswith('.wim'):
            return _generate_wim_boot_script(bootfile, http_uri)
        elif bootfile.lower().endswith('.iso'):
            return _generate_iso_boot_script(bootfile, http_uri)
        else:
            return f"#!ipxe\necho Unsupported file type: {bootfile}\nsleep 5\nexit"
    
    # 如果没有 'bootfile' 参数，则回退到基于 MAC 的菜单逻辑
    else:
        mac = params.get('mac', ['unknown'])[0]
        print(f"Dynamic script request for menu from MAC: {mac} ({client_ip})")
        return _generate_mac_based_menu(params)