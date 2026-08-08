import socket
import ipaddress
import urllib.request
import re

CIDR_FILE = "cidrs.txt"
OUTPUT_FILE = "cmi_valid_targets.txt"

# Cloudflare IPv6 Anycast 节点最常绑定的高频尾数模式
CF_IPV6_SUFFIXES = [
    "::",
    "::1",
    "::100",
    "::a29f:1001",
    "::b38c:2002",
    "::c100",
    "::d100",
    "::e100",
    "::1:1",
    "::8888",
    "::ffff",
]

def generate_candidate_ips(cidr_str):
    """根据高频模式生成真实可测的候选 IP"""
    candidate_ips = []
    try:
        # 去除可能存在的注释和空格
        clean_cidr = cidr_str.split('#')[0].strip()
        net = ipaddress.IPv6Network(clean_cidr, strict=False)
        
        # 获取网络前缀 (取前 64 位或当前掩码前缀)
        prefix = str(net.network_address).rstrip(':')
        if prefix.endswith(':'):
            prefix = prefix[:-1]
            
        for suffix in CF_IPV6_SUFFIXES:
            # 组合形成完整 IPv6 地址
            full_ip_str = f"{prefix}{suffix}"
            try:
                ip_obj = ipaddress.IPv6Address(full_ip_str)
                if ip_obj in net:
                    candidate_ips.append(str(ip_obj))
            except Exception:
                continue
    except Exception as e:
        print(f"⚠️ CIDR 解析格式错误 [{cidr_str}]: {e}")
    return candidate_ips

def check_tcp_port(ip, port=443, timeout=2):
    """通过 TCP 443 端口建连探测"""
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def check_cf_colo(ip):
    """尝试获取 Cloudflare 边缘机房"""
    try:
        url = f"http://[{ip}]/cdn-cgi/trace"
        req = urllib.request.Request(url, headers={'Host': 'cloudflare.com', 'User-Agent': 'Mozilla/5.0'}, timeout=2)
        with urllib.request.urlopen(req) as response:
            content = response.read().decode('utf-8')
            match = re.search(r'colo=([A-Z]+)', content)
            if match:
                return match.group(1)
    except Exception:
        pass
    return "UNKNOWN"

def main():
    valid_results = []
    
    try:
        with open(CIDR_FILE, "r") as f:
            lines = f.readlines()
            cidrs = [line.strip() for line in lines if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"❌ 找不到文件: {CIDR_FILE}")
        return

    print(f"==========================================")
    print(f"🔍 启动 CIDR 高频模式扫描 | 共有 {len(cidrs)} 个目标")
    print(f"==========================================\n")

    for idx, cidr in enumerate(cidrs, 1):
        print(f"[{idx}/{len(cidrs)}] 处理 CIDR: {cidr}")
        candidate_ips = generate_candidate_ips(cidr)
        
        if not candidate_ips:
            print(f"  └─ ❌ 生成候选 IP 失败，请检查网段格式\n")
            continue

        is_valid = False
        hit_ip = ""
        
        # 逐个探测高频 IP 尾数
        for test_ip in candidate_ips:
            if check_tcp_port(test_ip, port=443, timeout=2):
                is_valid = True
                hit_ip = test_ip
                break

        if is_valid:
            colo = check_cf_colo(hit_ip)
            print(f"  └─ 🎉 [探测成功] 响应 IP: {hit_ip} | Colo: {colo}\n")
            valid_results.append(f"{cidr} # Colo:{colo}")
        else:
            print(f"  └─ ❌ [网段无效] 轮询 10+ 种高频 IP 模式均无响应\n")

    # 保存有效段
    with open(OUTPUT_FILE, "w") as f:
        f.write("\n".join(valid_results))

    print(f"==========================================")
    print(f"🎉 扫描完成！成功保留有效段: {len(valid_results)} 个")
    print(f"==========================================")

if __name__ == "__main__":
    main()
