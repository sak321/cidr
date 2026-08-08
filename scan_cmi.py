import socket
import ipaddress
import urllib.request
import re

CIDR_FILE = "cidrs.txt"
OUTPUT_FILE = "cmi_valid_targets.txt"

def get_sample_ips(cidr_str):
    """从 CIDR 抽样 3 个常见 IP 地址，防止单点不通"""
    ips = []
    try:
        net = ipaddress.IPv6Network(cidr_str.strip(), strict=False)
        # 尝试 ::1, ::10, ::100
        ips.append(str(net[1]))
        if net.num_addresses > 16:
            ips.append(str(net[16]))
        if net.num_addresses > 256:
            ips.append(str(net[256]))
    except Exception as e:
        print(f"⚠️ CIDR 格式解析错误 [{cidr_str}]: {e}")
    return ips

def check_tcp_port(ip, port=443, timeout=3):
    """通过 TCP 建连测试端口通断 (最通用)"""
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def check_cf_colo(ip):
    """尝试获取 Cloudflare Colo 机房 (若失败返回 UNKNOWN)"""
    try:
        url = f"http://[{ip}]/cdn-cgi/trace"
        req = urllib.request.Request(url, headers={'Host': 'cloudflare.com', 'User-Agent': 'Mozilla/5.0'}, timeout=3)
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
    print(f"🔍 启动检测 | 共有 {len(cidrs)} 个 CIDR 待处理")
    print(f"==========================================\n")

    for idx, cidr in enumerate(cidrs, 1):
        print(f"[{idx}/{len(cidrs)}] 正在检测 CIDR: {cidr}")
        sample_ips = get_sample_ips(cidr)
        
        if not sample_ips:
            print(f"  └─ ❌ 提取 IP 失败，跳过。")
            continue

        is_valid = False
        hit_ip = ""
        
        # 轮询探测抽样的 IP
        for ip in sample_ips:
            print(f"  ├─ 尝试 TCP 443 探测: {ip} ... ", end="")
            if check_tcp_port(ip, port=443, timeout=3):
                print("✅ 成功!")
                is_valid = True
                hit_ip = ip
                break
            else:
                print("❌ 端口不通")

        if is_valid:
            colo = check_cf_colo(hit_ip)
            print(f"  └─ 🎉 [网段有效] 响应 IP: {hit_ip} | Colo 机房: {colo}\n")
            valid_results.append(f"{cidr} # Colo:{colo}")
        else:
            print(f"  └─ ❌ [网段无效] 所有抽样 IP 均无响应\n")

    # 写入结果
    with open(OUTPUT_FILE, "w") as f:
        f.write("\n".join(valid_results))

    print(f"==========================================")
    print(f"🎉 处理完成！保留有效段: {len(valid_results)} 个")
    print(f"==========================================")

if __name__ == "__main__":
    main()
