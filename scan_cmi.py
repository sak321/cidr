import urllib.request
import re
import ipaddress

CIDR_FILE = "cidrs.txt"
OUTPUT_FILE = "cmi_valid_targets.txt"

def get_sample_ip(cidr_str):
    """提取代表性 IP，尝试 ::1 或 ::100"""
    try:
        net = ipaddress.IPv6Network(cidr_str.strip(), strict=False)
        # 获取网段内常见有效 IP
        return str(net[1])
    except Exception as e:
        print(f"⚠️ 格式错误 [{cidr_str}]: {e}")
        return None

def check_cf_colo(ip):
    """验证 IP 是否可达并获取机房"""
    try:
        url = f"https://[{ip}]/cdn-cgi/trace"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=8)
        with urllib.request.urlopen(req) as response:
            content = response.read().decode('utf-8')
            match = re.search(r'colo=([A-Z]+)', content)
            if match:
                return True, match.group(1)
    except Exception as e:
        pass
    return False, "TIMEOUT/UNREACHABLE"

def main():
    valid_results = []
    
    try:
        with open(CIDR_FILE, "r") as f:
            cidrs = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"❌ 找不到文件: {CIDR_FILE}")
        return

    print(f"🔍 开始检测 {len(cidrs)} 个 CIDR...\n")

    for cidr in cidrs:
        ip = get_sample_ip(cidr)
        if not ip:
            continue
            
        print(f"正在测试: {cidr} (测试 IP: {ip})")
        
        # 1. 验证可达性与机房
        is_ok, colo = check_cf_colo(ip)
        if is_ok:
            print(f"  ✅ [有效节点] 机房/Colo: {colo}")
            valid_results.append(f"{cidr} # Colo:{colo}")
        else:
            # 如果 ::1 不通，尝试 ::100 再测一次
            try:
                net = ipaddress.IPv6Network(cidr.strip(), strict=False)
                backup_ip = str(net[256]) # ::100
                is_ok_2, colo_2 = check_cf_colo(backup_ip)
                if is_ok_2:
                    print(f"  ✅ [备用 IP 有效] 机房/Colo: {colo_2}")
                    valid_results.append(f"{cidr} # Colo:{colo_2}")
                    continue
            except Exception:
                pass
            print(f"  ❌ [无响应/不可达]")

    # 写入结果
    with open(OUTPUT_FILE, "w") as f:
        f.write("\n".join(valid_results))
        
    print(f"\n🎉 处理完毕，筛选出 {len(valid_results)} 个有效 CIDR，已写入 {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
