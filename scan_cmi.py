import json
import subprocess
import re
import urllib.request
import ipaddress

CIDR_FILE = "cidrs.txt"
OUTPUT_FILE = "cmi_valid_targets.txt"

def get_sample_ip(cidr_str):
    """提取代表性 IP，优先选择 ::1"""
    try:
        net = ipaddress.IPv6Network(cidr_str.strip(), strict=False)
        return str(net[1])
    except Exception as e:
        print(f"⚠️ invalid CIDR format [{cidr_str}]: {e}")
        return None

def check_cmi_route(ip):
    """检查路由中是否包含 CMI (AS58453)"""
    try:
        cmd = ["nexttrace", "--json", "--language", "en", ip]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            return False
        
        data = json.loads(result.stdout)
        for hop in data.get("hops", []):
            for route in hop.get("routes", []):
                as_num = route.get("as_number", "")
                if as_num == 58453 or "AS58453" in str(as_num):
                    return True
        return False
    except Exception as e:
        print(f"⚠️ Tracing error for {ip}: {e}")
        return False

def check_cf_colo(ip):
    """检测 Cloudflare 机房名称（若无法检测则返回 UNKNOWN）"""
    try:
        url = f"https://[{ip}]/cdn-cgi/trace"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
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
            cidrs = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"❌ Error: {CIDR_FILE} not found!")
        return

    print(f"🔍 Found {len(cidrs)} CIDRs to scan.\n")

    for cidr in cidrs:
        ip = get_sample_ip(cidr)
        if not ip:
            continue
            
        print(f"Processing: {cidr} (Test IP: {ip})")
        
        # 1. 检查路由
        is_cmi = check_cmi_route(ip)
        if is_cmi:
            colo = check_cf_colo(ip)
            print(f"  👉  MATCH! [CMI Route] | Colo: {colo}")
            valid_results.append(f"{cidr} # Colo:{colo}")
        else:
            print(f"  ❌  FAIL: No CMI (AS58453) found in route.")

    # 写入结果
    with open(OUTPUT_FILE, "w") as f:
        f.write("\n".join(valid_results))
        
    print(f"\n✅ Finished. Found {len(valid_results)} valid CMI CIDRs.")

if __name__ == "__main__":
    main()
