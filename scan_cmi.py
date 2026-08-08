import json
import subprocess
import re
import urllib.request
import ipaddress

# 输入的 IPv6 CIDR 列表文件
CIDR_FILE = "cidrs.txt"
# 输出筛选后的 CMI 候选 IP/CIDR 结果
OUTPUT_FILE = "cmi_valid_targets.txt"

def get_sample_ip(cidr_str):
    """从 CIDR 中提取一个代表性 IP（获取网段内的第 2 个 IP）"""
    try:
        net = ipaddress.IPv6Network(cidr_str.strip(), strict=False)
        return str(net[1])
    except Exception:
        return None

def check_cmi_route(ip):
    """通过 NextTrace 检查路由是否包含 AS58453 (CMI)"""
    try:
        cmd = ["nexttrace", "--json", "--language", "en", ip]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            return False
        
        data = json.loads(result.stdout)
        # 遍历所有路由跳数，检查是否有 AS58453
        for hop in data.get("hops", []):
            for route in hop.get("routes", []):
                as_num = route.get("as_number", "")
                if as_num == 58453 or "AS58453" in str(as_num):
                    return True
        return False
    except Exception as e:
        print(f"Error tracing {ip}: {e}")
        return False

def check_cf_colo(ip):
    """对 Cloudflare 节点检查 Colo (机房) 是否为 HKG / TYO / NRT"""
    try:
        url = f"https://[{ip}]/cdn-cgi/trace"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            content = response.read().decode('utf-8')
            match = re.search(r'colo=([A-Z]+)', content)
            if match:
                colo = match.group(1)
                # 仅保留香港、东京、成田机房
                if colo in ["HKG", "TYO", "NRT"]:
                    return True, colo
    except Exception:
        pass
    return False, None

def main():
    valid_results = []
    
    try:
        with open(CIDR_FILE, "r") as f:
            cidrs = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"❌ Error: {CIDR_FILE} not found in root directory!")
        return

    for cidr in cidrs:
        ip = get_sample_ip(cidr)
        if not ip:
            continue
            
        print(f"Checking {cidr} (Sample IP: {ip})...")
        
        # 1. 验证是否走 CMI 路由
        is_cmi = check_cmi_route(ip)
        if not is_cmi:
            print(f"❌ {cidr} -> Not CMI")
            continue
            
        # 2. 验证 CDN 机房 (针对 Cloudflare)
        is_valid_colo, colo = check_cf_colo(ip)
        if is_valid_colo:
            print(f"✅ {cidr} -> CMI Match! Colo: {colo}")
            valid_results.append(f"{cidr} # {colo}")
        else:
            print(f"⚠️ {cidr} -> CMI Route ok, but Colo check skipped/failed")

    # 保存筛选结果
    with open(OUTPUT_FILE, "w") as f:
        f.write("\n".join(valid_results))
    print(f"\nDone! Saved valid CMI targets to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
