import struct
import socket
import ipaddress
import os
import requests
import datetime

# === 配置项 ===
QQWRY_URL = "https://github.com/nmgliangwei/qqwry/raw/refs/heads/main/qqwry.dat"
DB_FILE = "qqwry.dat"
OUTPUT_DIR = "data"

# 1. 省份映射 (中文 -> 拼音)
PROVINCES = {
    "北京": "beijing", "天津": "tianjin", "河北": "hebei", "山西": "shanxi", "内蒙古": "neimenggu",
    "辽宁": "liaoning", "吉林": "jilin", "黑龙江": "heilongjiang", "上海": "shanghai", "江苏": "jiangsu",
    "浙江": "zhejiang", "安徽": "anhui", "福建": "fujian", "江西": "jiangxi", "山东": "shandong",
    "河南": "henan", "湖北": "hubei", "湖南": "hunan", "广东": "guangdong", "广西": "guangxi",
    "海南": "hainan", "重庆": "chongqing", "四川": "sichuan", "贵州": "guizhou", "云南": "yunnan",
    "西藏": "xizang", "陕西": "shaanxi", "甘肃": "gansu", "青海": "qinghai", "宁夏": "ningxia",
    "新疆": "xinjiang", "香港": "hongkong", "澳门": "macau", "台湾": "taiwan"
}

# 2. 运营商映射 (中文 -> 英文代码)
ISPS = {
    "移动": "cmcc",
    "联通": "unicom",
    "电信": "chinanet"
}

# 3. 预先生成反向映射 (用于写注释: beijing -> 北京, cmcc -> 移动)
CODE_TO_PROV_CN = {v: k for k, v in PROVINCES.items()}
CODE_TO_ISP_CN = {v: k for k, v in ISPS.items()}

class QQWryParser:
    def __init__(self, filename):
        self.filename = filename
        if not os.path.exists(filename):
            print(f"[Info] 正在下载数据库: {QQWRY_URL}")
            try:
                r = requests.get(QQWRY_URL, allow_redirects=True, stream=True)
                r.raise_for_status()
                with open(filename, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
                print("[Info] 下载完成")
            except Exception as e:
                print(f"[Error] 下载失败: {e}")
                raise

        with open(self.filename, 'rb') as f:
            self.data = f.read()
        
        self.first_index = struct.unpack('<I', self.data[:4])[0]
        self.last_index = struct.unpack('<I', self.data[4:8])[0]
        self.count = (self.last_index - self.first_index) // 7 + 1
        print(f"[Info] 数据库加载成功，共 {self.count} 条记录")

    def _get_long3(self, offset):
        return struct.unpack('<I', self.data[offset:offset+3] + b'\x00')[0]

    def _get_string(self, offset):
        end = self.data.find(b'\x00', offset)
        try:
            return self.data[offset:end].decode('gbk', errors='replace')
        except:
            return ""

    def _get_area_addr(self, offset):
        mode = self.data[offset]
        if mode == 1 or mode == 2:
            next_offset = self._get_long3(offset + 1)
            if next_offset == 0: return ""
            return self._get_area_addr(next_offset)
        else:
            return self._get_string(offset)

    def _get_addr(self, offset):
        try:
            mode = self.data[offset]
            if mode == 1:
                seek_offset = self._get_long3(offset + 1)
                return self._get_addr(seek_offset)
            elif mode == 2:
                seek_offset = self._get_long3(offset + 1)
                country = self._get_string(seek_offset)
                area = self._get_area_addr(offset + 4)
            else:
                country = self._get_string(offset)
                area = self._get_area_addr(offset + len(country.encode('gbk')) + 1)
            return f"{country} {area}"
        except:
            return ""

    def run(self):
        # results[省份拼音][运营商代码] = [ranges]
        results = {}
        for p_code in PROVINCES.values():
            results[p_code] = {isp_code: [] for isp_code in ISPS.values()}
        
        results['nationwide'] = {isp_code: [] for isp_code in ISPS.values()}

        print("[Info] 开始全库扫描与分类...")
        for i in range(self.count):
            if i % 200000 == 0 and i > 0:
                print(f"  - 进度: {i}/{self.count}")
                
            idx_offset = self.first_index + i * 7
            start_ip = struct.unpack('<I', self.data[idx_offset:idx_offset+4])[0]
            record_offset = self._get_long3(idx_offset + 4)
            end_ip = struct.unpack('<I', self.data[record_offset:record_offset+4])[0]
            
            location_str = self._get_addr(record_offset + 4)
            
            detected_isp_code = None
            for isp_cn, isp_code in ISPS.items():
                if isp_cn in location_str:
                    detected_isp_code = isp_code
                    break
            
            if not detected_isp_code:
                continue

            detected_prov_code = None
            for prov_cn, prov_code in PROVINCES.items():
                if prov_cn in location_str:
                    detected_prov_code = prov_code
                    break
            
            if detected_prov_code:
                results[detected_prov_code][detected_isp_code].append((start_ip, end_ip))
            
            results['nationwide'][detected_isp_code].append((start_ip, end_ip))

        print("[Info] 扫描完成，正在处理文件导出...")
        
        if not os.path.exists(OUTPUT_DIR):
            os.makedirs(OUTPUT_DIR)

        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for prov_code, isp_data in results.items():
            has_data = any(len(ranges) > 0 for ranges in isp_data.values())
            if not has_data:
                continue

            prov_dir = os.path.join(OUTPUT_DIR, prov_code)
            if not os.path.exists(prov_dir):
                os.makedirs(prov_dir)

            for isp_code, ranges in isp_data.items():
                if not ranges: continue

                merged = self._merge_ranges(ranges)
                filename = os.path.join(prov_dir, f"{isp_code}.txt")
                
                # === 获取中文名称用于注释 ===
                # 如果是 nationwide，手动显示为“全国”
                if prov_code == 'nationwide':
                    prov_cn_name = "全国(汇总)"
                else:
                    prov_cn_name = CODE_TO_PROV_CN.get(prov_code, prov_code)
                
                isp_cn_name = CODE_TO_ISP_CN.get(isp_code, isp_code)
                
                # === 写入文件 ===
                with open(filename, 'w') as f:
                    # 写入第一行注释
                    # 格式: # 陕西 移动 (共 520 条规则) - 2024-05-20 08:00:00
                    header = f"# {prov_cn_name} {isp_cn_name} IP段列表 | 规则数: {len(merged)} | 更新时间: {current_time}\n"
                    f.write(header)

                    for s, e in merged:
                        try:
                            s_addr = ipaddress.IPv4Address(s)
                            e_addr = ipaddress.IPv4Address(e)
                            for net in ipaddress.summarize_address_range(s_addr, e_addr):
                                f.write(str(net) + '\n')
                        except:
                            pass
            
        print("[Success] 所有文件生成完毕。")

    def _merge_ranges(self, raw_ranges):
        if not raw_ranges: return []
        raw_ranges.sort(key=lambda x: x[0])
        merged = []
        curr_s, curr_e = raw_ranges[0]
        
        for next_s, next_e in raw_ranges[1:]:
            if next_s <= curr_e + 1:
                curr_e = max(curr_e, next_e)
            else:
                merged.append((curr_s, curr_e))
                curr_s, curr_e = next_s, next_e
        merged.append((curr_s, curr_e))
        return merged

if __name__ == "__main__":
    parser = QQWryParser(DB_FILE)
    parser.run()
