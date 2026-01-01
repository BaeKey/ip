import struct
import socket
import ipaddress
import os
import requests
import datetime

# ==================================================
# 配置项
# ==================================================
QQWRY_URL = "https://github.com/nmgliangwei/qqwry/raw/refs/heads/main/qqwry.dat"
DB_FILE = "qqwry.dat"
OUTPUT_FILE = "china_ip_list.txt"

# ==================================================
# 1. 省份映射 (中文 -> 拼音)
# 保持这个顺序，生成的文件也会按照这个顺序排列
# ==================================================
PROVINCES = {
    "北京": "beijing", "天津": "tianjin", "河北": "hebei", "山西": "shanxi", "内蒙古": "neimenggu",
    "辽宁": "liaoning", "吉林": "jilin", "黑龙江": "heilongjiang", "上海": "shanghai", "江苏": "jiangsu",
    "浙江": "zhejiang", "安徽": "anhui", "福建": "fujian", "江西": "jiangxi", "山东": "shandong",
    "河南": "henan", "湖北": "hubei", "湖南": "hunan", "广东": "guangdong", "广西": "guangxi",
    "海南": "hainan", "重庆": "chongqing", "四川": "sichuan", "贵州": "guizhou", "云南": "yunnan",
    "西藏": "xizang", "陕西": "shaanxi", "甘肃": "gansu", "青海": "qinghai", "宁夏": "ningxia",
    "新疆": "xinjiang", "香港": "hongkong", "澳门": "macau", "台湾": "taiwan"
}

# ==================================================
# 2. 运营商映射 (中文 -> 英文代码)
# ==================================================
ISPS = {
    "移动": "cmcc",
    "联通": "unicom",
    "电信": "chinanet"
}

class QQWryParser:
    def __init__(self, filename):
        self.filename = filename
        
        # 检查数据库是否存在，不存在则下载
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

        # 读取数据库内容到内存
        with open(self.filename, 'rb') as f:
            self.data = f.read()
        
        # 解析头部信息
        self.first_index = struct.unpack('<I', self.data[:4])[0]
        self.last_index = struct.unpack('<I', self.data[4:8])[0]
        self.count = (self.last_index - self.first_index) // 7 + 1
        print(f"[Info] 数据库加载成功，共 {self.count} 条记录")

    # --------------------------------------------------
    # 内部辅助函数：读取 3 字节整数
    # --------------------------------------------------
    def _get_long3(self, offset):
        return struct.unpack('<I', self.data[offset:offset+3] + b'\x00')[0]

    # --------------------------------------------------
    # 内部辅助函数：读取字符串 (GBK 编码)
    # --------------------------------------------------
    def _get_string(self, offset):
        end = self.data.find(b'\x00', offset)
        try:
            return self.data[offset:end].decode('gbk', errors='replace')
        except:
            return ""

    # --------------------------------------------------
    # 内部辅助函数：获取区域信息（处理重定向模式）
    # --------------------------------------------------
    def _get_area_addr(self, offset):
        mode = self.data[offset]
        if mode == 1 or mode == 2:
            next_offset = self._get_long3(offset + 1)
            if next_offset == 0: return ""
            return self._get_area_addr(next_offset)
        else:
            return self._get_string(offset)

    # --------------------------------------------------
    # 内部辅助函数：获取完整地址信息
    # --------------------------------------------------
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

    # --------------------------------------------------
    # 合并连续 IP 段的逻辑
    # --------------------------------------------------
    def _merge_ranges(self, raw_ranges):
        if not raw_ranges: return []
        # 按起始 IP 排序
        raw_ranges.sort(key=lambda x: x[0])
        merged = []
        curr_s, curr_e = raw_ranges[0]
        
        for next_s, next_e in raw_ranges[1:]:
            # 如果下一段的开始 <= 当前段结束 + 1，则合并
            if next_s <= curr_e + 1:
                curr_e = max(curr_e, next_e)
            else:
                merged.append((curr_s, curr_e))
                curr_s, curr_e = next_s, next_e
        merged.append((curr_s, curr_e))
        return merged

    # --------------------------------------------------
    # 主运行逻辑
    # --------------------------------------------------
    def run(self):
        # 初始化结果字典: results[省份拼音][运营商代码] = [ranges]
        results = {}
        for p_code in PROVINCES.values():
            results[p_code] = {isp_code: [] for isp_code in ISPS.values()}
        
        print("[Info] 开始全库扫描与分类...")
        
        # 遍历所有记录
        for i in range(self.count):
            if i % 200000 == 0 and i > 0:
                print(f"  - 进度: {i}/{self.count}")
                
            idx_offset = self.first_index + i * 7
            start_ip = struct.unpack('<I', self.data[idx_offset:idx_offset+4])[0]
            record_offset = self._get_long3(idx_offset + 4)
            end_ip = struct.unpack('<I', self.data[record_offset:record_offset+4])[0]
            
            location_str = self._get_addr(record_offset + 4)
            
            # 1. 匹配运营商
            detected_isp_code = None
            for isp_cn, isp_code in ISPS.items():
                if isp_cn in location_str:
                    detected_isp_code = isp_code
                    break
            
            # 如果没有匹配到指定运营商，跳过
            if not detected_isp_code:
                continue

            # 2. 匹配省份
            detected_prov_code = None
            for prov_cn, prov_code in PROVINCES.items():
                if prov_cn in location_str:
                    detected_prov_code = prov_code
                    break
            
            # 只有当省份和运营商都匹配时才存入
            if detected_prov_code:
                results[detected_prov_code][detected_isp_code].append((start_ip, end_ip))

        print("[Info] 扫描完成，正在合并网段并写入单一文件...")
        
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 打开单一文件进行写入
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write(f"# Generated by script at {current_time}\n")
            f.write("# Format: IP_CIDR # Comment\n\n")

            # 按照 PROVINCES 的顺序遍历，保证输出有序
            for prov_cn, prov_code in PROVINCES.items():
                
                # 检查该省份是否有数据
                prov_has_data = any(len(results[prov_code][isp]) > 0 for isp in ISPS.values())
                if not prov_has_data:
                    continue
                
                # 写入省份大标题（使用 # 注释格式）
                f.write(f"# {'='*50}\n")
                f.write(f"# 省份区域: {prov_cn} ({prov_code})\n")
                f.write(f"# {'='*50}\n")

                for isp_cn, isp_code in ISPS.items():
                    ranges = results[prov_code][isp_code]
                    if not ranges:
                        continue

                    # 合并 IP 段
                    merged = self._merge_ranges(ranges)
                    
                    # 写入分组注释头
                    f.write(f"\n# === [{prov_cn}] {isp_cn} | 规则数: {len(merged)} ===\n")
                    
                    for s, e in merged:
                        try:
                            s_addr = ipaddress.IPv4Address(s)
                            e_addr = ipaddress.IPv4Address(e)
                            # 转换为 CIDR 格式并写入
                            for net in ipaddress.summarize_address_range(s_addr, e_addr):
                                f.write(f"{str(net)}\n")
                        except Exception as e:
                            # 极少数畸形IP段跳过
                            pass
                
                # 省份之间空一行
                f.write("\n")

        print(f"[Success] 所有数据已合并写入: {OUTPUT_FILE}")

# ==================================================
# 程序入口
# ==================================================
if __name__ == "__main__":
    parser = QQWryParser(DB_FILE)
    parser.run()
