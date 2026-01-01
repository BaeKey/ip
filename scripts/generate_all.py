import struct
import socket
import ipaddress
import os
import requests

# === 配置项 ===
QQWRY_URL = "https://github.com/nmgliangwei/qqwry/raw/refs/heads/main/qqwry.dat"
DB_FILE = "qqwry.dat"
OUTPUT_DIR = "output"

# 定义要抓取的运营商关键词
TASKS = {
    "cmcc": "移动",
    "unicom": "联通",
    "chinanet": "电信"
}

class QQWryParser:
    def __init__(self, filename):
        self.filename = filename
        # 自动下载逻辑
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
        # 存储各运营商的原始 IP 段
        matched_ips = {k: [] for k in TASKS.keys()}
        
        print("[Info] 开始全库扫描...")
        for i in range(self.count):
            if i % 100000 == 0 and i > 0:
                print(f"  - 进度: {i}/{self.count}")
                
            idx_offset = self.first_index + i * 7
            start_ip = struct.unpack('<I', self.data[idx_offset:idx_offset+4])[0]
            record_offset = self._get_long3(idx_offset + 4)
            end_ip = struct.unpack('<I', self.data[record_offset:record_offset+4])[0]
            
            location_str = self._get_addr(record_offset + 4)
            
            for file_key, keyword in TASKS.items():
                if keyword in location_str:
                    matched_ips[file_key].append((start_ip, end_ip))

        print("[Info] 扫描完成，正在处理文件导出...")
        
        if not os.path.exists(OUTPUT_DIR):
            os.makedirs(OUTPUT_DIR)
            
        # 1. 生成各运营商独立文件
        # 同时我们将所有抓到的段放入 total_list 用于生成 all.txt
        total_list = []
        
        for file_key, ranges in matched_ips.items():
            # 将该运营商的所有段加入总表
            total_list.extend(ranges)
            
            # 独立合并并写入
            merged = self._merge_ranges(ranges)
            self._write_to_file(merged, f"{file_key}.txt")
            print(f"[Success] {TASKS[file_key]} -> {file_key}.txt (共 {len(merged)} 条)")

        # 2. 生成合并版 (all.txt)
        print("[Info] 正在生成 all.txt (合并所有运营商)...")
        merged_all = self._merge_ranges(total_list)
        self._write_to_file(merged_all, "all.txt")
        print(f"[Success] 合并版 -> all.txt (共 {len(merged_all)} 条)")

    def _write_to_file(self, ranges, filename):
        full_path = os.path.join(OUTPUT_DIR, filename)
        with open(full_path, 'w') as f:
            for s, e in ranges:
                try:
                    s_addr = ipaddress.IPv4Address(s)
                    e_addr = ipaddress.IPv4Address(e)
                    # 转换为 CIDR
                    for net in ipaddress.summarize_address_range(s_addr, e_addr):
                        f.write(str(net) + '\n')
                except:
                    pass

    def _merge_ranges(self, raw_ranges):
        if not raw_ranges: return []
        # 按起始 IP 排序
        raw_ranges.sort(key=lambda x: x[0])
        merged = []
        curr_s, curr_e = raw_ranges[0]
        
        for next_s, next_e in raw_ranges[1:]:
            # 逻辑：如果下一段的起始 <= 当前段的结束+1，说明重叠或连续
            if next_s <= curr_e + 1:
                # 合并：结束点取两者最大值
                curr_e = max(curr_e, next_e)
            else:
                merged.append((curr_s, curr_e))
                curr_s, curr_e = next_s, next_e
        merged.append((curr_s, curr_e))
        return merged

if __name__ == "__main__":
    parser = QQWryParser(DB_FILE)
    parser.run()
