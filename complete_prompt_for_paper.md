import pandas as pd
import json
from pathlib import Path
import os

# 妫€鏌?train_all_with_nvd_cwe.xlsx
train_file = "knowledge/train_all_with_nvd_cwe.xlsx"
json_file = "datasets/MSR_vul_1.json"

print("=" * 80)
print("妫€鏌?train_all_with_nvd_cwe.xlsx 鐨勬暟鎹潵婧?)
print("=" * 80)

# 璇诲彇鏂囦欢
df = pd.read_excel(train_file)
print(f"\n[1] train_all_with_nvd_cwe.xlsx:")
print(f"    璁板綍鏁? {len(df)}")
print(f"    淇敼鏃堕棿: {os.path.getmtime(train_file)}")

# 璇诲彇 JSON
with open(json_file, 'r', encoding='utf-8') as f:
    json_data = json.load(f)

json_cves = set([v.get('CVE ID', '').strip().upper() for v in json_data.values() if v.get('CVE ID', '').strip()])
df_cves = set(df['cve_id'].astype(str).str.strip().str.upper())

overlap = json_cves.intersection(df_cves)
only_in_train = df_cves - json_cves
only_in_json = json_cves - df_cves

print(f"\n[2] CVE 瀵规瘮:")
print(f"    train鏂囦欢涓殑CVE鏁? {len(df_cves)}")
print(f"    MSR_vul_1.json涓殑CVE鏁? {len(json_cves)}")
print(f"    閲嶅彔鐨凜VE鏁? {len(overlap)}")
print(f"    閲嶅彔姣斾緥: {len(overlap)/len(df_cves)*100:.1f}%")
print(f"    鍙湪train涓殑CVE鏁? {len(only_in_train)}")
print(f"    鍙湪MSR涓殑CVE鏁? {len(only_in_json)}")

print(f"\n[3] 鍓?涓噸鍙燙VE: {list(overlap)[:5]}")
print(f"\n[4] 鍓?涓彧鍦╰rain涓殑CVE: {list(only_in_train)[:5]}")
print(f"\n[5] 鍓?涓彧鍦∕SR涓殑CVE: {list(only_in_json)[:5]}")

# 妫€鏌?train 鏂囦欢鐨勫墠鍑犱釜 CVE 鏄惁鍦?MSR 涓?
print(f"\n[6] train鏂囦欢鍓?0涓狢VE鏄惁鍦∕SR涓?")
train_first_10 = df['cve_id'].head(10).astype(str).str.strip().str.upper().tolist()
for cve in train_first_10:
    in_msr = cve in json_cves
    print(f"    {cve}: {'鉁? if in_msr else '鉁?}")

print("\n" + "=" * 80)
print("缁撹:")
if len(overlap) / len(df_cves) > 0.5:
    print("train_all_with_nvd_cwe.xlsx 涓昏鍖呭惈 Big-Vul 鏁版嵁")
else:
    print("train_all_with_nvd_cwe.xlsx 涓昏鍖呭惈 MegaVul 鏁版嵁锛屽彧鏈夐儴鍒?Big-Vul 鏁版嵁")
print("=" * 80)




























































