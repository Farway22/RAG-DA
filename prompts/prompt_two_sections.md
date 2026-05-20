# -*- coding: utf-8 -*-
"""
鍑嗗BigVul娴嬭瘯闆嗗瓙闆嗭紙涓嶮egaVul瀵归綈锛屼絾鎺掗櫎閲嶅彔CVE锛?
1. 浠嶣igVul娴嬭瘯闆嗕腑鎸塎egaVul鐨勪弗閲嶆€у垎甯冮噰鏍?,208涓牱鏈?
2. 鎺掗櫎涓嶮egaVul娴嬭瘯闆嗛噸鍙犵殑CVE锛岀‘淇濆畬鍏ㄤ笉鍚岀殑婕忔礊闆嗗悎
3. 娣诲姞description鍒楋紙浠庣幇鏈塏VD鏁版嵁鍚堝苟锛岀己澶辩殑鐢ㄧ┖瀛楃涓诧級
4. 淇濆瓨涓烘柊鐨勬祴璇曢泦鏂囦欢
"""
import pandas as pd
from pathlib import Path

def prepare_bigvul_subset_no_overlap():
    """鍑嗗BigVul娴嬭瘯闆嗗瓙闆嗭紙鎺掗櫎閲嶅彔CVE锛?""
    print("=" * 80)
    print("鍑嗗BigVul娴嬭瘯闆嗗瓙闆嗭紙鎺掗櫎閲嶅彔CVE锛岀‘淇濆畬鍏ㄤ笉鍚岀殑婕忔礊闆嗗悎锛?)
    print("=" * 80)
    
    # 1. 璇诲彇MegaVul娴嬭瘯闆嗭紙浣滀负鍙傝€冨垎甯冨拰鎺掗櫎鍒楄〃锛?
    mega_path = Path("datasets/test/test_all.xlsx")
    if not mega_path.exists():
        print(f"鉂?MegaVul娴嬭瘯闆嗕笉瀛樺湪: {mega_path}")
        return False
    
    df_mega = pd.read_excel(mega_path)
    mega_cves = set(df_mega["cve_id"].unique())
    print(f"\n[MegaVul鍙傝€僝")
    print(f"  鏍锋湰鏁? {len(df_mega)}")
    print(f"  鍞竴CVE鏁? {len(mega_cves)}")
    mega_sev = df_mega["Base Severity"].value_counts().sort_index()
    print("  涓ラ噸鎬у垎甯?")
    for sev, count in mega_sev.items():
        print(f"    {sev}: {count} ({count/len(df_mega)*100:.1f}%)")
    
    # 2. 璇诲彇BigVul娴嬭瘯闆?
    big_path = Path("datasets/bigvul_hf/test_all.xlsx")
    if not big_path.exists():
        print(f"鉂?BigVul娴嬭瘯闆嗕笉瀛樺湪: {big_path}")
        return False
    
    df_big = pd.read_excel(big_path)
    print(f"\n[BigVul鍘熷]")
    print(f"  鏍锋湰鏁? {len(df_big)}")
    big_cves_all = set(df_big["cve_id"].unique())
    print(f"  鍞竴CVE鏁? {len(big_cves_all)}")
    
    # 鎺掗櫎閲嶅彔CVE
    df_big_filtered = df_big[~df_big["cve_id"].isin(mega_cves)].copy()
    big_cves_filtered = set(df_big_filtered["cve_id"].unique())
    overlap_count = len(big_cves_all & mega_cves)
    
    print(f"\n[鎺掗櫎閲嶅彔CVE]")
    print(f"  閲嶅彔CVE鏁? {overlap_count}")
    print(f"  鎺掗櫎鍚嶣igVul鏍锋湰鏁? {len(df_big_filtered)}")
    print(f"  鎺掗櫎鍚嶣igVul鍞竴CVE鏁? {len(big_cves_filtered)}")
    
    if len(df_big_filtered) < len(df_mega):
        print(f"\n鉂?鎺掗櫎閲嶅彔鍚庢牱鏈暟涓嶈冻: {len(df_big_filtered)} < {len(df_mega)}")
        print(f"   鏃犳硶閲囨牱瓒冲鐨勬牱鏈?)
        return False
    
    # 3. 鎸変弗閲嶆€у垎甯冮噰鏍凤紙浠庢帓闄ら噸鍙犲悗鐨勬暟鎹腑锛?
    print(f"\n[閲囨牱] 鐩爣鏍锋湰鏁? {len(df_mega)}")
    sampled_list = []
    
    for sev in mega_sev.index:
        target_count = mega_sev[sev]
        available = df_big_filtered[df_big_filtered["Base Severity"] == sev]
        
        if len(available) >= target_count:
            sampled = available.sample(n=target_count, random_state=42)
            sampled_list.append(sampled)
            print(f"  {sev}: 閲囨牱 {target_count}/{len(available)} 鉁?)
        else:
            print(f"  {sev}: 鍙敤 {len(available)} < 闇€瑕?{target_count} 鈿狅笍  鍏ㄩ儴浣跨敤")
            sampled_list.append(available)
    
    df_sampled = pd.concat(sampled_list, ignore_index=True)
    print(f"\n閲囨牱鍚庢牱鏈暟: {len(df_sampled)}")
    
    # 楠岃瘉鍒嗗竷
    sampled_sev = df_sampled["Base Severity"].value_counts().sort_index()
    print("閲囨牱鍚庝弗閲嶆€у垎甯?")
    for sev, count in sampled_sev.items():
        print(f"  {sev}: {count} ({count/len(df_sampled)*100:.1f}%)")
    
    # 楠岃瘉鏃犻噸鍙?
    sampled_cves = set(df_sampled["cve_id"].unique())
    final_overlap = sampled_cves & mega_cves
    print(f"\n[楠岃瘉]")
    print(f"  閲囨牱鍚庡敮涓€CVE鏁? {len(sampled_cves)}")
    print(f"  涓嶮egaVul閲嶅彔CVE鏁? {len(final_overlap)}")
    if final_overlap:
        print(f"  鉂?浠嶆湁閲嶅彔: {list(final_overlap)[:5]}")
        return False
    else:
        print(f"  鉁?鏃犻噸鍙狅紝瀹屽叏涓嶅悓鐨勬紡娲為泦鍚?)
    
    # 4. 娣诲姞description鍒?
    print(f"\n[娣诲姞description鍒梋")
    
    # 4.1 灏濊瘯浠庣幇鏈塏VD鏁版嵁鍚堝苟
    nvd_path = Path("knowledge/train_all_with_nvd_cwe.xlsx")
    has_nvd = False
    
    if nvd_path.exists():
        try:
            df_nvd = pd.read_excel(nvd_path)
            if "description" in df_nvd.columns and "cve_id" in df_nvd.columns:
                print(f"  鎵惧埌NVD鏁版嵁: {len(df_nvd)} 鏉¤褰?)
                # 鍘婚噸NVD鏁版嵁锛堟瘡涓狢VE鍙繚鐣欎竴涓猟escription锛?
                df_nvd_unique = df_nvd[["cve_id", "description"]].drop_duplicates(subset=["cve_id"], keep="first")
                print(f"  鍘婚噸鍚? {len(df_nvd_unique)} 鏉″敮涓€CVE")
                
                # 鍚堝苟description锛坙eft join锛屼笉浼氬鍔犺鏁帮級
                df_sampled = df_sampled.merge(
                    df_nvd_unique,
                    on="cve_id",
                    how="left",
                    suffixes=("", "_nvd")
                )
                # 濡傛灉鍚堝苟鎴愬姛锛屼娇鐢∟VD鐨刣escription
                if "description_nvd" in df_sampled.columns:
                    df_sampled["description"] = df_sampled["description_nvd"].fillna("")
                    df_sampled = df_sampled.drop(columns=["description_nvd"])
                    has_nvd = True
                    nvd_count = (df_sampled["description"] != "").sum()
                    print(f"  鉁?浠嶯VD鍚堝苟: {nvd_count}/{len(df_sampled)} 涓牱鏈湁description ({nvd_count/len(df_sampled)*100:.1f}%)")
        except Exception as e:
            print(f"  鈿狅笍  鍚堝苟NVD鏁版嵁澶辫触: {e}")
    
    # 4.2 濡傛灉娌℃湁description鍒楋紝鍒涘缓骞跺～鍏呯┖瀛楃涓?
    if "description" not in df_sampled.columns:
        df_sampled["description"] = ""
        print(f"  鈿狅笍  鍒涘缓description鍒楋紙绌哄瓧绗︿覆锛?)
    
    # 纭繚description鍒楀瓨鍦ㄤ笖涓嶄负None
    df_sampled["description"] = df_sampled["description"].fillna("")
    
    # 5. 妫€鏌ュ繀闇€鍒?
    required_cols = ["func_before", "Base Severity", "cve_id", "base_score", "description"]
    missing_cols = [c for c in required_cols if c not in df_sampled.columns]
    if missing_cols:
        print(f"\n鉂?缂哄皯蹇呴渶鍒? {missing_cols}")
        return False
    
    # 6. 淇濆瓨
    output_path = Path("datasets/bigvul_hf/test_subset_1208_no_overlap.xlsx")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df_sampled.to_excel(output_path, index=False)
    
    print(f"\n[淇濆瓨]")
    print(f"  鉁?淇濆瓨鍒? {output_path}")
    print(f"  鏍锋湰鏁? {len(df_sampled)}")
    print(f"  鍒? {list(df_sampled.columns)}")
    
    # 缁熻闇€瑕佺埇鍙栫殑CVE
    unique_cves = df_sampled["cve_id"].nunique()
    has_desc_cves = df_sampled[df_sampled["description"] != ""]["cve_id"].nunique()
    need_crawl = unique_cves - has_desc_cves
    
    print(f"\n[缁熻]")
    print(f"  鍞竴CVE鏁? {unique_cves}")
    print(f"  宸叉湁description鐨凜VE: {has_desc_cves}")
    print(f"  闇€瑕佺埇鍙栫殑CVE: {need_crawl}")
    if need_crawl > 0:
        estimated_time = need_crawl * 1.2 / 60  # 鍋囪姣廋VE 1.2绉?
        print(f"  棰勮鐖彇鏃堕棿: {estimated_time:.1f} 鍒嗛挓")
        print(f"\n  馃挕 寤鸿: 鍏堢敤绌篸escription杩愯瀹為獙楠岃瘉娴佺▼锛?)
        print(f"     鐒跺悗鏍规嵁闇€瑕佸喅瀹氭槸鍚︾埇鍙栧墿浣欑殑description")
    else:
        print(f"  鉁?鎵€鏈塁VE閮芥湁description锛屾棤闇€鐖彇")
    
    print(f"\n鉁?BigVul娴嬭瘯闆嗗瓙闆嗗噯澶囧畬鎴愶紒")
    print(f"  鏂囦欢: {output_path}")
    print(f"  鏍锋湰鏁? {len(df_sampled)} (涓嶮egaVul鐩稿悓)")
    print(f"  涓ラ噸鎬у垎甯? 宸插榻怣egaVul")
    print(f"  鉁?瀹屽叏涓嶅悓鐨勬紡娲為泦鍚堬紙鏃犻噸鍙燙VE锛?)
    
    return True

if __name__ == "__main__":
    prepare_bigvul_subset_no_overlap()



