#!/usr/bin/env python3
"""Who is compromised and how.
python analyze_logs.py --dir ./evidence --inspect   (see columns first)
python analyze_logs.py --dir ./evidence --out out"""
import argparse, glob, os, re, pandas as pd

SHA=r"\b([a-fA-F0-9]{64})\b"
def load(p): return pd.read_csv(p, low_memory=False, dtype=str, on_bad_lines="skip")
def guess(cols, keys):
    for k in keys:
        for c in cols:
            if k in c.lower(): return c
def find(d, key):
    m=[f for f in glob.glob(os.path.join(d,"**","*.csv"),recursive=True) if key in os.path.basename(f).lower()]
    return m[0] if m else None
def flat(df): return df.fillna("").astype(str).agg(" | ".join,axis=1)

ap=argparse.ArgumentParser()
ap.add_argument("--dir",required=True); ap.add_argument("--out",default="out")
ap.add_argument("--inspect",action="store_true"); ap.add_argument("--window",type=int,default=30,help="minutes")
a=ap.parse_args(); os.makedirs(a.out,exist_ok=True)
paths={k:find(a.dir,k) for k in ("web","secur","usb")}; print(paths)
D={k:load(p) for k,p in paths.items() if p}
if a.inspect:
    for k,df in D.items(): print(f"\n== {k}: {df.shape}\n{df.head(3).T}\n")
    raise SystemExit

def prep(df):
    ep=guess(df.columns,["endpoint","host","device"]); t=guess(df.columns,["time","date"])
    df=df.copy(); df["_ep"]=df[ep]; df["_t"]=pd.to_datetime(df[t],errors="coerce",utc=True); df["_txt"]=flat(df); return df
sec=prep(D["secur"]); web=prep(D["web"]); usb=prep(D["usb"]) if "usb" in D else None
sec["_sha"]=sec["_txt"].str.extract(SHA)[0].str.lower()
print("Web:",len(web),"| Security:",len(sec),"| USB:",0 if usb is None else len(usb),"| Endpoints:",pd.concat([web._ep,sec._ep]).nunique())

kw=re.compile(r"malic|trojan|malware|virus|quarantin|ransom|backdoor|worm|pua|threat",re.I)  # tune after --inspect
mal=sec[sec["_txt"].str.contains(kw)].copy(); mal.to_csv(f"{a.out}/malicious_events.csv",index=False)
hosts=mal.groupby("_ep").agg(events=("_ep","size"),distinct_hashes=("_sha","nunique"),first=("_t","min"),last=("_t","max")).sort_values("distinct_hashes",ascending=False)
hosts.to_csv(f"{a.out}/malicious_hosts.csv"); print("\nEndpoints with malicious events:",len(hosts)); print(hosts.head(15))
cl=mal.dropna(subset=["_sha"]).groupby("_sha")["_ep"].agg(hosts="nunique",endpoints=lambda s:sorted(set(s))).sort_values("hosts",ascending=False)
cl.to_csv(f"{a.out}/hash_clusters.csv"); print("\nMulti-host hashes:\n",cl[cl.hosts>1])

rows=[]
for ep,g in mal.groupby("_ep"):
    w=web[web._ep==ep]
    for _,r in g.dropna(subset=["_t"]).iterrows():
        near=w[(w._t<=r._t)&(w._t>=r._t-pd.Timedelta(minutes=a.window))]
        for _,x in near.iterrows(): rows.append({"endpoint":ep,"detect_time":r._t,"detect":r._txt[:200],"web_time":x._t,"web":x._txt[:300]})
pd.DataFrame(rows).to_csv(f"{a.out}/web_before_detection.csv",index=False); print("\nweb-before-detection rows:",len(rows))
if usb is not None:
    rows=[{"endpoint":u._ep,"usb":u._txt[:200],"usb_time":u._t,
           "detections_within_24h":len(mal[(mal._ep==u._ep)&(mal._t>=u._t)&(mal._t<=u._t+pd.Timedelta(hours=24))])} for _,u in usb.iterrows()]
    pd.DataFrame(rows).to_csv(f"{a.out}/usb_correlation.csv",index=False); print(pd.DataFrame(rows))
for ep,g in mal.groupby("_ep"): g.sort_values("_t")[["_t","_txt"]].to_csv(f"{a.out}/timeline_{ep}.csv",index=False)