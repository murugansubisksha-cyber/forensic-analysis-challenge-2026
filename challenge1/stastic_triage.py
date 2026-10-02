#!/usr/bin/env python3
"""Static triage only. NEVER executes samples. Usage: python static_triage.py <dir> [out.md]"""
import sys, os, re, math, hashlib, collections
try: import pefile
except ImportError: pefile = None

SUSP = ["LoadLibrary","GetProcAddress","VirtualAlloc","VirtualProtect","CreateProcess","WinExec",
        "ShellExecute","URLDownloadToFile","powershell","cmd.exe","CreateRemoteThread","WriteProcessMemory",
        "RegSetValue","CreateService","http://","https://","LMIGuardian","IsDebuggerPresent"]

def entropy(b):
    if not b: return 0.0
    n=len(b); return -sum(c/n*math.log2(c/n) for c in collections.Counter(b).values())

def strings(b, m=6):
    a=re.findall(rb"[\x20-\x7e]{%d,}"%m,b)
    u=re.findall(rb"(?:[\x20-\x7e]\x00){%d,}"%m,b)
    return [s.decode() for s in a]+[s.decode("utf-16le") for s in u]

def secname(s): return s.Name.rstrip(b"\0").decode(errors="ignore")

def main(d, out):
    L=["# Static triage\n"]
    for root,_,files in os.walk(d):
      for f in sorted(files):
        p=os.path.join(root,f)
        b=open(p,"rb").read()
        L.append(f"\n## {f}\n- size: {len(b)}\n- MD5: {hashlib.md5(b).hexdigest()}\n- SHA1: {hashlib.sha1(b).hexdigest()}\n- SHA256: {hashlib.sha256(b).hexdigest()}\n- entropy: {entropy(b):.3f} bits/byte\n- header(32): {b[:32].hex()}\n- MZ header: {b[:2]==b'MZ'}")
        if b[:2]==b"MZ" and pefile:
            try:
                pe=pefile.PE(data=b)
                L.append(f"- compile timestamp: {pe.FILE_HEADER.TimeDateStamp} | DLL: {pe.is_dll()} | machine: {hex(pe.FILE_HEADER.Machine)}")
                L.append("- sections: "+", ".join(f"{secname(s)}(ent {s.get_entropy():.2f})" for s in pe.sections))
                if hasattr(pe,"DIRECTORY_ENTRY_IMPORT"):
                    for e in pe.DIRECTORY_ENTRY_IMPORT:
                        L.append(f"- imports {e.dll.decode()}: "+", ".join(i.name.decode() for i in e.imports if i.name)[:600])
                if hasattr(pe,"DIRECTORY_ENTRY_EXPORT"):
                    L.append("- exports: "+", ".join(s.name.decode() for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name)[:600])
                L.append(f"- has signature: {bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size)}")
            except Exception as e: L.append(f"- pefile error: {e}")
        S=strings(b)
        hits=sorted({s for s in S for k in SUSP if k.lower() in s.lower()})
        L.append(f"- interesting strings ({len(hits)}):\n```\n"+"\n".join(hits[:80])+"\n```")
        L.append("- referenced .dll/.exe names: "+", ".join(sorted({s for s in S if re.search(r'\.(dll|exe)$',s,re.I)})[:40]))
    open(out,"w").write("\n".join(L)); print("\n".join(L)); print("\nSaved:",out)
if __name__=="__main__": main(sys.argv[1], sys.argv[2] if len(sys.argv)>2 else "triage.md")