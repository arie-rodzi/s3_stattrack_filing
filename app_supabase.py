import streamlit as st
import pandas as pd
from passlib.hash import bcrypt
from hashlib import sha256
from supabase import create_client

st.set_page_config(page_title="UiTM Filing – Supabase", layout="wide")
st.title("Sistem Filing – Statistik UiTM N9 (Supabase)")

# ---- Supabase client from secrets ----
sb = create_client(st.secrets["SUPABASE_URL"], st.secrets["SUPABASE_KEY"])
SUPABASE_BUCKET = st.secrets.get("SUPABASE_BUCKET", "uitm-files")
SITE_SALT = st.secrets.get("SITE_SALT", "")

# ---- Helpers ----
def sha256_bytes(b: bytes) -> str:
    h = sha256(); h.update(b); return h.hexdigest()

def hash_pw(p: str) -> str:
    return bcrypt.hash(p + SITE_SALT)

def verify_pw(p: str, hashed: str) -> bool:
    try:
        return bcrypt.verify(p + SITE_SALT, hashed)
    except Exception:
        return False

def table_empty(table_name: str) -> bool:
    r = sb.table(table_name).select("id", count="exact").limit(1).execute()
    return (r.count or 0) == 0

# ---- Seeding ----
def seed_users_if_needed():
    if not table_empty("users"): return
    path = "seed/all_users_credentials.xlsx"
    try:
        df = pd.read_excel(path)
    except Exception:
        st.warning("Seed users not found; upload users later.")
        return
    recs = []
    for _, r in df.iterrows():
        pw = str(r.get("password","")).strip() or "ChangeMe!123"
        recs.append({
            "category": str(r.get("category","LECTURER")).upper(),
            "role": str(r.get("role","LECTURER")).upper(),
            "name": str(r.get("name","")),
            "username": str(r.get("username","")).lower(),
            "password_hash": hash_pw(pw),
            "notes": str(r.get("notes",""))
        })
    if recs: sb.table("users").insert(recs).execute()

def seed_subjects_if_needed():
    if not table_empty("subjects"): return
    path = "seed/subjects_master_with_periods_v2.xlsx"
    try:
        df = pd.read_excel(path)
    except Exception:
        st.warning("Seed subjects not found; upload subjects later.")
        return
    recs = []
    for _, r in df.iterrows():
        code = str(r.get("subject_code","")).strip()
        if not code: continue
        recs.append({
            "subject_code": code,
            "subject_name": str(r.get("subject_name","")).strip(),
            "lic": str(r.get("LIC","")).strip(),
            "lic_start": str(r.get("LIC_start","")).strip(),
            "lic_end": str(r.get("LIC_end","")).strip(),
            "rp": str(r.get("RP","")).strip(),
            "rp_start": str(r.get("RP_start","")).strip(),
            "rp_end": str(r.get("RP_end","")).strip(),
        })
    if recs: sb.table("subjects").insert(recs).execute()

seed_users_if_needed()
seed_subjects_if_needed()

# ---- Sidebar: auth & Public mode ----
st.sidebar.header("Log Masuk")
username = st.sidebar.text_input("Username")
password = st.sidebar.text_input("Password", type="password")
login_btn = st.sidebar.button("Login")

user = None
if login_btn:
    res = sb.table("users").select("*").eq("username", username.lower()).limit(1).execute()
    if res.data:
        u = res.data[0]
        if verify_pw(password, u["password_hash"]):
            st.session_state["user"] = u
            user = u
        else:
            st.sidebar.error("Username atau kata laluan salah.")
    else:
        st.sidebar.error("Username tidak ditemui.")
elif "user" in st.session_state:
    user = st.session_state["user"]

st.sidebar.markdown("---")
public_mode = st.sidebar.toggle("Public (student) view", value=False)

# ---- Public View ----
if public_mode:
    st.subheader("Dokumen Umum (Rubrics / Course Info / CAP)")
    q = st.text_input("Cari dokumen (jenis/nama fail)")
    r = sb.table("files").select("*").in_("doc_type", ["rubrics","course_info","cap"]).execute()
    dfp = pd.DataFrame(r.data or [])
    if q and not dfp.empty:
        ql = q.lower()
        dfp = dfp[dfp.apply(lambda row: any(ql in str(v).lower() for v in row.values), axis=1)]
    if dfp.empty:
        st.info("Belum ada dokumen umum.")
    else:
        st.dataframe(dfp[["doc_type","subject_code","semester","url","uploaded_at"]], use_container_width=True)
    st.markdown("---")
    st.subheader("Senarai LIC/RP & Tempoh Lantikan")
    s = sb.table("subjects").select("*").order("subject_code").execute()
    dfs = pd.DataFrame(s.data or [])
    q2 = st.text_input("Cari (kod/nama subjek atau nama pensyarah)")
    if q2 and not dfs.empty:
        ql = q2.lower()
        dfs = dfs[dfs.apply(lambda row: any(ql in str(v).lower() for v in row.values), axis=1)]
    if dfs.empty:
        st.info("Tiada data subjek.")
    else:
        st.dataframe(dfs[["subject_code","subject_name","lic","lic_start","lic_end","rp","rp_start","rp_end"]], use_container_width=True)
    st.stop()

# ---- Auth required below ----
if not user:
    st.info("Sila log masuk atau aktifkan Public view di sidebar.")
    st.stop()

st.sidebar.success(f"Log masuk sebagai: {user['username']} ({user['role']})")
if st.sidebar.button("Log Keluar"):
    st.session_state.pop("user", None)
    st.rerun()

role = (user["role"] or "").upper()
tabs = st.tabs(["Upload", "Arkib", "Subjek (LIC/RP)", "Admin"])

with tabs[0]:
    st.subheader("Muat Naik Dokumen Kursus")
    subs = sb.table("subjects").select("subject_code,subject_name").order("subject_code").execute().data or []
    if not subs:
        st.warning("Belum ada subjek.")
    else:
        options = {f"{x['subject_code']} — {x['subject_name']}": x["subject_code"] for x in subs}
        sub_label = st.selectbox("Subjek", list(options.keys()))
        subject_code = options[sub_label]

        col1, col2, col3 = st.columns(3)
        with col1: role_sel = st.selectbox("Peranan dalam subjek", ["LIC","RP","STAFF"])
        with col2: doc_type = st.selectbox("Jenis Dokumen", ["rubrics","course_info","cap","lesson_plan","slt","jsu_final","jsu_test","jsu_project","surat_lantikan_lic","surat_lantikan_rp"])
        with col3: semester = st.text_input("Semester", value="Okt 2025")

        up = st.file_uploader("Pilih fail", type=None)
        if up and st.button("Upload"):
            data = up.read()
            digest = sha256_bytes(data)
            path = f"{subject_code}/{semester}/{role_sel}/{digest[:8]}_{up.name}"
            sb.storage.from_(SUPABASE_BUCKET).upload(path, data, {"upsert": False})
            url = sb.storage.from_(SUPABASE_BUCKET).get_public_url(path)
            sb.table("files").insert({
                "subject_code": subject_code,
                "uploader_username": user["username"],
                "role": role_sel,
                "doc_type": doc_type,
                "semester": semester,
                "url": url,
                "sha256": digest
            }).execute()
            st.success("Berjaya dimuat naik ke Supabase ✅")

with tabs[1]:
    st.subheader("Arkib Dokumen")
    q = st.text_input("Cari (kod/jenis/semester/uploader):")
    query = sb.table("files").select("*").order("uploaded_at", desc=True)
    if role == "LECTURER":
        query = query.eq("uploader_username", user["username"])
    res = query.execute()
    df = pd.DataFrame(res.data or [])
    if q and not df.empty:
        ql = q.lower()
        df = df[df.apply(lambda row: any(ql in str(v).lower() for v in row.values), axis=1)]
    if df.empty:
        st.info("Tiada dokumen.")
    else:
        st.dataframe(df[["subject_code","doc_type","semester","uploader_username","uploaded_at","url"]], use_container_width=True)

with tabs[2]:
    st.subheader("Senarai Subjek (Siapa LIC/RP & Tempoh Lantikan)")
    s = sb.table("subjects").select("*").order("subject_code").execute()
    dfs = pd.DataFrame(s.data or [])
    q2 = st.text_input("Cari subjek/nama pensyarah")
    if q2 and not dfs.empty:
        ql = q2.lower()
        dfs = dfs[dfs.apply(lambda row: any(ql in str(v).lower() for v in row.values), axis=1)]
    st.dataframe(dfs, use_container_width=True)

with tabs[3]:
    if role not in {"ADMIN","KPP","AJK"}:
        st.info("Hanya Admin/KPP/AJK boleh akses tetapan ini.")
    else:
        st.markdown("**Pengguna**")
        users = sb.table("users").select("category,role,name,username,notes").order("username").execute().data or []
        st.dataframe(pd.DataFrame(users), use_container_width=True, height=250)

        st.markdown("---")
        st.markdown("**Subjek**")
        subs = sb.table("subjects").select("*").order("subject_code").execute().data or []
        sdf = pd.DataFrame(subs)
        st.dataframe(sdf[["subject_code","subject_name","lic","rp"]], use_container_width=True, height=250)

        colA, colB = st.columns(2)
        with colA:
            st.write("Tambah Subjek")
            new_code = st.text_input("Kod")
            new_name = st.text_input("Nama")
            if st.button("Tambah"):
                if new_code and new_name:
                    sb.table("subjects").insert({"subject_code": new_code.strip(),"subject_name": new_name.strip()}).execute()
                    st.success("Ditambah."); st.rerun()
                else:
                    st.warning("Isi kod & nama.")
        with colB:
            st.write("Buang Subjek")
            del_code = st.text_input("Kod untuk dibuang")
            if st.button("Buang"):
                sb.table("subjects").delete().eq("subject_code", del_code.strip()).execute()
                st.success("Dibuang."); st.rerun()
