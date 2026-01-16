
import tkinter as tk
from tkinter import ttk, messagebox
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import os
import sys

# ================= BULLETPROOF CSV LOADER =================
def get_csv_path(filename):
    if hasattr(sys, "_MEIPASS"):
        mei = os.path.join(sys._MEIPASS, filename)
        if os.path.exists(mei):
            return mei

    base_dir = (
        os.path.dirname(sys.executable)
        if getattr(sys, "frozen", False)
        else os.path.dirname(os.path.abspath(__file__))
    )
    exe_path = os.path.join(base_dir, filename)
    if os.path.exists(exe_path):
        return exe_path

    cwd_path = os.path.join(os.getcwd(), filename)
    if os.path.exists(cwd_path):
        return cwd_path

    raise FileNotFoundError(f"{filename} not found")

# ================= LOAD DATA =================
try:
    df = pd.read_csv(get_csv_path("siem_alerts.csv"))
except FileNotFoundError:
    df = pd.read_csv(get_csv_path("siem_features.csv"))

# ================= COLUMN NORMALIZATION =================
# Accept multiple possible names for risk score
RISK_ALIASES = ["risk_score", "risk", "score", "anomaly_score", "severity_score"]

found_risk_col = None
for col in RISK_ALIASES:
    if col in df.columns:
        found_risk_col = col
        break

if not found_risk_col:
    messagebox.showerror(
        "CSV Error",
        "No risk score column found.\n\n"
        "Expected one of:\n"
        f"{', '.join(RISK_ALIASES)}"
    )
    sys.exit(1)

# Normalize column name
df.rename(columns={found_risk_col: "risk_score"}, inplace=True)

# Validate remaining required columns
required_cols = ["alert_type", "user", "destination_host", "risk_score"]
missing = [c for c in required_cols if c not in df.columns]

if missing:
    messagebox.showerror(
        "CSV Error",
        f"Missing required columns:\n{', '.join(missing)}"
    )
    sys.exit(1)

# ================= RISK LEVEL =================
def compute_risk_level(score):
    try:
        score = float(score)
    except Exception:
        return "LOW"

    if score >= 0.70:
        return "HIGH"
    elif score >= 0.45:
        return "MEDIUM"
    return "LOW"

df["risk_score"] = df["risk_score"].astype(float)
df["risk_level"] = df["risk_score"].apply(compute_risk_level)
df["status"] = "NEW"

# ================= MITRE MAP =================
MITRE_MAP = {
    "PRIV_ESC": ("Privilege Escalation", "T1068"),
    "BRUTE_FORCE": ("Credential Access", "T1110"),
    "LATERAL_MOVE": ("Lateral Movement", "T1021"),
    "DATA_EXFIL": ("Exfiltration", "T1041"),
    "MALWARE_EXEC": ("Execution", "T1059"),
    "PORT_SCAN": ("Discovery", "T1046"),
    "AUTH_FAILURE": ("Credential Access", "T1110"),
}

# ================= ML EXPLANATION =================
def ml_explanation(score):
    if score >= 0.75:
        return [
            "Strong privilege escalation signal",
            "Off-hours administrative activity",
            "Multiple failed authentication attempts"
        ]
    elif score >= 0.45:
        return [
            "Suspicious behavior detected",
            "Moderate anomaly score"
        ]
    return [
        "Low-confidence anomaly",
        "Likely benign activity"
    ]

# ================= COLORS =================
BG = "#020617"
HIGH = "#7f1d1d"
MED = "#78350f"
LOW = "#1e3a8a"

CHART_COLORS = {
    "HIGH": "#dc2626",
    "MEDIUM": "#facc15",
    "LOW": "#38bdf8"
}

# ================= WINDOW =================
root = tk.Tk()
root.title("SOC Alert Triage Dashboard – Tier 1")
root.geometry("1600x900")
root.configure(bg=BG)

tk.Label(
    root,
    text="🛡️ SOC Alert Prioritization Dashboard (Tier-1)",
    bg=BG,
    fg="white",
    font=("Segoe UI", 18, "bold"),
    pady=12
).pack(fill="x")

# ================= SEVERITY FILTER =================
filter_frame = tk.Frame(root, bg=BG)
filter_frame.pack(fill="x", padx=10)

tk.Label(filter_frame, text="Severity Filter:", fg="white", bg=BG,
         font=("Segoe UI", 10, "bold")).pack(side="left")

severity_var = tk.StringVar(value="ALL")

for lvl in ["ALL", "HIGH", "MEDIUM", "LOW"]:
    ttk.Radiobutton(filter_frame, text=lvl,
                    variable=severity_var, value=lvl).pack(side="left", padx=6)

# ================= MAIN PANELS =================
main = tk.Frame(root, bg=BG)
main.pack(fill="both", expand=True)

left = tk.Frame(main, bg=BG)
left.pack(side="left", fill="both", expand=True)

right = tk.Frame(main, bg=BG, width=420)
right.pack(side="right", fill="y")

# ================= ALERT TABLE =================
columns = ("alert_type", "user", "destination_host",
           "risk_level", "risk_score", "status")

tree = ttk.Treeview(left, columns=columns, show="headings")

for col in columns:
    tree.heading(col, text=col.upper())
    tree.column(col, anchor="center")

tree.pack(fill="both", expand=True, padx=10, pady=10)

tree.tag_configure("HIGH", background=HIGH)
tree.tag_configure("MEDIUM", background=MED)
tree.tag_configure("LOW", background=LOW)

df_view = df.sample(frac=1).reset_index(drop=True)

# ================= POPULATE TABLE =================
def populate_table():
    tree.delete(*tree.get_children())
    sev = severity_var.get()
    data = df_view if sev == "ALL" else df_view[df_view["risk_level"] == sev]

    for idx, row in data.iterrows():
        tree.insert("", "end", iid=idx,
                    values=(
                        row["alert_type"],
                        row["user"],
                        row["destination_host"],
                        row["risk_level"],
                        f"{row['risk_score']:.3f}",
                        row["status"]
                    ),
                    tags=(row["risk_level"],))
    update_charts(data)

# ================= INVESTIGATION PANEL =================
invest = ttk.LabelFrame(right, text="Alert Investigation", padding=10)
invest.pack(fill="x", padx=10, pady=10)

invest_text = tk.Text(invest, height=14, bg=BG, fg="white", relief="flat")
invest_text.pack(fill="x")

def on_select(event):
    sel = tree.selection()
    if not sel:
        return

    row = df_view.iloc[int(sel[0])]
    tactic, tech = MITRE_MAP.get(row["alert_type"], ("Unknown", "N/A"))
    expl = ml_explanation(row["risk_score"])

    msg = (
        f"Alert Type: {row['alert_type']}\n"
        f"User: {row['user']}\n"
        f"Host: {row['destination_host']}\n"
        f"Risk: {row['risk_level']} ({row['risk_score']:.3f})\n"
        f"Status: {row['status']}\n\n"
        f"MITRE ATT&CK:\n"
        f"Tactic: {tactic}\n"
        f"Technique: {tech}\n\n"
        "ML Explainability:\n" +
        "\n".join(f"- {e}" for e in expl)
    )

    invest_text.delete("1.0", tk.END)
    invest_text.insert(tk.END, msg)

tree.bind("<<TreeviewSelect>>", on_select)

# ================= CHARTS =================
sev_frame = ttk.LabelFrame(right, text="Severity Distribution", padding=10)
sev_frame.pack(fill="x", padx=10, pady=10)

fig1, ax1 = plt.subplots(figsize=(4, 3))
canvas1 = FigureCanvasTkAgg(fig1, master=sev_frame)
canvas1.get_tk_widget().pack()

host_frame = ttk.LabelFrame(right, text="Top Targeted Servers", padding=10)
host_frame.pack(fill="both", expand=True, padx=10, pady=10)

fig2, ax2 = plt.subplots(figsize=(4, 3))
canvas2 = FigureCanvasTkAgg(fig2, master=host_frame)
canvas2.get_tk_widget().pack(fill="both", expand=True)

def update_charts(data):
    ax1.clear()
    counts = data["risk_level"].value_counts()
    ax1.bar(counts.index, counts.values,
            color=[CHART_COLORS[s] for s in counts.index])
    ax1.set_facecolor(BG)
    fig1.patch.set_facecolor(BG)
    ax1.tick_params(colors="white")
    ax1.set_title("Alert Severity Distribution", color="white")
    canvas1.draw()

    ax2.clear()
    top_hosts = data["destination_host"].value_counts().head(5)
    ax2.barh(top_hosts.index[::-1], top_hosts.values[::-1], color="#22c55e")
    ax2.set_facecolor(BG)
    fig2.patch.set_facecolor(BG)
    ax2.tick_params(colors="white")
    ax2.set_title("Most Targeted Servers", color="white")
    canvas2.draw()

severity_var.trace_add("write", lambda *_: populate_table())
populate_table()
root.mainloop()
