import os
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

df_raw = pd.read_csv("results.csv")

rename_map = {
    "Serial_s": "Serial",
    "CU_128": "CUDA_128",
    "CU_256": "CUDA_256",
    "CU_512": "CUDA_512"
}

df_raw = df_raw.rename(columns=rename_map)

df_raw["Size_MB"] = (
    df_raw["Size_MB"]
    .astype(str)
    .str.replace(",", "", regex=False)
    .astype(float)
)

enc_df = df_raw[df_raw["Operation"] == "Encryption"].copy()
dec_df = df_raw[df_raw["Operation"] == "Decryption"].copy()

omp_configs = {
    "OMP_2": ("OpenMP (2 Threads)", 2, "#3c8dbc", 1.8, "-"),
    "OMP_4": ("OpenMP (4 Threads)", 4, "#00a65a", 1.8, "-"),
    "OMP_8": ("OpenMP (8 Threads)", 8, "#f39c12", 1.8, "-")
}

cuda_configs = {
    "CUDA_128": ("CUDA (128 TPB)", 128, "#dd4b39", 1.8, "-"),
    "CUDA_256": ("CUDA (256 TPB)", 256, "#605ca8", 1.8, "-"),
    "CUDA_512": ("CUDA (512 TPB)", 512, "#001f3f", 1.8, "-")
}

data = []

for _, enc_row in enc_df.iterrows():
    filename = enc_row["Filename"]
    size_mb = enc_row["Size_MB"]

    dec_match = dec_df[dec_df["Filename"] == filename]
    dec_row = dec_match.iloc[0] if len(dec_match) > 0 else None

    serial_enc = float(enc_row["Serial"])
    serial_dec = (
        float(dec_row["Serial"])
        if (dec_row is not None and "Serial" in dec_row.index and pd.notna(dec_row["Serial"]))
        else np.nan
    )

    row = {
        "Filename": filename,
        "Size_MB": size_mb,
        "Serial_Enc": serial_enc,
        "Serial_Dec": serial_dec
    }

    for col, (name, threads, color, lw, ls) in omp_configs.items():
        if col not in enc_row.index or pd.isna(enc_row[col]):
            continue

        enc_time = float(enc_row[col])
        dec_time = (
            float(dec_row[col])
            if (dec_row is not None and col in dec_row.index and pd.notna(dec_row[col]))
            else np.nan
        )

        enc_speedup = (serial_enc / enc_time) if enc_time > 0 else np.nan
        enc_efficiency = ((enc_speedup / threads) * 100) if not np.isnan(enc_speedup) else np.nan

        dec_speedup = (
            (serial_dec / dec_time)
            if (not np.isnan(serial_dec) and not np.isnan(dec_time) and dec_time > 0)
            else np.nan
        )
        dec_efficiency = ((dec_speedup / threads) * 100) if not np.isnan(dec_speedup) else np.nan

        row[f"{col}_Enc"] = enc_time
        row[f"{col}_Dec"] = dec_time
        row[f"{col}_Enc_Speedup"] = enc_speedup
        row[f"{col}_Enc_Efficiency"] = enc_efficiency
        row[f"{col}_Dec_Speedup"] = dec_speedup
        row[f"{col}_Dec_Efficiency"] = dec_efficiency

    for col, (name, tpb, color, lw, ls) in cuda_configs.items():
        if col not in enc_row.index or pd.isna(enc_row[col]):
            continue

        enc_time = float(enc_row[col])
        dec_time = (
            float(dec_row[col])
            if (dec_row is not None and col in dec_row.index and pd.notna(dec_row[col]))
            else np.nan
        )

        enc_speedup = (serial_enc / enc_time) if enc_time > 0 else np.nan
        enc_efficiency = ((enc_speedup / tpb) * 100) if not np.isnan(enc_speedup) else np.nan

        dec_speedup = (
            (serial_dec / dec_time)
            if (not np.isnan(serial_dec) and not np.isnan(dec_time) and dec_time > 0)
            else np.nan
        )
        dec_efficiency = ((dec_speedup / tpb) * 100) if not np.isnan(dec_speedup) else np.nan

        row[f"{col}_Enc"] = enc_time
        row[f"{col}_Dec"] = dec_time
        row[f"{col}_Enc_Speedup"] = enc_speedup
        row[f"{col}_Enc_Efficiency"] = enc_efficiency
        row[f"{col}_Dec_Speedup"] = dec_speedup
        row[f"{col}_Dec_Efficiency"] = dec_efficiency

    data.append(row)

df = pd.DataFrame(data).sort_values("Size_MB").reset_index(drop=True)

df_smooth = df.copy()
all_configs = ["OMP_2", "OMP_4", "OMP_8", "CUDA_128", "CUDA_256", "CUDA_512"]
metrics = ["Enc_Speedup", "Enc_Efficiency", "Dec_Speedup", "Dec_Efficiency"]

for config in all_configs:
    for metric in metrics:
        column = f"{config}_{metric}"
        if column in df_smooth.columns:
            df_smooth[column] = df_smooth[column].rolling(window=5, min_periods=1, center=True).median()

plt.figure(figsize=(10, 6))

for col, (name, threads, color, lw, ls) in omp_configs.items():
    column = f"{col}_Enc_Speedup"
    if column in df_smooth.columns:
        plt.plot(df_smooth["Size_MB"], df_smooth[column], label=name, color=color, linewidth=2.0, linestyle=ls)

for col, (name, tpb, color, lw, ls) in cuda_configs.items():
    column = f"{col}_Enc_Speedup"
    if column in df_smooth.columns:
        plt.plot(df_smooth["Size_MB"], df_smooth[column], label=name, color=color, linewidth=2.0, linestyle=ls)

plt.axhline(1.0, color="#777777", linestyle=":", linewidth=1.5, label="Serial Baseline (1.0x)")

plt.title("Figure 1: AES-128 Encryption Speedup vs. Data Size", fontsize=13, fontweight="bold")
plt.xlabel("Input Data Size (MB)", fontsize=11, fontweight="bold")
plt.ylabel("Speedup Ratio", fontsize=11, fontweight="bold")

plt.xscale("log")
plt.yscale("log")
plt.grid(True, which="both", linestyle="--", alpha=0.5)
plt.legend(loc="upper left", fontsize=9)
plt.tight_layout()
plt.savefig("Figure_1_Encryption_Speedup.png", dpi=300)
plt.close()

plt.figure(figsize=(10, 6))

for col, (name, threads, color, lw, ls) in omp_configs.items():
    column = f"{col}_Dec_Speedup"
    if column in df_smooth.columns:
        plt.plot(df_smooth["Size_MB"], df_smooth[column], label=name, color=color, linewidth=2.0, linestyle=ls)

for col, (name, tpb, color, lw, ls) in cuda_configs.items():
    column = f"{col}_Dec_Speedup"
    if column in df_smooth.columns:
        plt.plot(df_smooth["Size_MB"], df_smooth[column], label=name, color=color, linewidth=2.0, linestyle=ls)

plt.axhline(1.0, color="#777777", linestyle=":", linewidth=1.5, label="Serial Baseline (1.0x)")

plt.title("Figure 2: AES-128 Decryption Speedup vs. Data Size", fontsize=13, fontweight="bold")
plt.xlabel("Input Data Size (MB)", fontsize=11, fontweight="bold")
plt.ylabel("Speedup Ratio", fontsize=11, fontweight="bold")

plt.xscale("log")
plt.yscale("log")  # Ensures OpenMP curves are clearly visible alongside CUDA
plt.grid(True, which="both", linestyle="--", alpha=0.5)
plt.legend(loc="upper left", fontsize=9)
plt.tight_layout()
plt.savefig("Figure_2_Decryption_Speedup.png", dpi=300)
plt.close()

plt.figure(figsize=(10, 6))

for col, (name, threads, color, lw, ls) in omp_configs.items():
    column = f"{col}_Enc_Efficiency"
    if column in df_smooth.columns:
        plt.plot(df_smooth["Size_MB"], df_smooth[column], label=f"{name} (p={threads})", color=color, linewidth=lw, linestyle=ls)

for col, (name, tpb, color, lw, ls) in cuda_configs.items():
    column = f"{col}_Enc_Efficiency"
    if column in df_smooth.columns:
        plt.plot(df_smooth["Size_MB"], df_smooth[column], label=f"{name} (TPB={tpb})", color=color, linewidth=lw, linestyle=ls)

plt.axhline(100.0, color="#dd4b39", linestyle="--", linewidth=1.5, label="Ideal Efficiency (100%)")

plt.title("Figure 3: AES-128 Encryption Parallel Efficiency vs. Data Size", fontsize=13, fontweight="bold")
plt.xlabel("Input Data Size (MB)", fontsize=11, fontweight="bold")
plt.ylabel("Parallel Efficiency (%)", fontsize=11, fontweight="bold")
plt.xscale("log")
plt.grid(True, which="both", linestyle="--", alpha=0.5)
plt.legend(loc="upper left", fontsize=9)
plt.tight_layout()
plt.savefig("Figure_3_Encryption_Efficiency.png", dpi=300)
plt.close()

plt.figure(figsize=(10, 6))

for col, (name, threads, color, lw, ls) in omp_configs.items():
    column = f"{col}_Dec_Efficiency"
    if column in df_smooth.columns:
        plt.plot(df_smooth["Size_MB"], df_smooth[column], label=f"{name} (p={threads})", color=color, linewidth=lw, linestyle=ls)

for col, (name, tpb, color, lw, ls) in cuda_configs.items():
    column = f"{col}_Dec_Efficiency"
    if column in df_smooth.columns:
        plt.plot(df_smooth["Size_MB"], df_smooth[column], label=f"{name} (TPB={tpb})", color=color, linewidth=lw, linestyle=ls)

plt.axhline(100.0, color="#dd4b39", linestyle="--", linewidth=1.5, label="Ideal Efficiency (100%)")

plt.title("Figure 4: AES-128 Decryption Parallel Efficiency vs. Data Size", fontsize=13, fontweight="bold")
plt.xlabel("Input Data Size (MB)", fontsize=11, fontweight="bold")
plt.ylabel("Parallel Efficiency (%)", fontsize=11, fontweight="bold")
plt.xscale("log")
plt.grid(True, which="both", linestyle="--", alpha=0.5)
plt.legend(loc="upper left", fontsize=9)
plt.tight_layout()
plt.savefig("Figure_4_Decryption_Efficiency.png", dpi=300)
plt.close()

plt.figure(figsize=(10, 6))

plt.plot(df["Size_MB"], df["Serial_Enc"], label="Serial CPU", color="black", linewidth=2.0)

for col, (name, threads, color, lw, ls) in omp_configs.items():
    column = f"{col}_Enc"
    if column in df.columns:
        plt.plot(df["Size_MB"], df[column], label=name, color=color, linewidth=1.5, linestyle=ls)

for col, (name, tpb, color, lw, ls) in cuda_configs.items():
    column = f"{col}_Enc"
    if column in df.columns:
        plt.plot(df["Size_MB"], df[column], label=name, color=color, linewidth=1.5, linestyle=ls)

plt.title("Figure 5: AES-128 Encryption Execution Time vs. Data Size", fontsize=13, fontweight="bold")
plt.xlabel("Input Data Size (MB)", fontsize=11, fontweight="bold")
plt.ylabel("Encryption Time (seconds)", fontsize=11, fontweight="bold")
plt.xscale("log")
plt.yscale("log")
plt.grid(True, which="both", linestyle="--", alpha=0.5)
plt.legend(loc="upper left", fontsize=9)
plt.tight_layout()
plt.savefig("Figure_5_Encryption_Execution_Time.png", dpi=300)
plt.close()

plt.figure(figsize=(10, 6))

plt.plot(df["Size_MB"], df["Serial_Dec"], label="Serial CPU", color="black", linewidth=2.0)

for col, (name, threads, color, lw, ls) in omp_configs.items():
    column = f"{col}_Dec"
    if column in df.columns:
        plt.plot(df["Size_MB"], df[column], label=name, color=color, linewidth=1.5, linestyle=ls)

for col, (name, tpb, color, lw, ls) in cuda_configs.items():
    column = f"{col}_Dec"
    if column in df.columns:
        plt.plot(df["Size_MB"], df[column], label=name, color=color, linewidth=1.5, linestyle=ls)

plt.title("Figure 6: AES-128 Decryption Execution Time vs. Data Size", fontsize=13, fontweight="bold")
plt.xlabel("Input Data Size (MB)", fontsize=11, fontweight="bold")
plt.ylabel("Decryption Time (seconds)", fontsize=11, fontweight="bold")
plt.xscale("log")
plt.yscale("log")
plt.grid(True, which="both", linestyle="--", alpha=0.5)
plt.legend(loc="upper left", fontsize=9)
plt.tight_layout()
plt.savefig("Figure_6_Decryption_Execution_Time.png", dpi=300)
plt.close()

