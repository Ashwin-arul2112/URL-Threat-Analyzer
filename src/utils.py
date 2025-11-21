import os
import glob
import pandas as pd
from tqdm import tqdm
from joblib import Parallel, delayed
from feature_extraction import extract_features


def process_in_chunks(input_csv, out_dir, chunk_size=50000, n_jobs=6):
    os.makedirs(out_dir, exist_ok=True)
    reader = pd.read_csv(input_csv, chunksize=chunk_size)
    part = 0
    processed_parts = 0

    print(f"\nStarting feature extraction from: {input_csv}")
    print(f"Output directory: {out_dir}")
    print(f"Using {n_jobs} parallel workers per chunk...\n")

    for df in reader:
        out_path = os.path.join(out_dir, f"features_part_{part}.csv")

        # Skip if already processed
        if os.path.exists(out_path):
            print(f"Skipping chunk {part} (already exists)")
            part += 1
            continue

        urls = df.iloc[:, 0].astype(str).tolist()
        print(f"Processing chunk {part} ({len(urls)} URLs)...")

        try:
            features_list = Parallel(n_jobs=n_jobs)(
                delayed(extract_features)(u) for u in tqdm(urls, desc=f"chunk {part}")
            )
            features_df = pd.DataFrame(features_list)

            # Attach label column if present
            if df.shape[1] >= 2:
                features_df["Label"] = df.iloc[:, 1].values

            features_df.to_csv(out_path, index=False)
            print(f"Saved: {out_path}")
            processed_parts += 1

        except Exception as e:
            print(f"Error processing chunk {part}: {e}")

        part += 1

    print(f"\nCompleted. Processed {processed_parts} chunks total.\n")
    return processed_parts


def merge_feature_parts(parts_dir, out_csv):
    print(f"\nMerging feature parts from: {parts_dir}")

    files = sorted(glob.glob(os.path.join(parts_dir, "features_part_*.csv")))
    if not files:
        raise FileNotFoundError(f"No part files found in {parts_dir}")

    print(f"Found {len(files)} parts to merge...")

    dfs = []
    for f in tqdm(files, desc="Merging"):
        try:
            dfs.append(pd.read_csv(f))
        except Exception as e:
            print(f"Skipping file {f} due to read error: {e}")

    merged = pd.concat(dfs, ignore_index=True)
    merged.to_csv(out_csv, index=False)
    print(f"\nMerged CSV saved to: {out_csv}")
    print(f"Total rows: {merged.shape[0]}, Columns: {merged.shape[1]}")
    return merged
