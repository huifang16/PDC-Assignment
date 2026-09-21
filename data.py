import os
import shutil
import sys
import urllib.request
import zipfile

DATA_URL = "https://github.com/huifang16/PDC-Assignment/releases/download/v1.0/Text.File.zip"
ZIP_NAME = "Text.File.zip"
TARGET_DIR = "Text file"

def reporthook(block_num, block_size, total_size):
    downloaded = block_num * block_size
    if total_size > 0:
        percent = (downloaded / total_size) * 100
        downloaded_mb = downloaded / (1024 * 1024)
        total_mb = total_size / (1024 * 1024)
        sys.stdout.write(f"\rDownloading: {downloaded_mb:.1f} MB / {total_mb:.1f} MB ({percent:.1f}%)")
    else:
        downloaded_mb = downloaded / (1024 * 1024)
        sys.stdout.write(f"\rDownloaded: {downloaded_mb:.1f} MB")
    sys.stdout.flush()

def main():
    if not os.path.exists(ZIP_NAME):
        print(f"Connecting to: {DATA_URL}...")
        try:
            urllib.request.urlretrieve(DATA_URL, ZIP_NAME, reporthook)
        except Exception as e:
            print(f"\nDownload error: {e}")
            return
    else:
        print(f"'{ZIP_NAME}' already exists, skipping download.")

    print("Extracting files...")
    temp_extract = "_temp_extract"
    if os.path.exists(temp_extract):
        shutil.rmtree(temp_extract)

    with zipfile.ZipFile(ZIP_NAME, 'r') as zip_ref:
        zip_ref.extractall(temp_extract)

    if not os.path.exists(TARGET_DIR):
        os.makedirs(TARGET_DIR)

    for root, dirs, files in os.walk(temp_extract):
        for file in files:
            src_path = os.path.join(root, file)
            dst_path = os.path.join(TARGET_DIR, file)
            shutil.move(src_path, dst_path)

    shutil.rmtree(temp_extract)

    if os.path.exists(ZIP_NAME):
        os.remove(ZIP_NAME)


if __name__ == "__main__":
    main()