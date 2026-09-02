import urllib.request
import sys

url = "https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/D6477C2EE3391555525A83E53C7895EB1/ntkrnlmp.pdb"
output_path = "ntkrnlmp.pdb"

print(f"Downloading {url} to {output_path}...")
try:
    urllib.request.urlretrieve(url, output_path)
    print("Download completed successfully!")
except Exception as e:
    print(f"Error during download: {e}")
    sys.exit(1)
