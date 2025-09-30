# HASH_CHECKER
Read searchable pdf, extract hashsums (MD5, SHA1, SHA256), check them for viruses by VIRUSTOTAL and convert to SHA256, return 3 excel files with results
#Description
## Pdf_reader.py
1. Read your searchable pdf
2. Extract hashsums to txt files
3. Make highlight.pdf with highlighted hashsums (you will need to check accuracy)
## Excel.py
1. Needed to create an excel object for further adding results to it.
## Main.py
1. Sends requests for file verification, and also records the hashsums in excel with the number of threats found.
