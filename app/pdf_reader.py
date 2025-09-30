import pypdf
import pymupdf
import re
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INPUT_DIR = os.path.join(BASE_DIR, 'input')
OUTPUT_DIR = os.path.join(BASE_DIR, 'output')
APP_DIR = os.path.join(BASE_DIR, 'app')


source = BASE_DIR + '\\highlight.pdf'  
destination = OUTPUT_DIR + '\\highlight.pdf'  

def pdf_reader():
    PDF_FILE = [f for f in os.listdir(INPUT_DIR) if f.lower().endswith('.pdf')][0]
    read_pdf = pypdf.PdfReader(INPUT_DIR+'\\'+PDF_FILE)
    highlight_pdf = pymupdf.open(INPUT_DIR+'\\'+PDF_FILE)
    page_num = 1

    # page = read_pdf.pages[8]
    # text = page.extract_text()
    # match_md5 = re.findall(r'([a-fA-F\d]{32})', text)

    sha256_res = []
    md5_res = []
    sha1_res = []

    for page in read_pdf.pages:
        text = page.extract_text()
        match_sha256 = [f'{i} {page_num}\n' for i in re.findall(r'\b[A-Fa-f0-9]{64}\b', text)]
        match_md5 = [f'{i} {page_num}\n' for i in re.findall(r'\b[a-fA-F\d]{32}\b', text)]
        match_sha1 = [f'{i} {page_num}\n' for i in re.findall(r'\b[0-9a-f]{40}\b', text)]
        if len(match_sha256) != 0 or len(match_md5) != 0 or len(match_sha1) != 0:
            if len(match_sha256) != 0:
                sha256_res += match_sha256
            if len(match_md5) != 0:
                md5_res += match_md5
            if match_sha1 != 0:
                sha1_res += match_sha1
        else:
            # 
            pass
        page_num += 1
    
    for hash in sha256_res:
        page_n = int(hash.split()[1])
        hash_sum = hash.split()[0]
        page = highlight_pdf[page_n-1]
        found_hash = page.search_for(hash_sum)
        page.add_highlight_annot(found_hash)
    
    for hash in md5_res:
        page_n = int(hash.split()[1])
        hash_sum = hash.split()[0]
        page = highlight_pdf[page_n-1]
        found_hash = page.search_for(hash_sum)
        page.add_highlight_annot(found_hash)
    
    for hash in sha1_res:
        page_n = int(hash.split()[1])
        hash_sum = hash.split()[0]
        page = highlight_pdf[page_n-1]
        found_hash = page.search_for(hash_sum)
        page.add_highlight_annot(found_hash)

    highlight_pdf.save("highlight.pdf")

    source = BASE_DIR + '\\highlight.pdf'  
    destination = OUTPUT_DIR + '\\highlight.pdf'  
    os.rename(source, destination)



    with open("sha256_pdf.txt", "w") as f:
        f.writelines(sha256_res)

    source = BASE_DIR + '\\sha256_pdf.txt'  
    destination = APP_DIR + '\\sha256_pdf.txt'  
    os.rename(source, destination)

    with open("md5_pdf.txt", "w") as f:
        f.writelines(md5_res)

    source = BASE_DIR + '\\md5_pdf.txt'  
    destination = APP_DIR + '\\md5_pdf.txt'  
    os.rename(source, destination)

    with open("sha1_pdf.txt", "w") as f:
        f.writelines(sha1_res)

    source = BASE_DIR + '\\sha1_pdf.txt'  
    destination = APP_DIR + '\\sha1_pdf.txt'  
    os.rename(source, destination)

if __name__ == "__main__":
    pdf_reader()
    
    