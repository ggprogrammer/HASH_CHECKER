import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INPUT_DIR = os.path.join(BASE_DIR, 'input')
OUTPUT_DIR = os.path.join(BASE_DIR, 'output')
APP_DIR = os.path.join(BASE_DIR, 'app')

def remover():
    try:
        os.remove(APP_DIR + '\\md5_pdf.txt')
    except:
        pass
    try:
        os.remove(APP_DIR + '\\sha1_pdf.txt')
    except:
        pass
    try:
        os.remove(APP_DIR + '\\sha256_pdf.txt')
    except:
        pass
    try:
        os.remove(OUTPUT_DIR + '\\highlight.pdf')
    except:
        pass
    try:
        os.remove(BASE_DIR + '\\MD5_results.xlsx')
    except:
        pass
    try:
        os.remove(BASE_DIR + '\\SHA1_results.xlsx')
    except:
        pass
    try:
        os.remove(BASE_DIR + '\\SHA256_results.xlsx')
    except:
        pass
    try:
        os.remove(OUTPUT_DIR + '\\MD5_results.xlsx')
    except:
        pass
    try:
        os.remove(OUTPUT_DIR + '\\SHA1_results.xlsx')
    except:
        pass
    try:
        os.remove(OUTPUT_DIR + '\\SHA256_results.xlsx')
    except:
        pass
    try:
        os.remove(BASE_DIR + '\\data.json')
    except:
        pass
    try:
        os.remove(BASE_DIR + '\\data_kasper.json')
    except:
        pass