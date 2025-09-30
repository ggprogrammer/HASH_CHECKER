import virustotal_python
import json
from excel import excel_creator
from pdf_reader import pdf_reader
import os
import requests as req
from remover import remover

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INPUT_DIR = os.path.join(BASE_DIR, 'input')
OUTPUT_DIR = os.path.join(BASE_DIR, 'output')
APP_DIR = os.path.join(BASE_DIR, 'app')
FILE_ID = ""
API_KEY_VIRUSTOTAL = ""
API_KEY_KASPERSKIY = ""
HEADERS_KASPER = {'x-api-key': ''}

def kasper_check(hash:str):
    print("Проверка с помощью Kasperskiy...")
    response = req.get(f'https://opentip.kaspersky.com/api/v1/search/hash?request={hash}', headers=HEADERS_KASPER)
    try:
        with open('data_kasper.json', 'w', encoding='utf-8') as file:
            json.dump(response.json(), file, ensure_ascii=False, indent=4)
        with open('data_kasper.json', 'r', encoding='utf-8') as file:
            data = json.load(file)
            print("Успешно")
            return [data["FileGeneralInfo"]["Sha256"], data["Zone"]+" "+data["FileGeneralInfo"]["FileStatus"]]
    except Exception as Ex:
        if str(Ex) == "Expecting value: line 1 column 1 (char 0)":
            print("Не найден kasperskiy")
            return ["НЕ НАЙДЕН", "НЕ НАЙДЕН"]
        else:
            print("Ошибка Kasperskiy")
            return [str(Ex), str(Ex)]

def scanning_hashes():
    try:
        print("СКАНИРВОАНИЕ MD5 ФАЙЛОВ")

        with open(APP_DIR+"\\md5_pdf.txt", "r") as file:
            table = excel_creator("MD5")
            lines = file.readlines()
            progress_counter = 1
            end_progress = len(lines)
            for line in lines:
                FILE_ID = line.split()[0]
                try:
                    with virustotal_python.Virustotal(API_KEY_VIRUSTOTAL, TIMEOUT=5.0) as vtotal:
                        resp = vtotal.request(f"files/{FILE_ID}")
                        with open('data.json', 'w', encoding='utf-8') as file:
                            json.dump(resp.data, file, ensure_ascii=False, indent=4)

                    with open('data.json', 'r', encoding='utf-8') as f:
                        data = json.load(f)

                        hash_code = FILE_ID
                        hash_code256 = data["attributes"]["sha256"]
                        malicious = data["attributes"]["last_analysis_stats"]["malicious"] + data["attributes"]["last_analysis_stats"]["suspicious"]
                        if malicious == 0:
                            print(f'{progress_counter} из {end_progress} ноль угроз virustotal')
                            kasper_results = kasper_check(hash_code)
                            table.add_row(hash_code, kasper_results[0], kasper_results[1])
                        else:
                            print(f'{progress_counter} из {end_progress} найдены угрозы virustotal')
                            table.add_row(hash_code, hash_code256, malicious)

                        progress_counter += 1
                except Exception as Ex:
                    if str(Ex) == "Error QuotaExceededError (429): Quota exceeded":
                        print("Достигнут лимит токена VIRUSTOTAL")
                        kasper_results = kasper_check(FILE_ID)
                        table.add_row(FILE_ID, kasper_results[0], kasper_results[1])
                    else:
                        print(f'{progress_counter} из {end_progress} не найден virustotal')
                        kasper_results = kasper_check(FILE_ID)
                        table.add_row(FILE_ID, kasper_results[0], kasper_results[1])
                        progress_counter += 1
                
                

        os.remove(APP_DIR + '\\md5_pdf.txt')
    except Exception as ex:
        print(ex)

    try:
        print("СКАНИРВОАНИЕ SHA1 ФАЙЛОВ")

        with open(APP_DIR+"\\sha1_pdf.txt", "r") as file:
            table = excel_creator("SHA1")
            lines = file.readlines()
            progress_counter = 1
            end_progress = len(lines)
            for line in lines:
                FILE_ID = line.split()[0]
                try:
                    with virustotal_python.Virustotal(API_KEY_VIRUSTOTAL, TIMEOUT=5.0) as vtotal:
                        resp = vtotal.request(f"files/{FILE_ID}")
                        with open('data.json', 'w', encoding='utf-8') as file:
                            json.dump(resp.data, file, ensure_ascii=False, indent=4)

                    with open('data.json', 'r', encoding='utf-8') as f:
                        data = json.load(f)

                        hash_code = FILE_ID
                        hash_code256 = data["attributes"]["sha256"]
                        malicious = data["attributes"]["last_analysis_stats"]["malicious"] + data["attributes"]["last_analysis_stats"]["suspicious"]
                        if malicious == 0:
                            print(f'{progress_counter} из {end_progress} ноль угроз virustotal')
                            kasper_results = kasper_check(hash_code)
                            table.add_row(hash_code, kasper_results[0], kasper_results[1])
                        else:
                            print(f'{progress_counter} из {end_progress} найдены угрозы virustotal')
                            table.add_row(hash_code, hash_code256, malicious)
                    
                        progress_counter += 1
                except Exception as Ex:
                    if str(Ex) == "Error QuotaExceededError (429): Quota exceeded":
                        print("Достигнут лимит токена VIRUSTOTAL, проверка с помощью KASPERSKIY")
                        kasper_results = kasper_check(FILE_ID)
                        table.add_row(FILE_ID, kasper_results[0], kasper_results[1])
                    else:
                        print(f'{progress_counter} из {end_progress} не найден virustotal')
                        kasper_results = kasper_check(FILE_ID)
                        table.add_row(FILE_ID, kasper_results[0], kasper_results[1])
                        progress_counter += 1
        os.remove(APP_DIR + '\\sha1_pdf.txt')
    except:
        print("ФАЙЛА С SHA1 НЕТ")

    try:
        print("СКАНИРВОАНИЕ SHA256 ФАЙЛОВ")

        with open(APP_DIR + "\\sha256_pdf.txt", "r") as file:
            table = excel_creator("SHA256")
            lines = file.readlines()
            progress_counter = 1
            end_progress = len(lines)
            for line in lines:
                FILE_ID = line.split()[0]
                try:
                    with virustotal_python.Virustotal(API_KEY_VIRUSTOTAL, TIMEOUT=5.0) as vtotal:
                        resp = vtotal.request(f"files/{FILE_ID}")
                        with open('data.json', 'w', encoding='utf-8') as file:
                            json.dump(resp.data, file, ensure_ascii=False, indent=4)

                    with open('data.json', 'r', encoding='utf-8') as f:
                        data = json.load(f)

                        hash_code = FILE_ID
                        hash_code256 = data["attributes"]["sha256"]
                        malicious = data["attributes"]["last_analysis_stats"]["malicious"] + data["attributes"]["last_analysis_stats"]["suspicious"]
                        if malicious == 0:
                            print(f'{progress_counter} из {end_progress} ноль угроз virustotal')
                            kasper_results = kasper_check(hash_code)
                            table.add_row(hash_code, kasper_results[0], kasper_results[1])
                        else:
                            print(f'{progress_counter} из {end_progress} найдены угрозы virustotal')
                            table.add_row(hash_code, hash_code256, malicious)

                        progress_counter += 1
                except Exception as Ex:
                    if str(Ex) == "Error QuotaExceededError (429): Quota exceeded":
                        print("Достигнут лимит токена VIRUSTOTAL, проверка с помощью KASPERSKIY")
                        kasper_results = kasper_check(FILE_ID)
                        table.add_row(FILE_ID, kasper_results[0], kasper_results[1])
                    else:
                        print(f'{progress_counter} из {end_progress} не найден virustotal')
                        kasper_results = kasper_check(FILE_ID)
                        table.add_row(FILE_ID, kasper_results[0], kasper_results[1])
                        progress_counter += 1
            APP_DIR + "\\sha256_pdf.txt"
    except Exception as Ex:
        print("ФАЙЛА С SHA256 НЕТ")

        os.remove(APP_DIR + '\\sha256_pdf.txt')

    source = BASE_DIR + '\\MD5_results.xlsx'  
    destination = OUTPUT_DIR + '\\MD5_results.xlsx'  
    os.rename(source, destination)

    source = BASE_DIR + '\\SHA1_results.xlsx'  
    destination = OUTPUT_DIR + '\\SHA1_results.xlsx'  
    os.rename(source, destination)

    source = BASE_DIR + '\\SHA256_results.xlsx'  
    destination = OUTPUT_DIR + '\\SHA256_results.xlsx'  
    os.rename(source, destination)


if __name__ == "__main__":
    remover()
    API_KEY_VIRUSTOTAL = input("Введите API KEY VIRUSTOTAL: ")
    API_KEY_KASPERSKIY = input("Введите API KEY KASPERSKIY: ")
    HEADERS_KASPER = {'x-api-key': f'{API_KEY_KASPERSKIY}'}
    pdf_reader()
    print("Проверьте файл highlight.pdf на правильность выделения хеш-сумм")
    choice = input("Программа правильно определила хеш-суммы? (Y/N):")
    if choice.lower() == "y":
        scanning_hashes()
    else:
        print("Программа завершена")





