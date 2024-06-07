import re
import json
import PyPDF2
import time
import requests
import hashlib
import os
from datetime import datetime
from pymongo import MongoClient

def download_pdf(file_url):
    filetime = str(datetime.now()).split(".")[0].replace(":", "_")
    filename = ("downloaded_" + filetime + ".pdf").replace(" ", "")

    response = requests.get(file_url)
    if response.status_code == 200:
        with open(filename, "wb") as file:
            file.write(response.content)
        return filename
    else:
        print("Failed to download PDF file.")
        return None
    
def calculate_sha256(filename):
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        chunk = f.read(4096)
        while chunk:
            sha256_hash.update(chunk)
            chunk = f.read(4096)
    return sha256_hash.hexdigest()

def retrieve_hash_values():
    client = MongoClient('mongodb://localhost:27017/')
    db = client["Seized_Addresses"]
    collection = db["PDF_Hashes"]

    hash_values = []
    oldfilename = []
    cursor = collection.find({}, {"_id": 0})  # Project only the hash_value field
    for document in cursor:
        hash_values.append(document['hash_value'])
        oldfilename.append(document['filename'])
        break
    client.close()
    return hash_values[0],oldfilename[0]

def store_hash_in_mongodb(hash_value,downloaded_file):
    client = MongoClient('mongodb://localhost:27017/')
    db = client['Seized_Addresses']
    collection = db['PDF_Hashes']
    data = {
        "filename":downloaded_file,
        "hash_value": hash_value,
        "timestamp": datetime.now()
    }
    collection.insert_one(data)
    client.close()  

def delete_entry_by_hash(hash_value):
    client = MongoClient('mongodb://localhost:27017/')
    db = client["Seized_Addresses"]
    collection = db["PDF_Hashes"]
    collection.delete_one({"hash_value": hash_value})
    client.close()

def extraction(filename,collectionname):
    client = MongoClient('mongodb://localhost:27017/')
    db = client['Seized_Addresses']
    collection = db[collectionname]

    pattern1 = r'([0-9\.\,]+)\s+(?:units|unit)+\s+of\s+([A-Za-z\s]+)\s+\(([A-Z]+)\)\s+formerly\s+(?:held|on deposit)\s+in\s+crypto\s+wallet\s+address\s+([a-zA-Z0-9\s\n]{30,}),\s+and\s+seized\s+by\s+the\s+Government\s+on\s+or\s+about\s+([A-Za-z]+\s+\d{1,2},\s+\d{4})\s+\(\d{2}-[A-Z]+-\d{6}\)'
    pattern20 = r'([\d.,]{2,})\s\s([A-Za-z]{3,})\s([a-zA-Z0-9._\n]{8,})\b(?=\d+\.\d+|$)'
    pattern21 = r'([\d.,]{2,})\s([A-Za-z]{3,})\s([a-zA-Z0-9._\n]{8,})\b(?=\d+\.\d+|$)'
    pattern22 = r'([\d.,]+)\s([A-Z\n]{0,3})([a-zA-Z0-9_\n]{30,})\b(?=\d+\.\d+|$)'
    pattern3 = r'([a-zA-Z0-9\n]{30,})\b(?=\d+\.\d+|$)'

    data_list = []
    count = 0

    with open(filename, "rb") as file:
        pdf_reader = PyPDF2.PdfReader(file)
        long_string_pages = []
        long_string_counts = []
        info = ""
        for page_num in range(len(pdf_reader.pages)):
            page = pdf_reader.pages[page_num]
            text = page.extract_text()
            if page_num == 1:
                date_text = page.extract_text()
                info = (date_text.split('\n')[0])
                # print(info)
            if re.search(r'[a-zA-Z0-9]{31,}', text):
                long_string_pages.append(page_num + 1)
                long_string_counts.append(len(re.findall(r'[a-zA-Z0-9]{31,}', text)))
        entries_text = ""
        
        for page_num in long_string_pages:
            page = pdf_reader.pages[page_num - 1]
            entries_text += page.extract_text()

        total_count = sum(long_string_counts)

        matches = re.findall(pattern1, entries_text.replace("\n",""))
        matches.extend(re.findall(pattern20, entries_text))
        matches.extend(re.findall(pattern21, entries_text))
        matches.extend(re.findall(pattern22, entries_text))
        pattern3_matches = re.findall(pattern3, entries_text) 
        for i in range(len(pattern3_matches)):
            pattern3_matches[i] = pattern3_matches[i].replace("\n", "")
            pattern3_matches[i] = pattern3_matches[i].replace(" ", "")

        addresses_from_patterns_1_2 = set()
        for match in matches:
            if len(match) == 5:
                _, _, _, address, _ = match
                address = address.replace("\n","")
                address =  address.replace(" ","")
                addresses_from_patterns_1_2.add(address.strip())
            elif len(match) == 3:
                _, _, address = match
                address = address.replace("\n","")
                address =  address.replace(" ","")
                addresses_from_patterns_1_2.add(address.strip())

        for address in pattern3_matches:
            if address not in addresses_from_patterns_1_2:
                if "0x" in address:
                    index = address.index("0x")
                    part1 = address[:index]
                    part2 = address[index:]
                    if part1 == part1.upper():
                        currency = part1 
                        address = part2
                        data = {
                            "currency": currency,
                            "address": address.replace("\n",""),
                            "tag":"sanctioned",
                            "source":"USAO Official",
                            "timestamp" : round(time.time()),
                            "confidence":"100",
                            "info": [info],
                            "mal": True
                        }
                        data_list.append(data)
                        count += 1
                elif "addr" in address:
                    index = address.index("addr")
                    part1 = address[:index]
                    part2 = address[index:]
                    if part1 == part1.upper():
                        currency = part1 
                        address = part2
                        data = {
                            "currency": currency,
                            "address": address.replace("\n",""),
                            "tag":"sanctioned",
                            "source":"USAO Official",
                            "timestamp" : int(time.time()),
                            "confidence":"100",
                            "info": [info],
                            "mal": True
                        }
                        data_list.append(data)
                        count += 1        
                else:
                    data = {
                        "currency":"",
                        "address": address.replace("\n",""),
                        "tag":"sanctioned",
                        "source":"USAO Official",
                        "timestamp" : round(time.time()),
                        "confidence":"100",
                        "info": [info],
                        "mal": True
                    }
                    data_list.append(data)
                    count += 1

        for match in matches:
            if len(match) == 5:
                amount, currency, currency2, address, date = match
                address = address.replace("\n","")
                address =  address.replace(" ","")
                data = {
                    "currency": f"{currency.strip()}({currency2.strip()})",
                    "address": address.strip().replace("\n",""),
                    "tag":"sanctioned",
                    "source":"USAO Official",
                    "timestamp" : round(time.time()),
                    "confidence":"100",
                    "info": [info],
                    "mal": True
                }
            elif len(match) == 3:
                amount, currency, address = match
                address = address.replace("\n","")
                address =  address.replace(" ","")
                data = {
                    "currency": currency.strip(),
                    "address": address.strip(),
                    "tag":"sanctioned",
                    "source":"USAO Official",
                    "timestamp" : round(time.time()),
                    "confidence":"100",
                    "info" : [info],
                    "mal": True
                }
            data_list.append(data)
            count += 1
        
        percentage_loss=(total_count-count)/total_count * 100
        print(f"Data loss is {percentage_loss}%")
        print(f"Data captured is {100-percentage_loss}%")

    # json_data = json.dumps(data_list, indent=4)

    # with open(outputfilename, "w") as file:
    #     file.write(json_data)

    for data in data_list:
        collection.insert_one(data)

    client.close()

    return filename

def main():
    collectionname = "DataInfo3"
    file_url = "https://www.forfeiture.gov/pdf/USAO/OfficialNotification.pdf"
    downloaded_file = download_pdf(file_url)
    if downloaded_file:
        new_hash_value = calculate_sha256(downloaded_file)
        old_hash_value,oldfile = retrieve_hash_values()
        if old_hash_value == new_hash_value:
            print("Document has not been modified.")
            os.remove(downloaded_file)
        else:
            print("Document has been modified. Doing further processing.")
            extraction(downloaded_file,collectionname)
            store_hash_in_mongodb(new_hash_value,downloaded_file)
            delete_entry_by_hash(old_hash_value)
            os.remove(oldfile)
    else:
        print("File not downloaded.")      

if __name__ == "__main__":
    main()