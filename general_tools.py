import json
from links import logger, project_path, current_date, URL
from datetime import datetime
import pandas as pd
import os
import shutil
from pathlib import Path
import requests


def create_json_summary_data(data, domain):
    json_object = json.dumps(data, indent=4)
    file = project_path + "results/summary_" + domain + "_" + current_date + ".json"
    with open(file, "w") as outfile:
        outfile.write(json_object)
    logger.info("crete json done: %s", domain)


def json_summary_data(data):
    json_object = json.dumps(data, indent=4)

    # new
    folder_path = project_path + "/results"

    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    file = folder_path + "/summary_expired_domains_" + current_date + ".json"
    # end new

    with open(file, "w") as outfile:
        outfile.write(json_object)
    logger.info("crete json done")

    # new
    send_file_to_slack(file)
    # response = webhook.send(files=file)
    # assert response.status_code == 200
    # assert response.body == "ok"


def extract_domains_from_text_file(text_file):
    domains = []
    with open(text_file, 'r') as file:
        for line in file:
            if ':' in line:
                domain = line.split(':')[0].strip().strip("'").replace("]", "").replace("[", "")
            else:
                domain = line.strip().strip("'").replace("]", "").replace("[", "")
            domains.append(domain)
    logger.info("domains were extracted from txt files")
    return domains


def update_domain_csv(text_file, csv_file):
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # existing_domains = set(pd.read_csv(csv_file, usecols=['Domain'])['Domain'])
    Path(csv_file).touch()

    if Path(csv_file).stat().st_size == 0:
        existing_domains = set()
    else:
        # Read the CSV file
        existing_domains = set(pd.read_csv(csv_file, usecols=['Domain'])['Domain'])

    new_domains = []

    domains = extract_domains_from_text_file(text_file)

    for domain in domains:
        if domain not in existing_domains:
            new_domains.append(domain)
            existing_domains.add(domain)

    new_data = pd.DataFrame({'Domain': new_domains, 'Time Added': current_time})

    # new_data.to_csv(csv_file, mode='a', header=not pd.read_csv(csv_file).empty, index=False)
    new_data.to_csv(csv_file, index=False)
    logger.info("csv with domains was created")
    return new_domains


def move_old_file_to_arc(file_path, destination_folder):
    filename = os.path.basename(file_path)
    destination_path = os.path.join(destination_folder, filename)
    # new
    if not os.path.exists(destination_folder):
        os.makedirs(destination_folder)
    # end new
    shutil.move(file_path, destination_path)
    logger.info("files were moved to archive")


# new
def send_file_to_slack(file_path):
    try:
        with open(file_path, 'rb') as file:
            file_content = file.read()

        payload = {
            'filename': file_path,
            'title': 'File from Python'
        }

        files = {
            'file': (file_path, file_content)
        }

        response = requests.post(URL, data=payload, files=files)

        if response.status_code == 200:
            logger.info("File sent successfully to Slack!")
        else:
            logger.error('Error sending file to Slack:', response.text)
    except Exception as e:
        logger.error('Error sending file to Slack:', str(e))

