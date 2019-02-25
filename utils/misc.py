import base64
import json
import os

from loguru import logger


def dump_service_file(file_path, service_file):
    try:
        decoded_key = json.loads(base64.b64decode(service_file['privateKeyData']))
        with open(file_path, 'w') as fp:
            json.dump(decoded_key, fp, indent=2)
        return True
    except Exception:
        logger.exception(f"Exception dumping service file to {file_path!r}: ")
    return False


def get_starting_account_number(service_key_folder):
    try:
        files = [os.path.join(service_key_folder, f) for f in os.listdir(service_key_folder) if
                 os.path.isfile(os.path.join(service_key_folder, f))]
        return len(files) + 1
    except Exception:
        logger.exception(f"Exception determining starting account number from {service_key_folder!r}: ")
    return None


def get_service_account_users(service_key_folder):
    try:
        service_key_users = []
        files = [os.path.join(service_key_folder, f) for f in os.listdir(service_key_folder) if
                 os.path.isfile(os.path.join(service_key_folder, f))]
        if not len(files):
            logger.error(f"There were no service key files found in {service_key_folder!r}")
            return None

        for service_key_file in files:
            service_key_data = {}
            with open(service_key_file, 'r') as fp:
                service_key_data = json.load(fp)

            if 'client_email' not in service_key_data:
                logger.warning(f"Unable to retrieve client_email from: {service_key_file!r}, skipping...")
                continue

            service_key_email = service_key_data['client_email']
            if service_key_email not in service_key_users:
                service_key_users.append(service_key_email)

        return service_key_users

    except Exception:
        logger.exception(f"Exception determining user(s) of service keys in {service_key_folder!r}: ")
    return None


def get_teamdrive_id(teamdrives, teamdrive_name):
    try:
        for teamdrive in teamdrives['teamDrives']:
            if teamdrive['name'].lower() == teamdrive_name.lower():
                logger.trace(f"Found teamdrive_id {teamdrive['id']!r} for teamdrive_name {teamdrive_name!r}")
                return teamdrive['id']
        logger.error(f"Failed to find teamdrive_id with name {teamdrive_name!r}")
        return None
    except Exception:
        logger.exception(f"Exception retrieving teamdrive_id for teamdrive_name {teamdrive_name}: ")
    return None
