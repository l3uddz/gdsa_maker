#!/usr/bin/env python3
import json
import os
import sys
import shutil
from copy import copy

import click
from loguru import logger

from utils import misc
from utils.google import Google

############################################################
# INIT
############################################################

# Globals
cfg = None
google = None


# Click
@click.group(help='service_account_maker')
@click.version_option('0.0.1', prog_name='service_account_maker')
@click.option('-v', '--verbose', count=True, default=0, help='Adjust the logging level')
@click.option(
    '--config-path',
    envvar='SA_MAKER_CONFIG_PATH',
    type=click.Path(file_okay=True, dir_okay=False),
    help='Configuration filepath',
    show_default=True,
    default=os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), "config.json")
)
@click.option(
    '--log-path',
    envvar='SA_MAKER_LOG_PATH',
    type=click.Path(file_okay=True, dir_okay=False),
    help='Log filepath',
    show_default=True,
    default=os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), "activity.log")
)
@click.option(
    '--token-path',
    envvar='SA_MAKER_TOKEN_PATH',
    type=click.Path(file_okay=True, dir_okay=False),
    help='Token filepath',
    show_default=True,
    default=os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), "token.json")
)
def app(verbose, config_path, log_path, token_path):
    global cfg, google

    # Ensure paths are full paths
    if not config_path.startswith(os.path.sep):
        config_path = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), config_path)
    if not log_path.startswith(os.path.sep):
        log_path = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), log_path)
    if not token_path.startswith(os.path.sep):
        token_path = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), token_path)

    # Load config
    from utils.config import Config
    cfg = Config(config_path=config_path).cfg

    # Load logger
    log_levels = {0: 'INFO', 1: 'DEBUG', 2: 'TRACE'}
    log_level = log_levels[verbose] if verbose in log_levels else 'TRACE'
    config_logger = {
        'handlers': [
            {'sink': sys.stdout, 'backtrace': True if verbose >= 2 else False, 'level': log_level},
            {'sink': log_path,
             'rotation': '30 days',
             'retention': '7 days',
             'enqueue': True,
             'backtrace': True if verbose >= 2 else False,
             'level': log_level}
        ]
    }
    logger.configure(**config_logger)

    # Load google
    google = Google(cfg.client_id, cfg.client_secret, cfg.project_id, token_path)

    # Display params
    logger.info("%s = %r" % ("LOG_PATH".ljust(12), log_path))
    logger.info("%s = %r" % ("LOG_LEVEL".ljust(12), log_level))
    logger.info("")
    return


############################################################
# CLICK FUNCTIONS
############################################################

@app.command(help='Authorize Google Account')
def authorize():
    global google, cfg

    logger.debug(f"client_id: {cfg.client_id!r}")
    logger.debug(f"client_secret: {cfg.client_secret!r}")

    # Provide authorization link
    logger.info("Visit the link below and paste the authorization code")
    logger.info(google.get_auth_link())
    logger.info("Enter authorization code: ")
    auth_code = input()
    logger.debug(f"auth_code: {auth_code!r}")

    # Exchange authorization code
    token = google.exchange_code(auth_code)
    if not token or 'access_token' not in token:
        logger.error("Failed exchanging authorization code for an access token....")
        sys.exit(1)
    else:
        logger.info(f"Exchanged authorization code for an access token:\n\n{json.dumps(token, indent=2)}\n")
    sys.exit(0)


@app.command(help='List user accounts')
def list_user_accounts():
    global google, cfg

    # retrieve admin accounts
    logger.info("Retrieving user accounts...")
    success, accounts = google.get_user_accounts()
    if success:
        logger.info(f"User accounts:\n{json.dumps(accounts, indent=2)}")
        sys.exit(0)
    else:
        logger.error(f"Failed to user accounts:\n{accounts}")
        sys.exit(1)


@app.command(help='List existing groups')
def list_groups():
    global google, cfg

    # retrieve groups
    logger.info("Retrieving existing groups...")
    success, groups = google.get_groups()
    if success:
        logger.info(f"Existing groups:\n{json.dumps(groups, indent=2)}")
        sys.exit(0)
    else:
        logger.error(f"Failed to retrieve groups:\n{groups}")
        sys.exit(1)


@app.command(help='Create group')
@click.option('--name', '-n', required=True, help='Name of the group')
@click.option('--domain', '-d', required=True, help='Domain of the G Suite account')
def create_group(name, domain):
    global google, cfg

    # create group
    logger.info(f"Creating group named: {name} - {name}@{domain}")

    success, group = google.create_group(name, domain)
    if success:
        logger.info(f"Created group {name!r}:\n{group}")
        sys.exit(0)
    else:
        logger.error(f"Failed to create group {name!r}:\n{group}")
        sys.exit(1)


@app.command(help='Remove a group')
@click.option('--name', '-n', required=True, help='Name of the group')
@click.option('--domain', '-d', required=True, help='Domain of the G Suite account')
def remove_group(name, domain):
    global google, cfg

    # retrieve group id
    success, groups = google.get_groups()
    if not success:
        logger.error(f"Unable to retrieve existing groups:\n{groups}")
        sys.exit(1)

    group_id = misc.get_group_id(groups, name, f'{name}@{domain}')
    if not group_id:
        logger.error(f"Failed to determine group_id of group with name {name!r}")
        sys.exit(1)

    # remove group
    logger.info(f"Removing group: {name} - {name}@{domain}")
    success, resp = google.delete_group(group_id)
    if success:
        logger.info(f"Deleted group!")
        sys.exit(0)
    else:
        logger.error(f"Failed removing group {name!r} - {name}@{domain}:\n{resp}")
        sys.exit(1)


@app.command(help='Set users for a group')
@click.option('--name', '-n', required=True, help='Name of the existing group')
@click.option('--key-prefix', '-k', required=True, help='Name prefix of service accounts')
def set_group_users(name, key_prefix):
    global google, cfg

    # validate the service key folder exists
    service_key_folder = os.path.join(cfg.service_account_folder, key_prefix)
    if not os.path.exists(service_key_folder):
        logger.error(f"The service key folder did not exist at: {service_key_folder}")
        sys.exit(1)

    # retrieve service key users to share teamdrive access with
    service_key_users = misc.get_service_account_users(service_key_folder)
    if service_key_users is None:
        logger.error(f"Failed to determine the service key user(s) to add to group: {name}")
        sys.exit(1)

    # retrieve group id
    success, groups = google.get_groups()
    if not success:
        logger.error(f"Unable to retrieve existing groups:\n{groups}")
        sys.exit(1)

    group_id = misc.get_group_id(groups, name)
    if not group_id:
        logger.error(f"Failed to determine group_id of group with name {name!r}")
        sys.exit(1)

    # retrieve group members
    success, group_members = google.get_group_users(group_id)
    if not success:
        logger.error(f"Failed retrieving users in group with name {name!r}:\n{group_members}")
        sys.exit(1)

    # remove users that are already a member
    if 'members' in group_members:
        for member in group_members['members']:
            if member['email'] in service_key_users:
                service_key_users.remove(member['email'])

    if not len(service_key_users):
        logger.info(f"There were no service key users to add to group with name {name!r}")
        sys.exit(0)

    # add user to group
    logger.info(
        f"Adding {len(service_key_users)} users to {name!r} group, user(s): {service_key_users}")

    for service_key_user in service_key_users:
        success, resp = google.set_group_user(group_id, service_key_user)
        if success:
            logger.info(f"Added user to {name!r} group: {service_key_user}")
        else:
            logger.error(f"Failed adding user to {name!r} group for user {service_key_user!r}:\n{resp}")
            sys.exit(1)
    sys.exit(0)


@app.command(help='List users for a group')
@click.option('--name', '-n', required=True, help='Name of the group')
def list_group_users(name):
    global google, cfg

    # retrieve the group id
    success, groups = google.get_groups()
    if not success:
        logger.error(f"Unable to retrieve existing groups:\n{groups}")
        sys.exit(1)

    group_id = misc.get_group_id(groups, name)
    if not group_id:
        logger.error(f"Failed to determine group_id of group with name {name!r}")
        sys.exit(1)

    # get group members
    success, group_members = google.get_group_users(group_id)
    if success:
        logger.info(f"Existing users on group {name!r}:\n{json.dumps(group_members, indent=2)}")
        sys.exit(0)
    else:
        logger.error(f"Failed retrieving users in group with name {name!r}:\n{group_members}")
        sys.exit(1)


@app.command(help='List existing service accounts')
def list_service_accounts():
    global google, cfg

    # retrieve service accounts
    logger.info("Retrieving existing service accounts...")
    success, service_accounts = google.get_service_accounts()
    if success:
        logger.info(f"Existing service accounts:\n{json.dumps(service_accounts, indent=2)}")
        sys.exit(0)
    else:
        logger.error(f"Failed to retrieve service accounts:\n{service_accounts}")
        sys.exit(1)


@app.command(help='Create service accounts')
@click.option('--name', '-n', required=True, help='Name prefix for service accounts')
@click.option('--amount', '-a', default=1, required=False, help='Amount of service accounts to create')
def create_service_accounts(name, amount=1):
    global google, cfg

    service_key_folder = os.path.join(cfg.service_account_folder, name)

    # does service key subfolder exist?
    if not os.path.exists(service_key_folder):
        logger.debug(f"Creating service key path: {service_key_folder!r}")
        if os.makedirs(service_key_folder, exist_ok=True):
            logger.info(f"Created service key path: {service_key_folder!r}")

    # count amount of service files that exist already in this folder
    starting_account_number = misc.get_starting_account_number(service_key_folder)
    if not starting_account_number:
        logger.error(f"Failed to determining the account number to start from....")
        sys.exit(1)

    for account_number in range(starting_account_number, starting_account_number + amount):
        account_name = f'{name}-{account_number:03d}'

        # create the service account
        success, service_account = google.create_service_account(account_name)
        if success and (isinstance(service_account, dict) and 'email' in service_account and
                        'uniqueId' in service_account):
            account_email = service_account['email']
            logger.info(f"Created service account: {account_email!r}")

            # create key for new service account
            success, service_key = google.create_service_account_key(account_email)
            if success and (isinstance(service_key, dict) and 'privateKeyData' in service_key):
                service_key_path = os.path.join(service_key_folder, f'{name}_{account_number:03d}.json')
                if misc.dump_service_file(service_key_path, service_key):
                    logger.info(f"Created service key for account {account_email!r}: {service_key_path}")
                else:
                    logger.error(f"Created service key for account, but failed to dump it to: {service_key_path}")
                    sys.exit(1)
            else:
                logger.error(f"Failed to create service key for account {account_email!r}:\n{service_key}\n")
                sys.exit(1)
        else:
            logger.error(f"Failed to create service account {account_name!r}:\n{service_account}\n")
            sys.exit(1)


@app.command(help='Remove service accounts')
@click.option('--name', '-n', required=True, help='Name prefix for service accounts')
def remove_service_accounts(name):
    global google, cfg

    service_key_folder = os.path.join(cfg.service_account_folder, name)

    # remove service accounts files
    if os.path.exists(service_key_folder):
        logger.debug(f"Removing service key folder: {service_key_folder!r}")
        try:
            shutil.rmtree(service_key_folder)
            logger.info(f"Removed server key folder: {service_key_folder!r}")
        except OSError as e:
            print("Error: %s - %s." % (e.filename, e.strerror))

    # retrieve service accounts
    emails = []
    logger.debug("Retrieving existing service accounts...")
    success, service_accounts = google.get_service_accounts()
    if success:
        logger.debug("Retrieved existing service accounts.")
        for account in service_accounts['accounts']:
            if account['email'].startswith(name):
                emails.append(account['email'])
        if len(emails) == 0:
            logger.info(f"No service account emails matched.")
            sys.exit(0)
    else:
        logger.error(f"Failed to retrieve service accounts:\n{service_accounts}")
        sys.exit(1)

    # remove service accounts
    for email in emails:
        logger.debug(f"Removing service account: {email}")
        success, resp = google.delete_service_account(email)
        if not success:
            logger.error(f"Failed removing service account: {email}")
            logger.error(f"Unexpected response when removing service account: {email!r}:\n{resp}")
            sys.exit(1)
        else:
            logger.info(f"Removed service account: {email}")
    sys.exit(0)


@app.command(help='List existing teamdrives')
def list_teamdrives():
    global google, cfg

    success, teamdrives = google.get_teamdrives()
    if success:
        logger.info(f'Existing teamdrives:\n{json.dumps(teamdrives, indent=2)}')
        sys.exit(0)
    else:
        logger.error(f'Failed to retrieve teamdrives:\n{teamdrives}')
        sys.exit(1)


@app.command(help='Create teamdrive')
@click.option('--name', '-n', required=True, help='Name of the new teamdrive')
def create_teamdrive(name):
    global google, cfg

    success, teamdrive = google.create_teamdrive(name)
    if success:
        logger.info(f'Created teamdrive {name!r}:\n{teamdrive}')
        sys.exit(0)
    else:
        logger.error(f'Failed to create teamdrive {name!r}:\n{teamdrive}')
        sys.exit(1)


@app.command(help='Set users for a teamdrive')
@click.option('--name', '-n', required=True, help='Name of the existing teamdrive')
@click.option('--key-prefix', '-k', required=True, help='Name prefix of service accounts')
def set_teamdrive_users(name, key_prefix):
    global google, cfg

    # validate the service key folder exists
    service_key_folder = os.path.join(cfg.service_account_folder, key_prefix)
    if not os.path.exists(service_key_folder):
        logger.error(f"The service key folder did not exist at: {service_key_folder}")
        sys.exit(1)

    # retrieve service key users to share teamdrive access with
    service_key_users = misc.get_service_account_users(service_key_folder)
    if service_key_users is None:
        logger.error(f"Failed to determine the service key user(s) to share with teamdrive: {name}")
        sys.exit(1)

    # retrieve teamdrive id
    success, teamdrives = google.get_teamdrives()
    if not success:
        logger.error(f"Unable to retrieve existing teamdrives:\n{teamdrives}")
        sys.exit(1)

    teamdrive_id = misc.get_teamdrive_id(teamdrives, name)
    if not teamdrive_id:
        logger.error(f"Failed to determine teamdrive_id of teamdrive with name {name!r}")
        sys.exit(1)

    logger.info(
        f"Sharing access to {name!r} teamdrive for {len(service_key_users)} service key user(s): {service_key_users}")

    # share access to teamdrive
    for service_key_user in service_key_users:
        success, resp = google.set_teamdrive_share_user(teamdrive_id, service_key_user)
        if success:
            logger.info(f"Shared access to {name!r} teamdrive for user: {service_key_user}")
        else:
            logger.error(f"Failed sharing access to {name!r} teamdrive for user {service_key_user!r}:\n{resp}")
            sys.exit(1)
    sys.exit(0)

@app.command(help='Set group for a teamdrive')
@click.option('--name', '-n', required=True, help='Name of the existing teamdrive')
@click.option('--group', '-g', required=True, help='Name of the group')
@click.option('--domain', '-d', required=True, help='Domain of the G Suite account')
def set_teamdrive_group(name, group, domain):
    global google, cfg

    # retrieve teamdrive id
    success, teamdrives = google.get_teamdrives()
    if not success:
        logger.error(f"Unable to retrieve existing teamdrives:\n{teamdrives}")
        sys.exit(1)

    teamdrive_id = misc.get_teamdrive_id(teamdrives, name)
    if not teamdrive_id:
        logger.error(f"Failed to determine teamdrive_id of teamdrive with name {name!r}")
        sys.exit(1)

    # share access to teamdrive
    group_email = name + '@' + domain
    success, resp = google.set_teamdrive_share_user(teamdrive_id, group_email)
    if success:
        logger.info(f"Shared access to {name!r} teamdrive for group: {group}")
    else:
        logger.error(f"Failed sharing access to {name!r} teamdrive for group {group!r}:\n{resp}")
        sys.exit(1)
    sys.exit(0)

@app.command(help='List users for a teamdrive')
@click.option('--name', '-n', required=True, help='Name of the teamdrive')
def list_teamdrive_users(name):
    global google, cfg

    # retrieve the teamdrive id
    success, teamdrives = google.get_teamdrives()
    if not success:
        logger.error(f"Unable to retrieve existing teamdrives:\n{teamdrives}")
        sys.exit(1)

    teamdrive_id = misc.get_teamdrive_id(teamdrives, name)
    if not teamdrive_id:
        logger.error(f"Failed to determine teamdrive_id of teamdrive with name {name!r}")
        sys.exit(1)

    # get permissions (users) on the teamdrive
    success, teamdrive_permissions = google.get_teamdrive_permissions(teamdrive_id)
    if not success:
        logger.error(f"Unable to retrieve existing permissions on teamdrive {name!r}:\n{teamdrive_permissions}")
        sys.exit(1)
    elif 'permissions' not in teamdrive_permissions:
        logger.error(
            f"Unexpected response when retrieving existing permission(s) on teamdrive {name!r}:\n"
            f"{teamdrive_permissions}")
        sys.exit(1)

    # remove permissions that are already deleted
    for permission in copy(teamdrive_permissions['permissions']):
        if permission['deleted']:
            # this permission is already deleted, lets remove it
            teamdrive_permissions['permissions'].remove(permission)

    logger.info(f"Existing users on teamdrive {name!r}:\n{json.dumps(teamdrive_permissions, indent=2)}")
    sys.exit(0)


@app.command(help='Remove users from a teamdrive')
@click.option('--name', '-n', required=True, help='Name of the teamdrive')
@click.option('--email', '-e', required=False, default='ALL', show_default=True, help='Email of user to remove')
@click.option('--keep-emails', '-k', required=False, multiple=True, help='Email of users to keep')
@click.option('--service-accounts-only', '-sao', is_flag=True, required=False, default=False, show_default=True,
              help='Only remove service accounts')
def remove_teamdrive_users(name, email, keep_emails, service_accounts_only):
    global google, cfg

    if email == 'ALL' and (not len(keep_emails) and not service_accounts_only):
        logger.error(f"You must specify an email to keep when removing access to all users (your teamdrive owner)")
        sys.exit(1)

    # retrieve the teamdrive id
    success, teamdrives = google.get_teamdrives()
    if not success:
        logger.error(f"Unable to retrieve existing teamdrives:\n{teamdrives}")
        sys.exit(1)

    teamdrive_id = misc.get_teamdrive_id(teamdrives, name)
    if not teamdrive_id:
        logger.error(f"Failed to determine teamdrive_id of teamdrive with name {name!r}")
        sys.exit(1)

    # get permissions (users) on the teamdrive
    success, teamdrive_permissions = google.get_teamdrive_permissions(teamdrive_id)
    if not success:
        logger.error(f"Unable to retrieve existing permissions on teamdrive {name!r}:\n{teamdrive_permissions}")
        sys.exit(1)
    elif 'permissions' not in teamdrive_permissions:
        logger.error(
            f"Unexpected response when retrieving existing permission(s) on teamdrive {name!r}:\n"
            f"{teamdrive_permissions}")
        sys.exit(1)

    # remove permissions that are already deleted
    for permission in copy(teamdrive_permissions['permissions']):
        if permission['deleted']:
            # this permission is already deleted, lets remove it
            teamdrive_permissions['permissions'].remove(permission)

    logger.info(f"Found {len(teamdrive_permissions['permissions'])} permissions for teamdrive {name!r}")

    # loop emails removing their access
    for permission in teamdrive_permissions['permissions']:
        # only go further (remove a user) if email was not supplied, or this permission email matches
        if email != 'ALL' and permission['emailAddress'].lower() != email.lower():
            continue

        # is this in service accounts only mode
        if service_accounts_only and not permission['emailAddress'].lower().endswith('.iam.gserviceaccount.com'):
            continue

        # is this a safe email?
        if misc.is_safe_email(keep_emails, permission['emailAddress']):
            logger.info(f"Keeping permissions on teamdrive {name!r} for: {permission['emailAddress']}")
            continue

        success, resp = google.delete_teamdrive_share_user(teamdrive_id, permission['id'])
        if success:
            logger.info(f"Removed permissions on teamdrive {name!r} for: {permission['emailAddress']}")
        else:
            logger.error(f"Unexpected response when removing permissions on teamdrive {name!r} for "
                         f"{permission['emailAddress']!r}:\n{resp}")
            sys.exit(1)
    sys.exit(0)


############################################################
# MAIN
############################################################

if __name__ == "__main__":
    app()
