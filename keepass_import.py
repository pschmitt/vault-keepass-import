#!/usr/bin/env python
# coding: utf-8


from __future__ import print_function
from __future__ import unicode_literals
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import argparse
import base64
import binascii
import getpass
import hvac
import libkeepass
import logging
import lxml.etree
import os
import re
import requests


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Disable logging for requests and urllib3
logging.getLogger('requests').setLevel(logging.CRITICAL)
logging.getLogger('urllib3').setLevel(logging.CRITICAL)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def safevalue(entry, path):
    value = entry.find(path)
    if value is None:
        return None
    elif value.text is None:
        return None
    elif value.text == '':
        return None
    else:
        return value.text


def get_entry_name(entry):
    for path_choice in ['String[Key="Title"]/Value', 'String[Key="URL"]/Value', 'UUID']:
        value = safevalue(entry, path_choice)
        if value:
            if path_choice == 'UUID':
                return '<UUID:{}>'.format(binascii.hexlify(base64.b64decode(value)).decode())
            else:
                return value


def get_entry_details(entry):
    return {e.find('Key').text: e.find('Value').text for e in entry.findall('String')}


def get_group_name(group):
    return group.find('Name').text


def clean_str(string):
    return string.strip().strip('/').strip()

def export_entries_from_group(xmldata, group, parent_name=None,
                              force_lowercase=False):
    group_name = get_group_name(group)
    path = '{}{}'.format(
        parent_name if parent_name else '',
        group_name if group_name else ''
    )
    entries = group.findall('Entry')
    groups = group.findall('Group')
    total_entries = []
    for e in entries:
        ed = get_entry_details(e)
        ed = dict(
            (k.lower() if force_lowercase else k, v) for k, v in ed.iteritems()
        )
        ed['_entry_name'] = clean_str(get_entry_name(e))
        ed['_path'] = clean_str('{}'.format(path))
        total_entries.append(ed)
    for g in groups:
        sub_entries = export_entries_from_group(
            xmldata, g, '{}/'.format(path if path else ''), force_lowercase
        )
        total_entries += sub_entries
    return total_entries


def export_entries(filename, password, keyfile=None, force_lowercase=False,
                   skip_root=False):
    with libkeepass.open(filename, password=password, keyfile=keyfile) as kdb:
        xmldata = lxml.etree.fromstring(kdb.pretty_print())
        tree = lxml.etree.ElementTree(xmldata)
        root_group = tree.xpath('/KeePassFile/Root/Group')[0]
        all_entries = export_entries_from_group(
            xmldata, root_group, force_lowercase=force_lowercase
        )
        if skip_root:
            regex = re.compile(r'^{}/?'.format(get_group_name(root_group)))
            for e in all_entries:
                e['_path'] = regex.sub('', e['_path'])

        logger.info('Total entries: {}'.format(len(all_entries)))
        return all_entries


def reset_vault_backend(vault_url, vault_token, vault_backend,
                        ssl_verify=True):
    client = hvac.Client(
        url=vault_url, token=vault_token, verify=ssl_verify
    )
    try:
        client.disable_secret_backend(vault_backend)
    except hvac.exceptions.InvalidRequest as e:
        if e.message == 'no matching mount':
            logging.debug('Could not delete backend: Mount point not found.')
        else:
            raise
    client.enable_secret_backend(
        backend_type='generic',
        description='KeePass import',
        mount_point=vault_backend,
    )


def find_similar_entries(vault_url, vault_token, entry_name, ssl_verify=True):
    client = hvac.Client(
        url=vault_url, token=vault_token, verify=ssl_verify
    )
    entry = client.read(entry_name)
    entries = [entry] if entry else []
    index = 2
    while True:
        entry = client.read('{} ({})'.format(entry_name, index))
        if entry:
            entries.append(entry)
        else:
            return entries
        index += 1


def get_next_similar_entry_index(vault_url, vault_token, entry_name,
                                 ssl_verify=True):
    return len(find_similar_entries(
        vault_url, vault_token, entry_name, ssl_verify
    )) + 1


def export_to_vault(keepass_db, keepass_password, keepass_keyfile,
                    vault_url, vault_token, vault_backend, ssl_verify=True,
                    force_lowercase=False, skip_root=False):
    entries = export_entries(
        keepass_db, keepass_password, keepass_keyfile, force_lowercase,
        skip_root
    )
    client = hvac.Client(
        url=vault_url, token=vault_token, verify=ssl_verify
    )
    ignored_indexes = [
        '_entry_name', '_path',
        'title' if force_lowercase else 'Title'
    ]
    for e in entries:
        cleaned_entry = {k: v for k, v in e.items() if k not in ignored_indexes}
        entry_path = '{}/{}{}'.format(
            vault_backend,
            e['_path'] + '/' if e['_path'] else '',
            e['_entry_name']
        )
        logger.debug(
            'INSERT: "{}" to "{}"'.format(
                e['_entry_name'],
                entry_path
            )
        )
        if client.read(entry_path):
            # There already is an entry at this path
            next_entry_index = get_next_similar_entry_index(
                vault_url, vault_token, entry_path, ssl_verify
            )
            new_entry_path = '{} ({})'.format(entry_path, next_entry_index)
            logger.info(
                'Entry "{}" already exists, '
                'creating a new one: "{}"'.format(entry_path, new_entry_path)
            )
            entry_path = new_entry_path
        client.write(
            entry_path,
            **cleaned_entry
        )


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-p', '--password',
        required=False,
        help='Password to unlock the KeePass database'
    )
    parser.add_argument(
        '-f', '--keyfile',
        required=False,
        help='Keyfile to unlock the KeePass database'
    )
    parser.add_argument(
        '-t', '--token',
        required=False,
        default=os.getenv('VAULT_TOKEN', None),
        help='Vault token'
    )
    parser.add_argument(
        '-v', '--vault',
        default=os.getenv('VAULT_ADDR', 'https://localhost:8200'),
        required=False,
        help='Vault URL'
    )
    parser.add_argument(
        '-k', '--ssl-no-verify',
        action='store_false',
        default=True if os.getenv('VAULT_SKIP_VERIFY', False) else False,
        required=False,
        help='Whether to skip TLS cert verification'
    )
    parser.add_argument(
        '-s', '--skip-root',
        action='store_false',
        required=False,
        help='Skip KeePass root folder (shorter paths)'
    )
    parser.add_argument(
        '-b', '--backend',
        default='keepass',
        help='Vault backend (destination of the import)'
    )
    parser.add_argument(
        '-e', '--erase',
        action='store_true',
        help='Erase the prefix prior to the import operation'
    )
    parser.add_argument(
        '-l', '--lowercase',
        action='store_true',
        help='Force keys to be lowercased'
    )
    parser.add_argument(
        'KDBX',
        help='Path to the KeePass database'
    )
    args = parser.parse_args()
    password = args.password if args.password else getpass.getpass()
    if args.token:
        # If provided argument is a file read from it
        if os.path.isfile(args.token):
            with open(args.token, 'r') as f:
                token = filter(None, f.read().splitlines())[0]
        else:
            token = args.token
    else:
        token = getpass.getpass('Vault token: ')

    if args.erase:
        reset_vault_backend(
            vault_url=args.vault,
            vault_token=token,
            ssl_verify=not args.ssl_no_verify,
            vault_backend=args.backend
        )
    export_to_vault(
        keepass_db=args.KDBX,
        keepass_password=password,
        keepass_keyfile=args.keyfile,
        vault_url=args.vault,
        vault_token=token,
        vault_backend=args.backend,
        ssl_verify=not args.ssl_no_verify,
        force_lowercase=args.lowercase,
        skip_root=args.skip_root
    )
