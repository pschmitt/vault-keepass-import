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
import requests


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Disable logging for requests and urllib3
logging.getLogger('requests').setLevel(logging.CRITICAL)
logging.getLogger('urllib3').setLevel(logging.CRITICAL)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def export_in_groups(sh, groups, count):
    for i, val in enumerate(groups):
        sh.do_cd(str(i))
        children_groups = sh._groups()
        entries = sh._entries()
        print('-->', sh.current_path, 'ENTRIES')
        if entries:
            for e_id, e_val in enumerate(entries):
                count += 1
                print('#', count)
                print(e_val)
                print(sh.do_show(str(e_id)))
                print()
        if children_groups:
            print('SUBFOLDER')
            export_in_groups(sh, children_groups, count)
        sh.do_cd('..')


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


def export_entries_from_group_simple(xmldata, group, parent_name=None):
    group_name = '{}{}'.format(parent_name if parent_name else '', get_group_name(group))
    entries = group.findall('Entry')
    groups = group.findall('Group')
    total_entries = []
    for e in entries:
        ed = get_entry_details(e)
        ed['_entry_name'] = get_entry_name(e)
        ed['_path'] = '{}{}'.format(parent_name, group_name)
        total_entries.append(ed)
    for g in groups:
        sub_entries = export_entries_from_group_simple(
            xmldata, g,
            '{}/'.format(group_name if group_name else '')
        )
        total_entries += sub_entries
    return total_entries


def export_entries_from_group(xmldata, group, parent_name=None, flat=False):
    group_name = '{}{}'.format(parent_name if parent_name else '', get_group_name(group))
    entries = group.findall('Entry')
    groups = group.findall('Group')
    # entries_str = [get_entry_name(e) for e in entries]
    # groups_str = [e.find('Name').text for e in groups]
    # print('ENTRIES: str: {} vs. {}'.format(len(entries_str), len(entries)))
    # pprint(entries_str)
    # print('GROUPS: str: {} vs. {}'.format(len(groups_str), len(groups)))
    # pprint(groups_str)
    if flat:
        total_entries = []
    else:
        total_entries = {}
        print(group_name)
        total_entries[group_name] = {}
    for e in entries:
        entry_name = get_entry_name(e)
        ed = get_entry_details(e)
        if flat:
            total_entries.append(ed)
        else:
            # Check if an entry with the same name alread exists
            if entry_name not in total_entries[group_name]:
                total_entries[group_name][entry_name] = ed
            else:
                logger.debug('Dupplicate entry found: {}'.format(entry_name))
                if type(total_entries[group_name][entry_name]) is not list:
                    previous_value = total_entries[group_name][entry_name]
                    total_entries[group_name][entry_name] = [previous_value, ed]
                else:
                    total_entries[group_name][entry_name].append(ed)
        # pprint(ed)
    for g in groups:
        sub_entries = export_entries_from_group(xmldata, g, '{}/'.format(group_name), flat)
        if flat:
            total_entries += sub_entries
        else:
            dups = []
            for s in sub_entries:
                # TODO Dupplicate group names are allowed
                if s in total_entries:
                    logging.debug('Dupplicate group found: {}'.format(s))
                    dups.append(s)
                # if type(total_entries[group_name]) is not list:
                #     previous_value = total_entries[group_name]
                #     total_entries[group_name] = [previous_value]
            if dups:
                total_entries.update(sub_entries)
            else:
                total_entries.update(sub_entries)
    return total_entries


def get_entries(filename, password, keyfile=None, flat=False):
    with libkeepass.open(filename, password=password, keyfile=keyfile) as kdb:
        xmldata = lxml.etree.fromstring(kdb.pretty_print())
        tree = lxml.etree.ElementTree(xmldata)
        root_group = tree.xpath('/KeePassFile/Root/Group')[0]
        return export_entries_from_group(xmldata, root_group, flat=flat)


def get_entries_simple(filename, password, keyfile=None, flat=False):
    with libkeepass.open(filename, password=password, keyfile=keyfile) as kdb:
        xmldata = lxml.etree.fromstring(kdb.pretty_print())
        tree = lxml.etree.ElementTree(xmldata)
        root_group = tree.xpath('/KeePassFile/Root/Group')[0]
        return export_entries_from_group_simple(xmldata, root_group)


def export_entries(filename, password, keyfile=None):
    with libkeepass.open(filename, password=password, keyfile=keyfile) as kdb:
        xmldata = lxml.etree.fromstring(kdb.pretty_print())
        tree = lxml.etree.ElementTree(xmldata)
        root_group = tree.xpath('/KeePassFile/Root/Group')[0]
        all_entries = export_entries_from_group(xmldata, root_group, flat=False)
        all_entries_flat = export_entries_from_group(xmldata, root_group, flat=True)
        # pprint(all_entries)
        flattened_count = 0
        all_entries_not_flat = []
        for g in all_entries:
            # print(g)
            for e in all_entries[g]:
                flattened_count += len(all_entries[g][e]) if type(all_entries[g][e]) is list else 1
            # count += len([x for x in all_entries[g] if type(x) is not list])
            # count += len(
            all_entries_not_flat += all_entries[g]
        logger.info('Total entries (dict - not flat): {}'.format(flattened_count))
        logger.info('Total entries (list - flat):     {}'.format(len(all_entries_flat)))
        assert flattened_count == len(all_entries_flat), 'Inconsitent number of entries'


def export_entries_simple(filename, password, keyfile=None):
    with libkeepass.open(filename, password=password, keyfile=keyfile) as kdb:
        xmldata = lxml.etree.fromstring(kdb.pretty_print())
        tree = lxml.etree.ElementTree(xmldata)
        root_group = tree.xpath('/KeePassFile/Root/Group')[0]
        all_entries = export_entries_from_group_simple(xmldata, root_group)
        logger.info('Total entries: {}'.format(len(all_entries)))
        return all_entries


def find_entry(name, entries, fuzzy=False):
    return [e for e in entries if e['_entry_name'].lower() == name.lower()]


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


def export_to_vault(keepass_db, keepass_password, vault_url, vault_token,
                    vault_backend, ssl_verify=True):
    entries = export_entries_simple(keepass_db, keepass_password)
    client = hvac.Client(
        url=vault_url, token=vault_token, verify=ssl_verify
    )
    for e in entries:
        logger.debug(
            'Insert: {} to {}'.format(
                e['_entry_name'],
                e['_path']
            )
        )
        client.write(
            '{}/{}/{}'.format(vault_backend, e['_path'], e['_entry_name']),
            password=e['Password']
        )


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-p', '--password',
        required=False
    )
    parser.add_argument(
        '-t', '--token',
        required=False,
        default=os.getenv('VAULT_TOKEN', None)
    )
    parser.add_argument(
        '-v', '--vault',
        default=os.getenv('VAULT_ADDR', 'https://localhost:8200'),
        required=False
    )
    parser.add_argument(
        '-k', '--ssl-no-verify',
        action='store_false',
        required=False
    )
    parser.add_argument(
        '-b', '--backend',
        default='keepass',
        help='Vault backend (destination of the import)')
    parser.add_argument(
        '-e', '--erase',
        action='store_true',
        help='Erase the prefix prior to the import operation'
    )
    parser.add_argument('KDBX')
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
            ssl_verify=args.ssl_no_verify,
            vault_backend=args.backend
        )
    export_to_vault(
        keepass_db=args.KDBX,
        keepass_password=password,
        vault_url=args.vault,
        vault_token=token,
        vault_backend=args.backend,
        ssl_verify=args.ssl_no_verify
    )
