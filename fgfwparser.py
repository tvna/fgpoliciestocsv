#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import os

import numpy as np
import pandas as pd

class FortiGateConfigParser(object):

    def read_config(self, input_file, output_dir):
        # fortigate firewall addresse host object
        results, keys = self.__config_parse(input_file, r'^\s*config firewall address$')
        drop_columns = ['associated-interface']
        df_addr_host = self.__list_to_dataframe(results, drop_columns)

        # fortigate firewall addresse group object
        results, keys = self.__config_parse(input_file, r'^\s*config firewall addrgrp$')
        df_addr_group = self.__list_to_dataframe(results)

        # fortigate firewall service host object
        results, keys = self.__config_parse(input_file, r'^\s*config firewall service$')
        drop_columns = ['comment']
        df_svc_host = self.__list_to_dataframe(results, drop_columns)

        # fortigate firewall service group object
        results, keys = self.__config_parse(input_file, r'^\s*config firewall service group$')
        drop_columns = ['comment']
        df_svc_group = self.__list_to_dataframe(results)

        # fortigate firewall policy object
        results, keys = self.__config_parse(input_file, r'^\s*config firewall policy$')
        drop_columns = ['comment']
        df_pol_group = self.__list_to_dataframe(results)

        return df_addr_host, df_addr_group, df_svc_host, df_svc_group, df_pol_group

    def __list_to_dataframe(self, ls, index_key='name', drop_columns=[]):
        df = pd.DataFrame(ls)

        if len(df.index):
            # set index by key (default: name)
            df = df.set_index(index_key)

            # set blank value to NaN
            df = df.replace(r'^\s*$', np.nan, regex=True)

            # drom unnecessary columns
            df = df.drop(columns=drop_columns)

        return df

    def __config_parse(self, fd, start_block_regex):
        """
        Parse the data according to several regexes

        @param fd:	input file descriptor
        @rtype:	return a list of addresses
            ([
                {'id': '1', 'srcintf': 'internal', ...},
                {'id': '2', 'srcintf': 'external', ...}, ...
            ])
            and the list of unique seen keys ['id', 'srcintf', 'dstintf', ...]
        """

        in_config_block = False

        start_block = re.compile(start_block_regex, re.IGNORECASE)
        edit_block = re.compile(r'^\s*edit\s+"(?P<object_name>.*)"$', re.IGNORECASE)
        set_block = re.compile(r'^\s*set\s+(?P<config_key>\S+)\s+(?P<config_value>.*)$', re.IGNORECASE)
        next_block = re.compile(r'^next$', re.IGNORECASE)
        end_block = re.compile(r'^end$', re.IGNORECASE)

        config_object_list = []
        config_object_elem = {}
        order_keys = []

        with open(fd, 'rb') as fd_input:
            for line in fd_input:
                line = line.lstrip().rstrip().strip().decode(encoding='utf-8')

                # We match a config object block
                if start_block.search(line):
                    in_config_block = True

                # We are in a config object block
                if in_config_block:
                    if edit_block.search(line):
                        config_object_name = edit_block.search(line).group('object_name')
                        config_object_elem['name'] = config_object_name
                        if not('name' in order_keys):
                            order_keys.append('name')

                    # We match a setting
                    if set_block.search(line):
                        config_key = set_block.search(line).group('config_key')
                        if not(config_key in order_keys):
                            order_keys.append(config_key)

                        config_object_val = set_block.search(
                            line).group('config_value').strip()
                        config_object_val = re.sub('["]', '', config_object_val)

                        config_object_elem[config_key] = config_object_val

                    # We are done with the current config object id
                    if next_block.search(line):
                        config_object_list.append(config_object_elem)
                        config_object_elem = {}

                # We are exiting the config object block
                if end_block.search(line):
                    in_config_block = False

        return (config_object_list, order_keys)

if __name__ == "__main__":
    input_file = os.path.dirname(os.path.abspath(__file__)) + r"/sample.cfg"
    output_file = os.path.dirname(os.path.abspath(__file__)) + r"/outputs/address.csv"

    fgcp = FortiGateConfigParser()
    df, _, _, _, _ = fgcp.read_config(input_file, output_file)

    df.to_csv(output_file)