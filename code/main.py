import os
import codecs
import pandas as pd

from dnssec.DNSSecInspector import DNSSecInspector
from httpsec.HTTPSInspector import HTTPSInspector


def get_keys(dictionary):
    return list(dictionary.keys())


def create_empty_dataframe(columns):
    dataframe = pd.DataFrame(columns=columns)
    return dataframe


def join_dataframes(dataframe1, dataframe2):
    for column in dataframe2.columns:
        dataframe1[column] = dataframe2[column]


def add_row_to_dataframe(dataframe, new_row):
    dataframe.loc[len(dataframe)] = new_row
    return dataframe


def add_empty_row(dataframe):
    dataframe.loc[len(dataframe)] = [''] * len(dataframe.columns)
    return dataframe


def create_error_dataframe(columns):
    dataframe = pd.DataFrame(columns=columns)
    dataframe['error'] = ''
    return dataframe


def add_error_row_to_error_dataframe(dataframe, error_row, error_message):
    error_row = list(error_row)[1:]
    error_row.append(error_message)
    dataframe.loc[len(dataframe)] = error_row
    return dataframe


def prepare_main_dataframe(main_dataframe, columns):
    for column in columns:
        for col in column:
            main_dataframe[col] = ''


if __name__ == '__main__':
    file_name = os.environ['INPUT_FILE']
    encoding = 'utf-8'

    host_default = 'www.google.com'
    keys_https = get_keys(HTTPSInspector(host_default).inspect().get_information())
    keys_dnssec = get_keys(DNSSecInspector(host_default).inspect().get_information())

    source_file_name = os.path.join("/", "data", file_name)

    hei = pd.read_csv(filepath_or_buffer=source_file_name, encoding=encoding, engine='python')
    errors_dataframe = create_error_dataframe(hei.columns)

    hei_size = len(hei)
    https_dataframe = create_empty_dataframe(keys_https)
    dnssec_dataframe = create_empty_dataframe(keys_dnssec)

    hei.url = hei.url.apply(lambda x: x.strip())

    for row in hei.itertuples():
        print("analyzing record:", getattr(row, 'Index') + 1, "/", hei_size)
        try:
            print("url:", row.url, "hex:", codecs.encode(row.url.encode("utf8"), "hex"))
            https_info = HTTPSInspector(row.url).inspect().get_information()
            print(https_info)
            dnssec_info = DNSSecInspector(row.url).inspect().get_information()
            add_row_to_dataframe(https_dataframe, https_info)
            add_row_to_dataframe(dnssec_dataframe, dnssec_info)
        except Exception as e:
            add_error_row_to_error_dataframe(errors_dataframe, row, str(e))
            add_empty_row(https_dataframe)
            add_empty_row(dnssec_dataframe)
            print(e)
            pass

    prepare_main_dataframe(hei, [keys_https, keys_dnssec])
    join_dataframes(hei, https_dataframe)
    join_dataframes(hei, dnssec_dataframe)

    base_output_path = os.path.join("/", "data", "results")
    if not os.path.exists(base_output_path):
        os.mkdir(base_output_path)
    destiny_file_name = os.path.join(base_output_path, file_name + '_with_sec_info.csv')
    errors_file_name = os.path.join(base_output_path, file_name + '_with_sec_info_with_errors.csv')

    hei.to_csv(path_or_buf=destiny_file_name, encoding=encoding, index=False)
    errors_dataframe.to_csv(path_or_buf=errors_file_name, encoding=encoding, index=False)
