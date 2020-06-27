# OPSWAT Metascan scanner
# Author: Ian Redden <ian.redden@rsa.com>
# 6/27/2020 rev. 6
#
# Change log:
# - Changed argparse to group -fp and -fl (filepath/filelist)
# - Added the ability to load from a file list (.txt file - one entry per line)
# - You can not use SCANUSER (--username), SCANPASS (--password) and SCANURL (--url) environment variables
#   rather than having to specify them each time!
# - ConnectionTimeout error checking so the entire script doesn't barf when it occurs
# - Ability to specify an archive password.
# - If archive is scanned, report on all files scanned within archive and not just
#   the scan result of the archive (--archivepwd)
#
import requests
import json
import os
import argparse
import csv
import glob
from time import sleep
from enum import Enum
from requests import exceptions


class EnvDefault(argparse.Action):
    def __init__(self, envvar, required=True, default=None, **kwargs):
        if not default and envvar:
            if envvar in os.environ:
                default = os.environ[envvar]
        if required and default:
            required = False
        super(EnvDefault, self).__init__(default=default, required=required,
                                         **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)

#
# Setup Argument Parsing using argparse
help_str = 'Example usage: ./scan.py -fp \"c:\\users\\george\\documents\\*.docx\"' \
           ' --recursive --url https://localhost:8008' \
           ' -o output.csv --user admin --password MyPassword'

parser = argparse.ArgumentParser(
    description='Scan a file against a OPSWAT Metascan server.',
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=help_str)

# either/or -- either specify a filepath or filelist
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-fp', '--filepath', help='File or directory to scan')
group.add_argument('-fl', '--filelist', help='Path to text file containing file listing to scan')

#
parser.add_argument('--url', required=True, action=EnvDefault, envvar='SCANURL', help='Hostname/URL of Metascan server. (i.e. https://localhost:8008)')
parser.add_argument('-u', '--username', required=True, action=EnvDefault, envvar='SCANUSER', help='Username for your Metascan server (i.e. admin)')
parser.add_argument('-p', '--password', required=True, action=EnvDefault, envvar='SCANPASS', help='Password for your Metascan server.')
parser.add_argument('-o', '--output', required=False, help='Filename to store results in CSV format.')
parser.add_argument('-ap', '--archivepwd', required=False, help='Password for encrypted/compressed archives')
parser.add_argument('-j', '--json', action='store_true', required=False, help='JSON output')
parser.add_argument('-r', '--recursive', action='store_true', required=False,
                    help='Recursively traverse paths with wildcards.')
args = parser.parse_args()


class MetaScanner:
    class ProcessResultsTable(Enum):
        CLEAN = 0
        INFECTED = 1

        def __str__(self):
            return self.name

    def __init__(self, url, username, password):
        self.session_id = ''
        self.username = username
        self.password = password
        self.url = url
        self.db = {}  # variable for storing all the results

    def login(self):
        try:
            url = "{0}/login".format(self.url)
            data = json.dumps({"user": self.username, "password": self.password})
            r = requests.post(url, data=data)
            response_json = json.loads(r.text)

            if "session_id" in response_json:  # session_id is used as apikey
                self.session_id = response_json["session_id"]
            else:
                raise SystemError("Could not login. Please check your credentials.")
        except ConnectionError:
            print("Could not connect to {0}".format(self.url))

    def get_sample(self, data_id):  # grabs samples from opswat using REST API
        url = '{0}/file/{1}'.format(self.url, data_id)
        headers = dict(apikey=self.session_id)
        r = requests.get(url=url, headers=headers)
        scan_report = json.loads(r.text)

        # if progress isn't 100%, we'll wait 2 seconds then recall the func
        progress = scan_report["process_info"]["progress_percentage"]

        if progress == 100:
            return scan_report
        else:
            print("Scanning ...")
            sleep(2)
            return self.get_sample(data_id)

    def scan(self, files, archivepwd=None):
        url = '{0}/file'.format(self.url)

        for file in files:
            print("Submitting file %s ..." % file)
            try:
                with open(file, 'rb') as f:  # read file for submitting
                    file_data = f.read()

                    filename = os.path.basename(file)  # submit the base filename (otherwise its blank in UI)
                    headers = dict(apikey=self.session_id, filename=filename, archivepwd=archivepwd)

                    r = requests.post(url=url, headers=headers, data=file_data)
                    json_r = json.loads(r.text)

                    if "data_id" in json_r:  # no data_id in response = something bad happened
                        data_id = json.loads(r.text)["data_id"]
                        self.get_report(data_id)
                    else:
                        raise SystemError(json_r["err"])
            except:
                print("Scan error occured. Skipping ...")

    def csv(self, report_filename):  # format results in csv format
        rows = []
        for data_id, record in self.db.items():
            scan_time_ms = record["scan_results"]["total_time"]

            # check for archive
            file_info = record["file_info"]
            if "parent_path" in record:
                file_name = record["file_info"]["display_name"]
                display_name = "{0}:{1}".format(record["parent_path"][-1]["display_name"], file_name)
            else:
                display_name = record["file_info"]["display_name"]

            file_size = file_info["file_size"]
            file_type = file_info["file_type"]
            file_type_description = file_info["file_type_description"]
            md5 = file_info["md5"]
            sha1 = file_info["sha1"]
            sha256 = file_info["sha256"]

            row_data = {
                'Report ID': data_id,
                'Filename': display_name,
                'Scan Time (ms)': scan_time_ms,
                'MD5': md5,
                'SHA1': sha1,
                'SHA256': sha256,
                'File Type': file_type,
                'File Description': file_type_description,
            }

            for engine, scan_detail in record["scan_results"]["scan_details"].items():
                def_time = scan_detail["def_time"]
                eng_id = scan_detail["eng_id"]
                location = scan_detail["location"]
                scan_result_i = self.ProcessResultsTable(scan_detail["scan_result_i"])
                scan_time = scan_detail["scan_time"]
                threat_found = scan_detail["threat_found"]
                wait_time = scan_detail["wait_time"]

                if scan_result_i == self.ProcessResultsTable.INFECTED:
                    scan_result = threat_found
                else:
                    scan_result = "OK"

                row_data[engine] = scan_result
            rows.append(row_data)
        columns = rows[0].keys()

        print("Writing {0} ...".format(report_filename))
        with open(report_filename, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=columns)
            writer.writeheader()

            for row in rows:
                writer.writerow(row)

    def json(self, report_filename):
        json_text = json.dumps(self.db, sort_keys=False, indent=4)
        with open(report_filename, 'w', newline='') as jsonfile:
            print("Writing {0} ...".format(report_filename))
            jsonfile.write(json_text)

    def results(self, report_filename=None, json=None):  # decide whether to use csv or stdout
        if report_filename:
            if json:
                self.json(report_filename)
            else:
                self.csv(report_filename)
        else:
            for data_id, record in self.db.items():
                if "parent_path" in record:
                    file_name = record["file_info"]["display_name"]
                    display_name = "{0}:{1}".format(record["parent_path"][-1]["display_name"], file_name)
                else:
                    display_name = record["file_info"]["display_name"]

                sha1 = record["file_info"]["sha1"]
                scan_result = record["scan_results"]["scan_all_result_a"]
                file_type = record["file_info"]["file_type_description"]

                print("{0} ({1}) => {2} - SHA1: {3}".format(display_name, file_type, scan_result, sha1))

    def get_report(self, data_id):
        scan_results = self.get_sample(data_id)
        if "extracted_files" in scan_results:
            extracted_files = scan_results["extracted_files"]
            files_in_archive = extracted_files["files_in_archive"]
            for archive in files_in_archive:
                id = archive["data_id"]
                print("(Archive) Retrieving report {0} ...".format(id))
                db_entry = self.get_sample(id)
                self.db[id] = db_entry
        else:
            self.db[data_id] = scan_results

    def get_files(self, filepath, recursive=False):  # use glob for wildcards if recursive is set
        files = []
        if os.path.isdir(filepath):
            if recursive:
                for root, directories, filenames in os.walk(filepath):
                    for file in filenames:
                        files.append(os.path.join(root, file))
            else:
                for file in os.listdir(filepath):
                    if os.path.isfile("%s/%s" % (filepath, file)):
                        files.append(os.path.join(filepath, file))

            return files

        if os.path.isfile(filepath):
            files.append(filepath)
        else:
            for file in glob.glob(filepath):
                if os.path.isfile(file):    # the glob will return directories but not traverse into them
                    files.append(file)

        return files


scan_engine = MetaScanner(args.url, args.username, args.password)
scan_engine.login()

if args.filepath:
    files = scan_engine.get_files(args.filepath, args.recursive)
elif args.filelist:
    # open the file list
    files = []
    with open(args.filelist, 'r') as file_listing:
        for row in file_listing:
            file = row.rstrip('\n')
            if not os.path.isdir(file):
                files.append(file)
            else:
                print("Skipping directory {0} ...".format(file))

scan_engine.scan(files, archivepwd=args.archivepwd)
scan_engine.results(args.output, args.json)
