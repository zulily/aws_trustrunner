#!/usr/bin/env python
"""
zutrust
   Called by AWS Lambda to run trust advisor checks
   and track changes since the last run.

   Copyright 2018 zulily, Inc.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""

import json
import logging
from datetime import datetime, timedelta
from multiprocessing import Process, Pipe
from time import sleep
import zlib

import boto3
from botocore import exceptions
from dateutil.parser import parse
import pytz

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

SNS_C = boto3.client('sns')
S3_C = boto3.client('s3')
TA_C = boto3.client('support')
LANG = 'en'

UTC = pytz.utc
LOCALTZ = pytz.timezone('America/Los_Angeles')
DEFS_PATH = 'trustdefs/'
ACCT_FILEPATH = DEFS_PATH + 'trustdefs.json'
MAX_SNS_MESSAGE = 1024 * 256

class TrustCheck(object):
    """
    Class for each AWS Trusted Advisor check, which could be a
    separate process, if desired.
    """
    def __init__(self, acct_info, chk_info, cur_dt, chk_defs):
        """
        Initialize the connector to S3.
        """
        self.s3 = boto3.client('s3')
        self.support = boto3.client('support')
        self.check_id = chk_info['check_id']
        self.freq = chk_info['freq_mins']
        self.warn = chk_info['warning']
        self.error = chk_info['error']
        self.bucket = acct_info['bucket']
        self.cur_dt = cur_dt
        self.chk_defs = chk_defs
        self.check_file = self.check_id + '-' + acct_info['S3_suffix'] + '.json'
        self.last_dt = self._get_last_check_time()


    def _save_check_history(self, check_dict, filename):
        """
        Save check history to S3 json
        """
        try:
            out = self.s3.put_object(Bucket=self.bucket, Key=filename,
                                     Body=json.dumps(check_dict,
                                                     ensure_ascii=False,
                                                     default=dateconverter))
        except exceptions.ClientError as err:
            LOGGER.error('Issue writing file:' + filename + ':' + str(err))

        return out['ResponseMetadata']['HTTPStatusCode']


    def determine_deltas(self, regs, last_regs):
        """
        Create lists of new regressions, and fixed issues, since previous run
        of checks, handling case when no timestamp exists
        """
        ret1 = {}
        try:
            idict = {a['resourceId']:a for a in regs['flaggedResources']}
        except KeyError:
            # no issues found
            idict = {}
        ret2 = idict.values()
        if last_regs:
            try:
                ldict = {a['resourceId']:a for a in last_regs['flaggedResources']}
            except KeyError:
                # no issues found
                ldict = {}
            set_regs = set(tuple(idict.keys()))
            set_last_regs = set(tuple(ldict.keys()))
            newregkeys = list(set_regs - set_last_regs)
            delregkeys = list(set_last_regs - set_regs)
            ret2 = [idict[a] for a in newregkeys]
            ret1 = [ldict[a] for a in delregkeys]

        return ret1, ret2


    def _get_last_check_time(self):
        """
        Retrieve last Trust Advisor check time
        """
        retval = None
        resp = self.support.describe_trusted_advisor_check_summaries(checkIds=[self.check_id])
        if resp:
            try:
                timestr = resp['summaries'][0]['timestamp']
                retval = parse(timestr)
            except (KeyError, ValueError):
                LOGGER.info('Received invalid describe check: %s', str(resp))
        else:
            LOGGER.error('No response from describe check')
        return retval


    def _refresh_check(self):
        """
        Resubmit the Trust Advisor check
        """
        retval = ''
        resp = self.support.refresh_trusted_advisor_check(checkId=self.check_id)
        if resp:
            try:
                retval = resp['status']['status']
            except ValueError:
                LOGGER.error('Received invalid refresh check: %s', str(resp))
        else:
            LOGGER.error('No response from refresh check')
        return retval


    def _get_check_results(self):
        """
        Retrieve Trust Advisor results
        """
        retval = {}
        resp = self.support.describe_trusted_advisor_check_result(checkId=self.check_id,
                                                                  language=LANG)
        if resp:
            try:
                retval = resp['result']
            except ValueError:
                LOGGER.error('Received invalid check results: %s', str(resp))
        else:
            LOGGER.error('No response from check result')
        return retval

    def _format_reg(self, reg):
        """
        Given a regression check result, determine if it's a true regression,
        and if so, format it
        """
        valid = True
        if str(reg['status']) == 'ok':
            # ignore results that are not issues
            valid = False
        reg_str = self.chk_defs['owner'] + ': '
        if 'metadata' in reg:
            for field in reg['metadata']:
                if isinstance(field, basestring):
                    reg_str += '  ' + str(field)

        return valid, reg_str


    def _process_regs(self, cur_run, new_regs, del_regs):
        """
        Given zutrust run results, format and handle regression alerts
        """
        new_needs, del_needs = False, False
        body = ''
        if new_regs:
            tmpreg = ''
            for reg in new_regs:
                valid, reg_str = self._format_reg(reg)
                if valid:
                    new_needs = True
                    # format alert
                    alert = 'Regression Alert: ' + self.chk_defs[self.check_id]['name']
                    alert += ' at ' + self.cur_dt.astimezone(LOCALTZ).strftime('%c') + '\n'
                    alert += reg_str
                    self._send_alert(alert, reg['status'])
                    tmpreg += reg_str + '<br>'

            if new_needs:
                body += '<h4>New Regressions:</h4>' + tmpreg
        else:
            body += '<h4>No new regressions.</h4>'
        if del_regs:
            tmpreg = ''
            for reg in del_regs:
                valid, reg_str = self._format_reg(reg)
                if valid:
                    del_needs = True
                    tmpreg += reg_str + '<br>'
            if del_needs:
                body += '<h4>Regressions removed:</h4>' + tmpreg
        else:
            body += '<h4>No removed regressions.</h4>'
        if new_needs or del_needs:
            output = '<h3>Regression Check: ' + self.chk_defs[self.check_id]['name'] + '</h3>'
            output += 'Account: ' + self.chk_defs['owner']
            output += '<br>Time:' + self.cur_dt.astimezone(LOCALTZ).strftime('%c') + '</h3>'
            output += '<br>Total resources checked: '
            output += str(cur_run['resourcesSummary']['resourcesProcessed'])
            output += body
            return output

        return None


    def _send_alert(self, alert_text, sev):
        """
        Send alert to AWS SNS endpoint
        Note: SNS takes a max of 256KB.
        """
        subj = str("Regression: " + self.cur_dt.astimezone(LOCALTZ).strftime('%c'))
        if sev == 'error':
            arn = self.error
        else:
            arn = self.warn
        overage = len(alert_text) - MAX_SNS_MESSAGE
        if overage > 0:
            alert_text = alert_text[:-overage - 20] + '\n<message truncated/>'
        SNS_C.publish(TopicArn=arn, Message=alert_text, Subject=subj)


    def _check_run_time(self, chk):
        """
        Given last check, determine if a new one should be run
        """
        # Handle un-refreshable checks
        if self.freq == 0:
            result = False
        else:
            result = True
            if chk:
                try:
                    old_dtstr = chk['timestamp']
                    old_dt = parse(old_dtstr)
                    if self.cur_dt - old_dt < timedelta(minutes=self.freq):
                        result = False
                except ValueError:
                    LOGGER.info('No time found in last check.')

        return result


    def run(self, conn):
        """
        Retrieve old check, run new check, save new check, compare diffs,
        process regressions, format report, and send it back to parent.
        """
        check = {}
        prev_results = load_s3_file(self.s3, self.bucket, self.check_file)
        if self._check_run_time(prev_results):
            self._refresh_check()
            runtime = None
            for i in range(0, 5):
                sleep(i*10)
                runtime = self._get_last_check_time()
                if runtime >= self.last_dt:
                    break
        chkresults = self._get_check_results()
        response = self._save_check_history(chkresults, self.check_file)
        del_regs, new_regs = self.determine_deltas(chkresults, prev_results)
        check_text = self._process_regs(chkresults, new_regs, del_regs)
        if check_text:
            check['zipped'] = zlib.compress(check_text)
            check['check_id'] = self.check_id
        conn.send(check)
        conn.close()

    #  END TrustCheck class


def dateconverter(date_obj):
    """
    Stringify datetime.datetime in a given instance
    """
    if isinstance(date_obj, datetime):
        return date_obj.__str__()


def load_defs_file(file_name):
    """
    Load JSON definitions file
    """
    try:
        with open(file_name, 'r') as monfile:
            mydict = json.load(monfile)
    except (ValueError, IOError) as error:
        mydict = ""
        LOGGER.warning('Failed to load: %s', file_name)
        LOGGER.critical('Critical Error: %s', str(error))
    return mydict


def load_s3_file(s3_client, bucket, filename):
    """
    Load JSON S3 file, either checks or history
    """
    hist = None
    try:
        obj = s3_client.get_object(Bucket=bucket, Key=filename)
        last_str = obj['Body'].read().decode('utf-8')
        hist = json.loads(last_str)
    except exceptions.ClientError as err:
        if err.response['Error']['Code'] == "NoSuchKey":
            LOGGER.warning('No file found: %s', filename)
    except ValueError:
        pass
    return hist


def load_check_definitions(lang):
    """
    Retrieve Trust Advisor check definitions
    """
    retval = {}
    resp = TA_C.describe_trusted_advisor_checks(language=lang)
    if resp:
        try:
            checks = resp['checks']
            retval = {a['id']:a for a in checks}
        except ValueError:
            LOGGER.error('Received invalid check definitions: %s', str(resp))
    else:
        LOGGER.error('No response from check definitions')
    return retval


def add_owner_name(chk_defs):
    """
    Add Owner's DisplayName to Trust Advisor check definitions
    """
    resp = S3_C.list_buckets()
    if resp:
        try:
            owner = resp['Owner']['DisplayName']
            chk_defs['owner'] = owner
        except ValueError:
            LOGGER.error('Received invalid bucket list: %s', str(resp))
    else:
        LOGGER.error('No response from S3 List Buckets ')
    return chk_defs


def expand_check_result(body, chk_defs):
    """
    Uncompress check result, adding definition
    """
    output = zlib.decompress(body['zipped'])
    output += '<details><summary>Definition(click to toggle):</summary><br>'
    output += chk_defs[body['check_id']]['description']
    output += '</details><hr>'

    return output


def send_report(report_text, report_arn, now_dt):
    """
    Publish report to AWS SNS endpoint
    Note: publish takes a max of 256KB.
    """
    subj = str("Regression Report for " + now_dt.astimezone(LOCALTZ).strftime('%c'))
    overage = len(report_text) - MAX_SNS_MESSAGE
    if overage > 0:
        report_text = report_text[:-overage - 20] + '\n<message truncated/>'
    resp = SNS_C.publish(TopicArn=report_arn, Message=report_text,
                         Subject=subj)
    return resp


def main(event, context):
    """
    Main functionality
    """
    now_dt = datetime.now(pytz.utc)

    checks = []
    parent_connects = []
    report = ''
    retval = 1

    ##### PROGRAM FLOW #####
    # Load team file
    acct_info = load_defs_file(ACCT_FILEPATH)
    checkfile = 'checks-' + acct_info['S3_suffix'] + '.json'
    checkdata = load_s3_file(S3_C, acct_info['bucket'], checkfile)
    # For each check, run the check, get the regressions
    checkdefs = load_check_definitions(lang=LANG)
    checkdefs = add_owner_name(checkdefs)
    for chk in checkdata['checks']:
        parent_conn, child_conn = Pipe()
        parent_connects.append(parent_conn)
        chkclass = TrustCheck(acct_info, chk, now_dt, checkdefs)
        process = Process(target=chkclass.run, args=(child_conn,))
        checks.append(process)
        process.start()

    for process in checks:
        process.join()

    # Receive report from each check (process)
    for pconn in parent_connects:
        resp = pconn.recv()
        if 'zipped' in resp and isinstance(resp['zipped'], basestring):
            report += expand_check_result(resp, checkdefs)

    if acct_info['send_report'] and report:
        report += 'Trusted Advisor Dashboard:\n' + acct_info['TA_link']
        resp = send_report(report, acct_info['report_ARN'], now_dt)
        try:
            if resp['ResponseMetadata']['HTTPStatusCode'] == 200:
                retval = 0
        except (TypeError, ValueError):
            pass

    return retval


#main('foo', 'bar')
