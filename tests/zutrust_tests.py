#!/usr/bin/env python
"""
   Tests for zutrust.py
   Called via nosetests tests/zutrust_tests.py
"""

# Global imports
import unittest
from datetime import datetime
from time import sleep
import zlib

import pytz

# Local imports
import zutrust

# Stop pylint from flagging unit tests
# pragma pylint: disable=protected-access

class TestZutrust(unittest.TestCase):
    """
    Standard test class, for all zutrust functions
    """
    Now_dt = datetime.now(pytz.utc)
    @staticmethod
    def svcinfo_helper():
        """
        provide minimal trustdef for test
        """
        return {
            'account' : 'infratest',
            'bucket' : '(REPLACE WITH YOUR TEST S3 BUCKET)',
            'S3_suffix' : 'infratest',
            'send_report' : True,
            'report_ARN' :
            '(REPLACE WITH YOUR SNS ENDPOINT: EMAIL REPORT DESTINATION)'
        }

    @staticmethod
    def chk_helper():
        """
        provide minimal check for test
        """
        return {
            'check' : {
                'check_id' : '1iG5NDGVre',
                'freq_mins' : 15,
                'warning' : '(REPLACE WITH YOUR SNS ENDPOINT: ALERT DESTINATION)',
                'error' : '(REPLACE WITH YOUR SNS ENDPOINT: ALERT DESTINATION)'
            }

        }

    @staticmethod
    def chkdefs_helper():
        """
        provide minimal checkdef for test
        """
        return {
            '1iG5NDGVre' : {
                'name' : 'Security Groups - Unrestricted Access',
                'description' : 'Checks security groups for rules that allow unrestricted access to a resource. Unrestricted access increases opportunities for malicious activity (hacking, denial-of-service attacks, loss of data).\n<br>\n<br>\n<b>Alert Criteria</b>\n<br>\nRed: A security group rule has a source IP address with a /0 suffix for ports other than 25, 80, or 443.\n<br>\n<br>\n<b>Recommended Action</b>\n<br>\nRestrict access to only those IP addresses that require it. To restrict access to a specific IP address, set the suffix to /32 (for example, 192.0.2.10/32). Be sure to delete overly permissive rules after creating rules that are more restrictive.\n<br>\n<br>\n<b>Additional Resources</b>\n<br><a href=\"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-network-security.html\" target=\"_blank\">Amazon EC2 Security Groups</a><br>\n<a href=\"https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing\" target=\"_blank\">Classless Inter-Domain Routing</a> (Wikipedia)'
            },
            'owner' : 'infraops-aws'
        }

    def setUp(self):
        """
        set up if needed
        """
        print ""

    def tearDown(self):
        """
        tear down!
        """
        print ""

    def test_load_defs_file(self):
        """
        Test the method used for loading the definitions json
        """
        acct_info = zutrust.load_defs_file(zutrust.ACCT_FILEPATH)
        self.assertEqual(len(acct_info), 8)

    def test_load_bad_defs_file(self):
        """
        Test the method used for load malformed definitions json
        """
        badpath = zutrust.DEFS_PATH + 'trustdefs_bad.json'
        acct_info = zutrust.load_defs_file(badpath)
        self.assertEqual(len(acct_info), 0)

    def test_load_s3_file(self):
        """
        Test the method used for loading the check definitions
        """
        test_info = self.svcinfo_helper()
        test_client = zutrust.S3_C
        filename = 'checks-' + test_info['S3_suffix'] + '.json'
        testchecks = zutrust.load_s3_file(test_client, test_info['bucket'],
                                          filename)
        self.assertGreaterEqual(len(testchecks), 1)

    def test_trusted_checks(self):
        """
        Test the methods used for starting/checking/saving/reading
        trusted advisor checks
        """
        test_info = self.svcinfo_helper()
        test_chk = self.chk_helper()
        test_chkdefs = self.chkdefs_helper()
        check_class = zutrust.TrustCheck(test_info, test_chk['check'],
                                         self.Now_dt, test_chkdefs)
        self.assertGreater(check_class.cur_dt, check_class.last_dt)
        status = check_class._refresh_check()
        self.assertIn(status, ('enqueued', 'processing', 'success'))
        runtime = None
        for i in range(0, 5):
            sleep(i*10)
            runtime = check_class._get_last_check_time()
            if runtime >= check_class.last_dt:
                break
        self.assertGreaterEqual(runtime, check_class.last_dt)
        chkresults = check_class._get_check_results()
        # ensure you have at least one unused 0.0.0.0/0 port, like 8080
        self.assertGreaterEqual(len(chkresults['flaggedResources']), 1)
        # test S3 write/read
        testfile = test_chk['check']['check_id'] + '--' + test_info['S3_suffix'] + '.json'
        response = check_class._save_check_history(chkresults, testfile)
        self.assertEqual(response, 200)
        s3data = zutrust.load_s3_file(check_class.s3, check_class.bucket,
                                      testfile)
        self.assertEqual(chkresults, s3data)
        # cleanup S3
        check_class.s3.delete_object(Bucket=check_class.bucket, Key=testfile)


    def test_determine_deltas(self):
        """
        Test the method used for comparing and processing
        regressions which may have timestamps
        """
        test_info = self.svcinfo_helper()
        test_chk = self.chk_helper()
        test_chkdefs = self.chkdefs_helper()
        check_class = zutrust.TrustCheck(test_info, test_chk['check'],
                                         self.Now_dt, test_chkdefs)
        prev_run = zutrust.load_s3_file(check_class.s3, check_class.bucket,
                                        'testpre-infra.json')
        cur_run = zutrust.load_s3_file(check_class.s3, check_class.bucket,
                                       'testpost-infra.json')
        del_regs, new_regs = check_class.determine_deltas(cur_run, None)
        self.assertEqual(len(new_regs), 2)
        self.assertEqual(del_regs, {})
        del_regs, new_regs = check_class.determine_deltas(cur_run, prev_run)
        self.assertEqual(len(new_regs), 1)
        self.assertEqual(len(del_regs), 2)

        report_text = check_class._process_regs(cur_run, new_regs, del_regs)
        self.assertEqual(len(report_text), 499)

        check = {}
        check['zipped'] = zlib.compress(report_text)
        check['check_id'] = test_chk['check']['check_id']
        result = zutrust.expand_check_result(check, test_chkdefs)
        self.assertEqual(len(result), 1517)

        resp = zutrust.send_report(result, test_info['report_ARN'], self.Now_dt)
        self.assertEqual(resp.keys(), ['ResponseMetadata', 'MessageId'])


    def test_load_checkdefs(self):
        """
        Test the method used for loading check definitions and owner
        """
        defs = zutrust.load_check_definitions('en')
        defs = zutrust.add_owner_name(defs)
        self.assertIn('1iG5NDGVre', defs.keys())
        self.assertIsNotNone(defs['owner'])


    def test_check_runtime(self):
        """
        Test the method used for checking run time
        """
        test_info = self.svcinfo_helper()
        test_chk = self.chk_helper()
        test_chkdefs = self.chkdefs_helper()
        check_class = zutrust.TrustCheck(test_info, test_chk['check'],
                                         self.Now_dt, test_chkdefs)
        prev_run = zutrust.load_s3_file(check_class.s3, check_class.bucket,
                                        'testpre-infra.json')
        result = check_class._check_run_time(prev_run)
        self.assertTrue(result)
        prev_run['timestamp'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        result = check_class._check_run_time(prev_run)
        self.assertFalse(result)
