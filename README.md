# AWS Trusted Advisor Helper

AWS Trusted Advisor is a great platform, which by default runs once a week, sending the runs of all its checks to three AWS contacts.

This "zutrust" helper will run one/more Trusted Advisor checks on demand (schedule driven), discover deltas since the last run (reporting new regressions to an endpoint if configured to do so), and send a summary to a different endpoint.

This helper is intended to help you keep a periodic watch on unintended security vulnerabilities.  As it only runs periodically, and depends on AWS Trusted Advisor which has minimum intervals for each check, this helper is not a substitute for a security tool constantly monitoring changes for compliance. (For example, the Trusted Advisor check for RDS snapshots open to public access cannot be refreshed, and currently runs every two hours).

## Setup
There are a few things you need to do to set this up for yourself (see details below):  
 
  - Create the AWS Simple Notification Service (SNS) topics/subscriptions for notifying based on check alert severity.
  - Create the AWS S3 bucket to store the check history and list of current checks.
  - Customize the JSON templates in the `trustdefs` directory as defined below, then store the `checks-(S3_suffix).json` file to your AWS S3 bucket.
  - Package and deploy the lambda function to AWS.

### Create AWS SNS topics/subscriptions
AWS uses SNS to handle notifications. zutrust uses the Amazon Resource Name (ARN) for a given SNS topic (connected to a notification endpoint) when sending check results and summaries.  Various SNS topic/subscriptions can be created as follows:

 - Create a PagerDuty integration for SNS following the process here: [link](https://www.pagerduty.com/docs/guides/aws-cloudwatch-integration-guide/)  (ARN is available following Step 4. of the "AWS SNS Console" section.)
 - Create a Slack integration for SNS by creating another AWS Lambda function, which pushes SNS events to the Slack Chat server. The description of the AWS Lambda template is found here: [link](https://aws.amazon.com/blogs/aws/new-slack-integration-blueprints-for-aws-lambda/). Note: there is a Slack lambda helper in the `sns_integrations` directory.
 - Create a hipchat integration for SNS by creating another AWS Lambda function. Note: there is a hipchat lambda helper in the `sns_integrations/cloudwatch_hipchat.js` template. 
 - Create an email integration, using the AWS process here: [link](http://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/US_SetupSNS.html). Note: there is an SMTP lambda helper in the `sns_integrations` directory.

### Create AWS S3 Bucket
This lambda function uses an S3 bucket to store the history of checks, in order to calculate which issues are regressions. Create an S3 bucket with prefix "zutrust-" to match the value used in the `s3_access.json` file.

### Customize the JSON templates

#### TrustRunner Global Settings

Edit `trustdefs/trustdefs.json` to modify:

 - `account` : Set to your team's name.
 - `bucket` : Set to your S3 bucket name.
 - `S3_suffix` : Make this unique per checks file (so if you have two checks files in the S3 bucket, make sure this value is changed).
 - `send_report` : Set to `false` if you do not want an email report sent after each check run that finds a regression.
 - `report_ARN` : Set this to the SNS ARN used for receiving the service report, generated for each service on each run giving total/added/deleted service instances.

#### TrustRunner Checks Settings
  
Edit `trustdefs/checks.json` to modify (saving as `checks-(S3_suffix).json`, in the `bucket` named above:

 -  `checks` list:  (Add/remove/change [checks](https://aws.amazon.com/premiumsupport/ta-iam/#table2) in this list as necessary. Note that the initial set is all 'security' checks).
	 - `check_id` : Set this to the appropriate `Check ID` value for the check you want to run.
	 - `freq_mins` : Set this integer to the number of minutes between runs of this check (minimum 15 for refreshable checks, using 0 if the check cannot be refreshed currently: rSs93HQwa1, ePs02jT06w).
	 -  `warning` : Set this to the SNS ARN used for receiving regressions matching `warning` [status](https://docs.aws.amazon.com/cli/latest/reference/support/describe-trusted-advisor-check-result.html).
	 -  `error` : Set this to the SNS ARN used for receiving regressions matching `error` [status](https://docs.aws.amazon.com/cli/latest/reference/support/describe-trusted-advisor-check-result.html).

		

The packaging step that follows will deploy everything in the `trustdefs` directory to the Lambda zip file (so you may wish to remove templates/files you don't use). Note that only the `checks-(S3_suffix).json` file in the S3 bucket will be used.
	
	
### Package and deploy the initial lambda function, IAM role, etc.

Note: this section requires admin privileges as IAM roles  and Lambda functions are being created.

1. Edit `vars.sh` to set the rate for the lambda function to run inside your VPC.
1. Run `deploy_lambda_function.sh`.  This will:

* Package up the script with its dependencies into the zip format that AWS Lambda expects (as defined in `package.sh`).
* Interact with the AWS API to set up the lambda function with the things it needs (as defined in `deployscripts/setup_lambda.py`):
* Creates an IAM role for the lambda function to use.  Review the json files in the `deployscripts` directory to see the permissions 
  required.
* Uploads the zip file from the previous step to create a Lambda function (possibly publishing a new version if the function 
  already exists).
  
### Subsequent package and deploy of an updated lambda package

Note: this section only requires write privileges for Lambda for the current user.

1. Edit `vars.sh` to set the rate for the lambda function to run inside your VPC.
2. Run `. ./vars` to source the environment variables.
3. Run `./package.sh` to create the new zip file to deploy.
4. Upload the new `aws_trustrunner.zip` to the AWS Lambda `TrustRunner` function.

## Testing Considerations

TrustRunner has some basic requirements for running the tests:

* Enterprise Support is currently required to call the Support APIs.
* The tests expect:
	* The test S3 bucket to exist, and referenced in `svcinfo_helper()` in the `zutrust_tests.py` file.
	* The SNS endpoint for reports to exist, and referenced in `svcinfo_helper()` in the `zutrust_tests.py` file.
	* The SNS endpoint for warning and error alerts (TrustRunner Checks Settings, above) to exist and referenced in `chk_helper()` in the `zutrust_tests.py` file.
	* The SNS endpoint for warning and error alerts is added to the `checks-infratest.json` file, and it is uploaded to the S3 bucket.
	* At least one bad security group; create at least one (unused!) security group that is open to 0.0.0.0/0, for a port like 8080.
	* The `testpost-infra.json, testpre-infra.json` files in the `misc` directory are in your S3 test bucket.

