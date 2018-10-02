#!/usr/bin/env python
'''
lambda-hosted smtp email handler, to be called from SNS
(Avoids the notification section from SNS Email that allows
 one user to stop alerts from being sent.)
'''
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

SMTPHOST = '(REPLACE WITH FQDN OF YOUR SMTP SERVER)'
SMTPPORT = 587
AUTH_USERNAME = '(REPLACE WITH SMTP AUTH USERNAME)'
AUTH_PASS = '(REPLACE WITH SMTP AUTH PASSWORD)'
REQUIRE_TLS = True
SENDER = AUTH_USERNAME
REQUIRE_TLS = True
RECEIVER = '(REPLACE WITH STANDARD OPS/ETC EMAIL ADDRESS)'
CC = '(REPLACE WITH STANDARD SECURITY/ETC CC EMAIL ADDRESS)'


def lambda_handler(event, context):
    '''
    The Lambda function handler
    '''

    sns = event['Records'][0]['Sns']
    json_msg = sns['Message']
    msg = MIMEMultipart('alternative')
    try:
        # Override standard recipient
        recipient = sns['MessageAttributes']['to']['Value']
    except KeyError:
        recipient = RECEIVER
    msg['To'] = recipient
    msg['CC'] = CC
    msg['From'] = SENDER
    msg['Subject'] = sns['Subject']
    toaddrs = [recipient, CC]

    html_header = '<html><head></head><body>'
    html_footer = '</body></html>'
    msg_html = html_header + json_msg + html_footer
    part1 = MIMEText(json_msg, 'plain')
    part2 = MIMEText(msg_html, 'html')

    msg.attach(part1)
    msg.attach(part2)

    try:
        server = smtplib.SMTP(SMTPHOST, SMTPPORT)
        server.ehlo()
        if REQUIRE_TLS:
            server.starttls()
        #stmplib docs recommend calling ehlo() before & after starttls()
        server.ehlo()
        server.login(AUTH_USERNAME, AUTH_PASS)
        server.sendmail(SENDER, toaddrs, msg.as_string())
        server.close()
    # Display an error message if something goes wrong.
    except Exception as err:
        print("Error: %s", str(err))
    else:
        print"Email sent!"
    return 0
