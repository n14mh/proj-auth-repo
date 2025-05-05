import csv
import dns.resolver
import imaplib
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


# Test Domain
domain = "thelncproject.eu"
# Test Email Sender
sender = "emily.byrne@thelncproject.eu"
# Test Email Recipients
recipients = ["thelncproject3@gmail.com", "thelncproject3@outlook.ie", "thelncproject3@yahoo.com"]

# Valid SMTP Login
outlook_smtp_server = "smtp-mail.outlook.com"
outlook_smtp_port = 587
outlook_smtp_user = sender
outlook_smtp_password = "cmccsnrknxkdhnpz"
# "wcpsxbhsylvjspgc"
# sender@projectauthentication.com app password: "dzypbjxlclscnjcy"

# External SMTP Login
postfix_smtp_server = "localhost"
postfix_smtp_port = 25

# Load Email Templates
def load_email_template(template_file):
    with open(template_file, "r") as f:
        return f.read()

# Send Emails by Test Case and Email Template
def send_email(smtp_server, smtp_port, sender, recipient, subject, body, smtp_user=None, smtp_password=None):
    msg = MIMEMultipart()
    msg['From'] =  f"Project Authentication <{sender}>"
    msg['To'] = recipient
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'html'))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            if smtp_server != 'localhost':
                server.starttls()

            if smtp_user:
                server.login(smtp_user, smtp_password)

            server.sendmail(sender, recipient, msg.as_string())
            print(f"SENT!")
    except Exception as e:
        print(f"FAILED: {e}")

# Test Case 1: Outlook SMTP, Legitimate email templates
def send_test_case_1(test_phase):
    for recipient in recipients:
        for i in range(1,4): # Sending three email templates
            subject = "Test Phase #" + str(test_phase) + " - Test Case #1 - Legit Email #" + str(i)
            print("Sending: " + subject + " - TO: " + recipient)
            template = load_email_template(f"emails/legit_email_{i}.html")
            send_email(outlook_smtp_server, outlook_smtp_port, sender, recipient, subject, template, outlook_smtp_user, outlook_smtp_password)

# Test Case 2: Outlook SMTP, Phishing email templates
def send_test_case_2(test_phase):
    for recipient in recipients:
        for i in range(1,4): # Sending three email templates
            subject = "Test Phase #" + str(test_phase) + " - Test Case #2 - Phish Email #" + str(i)
            print("Sending: " + subject + " - TO: " + recipient)
            template = load_email_template(f"emails/phish_email_{i}.html")
            send_email(outlook_smtp_server, outlook_smtp_port, sender, recipient, subject, template, outlook_smtp_user, outlook_smtp_password)

# Test Case 3: Postfix SMTP, Legitimate email templates
def send_test_case_3(test_phase):
    for recipient in recipients:
        for i in range(1,4): # Sending three email templates
            subject = "Test Phase #" + str(test_phase) + " - Test Case #3 - Legit Email #" + str(i)
            print("Sending: " + subject + " - TO: " + recipient)
            template = load_email_template(f"emails/legit_email_{i}.html")
            send_email(postfix_smtp_server, postfix_smtp_port, sender, recipient, subject, template)

# Test Case 4: Postfix SMTP, Phishing email templates
def send_test_case_4(test_phase):
    for recipient in recipients:
        for i in range(1,4): # Sending three email templates
            subject = "Test Phase #" + str(test_phase) + " - Test Case #4 - Phish Email #" + str(i)
            print("Sending: " + subject + " - TO: " + recipient)
            template = load_email_template(f"emails/phish_email_{i}.html")
            send_email(postfix_smtp_server, postfix_smtp_port, sender, recipient, subject, template)

def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            if 'v=spf1' in rdata.to_text():
                return "Y"
        return "N"
    except:
        return "N"


def check_dkim(domain, selector='default'):
    try:
        dkim_domain = f"{selector}._domainkey.{domain}"
        answers = dns.resolver.resolve(dkim_domain, 'TXT')
        if answers:
            return "Y"
        return "N"
    except:
        return "N"


def check_dmarc(domain):
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        if answers:
            return "Y"
        return "N"
    except:
        return "N"

# check gmail recipient inbox
def check_gmail_status(subject):
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login("testrecipient001@gmail.com","revqvmbccpwuejlu")

        # Check Spam folder first
        status, _ = mail.select("[Gmail]/Spam")
        if status == "OK":
            result, data = mail.search(None, f'(FROM "{sender}" SUBJECT "{subject}")')
            if data[0]:
                return "Spam"

        # Check Inbox last
        mail.select("Inbox")
        result, data = mail.search(None, f'(FROM "{sender}" SUBJECT "{subject}")')
        if data[0]:
            return "Inbox"

        return "Not Found"
    except Exception as e:
        return f"Error checking status: {e}"
    finally:
        if mail:
            try:
                mail.logout()
            except:
                pass

# check outlook recipient inbox
def check_outlook_status(subject):
    mail = None
    try:
        mail = imaplib.IMAP4_SSL("outlook.office365.com")
        mail.login("testrecipient002@outlook.com", "ftfkgxujpmgwtter")

        # Check Junk folder first
        status, _ = mail.select("Junk Email")
        if status == "OK":
            result, data = mail.search(None, f'(FROM "{sender}" SUBJECT "{subject}")')
            if data and data[0].strip():
                return "Spam"

        # Check Inbox only if not found in Junk
        status, _ = mail.select("Inbox")
        if status == "OK":
            result, data = mail.search(None, f'(FROM "{sender}" SUBJECT "{subject}")')
            if data and data[0].strip():
                return "Inbox"

        return "Not Found"
    except Exception as e:
        return f"Error checking status: {e}"
    finally:
        if mail:
            try:
                mail.logout()
            except:
                pass

# Log test phase results into cvs file
def log_results(results, filename="email_security_log.csv"):
    with open(filename, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(results)

def test_deployment_module(test_phase):
    # Deploy all test cases for the current test phase
    print("\n--- Deploying Emails ---")
    print("Sending Emails for Test Case 1")
    send_test_case_1(test_phase)
    print("Sending Emails for Test Case 2")
    send_test_case_2(test_phase)
    print("Sending Emails for Test Case 3")
    send_test_case_3(test_phase)
    print("Sending Emails for Test Case 4")
    send_test_case_4(test_phase)

    # Testing complete
    print("\n--- Phase " + str(test_phase) + " Test Email Deployments Complete ---")

def test_result_module(test_phase):
    print("\n--- Checking Test Recipient Inboxes and Assembling Test Results ---")
    # Create list to store test result for each email sent
    email_results = []

    # Checking DNS records to verify SPF, DKIM and DMARC
    spf_result = check_spf(domain)
    dkim_result = check_dkim(domain)
    dmarc_result = check_dmarc(domain)

    # Check email status by recipient inbox
    for recipient in recipients:
        for a in range(1, 3):
            for b in range(1, 4):
                # Iterating through test email subjects
                if a % 2 == 0:
                    subject = "Test Phase #" + str(test_phase) + " - Test Case #" + str(a) + " - Phish Email #" + str(b)
                    test_id = "P" + str(test_phase) + "-TC" + str(a) + "-PE" + str(b)
                else:
                    subject = "Test Phase #" + str(test_phase) + " - Test Case #" + str(a) + " - Legit Email #" + str(b)
                    test_id = "P" + str(test_phase) + "-TC" + str(a) + "-LE" + str(b)

                # Choose the appropriate checker based on recipient email provider
                if "gmail.com" in recipient:
                    email_status = check_gmail_status(subject)
                elif "outlook.com" in recipient:
                    email_status = "Check Manually"  # check_outlook_status(subject)
                elif "yahoo.com" in recipient:
                    email_status = "Check Manually"

                email_results.append(
                    [str(test_phase), spf_result, dkim_result, dmarc_result, str(a), recipient, test_id, email_status])

    # Printing list of test results to the console
    print("\n--- Displaying Test Results ---")
    for result in email_results:
        print(result)
        # Attaching a timestamp each result and logging all to CSV file
        log_results([time.strftime("%Y-%m-%d %H:%M:%S")] + result)

    print("Results logged to CSV file.")

    # Testing complete
    print("\n--- Phase " + str(test_phase) + " Email Deposition Result Logging Complete ---")

def main():
    # Indicate current phase of testing - adjust as testing progresses
    test_phase = 2
    print("\n--- Current Test Phase: " + str(test_phase) + " ---")

    test_deployment_module(test_phase)

    print("\n--- Waiting 5 Minutes Before Checking Test Recipient Inboxes ---")
    time.sleep(300)

    test_result_module(test_phase)

if __name__ == "__main__":
    main()
