import smtplib
import sys
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import getpass
# me == my email address
# you == recipient's email address
me = "mkkeffeler@gmail.com"
you = "mkkeffeler@crimson.ua.edu"

# Create message container - the correct MIME type is multipart/alternative.
msg = MIMEMultipart('alternative')
msg['Subject'] = "Link"
msg['From'] = me
msg['To'] = you

# Create the body of the message (a plain-text and an HTML version).
text = "Hello, \n I have attached your file below. Please enjoy."
html = """\
<html>
  <head></head>
  <body>
    <p>Hi!<br>
       How are you?<br>
       Here is the <a href="http://www.python.org">link</a> you wanted.
    </p>
  </body>
</html>
"""

# Record the MIME types of both parts - text/plain and text/html.
part1 = MIMEText(text, 'plain')
part2 = MIMEText(html, 'html')

# Attach parts into message container.
# According to RFC 2046, the last part of a multipart message, in this case
# the HTML message, is best and preferred.
msg.attach(part1)
msg.attach(part2)
# Send the message via local SMTP server.
mail = smtplib.SMTP('smtp.gmail.com', 587)
part = MIMEBase('application', "octet-stream")
part.set_payload(open(sys.argv[1], "rb").read())
encoders.encode_base64(part)

part.add_header('Content-Disposition', 'attachment; filename=' + sys.argv[2])

msg.attach(part)
mail.ehlo()

mail.starttls()

mail.login('mkkeffeler@gmail.com', getpass.getpass())
mail.sendmail(me, you, msg.as_string())
mail.quit()
