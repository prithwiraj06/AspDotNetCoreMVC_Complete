using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MailKit.Net.Smtp;
using MimeKit;

namespace MvcPractice.Utilities
{
    public interface IEmailSenderService
    {
        void SendEmail(string emailTo, string emailSubject, string emailBody);
    }
    public class EmailSenderService : IEmailSenderService
    {
        private string FromEmail = "emailformyproject@gmail.com";
        public void SendEmail(string emailTo, string emailSubject, string emailBody)
        {
            MimeMessage message = new MimeMessage();

            MailboxAddress from = new MailboxAddress("Admin", FromEmail);
            message.From.Add(from);

            MailboxAddress to = new MailboxAddress("User", emailTo);
            message.To.Add(to);

            message.Subject = emailSubject;

            BodyBuilder bodyBuilder = new BodyBuilder();
            bodyBuilder.HtmlBody = emailBody;

            message.Body = bodyBuilder.ToMessageBody();

            SmtpClient client = new SmtpClient();
            client.Connect("smtp.gmail.com", 465, true);
            client.Authenticate("emailformyproject@gmail.com", "myproject@123");

            client.Send(message);
            client.Disconnect(true);
            client.Dispose();
        }
    }
}
