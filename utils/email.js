const nodemailer = require('nodemailer');

const sendEmail = async options => {
  console.log('options', options);
  // 1) Create a transporter
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD
    }
    // activate in your gmail 'less secure app' option
  });

  // 2) Defined email options
  const emailOptions = {
    from: 'Kiran Pipaliya <hello@kiran.io>',
    to: options.email,
    subject: options.subject,
    text: options.message
    // html
  };
  // 3) Actually send the email
  await transporter.sendMail(emailOptions);
  console.log('emailOptions', emailOptions);
};

module.exports = sendEmail;
