var sendMail = function (content, type) {
    var setting = require(path.join(__dirname, 'setting.json'))
    if (setting.mail_notifiction === true) {

        let transporter = nodemailer.createTransport({
            host: setting.mail_host,
            port: setting.mail_port,
            secure: (setting.mail_port==="465")?true:false, // true for 465, false for other ports
            auth: {
                user: setting.mail_user, // generated ethereal user
                pass: setting.mail_pwd, // generated ethereal password
            },
        });

        switch (type) {
            case 'sqli':

                transporter.sendMail({
                    from: `"WAF NOTIFY SERVICE" <wafnotify3126@gmail.com>`, // sender address
                    to: setting.mail_to_sql, // list of receivers
                    subject: "[WARNING] SQL Injection Detected", // Subject line
                    text: "SQL Injection Detected", // plain text body
                    html: `<h3>Here's the detail</h3><p>${new Date().toJSON()}</p><p>${content}</p>`, // html body
                }).then(function (info) {
                    console.log("Message sent: %s", info.messageId);
                    console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));

                });

                break;
            case 'xss':

                transporter.sendMail({
                    from: `"WAF NOTIFY SERVICE" <wafnotify3126@gmail.com>`, // sender address
                    to: setting.mail_to_sql, // list of receivers
                    subject: "[WARNING] XSS Attack Detected", // Subject line
                    text: "XSS Attack Detected", // plain text body
                    html: `<h3>Here's the detail</h3><p>${new Date().toJSON()}</p><p>${content}</p>`, // html body
                }).then(function (info) {
                    console.log("Message sent: %s", info.messageId);
                    console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));

                });

                break;
        }


    }


}