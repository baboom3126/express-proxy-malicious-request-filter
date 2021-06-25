const express = require('express');
const {createProxyMiddleware} = require('http-proxy-middleware');
var bodyParser = require('body-parser');

var path = require('path');
var fs = require('fs')
var config = require(path.join(__dirname, 'config.json'))

const nodemailer = require('nodemailer')
console.log(config)
// Create Express Server
const app = express();
app.use(bodyParser.json());

// Configuration
const PORT = config.ProxyPort;
const RedirectURL = config.RedirectURL;
const MonitorPort = config.MonitorPort;




app.use('/*', function (req, res, next) {
    /////logger data for monitor
    var data = {}
    data.header = req.headers
    data.body = req.body
    data.baseUrl = req.originalUrl
    data.method = req.method
    data.ip = req.headers['x-forwarded-for'] || (req.connection && req.connection.remoteAddress) || ''

    data.timestamp = new Date().getTime()


    ///////check malicious request
    if (req.body != {}) {  ////////////if request post body has value

        let isSQLTestPassFlag = isSQLTestPass(JSON.stringify(req.body))
        let isXSSTestPassFlag = isXSSTestPass(JSON.stringify(req.body))

        if ( isSQLTestPassFlag && isXSSTestPassFlag) {

            writeLog(data)

            next()

        } else {
            console.log('[WARN] Malicious Request Detected! Request has blocked!')

            if(isSQLTestPassFlag==false){
                console.log('[WARN] Malicious Type : SQL injection')
                data.sqlTestPass = 'no'
                sendMail(JSON.stringify(req.body,'',2),'sqli')
            }
            if(isXSSTestPassFlag==false){
                console.log('[WARN] Malicious Type : XSS attack')

                data.xssTestPass = 'no'
                sendMail(JSON.stringify(req.body,'',2),'xss')

            }
            writeLog(data)


        }
    } else {             //////if request doesn't include POST body || is GET method

        writeLog(data)

        next()
    }


    //////

})


var restream = function (proxyReq, req, res, options) {
    if (req.body) {
        let bodyData = JSON.stringify(req.body);
        // incase if content-type is application/x-www-form-urlencoded -> we need to change to application/json
        proxyReq.setHeader('Content-Type', 'application/json');
        proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
        // stream the content
        proxyReq.write(bodyData);
    }
}
var apiProxy = createProxyMiddleware('/', {
    target: RedirectURL,
    pathRewrite: {[`^/`]: '',},
    secure: false,
    changeOrigin: true,
    onProxyReq: restream
});
app.use(apiProxy);


// Start Proxy
app.listen(PORT, () => {
    console.log(`Starting Proxy at port ${PORT}`);
});

//////Start Monitor web

const app_monitor = express()

app_monitor.use(express.static(path.join(__dirname, 'public')));
app_monitor.use(bodyParser.json());


app_monitor.get('/', function (req, res, next) {
    res.sendFile(path.join(__dirname, 'monitor.html'))
})

app_monitor.get('/setting', function (req, res, next) {
    res.sendFile(path.join(__dirname, 'setting.html'))
})



app_monitor.get('/log', function (req, res, next) {
    try {
        res.sendFile(path.join(__dirname, 'log.txt'))
    } catch (err) {
        res.send('')
    }

})

app_monitor.post('/clearLog', function (req, res, next) {
    try {
        console.log('clear log')
        fs.writeFile(path.join(__dirname, 'log.txt'),'',function (err){
            res.send('ok')
        })
    } catch (err) {
        res.send(err)

    }

})

app_monitor.post('/getSetting',function (req,res,next){
    try{
        res.sendFile(path.join(__dirname, 'setting.json'))

    }catch(err){
        res.send(err)
    }
})


app_monitor.post('/setMail',function (req,res,next){
    try{
        var host = req.body.mail_host
        var port = req.body.mail_port
        var auth_user = req.body.mail_user
        var auth_pwd = req.body.mail_pwd
        var sql_receivers = req.body.mail_to_sql
        var xss_receivers = req.body.mail_to_xss

        var data = fs.readFileSync(path.join(__dirname, 'setting.json'))
        var setting = JSON.parse(data)

        setting.mail_host = host
        setting.mail_port = port
        setting.mail_user = auth_user
        setting.mail_pwd = auth_pwd
        setting.mail_to_sql = sql_receivers
        setting.mail_to_xss = xss_receivers

        fs.writeFile(path.join(__dirname, 'setting.json'),JSON.stringify(setting),function (err){
            if(err){
                console.log(err)
                res.send('failed')
            }
            res.send('success')
        })


    }catch(err){
        console.log(err)
        res.send('failed')
    }
})

app_monitor.listen(MonitorPort, () => {
    console.log(`Starting Monitor at port ${MonitorPort}`);
});


var isSQLTestPass = function (str) {
    var flag = true
    var data = fs.readFileSync(path.join(__dirname, 'setting.json'))
    var setting = JSON.parse(data)

    var regex1 = new RegExp(/(\%27)|(\')|(\-\-)|(\%23)|(#)/, 'g');
    // filter the character like [ ' -- # ] and its hex equivalent. For preventing the unusual sql operation by annotating.
    var regex2 = new RegExp(/((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/, 'g')
    // fliter the character like [ = ' ; -- ] and its hex equivalent. For preventing classic attack 1'or'1'='1.
    var regex3 = new RegExp(/\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/, 'g')
    // filter the character like [ ' o O r R ]and its hex equivalent. For preventing the attack like 1'or2>1.
    var regex4 = new RegExp(/((\%27)|(\'))union/, 'g')
    // filter the charater like [ ' union ] and its hex equivalent. For preventing union selection attack.
    // Similar expressions can be written for other SQL queries such as >select, insert, update, delete, drop, and so on.
    var regex5 = new RegExp(/exec(\s|\+)+(s|x)p\w+/, 'g')
    // filter the word like [ exec sp xp white-space ]. For protecting stored procedure

    if (regex1.test(str)&&setting.sql_1) {
        flag = false
    } else if (regex2.test(str)&&setting.sql_2) {
        flag = false
    } else if (regex3.test(str)&&setting.sql_3) {
        flag = false
    } else if (regex4.test(str)&&setting.sql_4) {
        flag = false
    } else if (regex5.test(str)&&setting.sql_5) {
        flag = false
    }


    return flag
}

var isXSSTestPass = function (str) {

    var flag = true
    var data = fs.readFileSync(path.join(__dirname, 'setting.json'))
    var setting = JSON.parse(data)

    var regex1 = new RegExp(/((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)/, 'g')
    // filter the chatacter like [ < / > ] and its hex equivalent. For preventing any requests contain xml element.
    var regex2 = new RegExp(/((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))[^\n]+((\%3E)|>)/, 'g')
    // filter the character like [ < i I m M g G >] and its hex equivalent. For prevent classic attack like the injecting <img src
    var regex3 = new RegExp(/((\%3C)|<)[^\n]+((\%3E)|>)/, 'g')
    // filter the string start from the opening angled bracket < to closing angled bracket > through the whole request string and break line is included.

    if (regex1.test(str)&&setting.xss_1) {
        flag = false
    } else if (regex2.test(str)&&setting.xss_2) {
        flag = false
    } else if (regex3.test(str)&&setting.xss_3) {
        flag = false
    }

    return flag

}


var writeLog = function (data){
    fs.appendFile(path.join(__dirname, 'log.txt'), JSON.stringify(data) + "##@@\n", function (err) {
        if (err) {
            console.log(err)
        } else {

        }
    })
}



var sendMail = function (content, type) {

    fs.readFile(path.join(__dirname, 'setting.json'), function (err, data) {
        var setting = JSON.parse(data)

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
                        from: setting.mail_user, // sender address
                        to: setting.mail_to_sql, // list of receivers
                        subject: "[WARNING] SQL Injection Detected", // Subject line
                        text: "SQL Injection Detected", // plain text body
                        html: `<p><b>time</b></p><p>${new Date().toJSON()}</p><p><b>content</b></p><p>${content}</p>`, // html body
                    }).then(function (info) {
                        console.log("Message sent: %s", info.messageId);
                        console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));

                    }).catch(function (err){

                    });

                    break;
                case 'xss':

                    transporter.sendMail({
                        from: setting.mail_user, // sender address
                        to: setting.mail_to_xss, // list of receivers
                        subject: "[WARNING] XSS Attack Detected", // Subject line
                        text: "XSS Attack Detected", // plain text body
                        html: `<p><b>time</b></p><p>${new Date().toJSON()}</p><p><b>content</b></p><p>${content}</p>`, // html body
                    }).then(function (info) {
                        console.log("Message sent: %s", info.messageId);
                        console.log("Preview URL: %s", nodemailer.getTestMessageUrl(info));

                    }).catch(function (err){

                    });

                    break;
            }


        }

    })




}