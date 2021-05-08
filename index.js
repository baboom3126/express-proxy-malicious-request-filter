const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
var bodyParser = require('body-parser');

var path = require('path');
var fs = require('fs')
var config = require(path.join(__dirname,'config.json'))
console.log(config)
// Create Express Server
const app = express();
app.use(bodyParser.json());
// Configuration
const PORT = config.ProxyPort;
const HOST = config.ProxyHost;
const RedirectURL = config.RedirectURL;
const MonitorPort = config.MonitorPort;
const MonitorHost = config.MonitorHost
fs.writeFile(path.join(__dirname,'log.txt'), '', function (err) {
    if (err)
        console.log(err);
    else
        console.log('[INFO] Create log file successfully');
});

app.use('/*',function (req,res,next){
    /////logger data for monitor
    var data = {}
    data.header = req.headers
    data.body = req.body
    fs.appendFile(path.join(__dirname,'log.txt'),JSON.stringify(data)+"##@@\n",function(err){
        if(err){
            console.log(err)
        }else{

        }
    })
    ///////check malicious request
    if(req.body!={}){
        if(isSQLTestPass(JSON.stringify(req.body)) && isXSSTestPass(JSON.stringify(req.body))){
            next()

        }else{
            console.log('[WARN] Malicious Request Detected!')
        }
    }else{
        next()
    }


    //////

})



var restream = function(proxyReq, req, res, options) {
    if (req.body) {
        let bodyData = JSON.stringify(req.body);
        // incase if content-type is application/x-www-form-urlencoded -> we need to change to application/json
        proxyReq.setHeader('Content-Type','application/json');
        proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
        // stream the content
        proxyReq.write(bodyData);
    }
}
var apiProxy = createProxyMiddleware('/proxy',  {
    target: RedirectURL,
    pathRewrite: { [`^/proxy`]: '',},
    secure: false,
    changeOrigin: true,
    onProxyReq: restream
});
app.use(apiProxy);



// Start Proxy
app.listen(PORT, HOST, () => {
    console.log(`Starting Proxy at ${HOST}:${PORT}`);
});

//////Start Monitor web

const app_monitor = express()
app_monitor.get('/',function (req,res,next){
    res.sendFile(path.join(__dirname,'monitor.html'))
})

app_monitor.get('/log',function (req,res,next){
    res.sendFile(path.join(__dirname,'log.txt'))
})

app_monitor.listen(MonitorPort, MonitorHost , () => {
    console.log(`Starting Monitor at ${MonitorHost}:${MonitorPort}`);
});




var isSQLTestPass = function (str){
    var flag = true

    var regex1 = new RegExp(/(\%27)|(\')|(\-\-)|(\%23)|(#)/, 'g');
    var regex2 = new RegExp(/((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/,'g')
    var regex3 = new RegExp(/\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/,'g')
    var regex4 = new RegExp(/((\%27)|(\'))union/,'g')
    var regex5 = new RegExp(/exec(\s|\+)+(s|x)p\w+/,'g')

    if(regex1.test(str)){
        flag = false
    }
    else if(regex2.test(str)){
        flag = false
    }
    else if(regex3.test(str)){
        flag = false
    }
    else if(regex4.test(str)){
        flag = false
    }
    else if(regex5.test(str)){
        flag = false
    }


    return flag
}

var isXSSTestPass = function (str){

    var flag = true

    var regex1 = new RegExp(/((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)/,'g')
    var regex2 = new RegExp(/((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))[^\n]+((\%3E)|>)/,'g')
    var regex3 = new RegExp(/((\%3C)|<)[^\n]+((\%3E)|>)/,'g')

    if(regex1.test(str)){
        flag = false
    }
    else if(regex2.test(str)){
        flag = false
    }
    else if(regex3.test(str)){
        flag = false
    }

    return flag

}

