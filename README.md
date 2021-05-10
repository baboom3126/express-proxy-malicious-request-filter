# express-proxy-malicious-request-filter

This is a proxy server project for filtering malicious requests of web applications and chat bot webhooks.
(Line and Facebook are supported currently)

Edit config.json file of your own settings.
----

Following are the default settings

{

  "ProxyPort": 80,   // which port to build your proxy server 
    
  "RedirectURL": "http://localhost:3000/", // the server or api to redirect
  
  "MonitorPort": 3001,  // the port of localhost monitor page 
  
  "LineValidate": true, // whether to validate line messages
  
  "LineChannelSecret": "", // Channel secret for validating line messages 
  
  "FacebookValidate": true, // whether to validate facebook messages
  
  "FacebookToken": "", // Token for validating facebook messages
  
  "XSS-Prevention": true, // whether to filter potential xss attack request
  
  "SQLi-Prevention": true // whether to filter potential SQL injection attack request 

}
