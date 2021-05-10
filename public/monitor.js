var data

var settings = {
    "async": true,
    "crossDomain": true,
    "url": "http://127.0.0.1:3001/log",
    "method": "GET",
    "headers": {
        "content-type": "application/json",
        "cache-control": "no-cache",
        "postman-token": "29c19286-cb73-ea3d-51b4-b47d7ed49849"
    },
    "processData": false,
    "data": "{\"version\":\"1\"}"
}

$.ajax(settings).done(function (response) {
    data = response.split('##@@\n')

    var appendHtmlForTable = ``
    for(let i = 0 ; i<data.length-1;i++){
        let temp = JSON.parse(data[i])
        if(temp.header["user-agent"].includes("LineBotWebhook")){
            appendHtmlForTable+=`
                <tr onclick="show_data(${i},this)" style="background-color: #dcedc8;">
                    <td>${temp.ip} (Line)</td>
                    <td>${temp.method}</td>
                    <td>${temp.baseUrl}</td>
                    <td>${new Date(temp.timestamp).toLocaleString()}</td>
                </tr>
        `
        }else{
            appendHtmlForTable+=`
                <tr onclick="show_data(${i},this)">
                    <td>${temp.ip}</td>
                    <td>${temp.method}</td>
                    <td>${temp.baseUrl}</td>
                    <td>${new Date(temp.timestamp).toLocaleString()}</td>
                </tr>
        `
        }

    }
    $('#table_body_for_requests').html(appendHtmlForTable)

    ///show the first data
    // var formatterForHeader = new JSONFormatter(JSON.parse(data[0]).header);
    // document.getElementById('div_for_header').appendChild(formatterForHeader.render());
    //
    // var formatterForBody = new JSONFormatter(JSON.parse(data[0]).body,10);
    // document.getElementById('div_for_body').appendChild(formatterForBody.render());

});


var show_data = function (index,that){

    $('tr').removeClass('focus')
    $(that).addClass('focus','#eeeeee')

    document.getElementById('div_for_header').innerHTML=""
    document.getElementById('div_for_body').innerHTML=""

    console.log()
    var formatterForHeader = new JSONFormatter(JSON.parse(data[index]).header);
    document.getElementById('div_for_header').appendChild(formatterForHeader.render());

    var formatterForBody = new JSONFormatter(JSON.parse(data[index]).body,10);
    document.getElementById('div_for_body').appendChild(formatterForBody.render());

}