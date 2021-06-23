var data

var settings = {
    "async": true,
    "crossDomain": true,
    "url": "./log",
    "method": "GET",
    "headers": {
        "content-type": "application/json",
        "cache-control": "no-cache"
    },
    "processData": false,
    "data": "{\"version\":\"1\"}"
}

$.ajax(settings).done(function (response) {
    data = response.split('##@@\n')

    var appendHtmlForTable = ``
    for (let i = 0; i < data.length - 1; i++) {
        let temp = JSON.parse(data[i])
        if (temp.header["user-agent"]) {
            if (temp.header["user-agent"].includes("LineBotWebhook")) {
                appendHtmlForTable += `
               <tr onclick="show_data(${i},this)" >  <!-- style="background-color: #dcedc8;"-->
                    <td>${(temp.sqlTestPass=='no')||(temp.xssTestPass=='no')?`<i class="material-icons" style="color:red;">close</i>`:'<i class="material-icons" style="color:green;">check</i>'}</td>
                    <td>${temp.ip} (Line)</td>
                    <td>${temp.method}</td>
                    <td>${temp.baseUrl}</td>
                    <td>${new Date(temp.timestamp).toLocaleString()}</td>
                </tr>
        `
            }else{
                appendHtmlForTable += `
                <tr onclick="show_data(${i},this)">
                    <td>${(temp.sqlTestPass=='no')||(temp.xssTestPass=='no')?`<i class="material-icons" style="color:red;">close</i>`:'<i class="material-icons" style="color:green;">check</i>'}</td>
                    <td>${temp.ip}</td>
                    <td>${temp.method}</td>
                    <td>${temp.baseUrl}</td>
                    <td>${new Date(temp.timestamp).toLocaleString()}</td>
                </tr>
        `
            }

        } else {
            appendHtmlForTable += `
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
    $('#table_log').DataTable({responsive: true,"order": [[ 4, "desc" ]]})
    ///show the first data
    // var formatterForHeader = new JSONFormatter(JSON.parse(data[0]).header);
    // document.getElementById('div_for_header').appendChild(formatterForHeader.render());
    //
    // var formatterForBody = new JSONFormatter(JSON.parse(data[0]).body,10);
    // document.getElementById('div_for_body').appendChild(formatterForBody.render());

});


var show_data = function (index, that) {

    $('tr').removeClass('focus')
    $(that).addClass('focus', '#eeeeee')

    document.getElementById('div_for_header').innerHTML = ""
    document.getElementById('div_for_body').innerHTML = ""

    var isSqlPass = JSON.parse(data[index]).sqlTestPass
    var isXssPass = JSON.parse(data[index]).xssTestPass
    var appenHtmlForError = ''
    if(isSqlPass === 'no'){
        appenHtmlForError+=`SQL injection<br>`
    }
    if(isXssPass === 'no'){
        appenHtmlForError+=`Xss attack<br>`
    }
    if(appenHtmlForError===''){
        appenHtmlForError="none"
    }

    $('#div_for_error').html(appenHtmlForError)

    var formatterForHeader = new JSONFormatter(JSON.parse(data[index]).header);
    document.getElementById('div_for_header').appendChild(formatterForHeader.render());

    var formatterForBody = new JSONFormatter(JSON.parse(data[index]).body, 10);
    document.getElementById('div_for_body').appendChild(formatterForBody.render());

}


$('#btn_clear').click(function (){


    var settings = {
        "url": "./clearLog",
        "method": "POST",
        "timeout": 0,
        "headers": {
            "Content-Type": "application/json"
        },
        "data": JSON.stringify({"name":"test","email":"123@gmail.com","pwd":"123"}),
    };

    $.ajax(settings).done(function (response) {
        console.log(response);
        if(response=="ok"){
            alert('Success')
            location.reload()
        }
    });
})


$('#btn_export').click(function (){

    if(data[0]!=""){
    let rows = [["timestamp","ip","method","baseUrl","header","body"]];

    for(let i of data){
        rows.push([new Date((JSON.parse(data[0]).timestamp)).toJSON(),JSON.stringify(JSON.parse(data[0]).ip),JSON.stringify(JSON.parse(data[0]).method),JSON.stringify(JSON.parse(data[0]).baseUrl),JSON.stringify(JSON.parse(data[0]).header).replace(/,/g,'@'),JSON.stringify(JSON.parse(data[0]).body).replace(/,/g,'@')])
    }

    let csvContent = "data:text/csv;charset=utf-8,";

    rows.forEach(function(rowArray) {
        let row = rowArray.join(",");
        csvContent += row + "\r\n";
    });

    var encodedUri = encodeURI(csvContent);
    var link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", "history_"+new Date().toJSON()+".csv");
    document.body.appendChild(link); // Required for FF

    link.click(); // This will download the data file named "my_data.csv".

    }else{
        alert('No data')
    }




})





