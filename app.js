var fs = require('fs');
var nGram = require('n-gram');
var stringSimilarity = require('string-similarity');

/** APACHE LOG FORMAT: 
%h		IP address of the client (remote host)
%l		The "hyphen" in the output indicates that the requested piece of information is not available.
%u		The userid of the person requesting the document as determined by HTTP authentication.
%t		The time that the request was received. [day/month/year:hour:minute:second zone]
%r		The request line from the client. "method_used requested_resource protocol_used" | "%m %U%q %H"
%>s		Status code that the server sends back to the client.
%b		The size of the object returned to the client, not including the response headers. (payload)
%{ref}i	The "Referer" (sic) HTTP request header. This gives the site that the client reports having been referred from IN QUOTES. "-"
%{usr}i	The User-Agent HTTP request header. This is the identifying information that the client browser reports about itself IN QUOTES.
Ex.:
	%h %l %u [%t] "%m %U%q %H" %>s $b "%{ref}i" "%{usr}i"
	73.41.227.33 - - [09/May/2018:06:45:10 -0400] "GET /wp-login.php HTTP/1.1" 404 7985 "-" "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1"
	
	http://guidetodatamining.com/ngramAnalyzer/
**/



function diff_minutes(dt2, dt1) {
	var diff =(dt2.getTime() - dt1.getTime()) / 60000;
	return Math.abs(Math.round(diff)); 
}

function access_parse(log, window_mins, callback){
	var months = {'Jan':0, 'Feb':1, 'Mar':2, 'Apr':3, 'May':4, 'Jun':5, 'Jul':6, 'Aug':7, 'Sep':8, 'Oct':9, 'Nov':10, 'Dec':11};		
	var dataset = {};
	var set_index = 0;
	var slice = {};
	var slice_start = null;
	var cmp_score = [];
	var cmp_string = "";
	var cmp_string2 = "";
	
	for(i in log) {
		if (log[i] == "") break;
		var parsed_log = log[i].match(/(.*)\s(.*)\s(.*)\s\[(.*)\]\s\"(.*)\"\s(.*)\s(.*)\s\"(.*)\"\s\"(.*)\"/);
		var ip = parsed_log[1];
		var timestamp = parsed_log[4];
		var year = timestamp.substring(7,11),
			month = months[timestamp.substring(3,6)],
			day = timestamp.substring(0,2),
			hours = timestamp.substring(12,14),
			minutes = timestamp.substring(15,17),
			seconds = timestamp.substring(18,20),
			datetime = new Date(year, month, day, hours, minutes, seconds);
		
		//if (!ip.includes("180.76.15")) continue;
		//if (!parsed_log[5].includes("login")) continue;
		//if (parsed_log[6] != "200") continue;
		//if (parseInt(parsed_log[7])<=10000) continue;
		//if (parsed_log[8].toLowerCase().includes("nspw") || parsed_log[8]=="-") continue;
		//if (parsed_log[9].toLowerCase().includes("bot")) continue;
		
		var payload = parsed_log[2]+" "+parsed_log[3]+" "+parsed_log[5]+" "+parsed_log[6]+" "+parsed_log[7]+" "+parsed_log[8]+" "+parsed_log[9];
			
		if (slice_start == null){
			cmp_string = slice[datetime] = ip+" "+payload;
			slice_start = datetime;
		} else {
			if (diff_minutes(slice_start,datetime) <= window_mins){
				slice[datetime] = ip+" "+payload;
				cmp_string += ip+" "+payload;
			} else {
				dataset[++set_index] = slice;
				slice = {};
				slice[datetime] = ip+" "+payload;
				slice_start = datetime;
				
				if (set_index % 2 == 0){
					cmp_score[set_index-1] = stringSimilarity.compareTwoStrings(cmp_string, cmp_string2);
					cmp_string = ip+" "+payload;
					cmp_string2 = "";
				} else {
					cmp_string2 = cmp_string;
					cmp_string = "";
				}
			}
		}
	}
	if (Object.keys(slice).length != 0) dataset[++set_index] = slice;
	console.log(cmp_score);
	return dataset;
}

function error_parse(log, window_mins, callback){
	var dataset = {};
	var set_index = 0;
	var slice = {};
	var slice_start = null;
	
	for(i in log) {
		if (log[i] == "") break;
		var parsed_log = log[i].match(/\[(.*)\]\s\[(.*)\]\s\[pid\s(\d{5}|\d{4}|\d{3})\]\s(.*)/);
		var timestamp = new Date(parsed_log[1]);
		var payload = parsed_log[2]+" "+parsed_log[3]+" "+parsed_log[4];
		
		if (slice_start == null){
			slice[log[i].match(/(\d{2}\:\d{2}\:\d{2}\.\d{6})/)[1]] = payload;
			slice_start = timestamp;
		} else {
			if (diff_minutes(slice_start,timestamp) <= window_mins){
				slice[log[i].match(/(\d{2}\:\d{2}\:\d{2}\.\d{6})/)[1]] = payload;
			} else {
				dataset[++set_index] = slice;
				slice = {};
				slice[log[i].match(/(\d{2}\:\d{2}\:\d{2}\.\d{6})/)[1]] = payload;
				slice_start = timestamp;
			}
		}
	}
	if (Object.keys(slice).length != 0) dataset[++set_index] = slice;
	return dataset;
}

var array = "";
for(var i = 1; i<15; ++i){
	array = array + fs.readFileSync('apache2/access.log.'+i).toString();
	//array = array + fs.readFileSync('apache2/other_vhosts_access.log.'+i).toString();
}
var data = access_parse(array.split("\n"),10);

var array = ""
for(var i = 1; i<15; ++i){
	array = array + fs.readFileSync('apache2/error.log.'+i).toString();
}
var errors = error_parse(array.split("\n"),10);

//console.log(data);
var freq_dict = {};
var sus_ips = {};
for(i in data){
	for(j in data[i]){
		for(x in errors){
			var ip = data[i][j].match(/((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))/)[1];
			for(y in errors[x]){
				if (errors[x][y].includes(ip)){
					sus_ips[ip] = (sus_ips[ip] == null)? 1: sus_ips[ip]+1;
				}
			}
		}
		//var png = nGram(5)(data[i][j]);
		var png = data[i][j].split(" ");
		for(k in png) freq_dict[png[k]] = ((freq_dict[png[k]] == null)) ? 1 : freq_dict[png[k]]+1;
		
	}
}

var items = Object.keys(freq_dict).map(function(payload) {
    return [payload, freq_dict[payload]];
});
items.sort(function(first, second) {
    return second[1] - first[1];
});

console.log(items);
var len = Object.keys(freq_dict).length;
for(i in freq_dict){
//	if (freq_dict[i] >=100) console.log(freq_dict[i]+"\t=\t% "+(freq_dict[i]/len)+"\t--> "+i);
	for(x in errors){
		for(y in errors[x]){
			if (i.match(/((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))/) != null)
			if (errors[x][y].includes(ip)){
				sus_ips[ip] = (sus_ips[ip] == null)? 1: sus_ips[ip]+1;
			}
		}
	}
}
var items = Object.keys(sus_ips).map(function(ip) {
    return [ip, sus_ips[ip]];
});
items.sort(function(first, second) {
    return second[1] - first[1];
});
console.log(items);
