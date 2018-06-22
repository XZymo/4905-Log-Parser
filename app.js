var fs = require('fs');
var nGram = require('n-gram');
var stringSimilarity = require('string-similarity');

/** APACHE LOG FORMAT: 
%h		IP address of the client (remote host)
%l		the RFC 1413 identity of the client determined by identd on the clients machine. "-" indicates that the requested information is unavailable.
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

function shuffle(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]]; // eslint-disable-line no-param-reassign
    }
}

var colors = { 'R':'\x1b[31m%s\x1b[0m', 'G':'\x1b[32m%s\x1b[0m', 'B':'\x1b[36m%s\x1b[0m' }
var months = {'Jan':0, 'Feb':1, 'Mar':2, 'Apr':3, 'May':4, 'Jun':5, 'Jul':6, 'Aug':7, 'Sep':8, 'Oct':9, 'Nov':10, 'Dec':11};
var regex = /\/|\\|\s|\"|\[|\]|\(|\)|\;|\:|\?|,|'|=|%|\$|_|\+/;
var journal = {};

function parse(log, maxloglen, callback){
	var offsets = new Array(maxloglen);
	var timestamp;
	var count = 0;
	for(i in log) {
		if (log[i] == "") break;
		else ++count;
		/**/
		// Access datestring format
		var datestring = log[i].match(/\[([0-3]\d)\/(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\/((?:19|20)\d{2}):([0-2]\d):([0-5]\d):([0-5]\d)\s-([0-2]\d{3})\]/);
		if (datestring!=null){
			var year = datestring[3],
				month = months[datestring[2]],
				day = datestring[1],
				hours = datestring[4],
				minutes = datestring[5],
				seconds = datestring[6];
			timestamp = new Date(year, month, day, hours, minutes, seconds);
		} else {
		// Error datestring format
			datestring = log[i].match(/\[((?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s[0-3]\d\s[0-5]\d:[0-5]\d:[0-5]\d.\d{6}\s(?:19|20)\d{2})\]/);
			timestamp = new Date(datestring[1]);
		}
		var month_day = timestamp.getMonth()+"-"+timestamp.getDate()+"-"+timestamp.getHours();
		if (journal[month_day] == null) journal[month_day] = [];
		if (!journal[month_day].includes(log[i])) journal[month_day].push(log[i]);
		
		/**/
		// LEARNING STEP 1: Build offset word dictionary (Identify pn-grams)
		var prev_index = 0;
		/**
		var buf = "";
		var chr;
		for (var x=0;x<log[i].length;++x){
			//if (x > maxloglen) break;
			chr = String.fromCharCode(log[i].charCodeAt(x));
			if ("/ \\\"[]();:?,".includes(chr)){
				if (buf != ""){
					if (offsets[prev_index]==null) offsets[prev_index]={};
					offsets[prev_index][buf] = (offsets[prev_index][buf]==null)? 1: offsets[prev_index][buf]+1;
					buf = "";
				} else continue;
			} else {
				if (buf == "") prev_index = x;
				buf += chr;
			}
		/**/
		var buf = log[i].split(regex);
		for (var x = 0; x < buf.length; ++x){
			var word = buf[x]+"";
			if (word == "") continue;
			var index = log[i].indexOf(word,prev_index);
			prev_index = index+word.length-1;
			if (offsets[index]==null) offsets[index]={};
			offsets[index][word] = (offsets[index][word]==null)? 1: offsets[index][word]+1;
		/**/
		}
	}
	// LEARNING STEP 2: Calculate frequencies and select random p-word w/ freq >= 50%
	var freq = [];
	for(i in offsets){
		var words_found = Object.keys(offsets[i]).length;
		console.log("Index:\t"+i+"\n  Words found = "+words_found+" ===== "+count);
		var total_words = 0;
		for (w in offsets[i]){
			if (offsets[i][w]/count >= 0.5){
				console.log("\toccurences:\t"+offsets[i][w]+"\t"+w);
				console.log(colors['R'],"\tfreq:\t"+(offsets[i][w]/count)+"\t"+w);
				if (freq[i]==null) freq[i] = w;
			}
			total_words += offsets[i][w];
		}
		//console.log("  Total count = "+total_words+"\n  Sigma: "+sigmas[i]);
	}
	console.log(freq);
	return freq;
}

function scan(log, freq, callback){
	//TEST SCAN/EVALUATE
	var common = [];
	var anomaly = [];
	var count = 0;
	for(i in log) {
		if (log[i] == "") break;
		//console.log("\n================== Log"+(++count)+" Report ==================\n");
		for(j in freq){
			if (log[i].substring(j,parseInt(j)+freq[j].length) != freq[j])
				console.log(colors['B'],log[i]);
			else
				console.log(colors['R'],log[i]);
			break;
		}
		/**/
	}
	var len = Math.log(count) * Math.LOG10E + 1 | 0;
	//var str = "=================================================";
	//for (var c = 0; c < len-1; ++c) str+= "=";
	/**
	//console.log(str+"\n");
	console.log("COMMONS\n");
	for (i in common) console.log(i+"\t"+common[i]);
	console.log("ANOMALIES\n");
	for (i in anomaly) console.log(i+"\t"+anomaly[i]);
	/**/
}

var log_length = 2048;

var input_access = "";
var input_other_vhosts_access = "";
var input_error = "";

for(var i = 1; i<2; ++i){
	input_access += fs.readFileSync('apache2/access.log.'+i).toString();
	input_other_vhosts_access += fs.readFileSync('apache2/other_vhosts_access.log.'+i).toString();
	input_error += fs.readFileSync('apache2/error.log.'+i).toString();
}

var test_access = fs.readFileSync('apache2/access.log').toString().split("\n");
var test_other_vhosts_access = fs.readFileSync('apache2/other_vhosts_access.log').toString().split("\n");
var test_error = fs.readFileSync('apache2/error.log').toString().split("\n");

var freq_a = parse(input_access.split("\n"),log_length);
//var freq_o = parse(input_other_vhosts_access.split("\n"),log_length);
//var freq_e = parse(input_error.split("\n"),log_length);
/**/
console.log("\n\tACCESS LOGS\n\t-----------");
scan(input_access.split("\n"), freq_a);
//console.log("\n\tOTHER_VHOSTS LOGS\n\t-----------------");
//scan(test_other_vhosts_access, freq_o);
//console.log("\n\tERROR LOGS\n\t----------");
//scan(test_error, freq_e);
/**/