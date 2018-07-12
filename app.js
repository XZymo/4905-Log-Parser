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

// Binary tree node
function Node(val){
  this.value = val;
  this.p_word = null;
  this.left = null;
  this.right = null;
}

function height(tree){
	if (tree == null) return 0;
	return 1+Math.max(height(tree.left),height(tree.right));
}

function leaves(tree){
	var values = [];
	if (tree.p_word == null) return [tree.value];
	values = values.concat(leaves(tree.left));
	values = values.concat(leaves(tree.right));
	return values;
}

function toString(tree,layers=0){
	var output = "", buffer = "";
	if (tree == null) return output;
	for (var i = layers; i > 0; --i) buffer+="\t";
	var len = tree.value.length;
	/**
	if (tree.p_word == null&&len<=10){
		for (x in tree.value){
			output += buffer+tree.value[x]+"\n";
		}
	}
	/**/
	output += buffer+"Logs:\t"+len+"\n";
	if (tree.p_word != null){
		output += buffer+"Pos:\t"+tree.p_word[0]+"\n";
		output += buffer+"Word:\t"+tree.p_word[1]+"\n";
	}
	if (tree.left != null)
		output += buffer+"Present\n"+toString(tree.left,1+layers);
	if (tree.right != null)
		output += buffer+"Missing\n"+toString(tree.right,1+layers);
	return output;
}

function diff_minutes(dt2, dt1) {
	var diff =(dt2.getTime() - dt1.getTime()) / 60000;
	return Math.abs(Math.round(diff)); 
}

function shuffle(array) {
    for (let i = array.length - 1; i > 0; --i) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]]; // eslint-disable-line no-param-reassign
    }
}

function selectRandom(obj) {
	var keys = Object.keys(obj),
		i = keys.length * Math.random() << 0,
		j = obj[keys[i]].length * Math.random() << 0;
	return [keys[i],obj[keys[i]][j]];
}

var colors = { 'R':'\x1b[31m%s\x1b[0m', 'G':'\x1b[32m%s\x1b[0m', 'B':'\x1b[36m%s\x1b[0m', 'Y':'\x1b[33m%s\x1b[0m' }
var months = {'Jan':0, 'Feb':1, 'Mar':2, 'Apr':3, 'May':4, 'Jun':5, 'Jul':6, 'Aug':7, 'Sep':8, 'Oct':9, 'Nov':10, 'Dec':11};
var regex = /(\\|\s|\"|\[|\]|\(|\)|\;|\:|\?|,|'|=|%|\$|_|\+|-|\/)/;
var journal = {};

function check(log, freq){
	//TEST SCAN/EVALUATE
	var common = [];
	var anomaly = [];
	var count = 0;
	// Pick random frequent p-word
	var j = selectRandom(freq);
	//console.log(j);
	
	for(i in log) {
		if (log[i] == "") continue;
		if (log[i].substring(j[0],parseInt(j[0])+j[1].length) == j[1]){
			if (!common.includes(log[i])) {
				common.push(log[i]);
			}
		}else{
			if (!anomaly.includes(log[i])) {
				anomaly.push(log[i]);
			}
		}
	}
	/**
	console.log("COMMONS\n");
	for (i in common) console.log(colors['B'],i+"\t"+common[i]);
	console.log("ANOMALIES\n");
	for (i in anomaly) console.log(colors['R'],i+"\t"+anomaly[i]);
	/**/
	return [common,anomaly,j];
}

function parse(log, maxloglen, minlognum, frequency=0.5){
	var offsets = new Array(maxloglen);
	var root = new Node(log);
	// Binary tree model
	if (log.length<=minlognum) return root;
	var count = 0;
	for(i in log) {
		if (log[i] == "") continue;
		else ++count;
		// LEARNING STEP 1: Build offset word dictionary (Identify pn-grams)
		var prev_index = 0;
		/**
		var buf = "";
		var chr;
		for (var x=0;x<log[i].length;++x){
			//if (x > maxloglen) break;
			chr = log[i].charAt(x);
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
		//var buf = log[i].match(/.{1,2}/g);
		//var buf = log[i].match(/.{1,3}/g);
		//var buf = log[i].match(/.{1,7}/g);
		//var buf = nGram(3)(log[i]);
		
		for (var x = 0; x < buf.length; ++x){
			var word = buf[x]+"";
			if (word == "") continue;
			var index = log[i].indexOf(word,prev_index);
			prev_index = index+word.length;
			if (offsets[index]==null) offsets[index]={};
			offsets[index][word] = (offsets[index][word]==null)? 1: offsets[index][word]+1;
		/**/
		}
	}
	// LEARNING STEP 2: Calculate frequencies and select p-words w/ freq >= 50%
	var freq = {};
	var found_check = false;
	for(i in offsets){
		var total_words = 0;
		for (w in offsets[i]){
			if (offsets[i][w]/count >= frequency && offsets[i][w]/count <1){
				if (freq[i]==null) freq[i] = [w];
				else freq[i].push(w);
				found_check = true;
			}
			total_words += offsets[i][w];
		}
	}
	// LEARNING STEP 3: Build Model Recursively, randomly select p-word
	if (found_check){
		var log_split = check(log, freq);
		root.left = parse(log_split[0],maxloglen,minlognum);
		root.right = parse(log_split[1],maxloglen,minlognum);
		root.p_word = log_split[2];
	} //else console.log(colors['R'],"BELOW THREASHOLD");
	//console.log(colors['B'],"COUNT:\t"+count);
	return root;
}

function classify(log,tree){
	var sorted = {};
	for(i in log) {
		if (log[i] == "") continue;
		var node = tree;
		var str = "";
		while (node.p_word!=null){
			node.value.push(log[i]);
			if (log[i].substring(node.p_word[0] ,parseInt(node.p_word[0])+node.p_word[1].length) == node.p_word[1]){
				str += "\x1b[32m"+node.p_word+"\x1b[0m";
				node = node.left;
			} else {
				str += "\x1b[31m"+node.p_word+"\x1b[0m";
				node = node.right;
			}
			if (node.p_word!=null) str += " -> "
		}
		if (str != "")
		if (sorted[str]==null) sorted[str]=[log[i]];
		else sorted[str].push(log[i]);
		//console.log(colors['Y'],log[i]);
	}
	/**/
	for (i in sorted){
		console.log(i+": ");
		console.log(leaves(parse(sorted[i],2048,5,0.12)));
	}
	console.log("Leaf nodes used to sort:\t%d",Object.keys(sorted).length);
	/**/
}

var log_length = 2048;
var min_num_logs = 10;

var input_access = "";
var input_other_vhosts_access = "";
var input_error = "";

for(var i = 1; i<15; ++i){
	input_access += fs.readFileSync('apache2/access.log.'+i).toString();
	input_other_vhosts_access += fs.readFileSync('apache2/other_vhosts_access.log.'+i).toString();
	input_error += fs.readFileSync('apache2/error.log.'+i).toString();
}

var test_access = fs.readFileSync('apache2/access.log').toString().split("\n");
var test_other_vhosts_access = fs.readFileSync('apache2/other_vhosts_access.log').toString().split("\n");
var test_error = fs.readFileSync('apache2/error.log').toString().split("\n");

console.log(colors['G'],"ACCESS LOGS\n-----------");
var tree_a = parse(input_access.split("\n"),log_length,min_num_logs);
console.log(toString(tree_a)+"\nDEPTH:\t"+height(tree_a));
classify(test_access,tree_a);
console.log("Total leaves (categories):\t%d",leaves(tree_a).length);
/**/
console.log(colors['B'],"OTHERV LOGS\n-----------");
var tree_o = parse(input_other_vhosts_access.split("\n"),log_length,min_num_logs);
console.log(toString(tree_o)+"\nDEPTH:\t"+height(tree_o));
classify(test_other_vhosts_access,tree_o);
console.log("Total leaves (categories):\t%d",leaves(tree_o).length);
console.log(colors['R'],"ERROR LOGS\n----------");
var tree_e = parse(input_error.split("\n"),log_length,min_num_logs);
console.log(toString(tree_e)+"\nDEPTH:\t"+height(tree_a));
classify(test_error,tree_e);
console.log("Total leaves (categories):\t%d",leaves(tree_e).length);
/**/