var fs = require('fs');
const express = require('express');
const app = express();

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

**/

// Binary tree node
function Node(val){
  this.value = val;
  this.p_word = null;
  this.parent = null;
  this.left = null;
  this.right = null;
  // for classifying step
  this.new_vals = 0;
}

function height(tree){
	if (tree == null) return 0;
	return 1+Math.max(height(tree.left),height(tree.right));
}

function leaves(tree){
	var values = [];
	if (tree == null) return values;
	if (tree.p_word == null) return [tree.value];
	values = values.concat(leaves(tree.left));
	values = values.concat(leaves(tree.right));
	return values;
}

function prune(tree,size,itr=0,threshold=0.02){
	if (tree == null || size == 0) return;
	if (tree.p_word != null){
		if (tree.parent==null){
			prune(tree.left,size,itr+1,threshold);
			prune(tree.right,size,itr+1,threshold);
		} else {
			var node;
			if (tree.left.new_vals == 0){
				node = tree.right;
				node.parent = tree.parent;
				if (tree.parent.left === tree) tree.parent.left = node;
				else tree.parent.right = node;
				console.log(tree.p_word+" was removed, replaced (LEFT) with "+node.p_word);
			} else if (tree.right.new_vals == 0){
				node = tree.left;
				node.parent = tree.parent;
				//console.log(tree.parent+" "+tree.new_vals);
				if (tree.parent.left === tree) tree.parent.left = node;
				else tree.parent.right = node;
				console.log(tree.p_word+" was removed, replaced (RIGHT) with "+node.p_word);
			} else {
				prune(tree.left,size,itr+1,threshold);
				prune(tree.right,size,itr+1,threshold);
			}
			prune(node,size,itr+1,threshold);
		}
	} else {
		//console.log("LEAF -> "+tree.new_vals/size);
		if (tree.new_vals/size > threshold){
			var str = tree.value.length+" logs split ";
			shuffle(tree.value);
			tree = parse(tree.value);
			console.log(str+((tree.p_word==null)?"Failed to identify (p,n)-gram.":"-> "+tree.p_word));
		}
	}
	//console.log("itr = "+itr+" "+tree.p_word+" "+(tree.new_vals/size));
}

function reset(tree,clear=true){
	if (tree == null) return tree;
	if (clear) tree.value = [];
	tree.new_vals = 0;
	reset(tree.left);
	reset(tree.right);
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

function selectRandom(obj,flip) {
	var keys = Object.keys(obj),
		i = (flip) ? keys.length-1 : keys.length*Math.random() << 0,
		j = obj[keys[i]].length * Math.random() << 0;
	return [keys[i],obj[keys[i]][j]];
}

var colors = { 'R':'\x1b[31m%s\x1b[0m', 'G':'\x1b[32m%s\x1b[0m', 'B':'\x1b[36m%s\x1b[0m', 'Y':'\x1b[33m%s\x1b[0m' }
var months = {'Jan':0, 'Feb':1, 'Mar':2, 'Apr':3, 'May':4, 'Jun':5, 'Jul':6, 'Aug':7, 'Sep':8, 'Oct':9, 'Nov':10, 'Dec':11};
var regex = /(\\|\s|\"|\[|\]|\(|\)|\;|\:|\?|,|'|=|%|\$|_|\+|-|\/)/;
var journal = {};

function split(log,freq,flip){
	//TEST SCAN/EVALUATE
	var common = [];
	var anomaly = [];
	var count = 0;
	// Pick random frequent p-word
	var j = selectRandom(freq,flip);
	var len = j[1].length;
	//console.log(j);
	
	for(i in log) {
		if (log[i] == "") continue;
		if (log[i].substring(j[0],parseInt(j[0])+len) == j[1]){
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

function parse(log, maxloglen=2048, minlognum=1, stddev=0.0, flip=false){
	var offsets = new Array(maxloglen);
	var root = new Node(log);
	// Binary tree model
	if (log.length<=minlognum) return root;
	var count = 0;
	for(i in log) {
		if (log[i] == "") continue;
		else ++count;
		//if (count == 1000) break;
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
				}
				if (offsets[x]==null) offsets[x]={};
				offsets[x][chr] = (offsets[x][chr]==null)? 1: offsets[x][chr]+1;
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
	// LEARNING STEP 2: Calculate frequencies and select p-words w/ freq >= 50% +- stddev
	var freq = {};
	var found_check = false;
	for(i in offsets){
		var total_words = 0;
		for (w in offsets[i]){
			var calc = (stddev!=0.0) ?
				(offsets[i][w]/count >= 0.5-stddev && offsets[i][w]/count <= 0.5+stddev):
				(offsets[i][w]/count >= 0.5 && offsets[i][w]/count <1);
			if (calc){
				if (freq[i]==null) freq[i] = [w];
				else freq[i].push(w);
				found_check = true;
			}
			total_words += offsets[i][w];
		}
	}
	// LEARNING STEP 3: Build Model Recursively, randomly select p-word
	if (found_check){
		var log_split = split(log, freq, flip);
		root.left = parse(log_split[0],maxloglen,minlognum,stddev,flip);
		root.right = parse(log_split[1],maxloglen,minlognum,stddev,flip);
		root.p_word = log_split[2];
		root.left.parent = root.right.parent = root;
	} //else console.log(colors['R'],"BELOW THREASHOLD");
	//console.log(colors['B'],"COUNT:\t"+count);
	return root;
}

function classify(log,tree,clear=true,windowmin=500,minslicelen=100){
	var timestamp,slice_start=null,slice_size=0;
	for(i in log) {
		if (log[i] == ""||log[i] == "\n") continue;
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
		if (slice_start==null) slice_start = timestamp;
		else if (diff_minutes(slice_start,timestamp) > windowmin && slice_size >= minslicelen){
			// Xhrs of logs added, prune tree through splitting/deletion
			prune(tree,slice_size);
			reset(tree,clear);
			slice_start = timestamp;
			slice_size = 0;
		} ++slice_size;
		/**/
		var node = tree;
		while (node.p_word!=null){
			node.value.push(log[i]);
			node.new_vals+=1;
			node = (log[i].substring(node.p_word[0],parseInt(node.p_word[0])+node.p_word[1].length)==node.p_word[1]) ? node.left: node.right;
		}
		node.value.push(log[i]);
		node.new_vals+=1;
	}
	if (slice_size>=minslicelen) prune(tree,slice_size);
}

var input_access = "";
var input_other_vhosts_access = "";
var input_error = "";
/**
process.argv.forEach(function (val, index, array) {
  console.log(index + ': ' + val);
});
/**/
for(var i = 14; i>0; --i){
	input_access += fs.readFileSync('apache2/access.log.'+i).toString();
	input_other_vhosts_access += fs.readFileSync('apache2/other_vhosts_access.log.'+i).toString();
	input_error += fs.readFileSync('apache2/error.log.'+i).toString();
}

var test_access = fs.readFileSync('apache2/access.log').toString().split("\n");
var test_other_vhosts_access = fs.readFileSync('apache2/other_vhosts_access.log').toString().split("\n");
var test_error = fs.readFileSync('apache2/error.log').toString().split("\n");

/**/
console.log(colors['G'],"ACCESS LOGS\n-----------");
var tree_a = parse(test_access);
console.log(toString(tree_a)+"\nDEPTH:\t"+height(tree_a));
console.log("Total leaves (categories):\t"+leaves(tree_a).length);
classify(input_access.split("\n"),tree_a);
console.log("New Tree:\n"+toString(tree_a)+"\nDEPTH:\t"+height(tree_a));
console.log("Total leaves (categories):\t"+leaves(tree_a).length);
/**
console.log(colors['B'],"OTHERV LOGS\n-----------");
var tree_o = parse(test_other_vhosts_access,2048,1,0.1);
console.log(toString(tree_o)+"\nDEPTH:\t"+height(tree_o));
console.log("Total leaves (categories):\t"+leaves(tree_o).length);
classify(input_other_vhosts_access.split("\n"),tree_o);
console.log("New Tree:\n"+toString(tree_o)+"\nDEPTH:\t"+height(tree_o));
console.log("Total leaves (categories):\t"+leaves(tree_o).length);
/**
console.log(colors['R'],"ERROR LOGS\n----------");
var tree_e = parse(test_error,2048,1,0.3);
console.log(toString(tree_e)+"\nDEPTH:\t"+height(tree_e));
console.log("Total leaves (categories):\t"+leaves(tree_e).length);
classify(input_error.split("\n"),tree_e,false);
console.log("New Tree:\n"+toString(tree_e)+"\nDEPTH:\t"+height(tree_e));
console.log("Total leaves (categories):\t"+leaves(tree_e).length);
/**/

function plot_html(path,tree){
	var node = tree;
	if (path != "/null")
	for (var i = 1; i < path.length; ++i)
	node = (path.charAt(i)=='1') ? node.left: node.right;
	var output = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Corresponding Logs</title></head><body><p>';
	for (x in node.value)
	output += node.value[x]+"<br>";
	return output+"</p></body></html>";
}

function toHTML(tree,path=""){
	var output = "";
	if (tree == null) return output;
	var len = tree.value.length;
	output += '<li><a href="'+((path=="")?null:path)+'">';
	output += "Logs: "+len+"<br>";
	if (tree.p_word != null){
		output += "Pos: "+tree.p_word[0]+"<br>";
		output += "Word: '"+tree.p_word[1]+"'";
	}
	output += "</a>";
	if (tree.left != null)
		output += "<ul>"+toHTML(tree.left,path+'1');
	if (tree.right != null)
		output += toHTML(tree.right,path+'0')+"</ul>";
	output += "</li>";
	return output;
}

var html = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><link rel="stylesheet" href="style.css"><title>Binary (p,n)-gram Tree</title></head><body><div class="tree">';
html+= "<ul>"+toHTML(tree_a)+"</ul>";
html+= "</div></body></html>";

app.use(express.static('public'));
app.get('*', (req, res, next) => (req.url === '/') ? next(): res.send(plot_html(req.url,tree_a)));
app.get('/', (req, res) => res.send(html));
app.listen(3000, () => console.log('Application available @ http://localhost:3000'));