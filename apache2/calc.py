from __future__ import division

log = "error.log"
with open(log, "r") as f:
		lines = f.readlines()
		print("Length: "+str(len(lines)))
		print(sum(len(line) for line in lines) / len(lines))
		print
for i in xrange(1,15): 
	with open(log+"."+str(i), "r") as f:
		lines = f.readlines()
		print("Length: "+str(len(lines)))
		print(sum(len(line) for line in lines) / len(lines))
		print