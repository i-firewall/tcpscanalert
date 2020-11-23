#!/usr/bin/perl

#23/11/2020
#Find path to iptables and set as a variable.
#v1


$fwall = `find \/sbin \/usr\/sbin \/usr\/local\/sbin  -executable -name "iptables" | grep -A 1 iptables`;

chomp $fwall;

print "iptables path is $fwall";


# Create a chain to handle/hold all temporary firewall rules.

# Set up BLOCKER Chain & Flush it out first.
`$fwall -F BLOCKER >> /dev/null 2>&1`;

# Delete the INPUT Rule for BLOCKER Chain
`$fwall -D INPUT -j BLOCKER >> /dev/null 2>&1`;

# Delete the BLOCKER Chain"
`$fwall -X BLOCKER >> /dev/null 2>&1`;

# Create the BLOCKER Chain
`$fwall -N BLOCKER`;

# INSERT the BLOCKER Chain into INPUT Rule
`$fwall -I INPUT -j BLOCKER`;

# Now just need to take the captured offending IP and insert it into the chain as a blocking rule if not already being used.

$SEEIFTHERE=`$fwall -nL | grep DROP | grep -A 0 $culprit | cut -f 12 -d ' '`;

if ($SEEIFTHERE == "$culprit") {
#               print "its already blocked, move on
} elsif ($addr == "$culprit") {
#       $culprit is our own IP, so move on
} else {
# do the block.
	`$fwall -I BLOCKER -s $culprit -j DROP`;
}


exit 0;


