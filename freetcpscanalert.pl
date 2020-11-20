#!/usr/bin/perl
#
#Portions of this are code used from Bri Hatch, 2003, for packet capture,
#released by him under GPL.
#His code is therefore reproduced as is with ultrasecure-it's own code 
#included around it.
#If you want to get Bri's code in full, at time of writing this, you can
#find it at http://www.hackinglinuxexposed.com/articles/20030730.html .
#Many thanks, Bri.
#
#Version 1.
#20/11/2020.
#
#
#
# Portions are Copyright 2003, Bri Hatch, released under the GPL
#
# The unprivileged uid/gid under which we should run.
my $UNPRIV="1007";


################################


sub trim { # (string) -> trimmed string
  my $s=shift; 
  chomp($s);  # get rid of \n
  $s =~ s/^\s+//; # remove leading spaces
  $s =~ s/\s+$//; # remove trailing spaces
  return $s;
} # /sub




sub interface {

# If we have a ppp0 and only 1 eth interface, then use eth0 for LAN,
# but use eth1 for LAN always otherwise.

$myip = `/sbin/ifconfig`; # | grep -A 1 inet`;

if ($myip =~ "ppp0") {
        $int = "ppp0";
} else {
        $int = "eth0";
}

if ($int eq "ppp0") {
                $addr = `/sbin/ifconfig ppp0 | grep -A 0 inet`;
        } else {
                $addr = `/sbin/ifconfig eth0 | grep -A 1 inet | grep Bcast`;
        }
        $addr = trim($addr);
        chomp $addr;
        $now = `date`;
        chomp $now;
        $addr = substr($addr, 10);
        substr($addr, index($addr, 'Bcast:'), 6) = '      ';
        $addr = substr($addr, 0, 15);
        chomp $addr;
        $addr=trim($addr);
        undef($myip);
        undef($int);
}

################

interface();

##############

sub localint {

# If we have a ppp0 interface, then use eth0 for LAN,
# but only if no other eth ports present (always use eth1 for lan if poss.)

$myip = `/sbin/ifconfig`; # | grep -A 1 inet`;

if ($myip =~ "eth1") {
        $int = "eth1";
} elsif ($myip =~ "eth2") {
        $int = "eth2";
} else {
        $int = "eth0";
}

#if ($myip =~ "eth2") {
#        $int = "eth2";
#} elsif ($myip =~ "eth1") {
#        $int = "eth1";
#} else {
#        $int = "eth0";
#}


if ($int eq "eth2") {
                $loaddr = `/sbin/ifconfig eth2 | grep Bcast | cut -f 3 -d ':'`;
        } elsif ($int eq "eth1") {
                $loaddr = `/sbin/ifconfig eth1 | grep Bcast | cut -f 3 -d ':'`;
        } else {
                $loaddr = `/sbin/ifconfig eth0 | grep Bcast | cut -f 3 -d ':'`;
        }


$loaddr = trim($loaddr);



        substr($loaddr, index($loaddr, '255'), 9) = '';
        chomp $loaddr;
        $loaddr = trim($loaddr);
        undef($myip);
        undef($int);

$CIDRBIT="0/24";
chomp $CIDRBIT;
$CIDRBIT=trim($CIDRBIT);
#$loclan="$loaddr$CIDRBIT";
$loclan="$loaddr";
chomp $loclan;
$loclan=trim($loclan);

}

##### end of sub#####

# call localint
localint();

#####



use Net::Pcap;
use FileHandle;
#use strict;
#use English;	# for example purposes only - I prefer obfuscated code.

#STDOUT->autoflush(1);

$counter=1;

while ( 1 ) {
#print "counter is $counter\n\n";

    my $pid = fork();
    if ( ! defined $pid ) { die "Unable to fork.  Yikes." };

    if ( $pid ) {
        # Parent process (running as root) will wait for
	# child.  If child exits, we'll create another one.
        wait();	
	sleep(1);  # To keep us from respawning too fast if necessary.
    } else {
#	print "Counter at Child bit is $counter\n";
	if ( $counter >10) {
                print "counter level reached\n";
        	die "time to go";
	}

#    	print "Child starting\n";

	# Child process will do actual sniffing.
	# First, create our packet capturing device
        my($pcap_t) = create_pcap();

        unless ( $pcap_t ) {
            die "Unable to create pcap";
        }

        # Let's stop running as root.  Since we already
	# have our pcap descriptor, we can still use it.
        $EGID="$UNPRIV $UNPRIV";	# setgid and setgroups()
        $GID=$UNPRIV;
        $UID=$UNPRIV; $EUID=$UNPRIV;

	# Capture packets forever.
        Net::Pcap::loop($pcap_t, -1, \&process_pkt, 0);

        # Technically, we shouldn't get here since the loop
        # is infinite (-1), but just in case, close and exit.
        Net::Pcap::close($pcap_t);
        exit 1;
    }

}

sub create_pcap {
    my $promisc = 0;   # We're only looking for packets destined to us,
                       # so no need for promiscuous mode.
    my $snaplen = 125; # Allows a max of 80 characters in the domain name

    my $to_ms = 0;			# timeout
    my $opt=1;                          # Sure, optimisation is good...
    my($err,$net,$mask,$dev,$filter_t);

    my $only_syn = 1;

    my $filter = 'tcp[13] & 0x3f = 0x02';


    # Look up an appropriate device (eth0 usually)
    $dev = Net::Pcap::lookupdev(\$err);
    $dev or die "Net::Pcap::lookupdev failed.  Error was $err";
    
    if ( (Net::Pcap::lookupnet($dev, \$net, \$mask, \$err) ) == -1 ) {
        die "Net::Pcap::lookupnet failed.  Error was $err";
    }
    
    # Actually open up our descriptor
    my $pcap_t = Net::Pcap::open_live($dev, $snaplen, $promisc, $to_ms, \$err);
    $pcap_t || die "Can't create packet descriptor.  Error was $err";
    
    if ( Net::Pcap::compile($pcap_t, \$filter_t, $filter, $opt, $net) == -1 ) {
        die "Unable to compile filter string '$filter'\n";
    }

    # Make sure our sniffer only captures those bytes we want in
    # our filter.
    Net::Pcap::setfilter($pcap_t, $filter_t);

    # Return our pcap descriptor
    $pcap_t;
}


# Routine to process the packet -- called by Net::Pcap::loop()
# every time an appropriate packet is snagged.

sub process_pkt {
    my($user_data, $hdr, $pkt) = @_;

    my($src_ip) = 26;           # start of the source IP in the packet
    my($dst_ip) = 30;           # start of the dest IP in the packet
    my($domain_start) = 55;     # start of the domain in the packet
    my($data);


    # extract the source IP addr into dotted quad form.
    my($source) = sprintf("%d.%d.%d.%d",
        ord( substr($pkt, $src_ip, 1) ),
        ord( substr($pkt, $src_ip+1, 1) ),
        ord( substr($pkt, $src_ip+2, 1) ),
        ord( substr($pkt, $src_ip+3, 1) ));

    # extract the destination IP addr into dotted quad form.
    my($destination) = sprintf("%d.%d.%d.%d",
        ord( substr($pkt, $dst_ip, 1) ),
        ord( substr($pkt, $dst_ip+1, 1) ),
        ord( substr($pkt, $dst_ip+2, 1) ),
        ord( substr($pkt, $dst_ip+3, 1) ));

    $data = substr($pkt, $domain_start);



    $data =~ s/\00.*//g;             # strip off everything after the domain
    $data =~ s/[^-a-zA-Z0-9]/./g;    # change the domain component separators
                                     # back int to dots.
$counter++;
#print "counter is $counter\n";


####
	my $now = localtime time;
        chomp $now;
chomp $mydump;
###


$mydump = `echo "$mydump\nScan detected \@ $now From Source address = $source -> $destination"`

    	if ( $source and $destination and $data);  
if ($counter > 20) {

#### do something ####

chomp $mydump;
$mydump=trim($mydump);


#pcap dupes.
$myscandata = `echo "$mydump" | cut -f 2 -d '\@' | sort | uniq -D`;

#count lines captured.
$myscandatacount = `echo "$mydump" | cut -f 2 -d '\@' | sort | uniq -dc | grep $addr`;


#more line checking.
$mylinecount = `echo "$mydump" | grep -v " Source address = $addr " | grep -v " Source address = $loclan" | cut -f 2 -d '\@' | sort | uniq -D | grep -c $addr`;

# array to count number of uniq dupe lines
@myxtrlinecount = `echo "$mydump" | grep -v " Source address = $addr " | grep -v " Source address = $loclan" | cut -f 2 -d '\@' | sort | uniq -dc | grep $addr`;

# set default mail to false.
$domail=0;

# if one of lines of dupes in array is over 10 entries set mail to true.
foreach (@myxtrlinecount) {
        chomp $_;
        $_=trim($_);
        $_=`echo "$_" | cut -f 1 -d ' '`;
        chomp $_;
        $_=trim($_);
#        print "xtra line count is $_\n\n";
        if ( $_ > 9 ) {
                $domail=1;
        } else {
                next;
        }
}

	

$myscandata=trim($myscandata);


chomp $myscandatacount;
$myscandatacount=trim($myscandatacount);

print "the whole recorded bit is $myscandatacount\n\n";


#catch the offending IP from the $myscandata
$culprit = `echo "$myscandata" | cut -f 2 -d '=' | cut -f 1 -d '-' | sort -u`;
chomp $culprit;
$culprit=trim($culprit);
#######

#send alert if data not empty and more than 9 entries and do mail is true.
if ( ( $myscandatacount ne "" ) && ( $mylinecount > 9 ) && ( $domail == 1 ) && ( $culprit ne "$addr" ) ) {


# get my IP
#interface;

       #Set date up.
        ($null,$minute,$hour,$day,$month,$year,$null,$null,$null)=localtime(time); #lese aktuelle Zeitho
        $year = $year + 1900;


# -------------- ADD SOME CODE TO MAIL OUT ALERT OR OTHER




##############################

#Number of seconds to wait after alert before resuming detection.
sleep 120;

} else {


# But clear the $mydump var anyway.
undef $mydump;

#sleep for 10 seconds
sleep 10;
}

####### resume #########


	exit 2;
}

}




