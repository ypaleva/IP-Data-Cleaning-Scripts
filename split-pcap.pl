
use Net::Pcap;
use strict;
use warnings;

my $type;
my $length;
my $header;
my $size;
my $bytes = 0;
my %fourTuple;
my $fourTupleKey;
my $fourTupleSavedCount = 0;
my $fourTupleNotSavedCount = 0;
my $okToOpen = 1;
my $dumpFile;

if ($#ARGV lt 1)  {
    print "Usage: pcap.pl [ether | sll | evlan] \n";
    exit;
}
if ($#ARGV gt 1 ) {
    print "Usage: pcap.pl [ether | sll | evlan] \n";
    exit;
}

open(INFILE, $ARGV[1]) || die "Can't open $ARGV[1]. $!\n";
$length = read(INFILE,$header,8);
die "Can't read from " . $ARGV[1] . ", $length < 8\n" if $length < 8;
$size = -s $ARGV[1];
close(INFILE);

$type = $ARGV[0];

my ($pcap, $err);
$pcap = Net::Pcap::open_offline ($ARGV[1], \$err) || die "Could not open file " . $ARGV[1] . ". $!";

Net::Pcap::loop ($pcap, -1, \&processPacket, 0);


foreach (sort keys %fourTuple) {
    if ($fourTuple{$_} >0) {
     Net::Pcap::pcap_dump_close ($fourTuple{$_});
    }
  }

open (OUTFILE, ">", $ARGV[1] . "-missed-4-tuples") or die $!;
foreach (sort keys %fourTuple) {
    if ($fourTuple{$_} == -1) {
     print OUTFILE "$_\n";
    }
  }
close (OUTFILE);

sub processPacket {
    my($user_data, $hdr, $pkt) = @_;

    my($etherTypeLoc) = 12;     # start of the Protocol Type for Ethernet frame
    my($sllTypeLoc) = 14;       # start of the Protocol Type for SLL (Linux cooked) frame
    my($etherVlanTypeLoc) = 18;      # start of the Protocol Type for an Ethernet Frame with a VLAN tag
    my($typeOffset);
    my($protoType);
    my($ipHeaderLen);
    my($ipProto);
    my($ipSrcAddr);
    my($ipDstAddr);
    my($tcpSrcPort);
    my($tcpDstPort);
    my($dumpFileName);

    if ($type eq "ether") {
       $typeOffset = 12;
    } elsif ($type eq "sll") {
       $typeOffset = 14;
    } else {
       $typeOffset = 16;
    }

    $protoType = ord (substr($pkt, $typeOffset, 1)) * 256 +
            ord (substr($pkt, $typeOffset+1, 1));

    if ($protoType == 0x0800) {   # Frame type is IP
       $ipHeaderLen = (ord (substr($pkt, $typeOffset+2, 1)) & 0x0F) * 4;
       $ipProto = ord ( substr($pkt, $typeOffset+11, 1));
       if ($ipProto == 6) {   # frame type is TCP
          $ipSrcAddr = sprintf("%d.%d.%d.%d",
             ord( substr($pkt, $typeOffset+14, 1) ),
             ord( substr($pkt, $typeOffset+15, 1) ),
             ord( substr($pkt, $typeOffset+16, 1) ),
             ord( substr($pkt, $typeOffset+17, 1) ));
          $ipDstAddr = sprintf("%d.%d.%d.%d",
             ord( substr($pkt, $typeOffset+18, 1) ),
             ord( substr($pkt, $typeOffset+19, 1) ),
             ord( substr($pkt, $typeOffset+20, 1) ),
             ord( substr($pkt, $typeOffset+21, 1) ));
          $tcpSrcPort = ord (substr($pkt,
                             $typeOffset+2+$ipHeaderLen, 1)) * 256 +
                        ord (substr($pkt, $typeOffset+2+$ipHeaderLen+1, 1));
          $tcpDstPort = ord (substr($pkt,
                             $typeOffset+2+$ipHeaderLen+2, 1)) * 256 +
                        ord (substr($pkt, $typeOffset+2+$ipHeaderLen+3, 1));

          if ($tcpSrcPort < $tcpDstPort) {
             $fourTupleKey = $ipSrcAddr . "-" .
                             $ipDstAddr ;
          } else {
             $fourTupleKey = $ipDstAddr .  "-" .
                             $ipSrcAddr ;
          }

          if ($fourTuple{$fourTupleKey}) {   # file for 4 tuple already open ?
             $dumpFile = $fourTuple{$fourTupleKey};
             if ($dumpFile > 0) {
                Net::Pcap::pcap_dump ($dumpFile, $hdr, $pkt);
             }
          } else {   # else file for 4 tuple already open ?
            if ($okToOpen) { # we haven't had an open error yet
               $dumpFileName = $ARGV[1] . "-" . $fourTupleKey . ".pcap";
               $dumpFile = Net::Pcap::pcap_dump_open ($pcap, $dumpFileName);
               if ($dumpFile) { # did we opened a new dump file
                  $fourTuple{$fourTupleKey} = $dumpFile;
                  Net::Pcap::pcap_dump ($fourTuple{$fourTupleKey}, $hdr, $pkt);
                  $fourTupleSavedCount++;
               } else {   # else did we opened a new dump file
                 print "Could not open outfile file for 4 tuple " . $fourTupleKey .
                       ". $!\n";
                 print "Countinuing to process.\n";
                 $okToOpen = 0;
                 $fourTupleNotSavedCount = 1;
                 $fourTuple{$fourTupleKey} = -1;
               }   # end else did we opened a new dump file
            } else {   # else we haven't had an open error yet
                   $fourTupleNotSavedCount++;
                   $fourTuple{$fourTupleKey} = -1;
            }   # end else we haven't had an open error yet
          }   # end else file for 4 tuple already open ?
       }   # end Frame type is TCP
    }   # end Frame type is IP

    $bytes += (length ($hdr) + length ($pkt));
    if ($okToOpen) {
       printf("%s %2.0f%% (%d/%d) 4-tuple Saved/No Saved count is %d/%d\n",
          "                  ", (100*$bytes/$size), $bytes, $size,
          $fourTupleSavedCount, $fourTupleNotSavedCount);
    } else {
       printf("%s %2.0f%% (%d/%d) 4-tuple Saved/No Saved count is %d/%d\n",
          "File limit reached", (100*$bytes/$size), $bytes, $size,
          $fourTupleSavedCount, $fourTupleNotSavedCount);
    }
}
