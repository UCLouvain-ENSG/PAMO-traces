define ($snap 2000);
define ($shiftip 65536);
define ($shiftport 1000);
define ($print false);
define ($v4prefix 0267);
define ($prefix6 efc1e627dff9);

classifier :: Classifier(12/0800, 12/86DD, -);

//Counter for good packets
legit   :: AverageCounterMP(IGNORE 0);
//Counter for dropping unknown packets
dropped :: AverageCounterMP(IGNORE 0);
//Counter for dropping because there is no known prefix
droppedpref :: AverageCounterMP(IGNORE 0);

fdIN :: FromDump($trace, STOP true, TIMING false, BURST 1);
tdIN :: ToDump($traceOUT, SNAPLEN $snap, FORCE_TS true);

fdIN
//    -> Counter(COUNT_CALL 2 stop)
    -> MarkMACHeader
//    -> SetTimestampDelta
	-> classifier;

classifier[0]
    -> Print(IN,-1, ACTIVE $print)
	-> Strip(14)
	-> fcip :: CheckIPHeader(CHECKSUM false)
    -> IPPrint(IN, ACTIVE $print)
    -> ipc::Classifier(12/$v4prefix,16/$v4prefix,-);
	

    out ::

     Unstrip(14)
    -> IPClassifier(tcp,udp,-) => [0-2]{ 
        [2] -> [0];
        [1] -> su :: SetUDPChecksum -> [0]; 
        [0] -> SetTCPChecksum -> [0]; 
su[1] -> IPPrint("BADUDP") -> [0];
        }
    -> cip :: CheckIPHeader(OFFSET 14)
    -> IPPrint(OUT,ACTIVE $print)
    -> Print(OUT,ACTIVE $print)
	-> legit
	-> tdIN;

elementclass PortShift {
    input -> pc :: IPClassifier(src port < 1024,dst port < 1024,-);
    pc[0] -> Shifter(0,0,0,$shiftport) -> output;
    pc[1] -> Shifter(0,$shiftport,0,0) -> output;
    pc[2] -> output;
}

ipc[0]  -> Shifter($shiftip, 0, 0, 0) -> PortShift() -> out;
ipc[1]  -> Shifter(0,0, $shiftip, 0) -> PortShift() -> out;
ipc[2]  -> IPPrint("INVALID IP", ACTIVE false) -> droppedpref;


fcip[1] -> Print("BADBIP") -> dropped;
cip[1] -> Print("BADAIP") -> dropped;

// !! IPv6

classifier[1]
    -> Print(IN,-1, ACTIVE $print)
	-> Strip(14)
	-> fcip6 :: CheckIP6Header()
    -> IP6Print(IN, ACTIVE $print)
    -> ip6c::Classifier(8/$prefix6,24/$prefix6,-);
	
    out6 ::
 Unstrip(14)
->        SetTransportChecksumIP6
    -> cip6 :: CheckIP6Header(OFFSET 14)
    -> IP6Print(OUT,ACTIVE $print)
    -> Print(OUT,ACTIVE $print)
	-> legit;

ip6c[0] -> StoreData(OFFSET 8, DATA \<$prefix6>) -> out6;
ip6c[1] -> StoreData(OFFSET 24, DATA \<$prefix6>) -> out6;
ip6c[2]  -> IPPrint("INVALID IP", ACTIVE false) -> dropped;


fcip6[1] -> Print("BADBIP6") -> dropped;
cip6[1] -> Print("BADIP6") -> dropped;


classifier[2] -> dropped;
dropped -> Discard;
droppedpref -> Discard;

DriverManager(
	pause,
	print "EVENT GEN_STOPPED",
	print "",
	print "       IPv4: "$(legit.count),
	print " Dropped by Classifier (not IP): "$(dropped.count),
	print " Dropped by Classifier (unknon prefix): "$(droppedpref.count),
	print " Dropped by CheckIPHeader: "$(fcip.drops),
    print " Dropped by CheckIP6Header: "$(cip6.drops),
	print " Dropped by CheckIPHeader after v4 rewrite: "$(cip.drops),
	print " Dropped: "$(dropped.count),
	print "",
	print "Trace: $(trace)",
	print "Count: $(legit.count) packets",
	print "Rate: $(div $(legit.link_rate) 1000000000) Gbps",
	stop
);

ProgressBar(fdIN.filepos, fdIN.filesize);
