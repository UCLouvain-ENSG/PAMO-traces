# PAMO trace scripts

Scripts to split and accelerate a trace. This was used for PAMO evaluation on real traffic, accelerated from the ~3Gbps to up to ~70.

The naive approach would just accelerate the replay speed by 20 times. This would make flows 20 times shorter, so the number of active flows at any time would be around 20 times smaller.
Also, this could cause unrealistic edge-cases where the SYN and ACK get so close that they follow each other.

The overall technique is to split the traffic in 30 second windows. Then rewrite them using different prefix.
Then, we can replay all the "splits" in parallel as flows that would span two windows would not appear to collide anymore. To play on the overall speed, one can simply replay less or more windows in parallel.
With 20 windows, that would lead to some aliasing. So we split again the windows in a flow-aware fashion in 4 files each. That gives, in the end, a ~1Gbps granularity.


## Dependencies

### Various packages

For all software

    sudo apt install libelf-dev build-essential pkg-config zlib1g-dev libnuma-dev python3-pyelftools ninja-build meson  libelf-dev pkg-config zlib1g-dev libnuma-dev python3-pyelftools vim git zsh htop autoconf python3-pip git libpapi-dev libre2-dev libbpf-dev libmicrohttpd-dev libpci-dev libibverbs-dev libpcap-dev libbpf-dev  libjansson-dev libisal-dev libpcap-dev libarchive-dev libfdt-dev zsh

### DPDK

[DPDK](https://www.dpdk.org) is a high-speed I/O userlevel library,
originally made by Intel but now part of the Linux Foundation. It uses
userlevel-drivers to avoid Kernel context switches, among other
improvement.

``` bash
    meson setup -Ddisable_drivers=regex/octeontx2 build -Dprefix=$(pwd)/install
    cd build
    ninja
    ninja install


    export RTE_SDK=/home/tbe/dpdk-stable-23.11.1
    export DPDK_PATH=$RTE_SDK/install
    export LD_LIBRARY_PATH=$DPDK_PATH/lib/x86_64-linux-gnu/:/usr/lib64/:/usr/lib/:/usr/lib/x86_64-linux-gnu/mstflint/:/usr/lib64/mft/
    export PKG_CONFIG_PATH=$DPDK_PATH/lib/x86_64-linux-gnu/pkgconfig


    echo 16 | sudo tee /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages
    sudo mount -t hugetlbfs -o pagesize=1GB nodev /mnt/huge_1G
```

### FastClick

[FastClick](https://www.github.com/tbarbette/fastclick) is a high-speed
version of the Click modular router made by Barbette et al.

```bash
./configure --enable-multithread --disable-linuxmodule --enable-intel-cpu --enable-user-multithread --verbose CFLAGS="-g -O3" CXXFLAGS="-g -std=gnu++11 -O3" --disable-dynamic-linking --enable-poll --enable-bound-port-transfer --enable-dpdk --enable-batch --with-netmap=no --enable-zerocopy --disable-dpdk-pool --disable-dpdk-packet
make -j16
make
```

### Traceanon

Traceanon is used to anonymize the trace. It is part of libtrace.

During the capture we discovered a bug in traceanon that lead to the
loss of nanosecond precision when anonymizing the trace
(<https://github.com/LibtraceTeam/libtrace/issues/208>) therefore one
needs to compile libtrace from [the GitHub
version](https://github.com/LibtraceTeam/libtrace).

## Capture

It was quickly established that tcpdump was dropping too many packets.

Therefore, we decided to use FastClick, using 2 threads for the TX side,
and 4 threads for the RX side which represents more traffic.

It allows the following features:

-   Hardware timestamping in the NIC
-   Use one capture file per thread and different files for each side so
    there is no inter-core bottleneck
-   Configurable RAM-based packet queuing inside the pipeline (2M
    packets total, 400K per thread)

FastClick configuration (capture.click):

```
        define($desc 16384)

        DPDKInfo(2000000);
        define($cap 400000)

        fd0 :: FromDPDKDevice(0, PROMISC true, NDESC $desc, VERBOSE 99, MAXTHREADS 4, TIMESTAMP true, ACTIVE true)

        fd0

        -> s0 :: Switch()
        -> Discard;

        s0[1]

        ->  TSCClock(SOURCE fd0, CONVERT_STEADY true, INSTALL false, VERBOSE 2, READY_CALL activate.run)
        -> e0 :: ExactCPUSwitch();
        e0[0] -> avg0_0 :: AverageCounter ->  td0_0 :: ToDump($trace-if1-0$traceext, FORCE_TS true, SNAPLEN 0);
        e0[1] -> avg0_1 :: AverageCounter ->  td0_1 :: ToDump($trace-if1-1$traceext, FORCE_TS true, SNAPLEN 0);
        e0[2] -> avg0_2 :: AverageCounter ->  td0_2 :: ToDump($trace-if1-2$traceext, FORCE_TS true, SNAPLEN 0);
        e0[3] -> avg0_3 :: AverageCounter ->  td0_3 :: ToDump($trace-if1-3$traceext, FORCE_TS true, SNAPLEN 0);

        fd1  :: FromDPDKDevice(1, PROMISC true, NDESC $desc, VERBOSE 99, MAXTHREADS 2, TIMESTAMP true, ACTIVE true)
        -> s1 :: Switch()
        -> Discard;

        s1[1]

        -> TSCClock(SOURCE fd1, CONVERT_STEADY true, INSTALL false, VERBOSE 2, READY_CALL activate.run)
        -> e1 :: ExactCPUSwitch();
        e1[0] -> avg1_0 :: AverageCounter ->  td1_0 :: ToDump($trace-if2-0$traceext, FORCE_TS true, SNAPLEN 0);
        e1[1] -> avg1_1 :: AverageCounter ->  td1_1 :: ToDump($trace-if2-1$traceext, FORCE_TS true, SNAPLEN 0);



        stats :: Script(TYPE ACTIVE,
        //      read fd0.xstats,
        //      read fd1.xstats,
                set ddropped $(add $(fd0.xstats rx_phy_discard_packets) $(fd1.xstats rx_phy_discard_packets)),
                set oo $(add $(fd0.xstats rx_out_of_buffer) $(fd1.xstats rx_out_of_buffers)),
                set tdcount $(add $(td0_0.count) $(td0_1.count) $(td0_2.count) $(td0_3.count)  $(td1_0.count) $(td1_1.count)  ),
                set rxrate $(add $(avg0_0.link_rate)  $(avg0_1.link_rate) $(avg0_2.link_rate) $(avg0_3.link_rate) ),
                set txrate $(add $(avg1_0.link_rate)  $(avg1_1.link_rate) ),
                set pcount $(add $(fd0.count) $(fd1.count)),
                print "Dropped $ddropped Oo : $oo",
                print "count $pcount, tdcount $tdcount, rate rx $rxrate tx $txrate",
                wait 1s,
                loop);

        // The goal of this script is to wait for the hardware clock to synchronize before starting to record packets
        activate :: Script(TYPE PASSIVE,

                print "One clock is activated!",
                init nwait 0,
                set nwait $(add $nwait 1),
                print "Nwait $nwait",
                goto q $(lt $nwait 2),
                print "Ready!",
                wait 1s,
                print "Running...",
                write s0.switch 1,
                write s1.switch 1,
                label q,
        );

        DriverManager(
            print "Activating...",

            wait,
            read fd0.xstats,
            read fd1.xstats
        );
```

During capture, the counters showed no dropped packets. The main
bottleneck appeared to be the NVMe drive, as \~9Gbps is a lot. The RAM
was enough to absorb the peaks though.

## Anonymisation + Copy over SSH

`$k` is a randomly generated key.

```bash
cat trace-in.pcap | traceanon -c \"$k\" -s pcapfile:- pcapfile:- | gzip -c | ssh DEST -C "cat - > capture.anon.pcap.gz"
```

Use traceanon `-d` on the other side.

## Trace acceleration

Note that this pipeline is IPv4-only.

### Splitting the trace in 30 seconds window

To combine multiple traces together in parallel (we consider all of their first packets to start at time 0), rewriting flows along the way to prevent collisions.

First, use tracesplit to split the huge trace in 30 seconds windows as follow:
```bash
tracesplit -i 30 pcapfile:bigtrace.pcap pcapfile:splits/smalltraces.pcap
```

### Rewriting windows

Then rewrite each trace to have flow in a unique prefix. The rewriting is adding 65536 to the "internal" IP address of the trace. As we now our trace uses a /16 suffix on the "internal" side of the campus, it is sufficient.

FastClick is used again, the configuration is in `pcap-rewrite-bidirect.click`. Be sure to change the v4prefix to the /16 prefix of the "internal" side of your campus. If it has a different mask then you have to change the script. If you use something where an internal side has no sense (like an IXP, such as the caida trace), then you should not run an IDS on that because nobody should inspect the content of packets that are not theirs.

```bash
for i in $(seq 0 15) ; do list=(window-30-ipv4_000$(printf "%02d" $i)*.pcap) && sudo LD_LIBRARY_PATH=$LD_LIBRARY_PATH ~/workspace/fastclick/bin/click -- pcap-rewrite-bidirect.click trace=$list[1] traceOUT=window-30-ipv4-rewrite.pcap-$i shiftip=$((65536 * $i)) shiftport=$((1000 * $i)) print=false ; done
```

You now have 30 seconds window with a different prefix for each one.
We also shift ports to avoid creating an artificial skew in the hashing done by RSS.


## Splitting the trace again

The merged trace will then be re-split in a flow-aware fashion each windows in 4 "parallel" windows.
We need it to be flow-aware because using independent threads
might lead to some inter-thread reordering. PAMO's statistic would
then see too much reordering which would be entierly artificial.

FastClick is used again.

```
    //Split a trace in 4 sub-traces using RR
    define($trace /tmp/in.pcap)
    define($snap 2000)
    define($limit 40000000)

    FromDump($trace, STOP 1) ->
             //Classifier(12/0800,12/86DD) [0-1] => [0] //Comment to keep only ipv4 or ipv6

    //       Classifier(12/86DD) [0] => [0] //v6 only
            Counter(COUNT_CALL $limit stop)
            -> Pad
        -> rr::
    {
            hs4 :: HashSwitch(26,8) [0-3]=>[0-3]output;

            hs6 :: HashSwitch(22,16) [0-3]=>[0-3]output;

            rr :: RoundRobinSwitch  [0-3]=>[0-3]output;
            [0] -> c :: Classifier(12/0800, 12/86DD, -);
            c[0] -> hs4;
            c[1] -> hs6;
            c[2] -> rr;
    }
    rr[0] -> ToDump($(outtrace)-1, FORCE_TS true, SNAPLEN $snap) ;
    rr[1] -> ToDump($(outtrace)-2, FORCE_TS true, SNAPLEN $snap) ;
    rr[2] -> ToDump($(outtrace)-3, FORCE_TS true, SNAPLEN $snap) ;
    rr[3] -> ToDump($(outtrace)-4, FORCE_TS true, SNAPLEN $snap) ;
````

## Trace replay

The fastclick-play-single-mt module of NPF is used to replay the trace.
With the timing tag it replays at the original speed, accelerated by a `TIMING_FNT` in percent. Without the timing
tag it replays as fast as possible, reaching 100G. This is not a valid
acceleration, as explained above.

The GEN_MULTI_TRACE variable is used to run the multiple traces.
Assuming all your small windows are named `/path/to/trace.pcap-1`, `/path/to/trace.pcap-2` ...:
```
python3 npf.py local --test replay.npf --cluster client=elrond --tags promisc  scale_multi_trace --variables GEN_MULTI_TRACE=20 GEN_BLOCKING=true trace=/path/to/trace.pcap PKTGEN_REPLAY_COUNT=1 GEN_RX_THREADS=4 GEN_THREADS=4 GEN_CSUM=0 --tags trace_is_ip --show-cmd --show-files --preserve-temporaries
```

## Example for trace duplication
Altough a slightly different use-case, we can use the prefix-rewriting script to duplicate a trace in a way that will prevent collisions.

In this example we use `2015-07-28_mixed.before.infection.pcap` from [Stratosphere](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Mixed-Capture-1/).

```bash
for i in $(seq 64)
do
    LD_LIBRARY_PATH=$LD_LIBRARY_PATH ~/workspace/fastclick/bin/click -- ../PAMO-traces/pcap-rewrite-bidirect.click trace=/mnt/traces4/2015-07-28_mixed.before.infection.pcap traceOUT=/mnt/traces2/strato.pcap-$i shiftip=$((65536 * $i)) shiftport=$((1000 * $i)) v4prefix=0a00
done
```