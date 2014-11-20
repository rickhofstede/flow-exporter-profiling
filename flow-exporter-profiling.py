#!/usr/bin/python

# Script for determining the brand, type and model of a flow exporter, merely based
# on data collected by nfcapd (i.e., the flow collector).
#
# Author:   Rick Hofstede <rick.hofstede@redsocks.nl>
#           RedSocks B.V.
#

from datetime import datetime
from dateutil import parser
import operator         # For funtions related to itemgetter, for example
import os               # For functions related to file and directory handling
import socket, struct   # For function related to IP address to/from number conversions
import sys              # For parsing command-line arguments and exiting, among others

# Configuration (adapt to your setup before execution)
NFDUMP_PATH         = "/usr/local/bin/nfdump"
NFCAPD_DATA_PATH    = "/data/nfsen/profiles-data/live/<source>"
FILE_NAME           = "nfcapd.201409200350"

def parse_flow_record_pipe (line):
    splitted_line   = line.split('|')

    # Ignore IPv6 traffic
    if (int(splitted_line[0].strip()) != 2):
        return None

    flow_record = {
        'start'     : int(splitted_line[1].strip()),
        'end'       : int(splitted_line[3].strip()),
        'src_ipv4'  : int(splitted_line[9].strip()),
        'src_port'  : int(splitted_line[10].strip()),
        'dst_ipv4'  : int(splitted_line[14].strip()),
        'dst_port'  : int(splitted_line[15].strip()),
        'protocol'  : int(splitted_line[5].strip()),
        'flags'     : int(splitted_line[20].strip()),
        'tos'       : int(splitted_line[21].strip()),
        'packets'   : int(splitted_line[22].strip()),
        'bytes'     : int(splitted_line[23].strip())
    }

    return flow_record

def parse_flow_record_custom_aggr (line):
    splitted_line   = line.split(',')

    # Ignore IPv6 traffic
    if ((splitted_line[2].strip()).count(":") >= 1):
        return None

    # Ignore ICMP traffic (due to misuse of dstport field)
    if splitted_line[5].strip().count(".") == 1:
        return None

    flow_record = {
        # 'start'     : parser.parse(splitted_line[0].strip()).strftime('%s'),
        # 'end'       : parser.parse(splitted_line[1].strip()).strftime('%s'),
        'src_ipv4'  : ip2long(splitted_line[2].strip()),
        'src_port'  : int(splitted_line[3].strip()),
        'dst_ipv4'  : ip2long(splitted_line[4].strip()),
        'dst_port'  : int(splitted_line[5].strip()),
        'protocol'  : int(splitted_line[6].strip()),
        'packets'   : int(splitted_line[7].strip()),
        'bytes'     : int(splitted_line[8].strip()),
        'flows'     : int(splitted_line[9].strip()),
        'tos'       : int(splitted_line[10].strip())
    }

    return flow_record

def ip2long (ip_addr):
    return int(struct.unpack("!I", socket.inet_aton(ip_addr.strip()))[0])

def long2ip (ip_number):
    return str(socket.inet_ntoa(struct.pack('!L', ip_number)))

def flags2string (flags_number):
    # bin_flags = int(bin(flags_number))
    str_flags = list("......")
    if bool(flags_number & 0b100000): str_flags[0] = "U" 
    if bool(flags_number & 0b010000): str_flags[1] = "A"
    if bool(flags_number & 0b001000): str_flags[2] = "P"
    if bool(flags_number & 0b000100): str_flags[3] = "R"
    if bool(flags_number & 0b000010): str_flags[4] = "S"
    if bool(flags_number & 0b000001): str_flags[5] = "F"

    return "".join(str_flags)

def add_comment (comment):
    if comment in COMMENTS:
        return
    else:
        COMMENTS.append(comment)

# CONSTANTS - flow data
IDLE_TIMEOUT_TUPLES         = 250   # Number of tuples to be considered for estimating idle timeout
MIN_IDLE_TIMEOUT            = 10    # Minimum allowed value for the idle timeout

# SESSION VARIABLES (don't change)
ACTIVE_TIMEOUT              = None
IDLE_TIMEOUT                = None
DURATION_HISTOGRAM          = {}
COMMENTS                    = []
INTER_FLOW_GAP_HISTOGRAM    = {}

nfdump_base_cmd = NFDUMP_PATH + " -M " + NFCAPD_DATA_PATH + " -r " + FILE_NAME + " -6mNq"

if not os.path.isfile(NFDUMP_PATH):
    print "\nERROR: Could not find nfdump binary (" + NFDUMP_PATH + ")"
    sys.exit(1)

if not os.path.isdir(NFCAPD_DATA_PATH):
    print "\nERROR: Could not find data directory (" + NFCAPD_DATA_PATH + ")"
    sys.exit(1)

#########################
#
# Active timeout
#
#########################

print "Determining active timeout..."
print "  -> Loading flow data... (%i MB)" % (os.path.getsize(NFCAPD_DATA_PATH + "/" + FILE_NAME) / 1000000)
nfdump_fi, nfdump_fo, nfdump_fe = os.popen3(nfdump_base_cmd + " -o pipe" + " 2> /dev/null")
flow_data = nfdump_fo.readlines()
total_flow_records = len(flow_data)

if total_flow_records == 0:
    print "\nERROR: empty flow data file (" + FILE_NAME + ")"
    sys.exit(1)

print "  -> Parsing flow data... (%i records)" % len(flow_data)
for line in flow_data:
    flow_record = parse_flow_record_pipe(line)

    if flow_record is None:
        continue

    # Establish flow duration histogram
    flow_duration = int(flow_record['end'] - flow_record['start'])
    if flow_duration in DURATION_HISTOGRAM.keys():
        DURATION_HISTOGRAM[flow_duration] += 1
    else:
        DURATION_HISTOGRAM[flow_duration] = 1

print "  -> Evaluating results..."
last_duration_histogram_value = None
duration_peaks = {} # Histogram, <duration, no. of flow records with duration>
for key in sorted(DURATION_HISTOGRAM.keys()):
    value = DURATION_HISTOGRAM[key]

    # Skip very short flows
    if key < 10:
        continue

    # Look for sudden peaks in duration
    if last_duration_histogram_value is not None \
            and DURATION_HISTOGRAM[key] > 2 * last_duration_histogram_value:
        duration_peaks[key] = value

    last_duration_histogram_value = value

# We have to guess whether we are dealing with a hardware or software flow exporter.
# In case of a software flow exporter, we should see no flow longer than the configured
# active timeout and we assume the active timeout to be a multiple of 2 or 5. In addition,
# there should be more flow records featuring the highest flow duration (which should be
# the same as the active timeout) than flow records feature the one-bug-highest flow duration.
highest_flow_duration = max(DURATION_HISTOGRAM.keys())
if (highest_flow_duration % 2 == 0 or highest_flow_duration % 5 == 0) \
        and DURATION_HISTOGRAM[sorted(DURATION_HISTOGRAM.keys())[-1]] > DURATION_HISTOGRAM[sorted(DURATION_HISTOGRAM.keys())[-2]]:
    print "  -> Likely using a software-based flow exporter"
    ACTIVE_TIMEOUT = highest_flow_duration
else:
    print "  -> Likely using a hardware-based flow exporter"
    ACTIVE_TIMEOUT = max(duration_peaks.iteritems(), key=operator.itemgetter(1))[0]

print "  -> Active timeout: " + str(ACTIVE_TIMEOUT) + " sec."

if highest_flow_duration > 4000000:
    print "  -> Likely using a Cisco SUP2T supervisor module (flow duration > 4000000 sec.)"

#########################
#
# Idle timeout
#
#########################

print "Determining idle timeout..."
print "  -> Loading flow data... (%i MB)" % (os.path.getsize(NFCAPD_DATA_PATH + "/" + FILE_NAME) / 1000000)

# We consider only UDP traffic or TCP traffic without TCP RST or FIN flag to avoid problems with 'natural expiration'
nfdump_fi, nfdump_fo, nfdump_fe = os.popen3(nfdump_base_cmd \
        + " -o \"fmt: %ts,%te,%sa,%sp,%da,%dp,%pr,%pkt,%byt,%fl,%tos\"" \
        + " -A srcip,srcport,dstip,dstport,proto,tos" \
        + " \" (proto udp and not net 224.0.0.0/4 and not ip 255.255.255.255) or (proto tcp and not flags RF)\""
        + " 2> /dev/null")
flow_data = nfdump_fo.readlines()

print "  -> Parsing flow data... (%i records)" % len(flow_data)
flow_records_aggregated = []
for line in flow_data:
    flow_record = parse_flow_record_custom_aggr(line)

    if flow_record is None:
        continue

    if flow_record['flows'] >= 5:
        flow_records_aggregated.append(flow_record)

print "  -> Evaluating results..."

# Sort the flow_records_aggregated list based on 'flows' field of flow records (descending)
flow_records_aggregated = sorted(flow_records_aggregated, key=operator.itemgetter('flows'))
flow_records_aggregated.reverse()

# Take only top IDLE_TIMEOUT_TUPLES aggregated flow records (i.e., tuples)
flow_records_aggregated = flow_records_aggregated[0:IDLE_TIMEOUT_TUPLES]

for i in range(len(flow_records_aggregated)):
    percentage = (float(i) / float(len(flow_records_aggregated))) * 100
    sys.stdout.write("\r    -> Progress: %.1f%%" % percentage)

    flow_record_aggr = flow_records_aggregated[i]
    # print "    -> Loading flow data... (%i MB)" % (os.path.getsize(NFCAPD_DATA_PATH + "/" + FILE_NAME) / 1000000)
    nfdump_filter = "src ip " + long2ip(flow_record_aggr['src_ipv4']) \
            + " and dst ip " + long2ip(flow_record_aggr['dst_ipv4']) \
            + " and src port " + str(flow_record_aggr['src_port']) \
            + " and dst port " + str(flow_record_aggr['dst_port']) \
            + " and tos " + str(flow_record_aggr['tos'])
    nfdump_fi, nfdump_fo, nfdump_fe = os.popen3(nfdump_base_cmd + " -o pipe" + " \"" + nfdump_filter + "\"" + " 2> /dev/null")
    flow_data = nfdump_fo.readlines()

    # print "    -> Parsing flow data... (%i records)" % len(flow_data)
    for j in range(len(flow_data)):
        flow_record = parse_flow_record_pipe(flow_data[j])
        previous_flow_record = parse_flow_record_pipe(flow_data[j - 1])

        if flow_record is None:
            continue

        if j > 0: # if i == 0 there is no previous record to compare with
            delta_time = flow_record['start'] - previous_flow_record['end']
            # print "Delta time: " + str(delta_time) + "; start: "+ str(flow_record['start']) + ", end: " + str(flow_record['end']) + ", " + str(long2ip(flow_record['src_ipv4'])) + ":" + str(flow_record['src_port']) + ", " + str(long2ip(flow_record['dst_ipv4'])) + ":" + str(flow_record['dst_port']) + ", flags: " + flags2string(flow_record['flags'])

            if delta_time < 0:
                add_comment("Overloaded flow cache detected (overlapping flow records)...")
            elif delta_time >= MIN_IDLE_TIMEOUT:
                if delta_time in INTER_FLOW_GAP_HISTOGRAM:
                    INTER_FLOW_GAP_HISTOGRAM[delta_time] += 1
                else:
                    INTER_FLOW_GAP_HISTOGRAM[delta_time] = 1

# for key in INTER_FLOW_GAP_HISTOGRAM:
    # print str(key) + ": " + str(INTER_FLOW_GAP_HISTOGRAM[key])

# Determine idle timeout by reversing the inter-flow gap sizes and taking the
# first encountered peak as the idle timeout; the value after the peak should
# be at least 25% smaller than the peak.
if len(INTER_FLOW_GAP_HISTOGRAM) > 0:
    total_flow_records = sum(INTER_FLOW_GAP_HISTOGRAM.values())
    previous_gap = None
    previous_gap_freq = None
    for gap in sorted(INTER_FLOW_GAP_HISTOGRAM.keys(), reverse=True):
        gap_freq = INTER_FLOW_GAP_HISTOGRAM[gap]
        if previous_gap_freq is not None and gap_freq < 0.75 * previous_gap_freq and (float(gap_freq) / float(total_flow_records)) > 0.01:
            IDLE_TIMEOUT = previous_gap
            break

        previous_gap = gap
        previous_gap_freq = gap_freq

sys.stdout.write("\r")

if IDLE_TIMEOUT is not None:
    print "  -> Idle timeout: " + str(IDLE_TIMEOUT) + " sec."

#########################
#
# TCP flags
#
#########################

print "Checking for hardware-switched TCP flows without flags..."
print "  -> Loading flow data... (%i MB)" % (os.path.getsize(NFCAPD_DATA_PATH + "/" + FILE_NAME) / 1000000)
nfdump_filter = "proto tcp"
nfdump_fi, nfdump_fo, nfdump_fe = os.popen3(nfdump_base_cmd + " -o pipe" + " \"" + nfdump_filter + "\"" + " 2> /dev/null")
flow_data = nfdump_fo.readlines()

print "  -> Parsing flow data... (%i records)" % len(flow_data)
tcp_flow_records_with_flags = 0
tcp_flow_records_without_flags = 0
for line in flow_data:
    flow_record = parse_flow_record_pipe(line)

    if flow_record is None:
        continue

    if flow_record['flags'] == 0:
        tcp_flow_records_without_flags += 1
    else:
        tcp_flow_records_with_flags += 1

print "  -> Evaluating results..."
if tcp_flow_records_without_flags > tcp_flow_records_with_flags:
    print "  -> Likely using a Cisco SUP720 supervisor module (no TCP flags exported for hardware-switched flows)"
else:
    print "  -> No abnormal behavior detected"

if len(COMMENTS) > 0:
    print "\nComments about flow data:"

    for comment in COMMENTS:
        print " * " + comment

print "\nDone."

