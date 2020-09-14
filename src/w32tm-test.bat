@echo off
on break quit

w32tm -stripchart -computer:tick.usno.navy.mil -rdtsc -samples:10 -dataonly -ipprotocol:4 -packetinfo

quit

w32tm /stripchart /computer:<target> [/period:<refresh>]
    [/dataonly] [/samples:<count>] [/packetinfo] [/ipprotocol:<4|6>] [/rdtsc]
  Display a strip chart of the offset between this computer and
  another computer.
  computer:<target> - the computer to measure the offset against.
  period:<refresh> - the time between samples, in seconds. The
    default is 2s
  dataonly - display only the data, no graphics.
  samples:<count> - collect <count> samples, then stop. If not
    specified, samples will be collected until Ctrl-C is pressed.
  packetinfo - print out NTP packet response message.
  ipprotocol - specify the IP protocol to use. The default is
    to use whatever is available.
  rdtsc - display the TSC values and time offset data in CSV format.
    The output displays TSC and FILETIME values captured before the
    NTP request is sent, TSC value after an NTP response is received
    along with NTP roundtrip and time offset values.
