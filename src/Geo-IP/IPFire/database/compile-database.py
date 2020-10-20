#!/usr/bin/python3

#
# Scraped from an old version of 'compile-database' from
#  https://git.ipfire.org/?p=location/location-database.git;a=blob;f=compile-database;h=01c12e80ae09e3b8893ff86b7977234ac16d6b2c;hb=b969fadda8f3bd8a1e57c0dbf42433bc8ed0923b
#
# and heavily edited.
#
# The original copyright header:

###############################################################################
#                                                                             #
# location-database - A database to determine someone's                       #
#                     location on the Internet                                #
# Copyright (C) 2018 Michael Tremer                                           #
#                                                                             #
# This program is free software: you can redistribute it and/or modify        #
# it under the terms of the GNU General Public License as published by        #
# the Free Software Foundation, either version 3 of the License, or           #
# (at your option) any later version.                                         #
#                                                                             #
# This program is distributed in the hope that it will be useful,             #
# but WITHOUT ANY WARRANTY; without even the implied warranty of              #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the               #
# GNU General Public License for more details.                                #
#                                                                             #
# You should have received a copy of the GNU General Public License           #
# along with this program.  If not, see <http://www.gnu.org/licenses/>.       #
#                                                                             #
###############################################################################

import os, sys, re, time, argparse

#
# Just for now do this hack
#
sys.path.append ("../libloc/src/py3_install")

import location

RE_AS = re.compile ("^AS(\d+)$")

opt = None

def trace (level, str):
  if opt.verbose >= level:
    print (str)
    sys.stdout.flush()

def iterate_over_blocks (f, charsets=("utf-8", "latin1")):
  block = []
  for line in f:
    for charset in charsets:
      try:
        line = line.decode (charset)
      except UnicodeDecodeError:
        continue
      else:
        break

    line = line.rstrip()
    if line.startswith("#") or line.startswith("%"):
      continue

    line, _, comment = line.partition ("#")
    if comment:
      line = line.rstrip()
      if not line:
        continue

    if line:
      block.append (line)
      continue

    if block:
      yield block   # The block ends on an empty line
    block = []

def split_line (line):
  key, colon, val = line.partition (":")
  key = key.strip()
  val = val.strip()
  return key, val

class Database (object):
  def __init__ (self, vendor=None, description=None, license=None):
    self.writer = location.Writer()
    if vendor:
      self.writer.vendor = vendor
    if description:
      self.writer.description = description
    if license:
      self.writer.license = license

    self.num_db_records = self.num_countries = self.num_overrides = 0

  def write (self, path):
    self.writer.write (path)

  def _parse_asnum_block (self, block):
    asn  = None
    name = None

    for line in block:
      key, val = split_line (line)
      if key == "aut-num":
        m = RE_AS.match (val)
        if m:
          asn = int(m.group(1))
      elif key == "name":
        name = val

    if asn and name:
      a = self.writer.add_as (asn)
      a.name = name
      trace (1, "Added: %s" % a)
      self.num_db_records += 1

  def _parse_network_block (self, block):
    network = None
    asn     = None
    country = None
    is_sat_provider = is_anon_proxy = is_anycast = 0

    for line in block:
      key, val = split_line (line)
      if key == "net":
        network = val

      elif key == "country":
        country = val

      elif key == "aut-num":
        m = RE_AS.match (val)
        if m:
          asn = int (m.group(1))

      elif key == "is-anonymous-proxy":
        is_anon_proxy = 1

      elif key == "is-satellite-provider":
        is_sat_provider = 1

      elif key == "is-anycast":
        is_anycast = 1

      else:
        trace (1, "val: %s" % val)

    if network and country:
      try:
        n = self.writer.add_network (network)
      except IndexError:
        trace (1, "Skipping network %s, because one already exists at this address" % network)
        return

      # Save attributes
      n.country_code = country
      if asn:
        n.asn = asn

      if is_anycast:
        n.set_flag (location.NETWORK_FLAG_ANYCAST)

      if is_sat_provider:
        n.set_flag (location.NETWORK_FLAG_SATELLITE_PROVIDER)

      if is_anon_proxy:
        n.set_flag (location.NETWORK_FLAG_ANONYMOUS_PROXY)

      trace (1, "Added network: %s" % n)
      self.num_db_records += 1

  def import_countries (self, filename="./countries.txt"):
    with open(filename) as f:
      for line in f:
        line = line.rstrip()
        if line.startswith("#"):
          continue

        try:
          country_code, continent_code, country_name = line.split (maxsplit=2)
        except:
          trace (0, "Could not parse line in %s: %s" % (filename, line))
          raise

        trace (2, "country_code: %s, continent_code: %s, country_name: %s" % \
               (country_code, continent_code, country_name))
        c = self.writer.add_country (country_code)
        c.continent_code = continent_code
        c.name = country_name
        self.num_countries += 1

  def import_database_txt (self, filename="./database.txt", max=sys.maxsize):
    fsize = int (os.stat (filename).st_size)
    MByte = fsize / (1024*1024)
    print ("fsize: %d MByte: " % MByte, end="")
    sys.stdout.flush()

    with open ("./database.txt", "rb") as f:
      for block in iterate_over_blocks (f):
        if block[0].startswith('aut-num:'):
          db._parse_asnum_block (block)
          continue
        else:
          db._parse_network_block (block)

        if not opt.verbose and db.num_db_records % 100 == 0:
          percent = (100 * f.tell()) / fsize
          print ("%3.0f%%\b\b\b\b" % percent, end="")
          sys.stdout.flush()

        if db.num_db_records >= max:
          break

  def import_overrides (self, filenames="./overrides/override*.txt"):
    trace (0, "import_overrides() not finished")

def show_help():
  print ("""  usage: %s [options] <database-file.db>
  options:
  -h   show this help message and exit.
  -d   dump an earlier created database-file.
  -n   dry-run; do nothing.
  -v   increase verbosity level.

  Unless option '-d' was used, I will create a new 'database-file.db' from these files:
    countries.txt
    database.txt
    overrides/override-a1.txt
    overrides/override-a2.txt
    overrides/override-a3.txt
    overrides/override-other.txt""" % os.path.basename(__file__))
  sys.exit()

#
# Parse the cmd-line
#
def parse_cmdline():
  parser = argparse.ArgumentParser (add_help = False)
  parser.add_argument ("-h", dest="help",    action="store_true")
  parser.add_argument ("-d", dest="dump",    action="store_true")
  parser.add_argument ("-n", dest="dry_run", action="store_true")
  parser.add_argument ("-v", dest="verbose", action="count", default=0)
  parser.add_argument ("database_file", nargs = '?', default = None)
  return parser.parse_args()

def dump_db (db_file):
  if not os.path.exists (db_file):
    trace (0, "file '%s' does not exist." % db_file)
    return

  flags = { location.NETWORK_FLAG_ANONYMOUS_PROXY    : "is-anonymous-proxy",
            location.NETWORK_FLAG_SATELLITE_PROVIDER : "is-satellite-provider",
            location.NETWORK_FLAG_ANYCAST            : "is-anycast",
          }

  try:
    d = location.Database (db_file)
  except:
    trace (0, "file '%s' is not a legal database." % db_file)
    return

  # print (dir(d))
  print ("created:     %s" % time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(d.created_at)))
  print ("description: %s" % d.description)
  print ("license:     %s" % d.license)
  print ("vendor:      %s" % d.vendor)

  i = 0
  print ("Countries:")
  for c in d.countries:
    print ("  short: %s, continent: %s, long: %s" % (c.code, c.continent_code, c.name))
    i += 1
  print ("  %d" % i)

  i = 0
  print ("\nNetworks:")
  for n in d.networks:
    if i == 0: print (dir(n))
    i += 1
    print ("  network: %s, family: %d, flags: " % (n, n.family), end="")
    for flag in flags:
      if n.has_flag(flag):
        print ("%s " % flags[flag], end="")
    print()
    if n.country_code:
      print ("  country: %s" % n.country_code)
  print ("  %d" % i)

  i = 0
  print ("\nAutonomous Systems:")
  for a in d.ases:
    i += 1
    print ("  ASN: %s, " % a.number, end="")
    try:
      print ("name:    '%s'" % a.name)
    except (UnicodeDecodeError, UnicodeEncodeError):
      print ("name:     %s" % "<err>")
  print ("  %d" % i)
  sys.exit (0)

opt = parse_cmdline()

if opt.help or not opt.database_file:
  show_help()

if opt.dump:
  dump_db (opt.database_file)

db = Database (vendor = "IPFire", description = "IPFire test Database")

db.import_countries()
db.import_database_txt()
db.import_overrides()

db.write (opt.database_file)

trace (1, "Wrote %4d entries to '%s' for './countries.txt'"   % (db.num_countries, opt.database_file))
trace (1, "Wrote %4d entries to '%s' for './database.txt'"    % (db.num_db_records, opt.database_file))
trace (1, "Wrote %4d entries to '%s' for './overrides/*.txt'" % (db.num_overrides, opt.database_file))
