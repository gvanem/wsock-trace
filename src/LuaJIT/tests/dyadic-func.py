#
# Adapted from:
#  https://www.exploringbinary.com/print-precision-of-dyadic-fractions-varies-by-language/
#
def check_num (num, format, expected):
  x = format % num
  if x == expected:
     print ("Okay")
  else:
     print ("expected: '%s' but got:\n'%s'" % (expected, x))

check_num (2**-1074, "%.99e",
           "4.940656458412465441765687928682213723650598026143247644255856825006755072702087518652998363616359924e-324")

