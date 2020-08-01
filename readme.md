# Converting the Have I Been Pwned password hash databases into bloomfilters

The HIBP pwned password list file can be found here: https://haveibeenpwned.com/Passwords

Because an 24GB uncompressed text file isn't convenient to work with, and keeping all this into a sql database can also be inconvenient, this code converts each entries from the password list into partitioned bloom filters that can later be queried to determine if the sha1 hash has been observed as leaked or not, as well as an indication of how bad the sha1 hash is.

Partitions:
* worst passwords. between 10000 and 99999999 occurences in the wild
* suck: between 1000 and 10000
* bad: between 100 and 1000
* common: between 10 and 100
* rare: between 3 and 10
* low: between 1 and 3
* blacklist: custom list defined in `blacklist.txt`

The common, rare and low filters are quite big compared to the first ones because of the high number of hashes in these categories. Using smaller filters would increase the risks of collisions, therefore of false positives.

# Python Libraries Requirement
```
# pip3 install bitarray
# pip3 install PyYAML
```

# Usage
First, download the HIBP list from the the site above, then uncompress it.
The `ordered-by-count` version is preferred.


##  Dry Run

Start the conversion of the txt file into the filters
```
$ python3 make_filters.py pwned-passwords-sha1-ordered-by-count-v6.sample.txt
```

The output should look like this
```
Starting in testing mode. this can be disabled by setting `testing_mode` to False
Creating a new knowledge file hibp_20200801_21bits_worst.bloomfilter size 21
Initializing memory (0.25MB)
size of filter 0: 2097152
Creating a new knowledge file hibp_20200801_25bits_suck.bloomfilter size 25
Initializing memory (4.0MB)
size of filter 1: 33554432
Creating a new knowledge file hibp_20200801_28bits_bad.bloomfilter size 28
Initializing memory (32.0MB)
size of filter 2: 268435456
Creating a new knowledge file hibp_20200801_31bits_common.bloomfilter size 31
Initializing memory (256.0MB)
size of filter 3: 2147483648
Creating a new knowledge file hibp_20200801_32bits_rare.bloomfilter size 32
Initializing memory (512.0MB)
size of filter 4: 4294967296
Creating a new knowledge file hibp_20200801_32bits_low.bloomfilter size 32
Initializing memory (512.0MB)
size of filter 5: 4294967296
Creating a new knowledge file hibp_20200801_20bits_blacklist.bloomfilter size 20
Initializing memory (0.125MB)
size of filter 6: 1048576
partition: 0, Upper bound: 99999999, current hash frequency: 23597311, lower bound: 10000
total count per partition: [10, 0, 0, 0, 0, 0, 0]
blacklist word: garbage 78c67c126575c20c6b468447355e9bd20d221202
total count per partition: [0, 0, 0, 0, 0, 0, 1]
Saving filter files...
0 hibp_20200801_21bits_worst.bloomfilter
1 hibp_20200801_25bits_suck.bloomfilter
2 hibp_20200801_28bits_bad.bloomfilter
3 hibp_20200801_31bits_common.bloomfilter
4 hibp_20200801_32bits_rare.bloomfilter
5 hibp_20200801_32bits_low.bloomfilter
6 hibp_20200801_20bits_blacklist.bloomfilter
```

# Testing

These are not exhaustive tests (I am not testing if random values trigger false positives), but to confirm that the filters work, run the following command:

```
$ python3 test_filters.py
```

the result should look like this
```
Loading existing knowledge file hibp_20200801_21bits_worst.bloomfilter
Loading existing knowledge file hibp_20200801_25bits_suck.bloomfilter
Loading existing knowledge file hibp_20200801_28bits_bad.bloomfilter
Loading existing knowledge file hibp_20200801_31bits_common.bloomfilter
Loading existing knowledge file hibp_20200801_32bits_rare.bloomfilter
Loading existing knowledge file hibp_20200801_32bits_low.bloomfilter
Loading existing knowledge file hibp_20200801_20bits_blacklist.bloomfilter
Testing source file pwned-passwords-sha1-ordered-by-count-v6.txt
total count: 10
successes: 10
not found: 0
losts: 0
Testing blacklist file: blacklist.txt. Partition 6
garbage 78c67c126575c20c6b468447355e9bd20d221202
total count: 1
successes: 1
not found: 0
```

# Full training

modify the line 38 of the `config.yml` file to disable the testing mode
```
testing_mode:
  enable: false
  limit: 1000
```

then restart the full process
```
time python3 make_filters.py pwned-passwords-sha1-ordered-by-count-v6.txt
```

# What to do with these filters?

Now that they are encoded, you can use them in your favorite custom app to check for hash values.
In separated files like that, they take 1.3GB of ram instead of 25GB+index after inserting them into a database.
The filters could be smaller if you don't mind about false positives too much.

5 offsets needs to be queried to know if a value was observed or not, which is relatively quick, especially in memory.
