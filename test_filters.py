import os, io, sys
import time

from datetime import datetime
from bitarray import bitarray
import hashlib
import math
import yaml

knowledge_filenames = []
if len(sys.argv) != 2:
    source = "pwned-passwords-sha1-ordered-by-count-v6.txt"
    print("File containing hashes to test was not provided. Using %s" % source)
else:
    source = sys.argv[1]

def configuration():
    with io.open('config.yaml', 'r') as inputfile:
        config = yaml.safe_load(inputfile)

        return {
            'partitions': config['partitions'],
            'nb_hashes': config['nb_hashes'],
            'content': config['content'],
            'content_date': config['date'],
            'testing_mode': config['testing_mode']['enable'],
            'testing_limit': config['testing_mode']['limit'],
            'blacklist': config['blacklist']
        }
conf = configuration()

def getPartition(count):
    for i in range(len(conf['partitions'])):

        if conf['partitions'][i]['maximum'] > count and count >= conf['partitions'][i]['minimum']:
            return i, conf['partitions'][i]['maximum'], conf['partitions'][i]['minimum']

    return 0, 0, 0


def process_word(word, size, hashes):
    offsets = []
    for h in range(hashes):
        payload = str(h).encode('utf-8') + word.encode('utf-8')
        offsets.append(int.from_bytes(hashlib.md5(payload).digest(), "little") % size)

    return {"word": word, "offsets": offsets}

def record_word(filter, offset):
    filter[offset]=True

def read_offset(filter, offsets, hashes):
    hit = 0

    for o in offsets:
        if bit_arrays[filter][o] == True:
            hit += 1

    return hit == hashes

def testfile(source, hashes):
    with open(source) as fp:
        line = fp.readline()
        cnt = 0
        partition = -1
        higher = 0
        lower = 0
        success = 0
        notfound = 0
        lost = 0
        print("Testing source file %s" % source)

        while line and cnt < conf['testing_limit']:
            splited = line.split(":")
            hash = splited[0]
            freq = int(splited[1])
            partition, higher, lower = getPartition(freq)

            for i in range(len(bit_arrays)):
                size = 2**conf['partitions'][i]['bitsize']
                p = process_word(hash, size, conf['nb_hashes'])

                found = read_offset(i, p["offsets"], hashes)

                if found == True and partition == i:
                    success += 1
                elif found == False and partition == i:
                    notfound += 1
                    print("FAILED: hash %s was supposed to be found in partition %d. " % (hash, partition))
                elif found == True and partition != i:
                    lost += 1
                    print("FAILED: hash %s was found in the wrong partition %d. " % (hash, partition))

            line = fp.readline()
            cnt += 1

    print("total count: {}".format(cnt))
    print("success: %d" % successes)
    print("not found: %d" % notfounds)
    print("lost: %d" % losts)


def testblacklist(source, hashes):
    with open(source) as fp:
        partition = -1
        cnt = 0
        success = 0
        notfound = 0

        for i in range(len(conf['partitions'])):
            if conf['partitions'][i]['label'] == "blacklist":
                partition = i

        if partition >= 0:
            size = 2**conf['partitions'][partition]['bitsize']

            print("Testing blacklist file: %s. Partition %d " % (source, partition))

            line = fp.readline()
            while line:
                line = line.rstrip()
                hash = hashlib.sha1(line.encode('utf-8')).hexdigest()
                print(line, hash)

                p = process_word(hash, size, conf['nb_hashes'])

                found = read_offset(partition, p["offsets"], hashes)

                if found == True:
                    success += 1
                else:
                    notfound += 1
                    print("FAILED: hash %s was supposed to be found in partition %d. " % (hash, partition))

                line = fp.readline()
                cnt += 1
        else:
            print("no blacklist partition defined in config.yaml")

    print("total count: {}".format(cnt))
    print("success: %d" % successes)
    print("not found: %d" % notfounds)

if os.path.exists(source):
    for p in conf['partitions']:
        knowledge_filenames.append("{}_{}_{}bits_{}.bloomfilter".format(conf['content'], conf['content_date'], p['bitsize'], p['label']))

    bit_arrays = [False for x in range(len(knowledge_filenames))]

    for i in range(len(knowledge_filenames)):
        if os.path.exists(knowledge_filenames[i]) == True:
            print("Loading existing knowledge file {}".format(knowledge_filenames[i]))

            bit_arrays[i] = bitarray()
            with open(knowledge_filenames[i], 'rb') as f:
                bit_arrays[i].fromfile(f)

        else:
            print("could not load filter %s" % knowledge_filenames[i])

    testfile(source, conf['nb_hashes'])
    testblacklist(conf['blacklist'], conf['nb_hashes'])
