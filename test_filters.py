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

        while line: # and cnt < conf['testing_limit']:
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
    print("success:", success)
    print("not found:", notfound)
    print("lost:", lost)


def test_wordlist(source, hashes):
    with open(source) as fp:
        cnt = 0
        successes = []
        notfounds = []
        line = fp.readline()

        while line and cnt < conf['testing_limit']:
            line = line.rstrip()
            hash = hashlib.sha1(line.encode('utf-8')).hexdigest().upper()

            found_somewhere = False
            for i in range(len(bit_arrays)):
                size = 2**conf['partitions'][i]['bitsize']
                p = process_word(hash, size, conf['nb_hashes'])

                found = read_offset(i, p["offsets"], hashes)

                if found == True:
                    # print("word {} (hash: {}) found in filter {}: {}".format(line, hash, i, conf['partitions'][i]['label']))
                    successes.append({"word": line, "partition": i, "label": conf['partitions'][i]['label']})
                    found_somewhere = True
            if not found_somewhere:
                # print("FAILED: word {} (hash {}) was not found.".format(line, hash))
                notfounds.append({"word": line, "partition": -1, "label": ""})

            line = fp.readline()
            cnt += 1

    print("total count: {}".format(cnt))
    print("success count:", len(successes), "First {}:".format(min(len(successes),50)))
    for i in successes[:min(len(successes),50)]:
        print(i)
    print("not found count:", len(notfounds), "First {}:".format(min(len(notfounds),50)))
    for i in notfounds[:min(len(notfounds),50)]:
        print(i)

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


    print("Testing hash source file:", source)
    testfile(source, conf['nb_hashes'])

    # This is for custom wordlist testing
    for f in [conf['blacklist'], '10-million-password-list-top-100.txt']:
        print("\nTesting plain list of words file:", f)
        test_wordlist(f, conf['nb_hashes'])
