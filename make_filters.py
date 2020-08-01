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
    print("Source file undefined, default to %s" % source)
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

test_mode = conf['testing_mode']
if test_mode:
    print("Starting in testing mode. this can be disabled by setting `testing_mode` to False")


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

def learn_hash(hash, partition, hashes):
    global conf
    global bit_arrays

    size = 2**conf['partitions'][partition]['bitsize']
    p = process_word(hash, size, hashes)

    for o in p['offsets']:
        record_word(bit_arrays[partition], o)

    hit = 0
    for o in p['offsets']:
        if bit_arrays[partition][o] == True:
            hit += 1

    if test_mode:
        if hit != hashes:
            print("hash %s is not present %d times in the %d partition" % (hash, hashes, partition))
            raise

    return True

def readfile(source, hashes):
    with open(source) as fp:
        line = fp.readline()
        cnt = [0 for x in range(len(conf['partitions']))]
        count = 0

        partition = -1
        higher = 0
        lower = 0

        while line:
            splited = line.split(":")
            freq = int(splited[1])

            if partition == -1 or not (higher > freq and freq >= lower):
                partition, higher, lower = getPartition(freq)
                print("partition: {}, Upper bound: {}, current hash frequency: {}, lower bound: {}".format(partition, higher, freq, lower))


            learn_hash(splited[0], partition, hashes)
            line = fp.readline()
            cnt[partition] += 1
            count+=1

            if conf['testing_mode'] == True and count >= conf['testing_limit']:
                break


    print("total count per partition: {}".format(cnt))

    return True

def read_blacklist(source, hashes):
    with open(source) as fp:
        partition = -1
        cnt = [0 for x in range(len(conf['partitions']))]

        for i in range(len(conf['partitions'])):
            if conf['partitions'][i]['label'] == "blacklist":
                partition = i

        if partition >= 0:
            line = fp.readline()
            line = line.rstrip()
            hash = hashlib.sha1(line.encode('utf-8')).hexdigest()

            print('blacklist word:', line, hash)

            while line:
                learn_hash(hash, partition, hashes)
                line = fp.readline()
                cnt[partition] += 1
        else:
            print("no blacklist partition defined in config.yaml")
    print("total count per partition: {}".format(cnt))

def create_array(bits):
    size = 2**bits
    print("Initializing memory ({}MB)".format(size/8/1024/1024))
    array = bitarray(size)
    array.setall(0)
    return array

def save_array(arrays):
    print("Saving filter files...")
    for a in range(len(arrays)):
        print("{} {}".format(a, knowledge_filenames[a]))
        with open(knowledge_filenames[a], 'wb') as f:
            arrays[a].tofile(f)

if os.path.exists(source):
    for p in conf['partitions']:
        knowledge_filenames.append("{}_{}_{}bits_{}.bloomfilter".format(conf['content'], conf['content_date'], p['bitsize'], p['label']))

    bit_arrays = [False for x in range(len(knowledge_filenames))]

    for i in range(len(knowledge_filenames)):
        print("Creating a new knowledge file {} size {}".format(knowledge_filenames[i], conf['partitions'][i]['bitsize']))
        bit_arrays[i] = create_array(conf['partitions'][i]['bitsize'])
        print("size of filter {}: {}".format(i, len(bit_arrays[i])))

    readfile(source, conf['nb_hashes'])
    read_blacklist(conf['blacklist'], conf['nb_hashes'])

    save_array(bit_arrays)
