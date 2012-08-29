#!/usr/bin/python

"""
Rainbow tables success probability calculator

Author: George Argyros (argyros.george@gmail.com)

Note: 
implementation is straightforward application of the rainbow tables
formula, so it might get a bit slow with very large parameters.

Parameters:
<chain num> : Number of chains in the rainbow table.

<chain len> : Length of each chain.

<table num> : Number of distinct rainbow tables.

<keyspace>  : Total number of passwords (default is 2^{32}).
"""

from sys import argv
from math import exp

KeySpace  = 1 << 32

def main( argc, argv ):

    if (argc < 4):
        print 'Usage: %s <chain num> <chain len> <table num> <keyspace>' \
            % (argv[0])
        return
    
    m = float(argv[1])
    t = int(argv[2])
    tables = int(argv[3])
    N = KeySpace if argc < 5 else float(argv[4])
    
    ml = [m]
    for i in range(t):
        ml.append( N * (1 - exp(-ml[i]/N)) )

    p = 1
    for i in range(t):
        p *= (1 - (ml[i] / N))
        
    print 'Success probability is: %f' % (1 - pow(p,float(tables)))


if __name__ == '__main__':
    main( len(argv), argv )
