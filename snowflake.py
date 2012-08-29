from ctypes import *

CRACKERLIB_PATH = "../release/snowflake.so"
bitMask = 0xffffffff

class MtRand:

    N = 624
    M = 397

    def __init__(self, php = True):
        self.php = php
        self.twist = self.phpTwist if php else self.mtTwist
        self.seeded = False
        self.state = []
        self.next = self.N


    def phpTwist(self, m, u, v):
        """
        The invalid twist operation of the PHP generator
        """
        return (m ^ (((u) & 0x80000000)|((v) & 0x7fffffff))>>1) ^ \
            ((-((u) & 0x00000001)) & 0x9908b0df)


    def mtTwist(self, m, u, v):
        """
        The original mt twist operation
        """
        return (m ^ (((u) & 0x80000000)|((v) & 0x7fffffff))>>1) ^ \
            ((-((v) & 0x00000001)) & 0x9908b0df)


    def mtSrand(self, seed):
        """
        The default seeding procedure from the original MT code
        """
        self.seeded = True
        self.next = self.N
        self.state = [seed & bitMask]
        for i in range(1, self.N):
            s = (1812433253 * (self.state[i-1] ^ (self.state[i-1] >> 30))+ i)
            self.state.append(s & bitMask)

 
    def setState(self, state):
        """
        Replace existing state with another one and considers the 
        generator initialized
        """
        self.next = self.N
        self.state = state
        self.seeded = True


    def reload(self):
        """
        Generate the next N words of the internal state
        """        
        N = self.N
        M = self.M
        for i in range(N - M):
            self.state[i] = self.twist(self.state[M + i], self.state[i], 
                                       self.state[i+1])
        for i in range(i+1, N-1):
            self.state[i] = self.twist(self.state[i+(M-N)], self.state[i], 
                                       self.state[i+1])
        self.state[N-1] = self.twist(self.state[M-1], self.state[N-1],
                                     self.state[0])
        self.next = 0
        return


    def mtRand(self, min = None, max = None):
        """
        Generate a 32 bit integer
        """
        if not self.seeded:
            self.mtSrand(0xdeadbeef)
            
        if self.next == self.N:
            self.reload()

        num = self.state[ self.next ]
        self.next += 1
        
        num = (num ^ (num >> 11))
        num = (num ^ ((num << 7) & 0x9d2c5680))
        num = (num ^ ((num << 15) & 0xefc60000))
        num = (num ^ (num >> 18))

        if not min and not max:
            return num

        return (min + (num*(max - min + 1)) / (1<<32))

    def phpMtRand(self, rmin = None, rmax= None):
        """
        as returned by PHP
        """
        num = self.mtRand() >> 1
        if not rmin and not rmax:
            return num
        return (rmin + (num*(rmax - rmin + 1)) / (1 <<31))



class Snowflake:
    
    def __init__(self, path=None):
        """
        Load the functions from the shared library.
        """
        if not path:
            path = CRACKERLIB_PATH
        crackerLib = cdll.LoadLibrary(path)
        self.initialized = False
        
        if not crackerLib:
            return
        self.searchRainbowTableFunc = crackerLib.searchRainbowTable
        self.searchHashOnlineFunc = crackerLib.searchHashOnline
        self.initialized = True


    def oneWayOrAnother(self, targetHash, tableList=[], hashFuncName=None):
        """
        Will try to crack the hash using either rainbow tables or 
        an online search if the first method fails.
        """
        seed = None
        if not targetHash or not self.initialized:
            return None

        for table in tableList:
            seed = self.searchRainbowTables(targetHash, tableList)
            if seed:
                return seed

        if hashFuncName:
            seed = self.searchHashOnline(targetHash, hashFuncName)
            
        return seed                

        
    def searchRainbowTables(self, targetHash, tableList):
        """
        Will search all tables in tableList for the targetHash
        hash. It will return the seed value or None if its not 
        found.
        """
        if not self.initialized  or not (targetHash and tableList):
            return None

        chash = create_string_buffer(targetHash, len(targetHash))
        for t in tableList:
            ct = c_char_p(t)
            cseed = c_uint()
            ret = self.searchRainbowTableFunc(ct, chash, byref(cseed))
            if ret > 0:
                return cseed.value
        return None        

    
    def searchHashOnline(self, targetHash, hashFunc):
        """
        Do an exhaustive search on all 2^32 possible seeds using the
        respective function from the library.
        """

        if not self.initialized or  not (targetHash and hashFunc):
            return None
        
        chash = c_char_p(targetHash)
        chashFunc = c_char_p(hashFunc)
        cseed = c_uint()

        ret = self.searchHashOnlineFunc(chashFunc, chash, byref(cseed))
        if ret > 0:
            return cseed.value
        return None
        
        
if __name__ == '__main__':
    print 'Snowflake module for attacking PHP PRNGs'
