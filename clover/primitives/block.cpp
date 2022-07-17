// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

//#include "hash.h"
//#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/common.h"
#include "crypto/scrypt.h"
#include "crypto/dag.h"

uint256 CBlockHeader::GetPoWHash() const
{
    uint256 thash;
    CDAGSystem sys;
    if(this->nVersion & 0x00000100) {
        CHashimotoResult res = sys.Hashimoto(*this);
        return res.GetResult();
    }
    scrypt_1024_1_1_256(BEGIN(nVersion), BEGIN(thash));
    return thash;
}
