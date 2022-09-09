// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "chain.h"

using namespace std;

/**
 * CChain implementation
 */
void CChain::SetTip(CBlockIndex *pindex) {
    lastTip = pindex;
    if (pindex == NULL) {
        vChain.clear();
        mmr.Truncate(0);
        return;
    }
    uint32_t modCount = 0;
    vChain.resize(pindex->GetHeight() + 1);
    while (pindex && vChain[pindex->GetHeight()] != pindex) {
        modCount++;
        vChain[pindex->GetHeight()] = pindex;
        pindex = pindex->pprev;
    }
    mmr.Truncate(vChain.size() - modCount);
    for (int i = (vChain.size() - modCount); i < vChain.size(); i++)
    {
        // add this block to the Merkle Mountain Range
        mmr.Add(vChain[i]->GetBlockMMRNode());
    }
}

// returns false if unable to fast calculate the VerusPOSHash from the header. 
// if it returns false, value is set to 0, but it can still be calculated from the full block
// in that case. the only difference between this and the POS hash for the contest is that it is not divided by the value out
// this is used as a source of entropy
bool CBlockIndex::GetRawVerusPOSHash(uint256 &ret) const
{
    // if below the required height or no storage space in the solution, we can't get
    // a cached txid value to calculate the POSHash from the header
    if (!(CPOSNonce::NewNonceActive(GetHeight()) && IsVerusPOSBlock()))
    {
        ret = uint256();
        return false;
    }

    // if we can calculate, this assumes the protocol that the POSHash calculation is:
    //    hashWriter << ASSETCHAINS_MAGIC;
    //    hashWriter << nNonce; (nNonce is:
    //                           (high 128 bits == low 128 bits of verus hash of low 128 bits of nonce)
    //                           (low 32 bits == compact PoS difficult)
    //                           (mid 96 bits == low 96 bits of HASH(pastHash, txid, voutnum)
    //                              pastHash is hash of height - 100, either PoW hash of block or PoS hash, if new PoS
    //                          )
    //    hashWriter << height;
    //    return hashWriter.GetHash();
    if (nVersion == CBlockHeader::VERUS_V2)
    {
        CVerusHashV2Writer hashWriter = CVerusHashV2Writer(SER_GETHASH, PROTOCOL_VERSION);

        hashWriter << ASSETCHAINS_MAGIC;
        hashWriter << nNonce;
        hashWriter << GetHeight();
        ret = hashWriter.GetHash();
    }
    else
    {
        CVerusHashWriter hashWriter = CVerusHashWriter(SER_GETHASH, PROTOCOL_VERSION);

        hashWriter << ASSETCHAINS_MAGIC;
        hashWriter << nNonce;
        hashWriter << GetHeight();
        ret = hashWriter.GetHash();
    }
    return true;
}

// depending on the height of the block and its type, this returns the POS hash or the POW hash
uint256 CBlockIndex::GetVerusEntropyHashComponent() const
{
    uint256 retVal;
    // if we qualify as PoW, use PoW hash, regardless of PoS state
    if (GetRawVerusPOSHash(retVal))
    {
        // POS hash
        return retVal;
    }
    return GetBlockHash();
}

// if pointers are passed for the int output values, two of them will indicate the height that provides one of two
// entropy values. the other will be -1. if pALTheight is not -1, its block type is the same as the other, which is
// not -1.
uint256 CChain::GetVerusEntropyHash(int forHeight, int *pPOSheight, int *pPOWheight, int *pALTheight) const
{
    uint256 retVal;
    int height = forHeight - 100;

    // we want the last value hashed to be a POW hash to make it difficult to predict at source tx creation, then we hash it with the
    // POS entropy. for old version, we just do what we used to and return the type of hash with the -100 height
    int _posh, _powh, _alth;
    int &posh = pPOSheight ? *pPOSheight : _posh;
    int &powh = pPOWheight ? *pPOWheight : _powh;
    int &alth = pALTheight ? *pALTheight : _alth;
    posh = powh = alth = -1;

    if (!(height >= 0 && height < vChain.size()))
    {
        LogPrintf("%s: invalid height for entropy hash %d, chain height is %d\n", __func__, height, vChain.size() - 1);
        return retVal;
    }
    if (CConstVerusSolutionVector::GetVersionByHeight(forHeight) < CActivationHeight::ACTIVATE_EXTENDEDSTAKE || height < 11)
    {
        if (vChain[height]->IsVerusPOSBlock())
        {
            posh = height;
        }
        else
        {
            powh = height;
        }
        return vChain[height]->GetVerusEntropyHashComponent();
    }

    int i;
    for (i = 0; i < 10; i++)
    {
        if (posh == -1 && vChain[height - i]->IsVerusPOSBlock())
        {
            posh = height - i;
        }
        else if (powh == -1)
        {
            powh = height - i;
        }
        if (posh != -1 && powh != -1)
        {
            break;
        }
    }

    // only one type of block found, set alt
    if (i == 10)
    {
        alth = height - i;
    }

    CVerusHashV2Writer hashWriter = CVerusHashV2Writer(SER_GETHASH, 0);
    if (posh != -1)
    {
        hashWriter << vChain[posh]->GetVerusEntropyHashComponent();
    }
    if (powh != -1)
    {
        hashWriter << vChain[powh]->GetVerusEntropyHashComponent();
    }
    if (alth != -1)
    {
        hashWriter << vChain[alth]->GetVerusEntropyHashComponent();
    }
    return hashWriter.GetHash();
}

CBlockLocator CChain::GetLocator(const CBlockIndex *pindex) const {
    int nStep = 1;
    std::vector<uint256> vHave;
    vHave.reserve(32);

    if (!pindex)
        pindex = Tip();
    while (pindex) {
        vHave.push_back(pindex->GetBlockHash());
        // Stop when we have added the genesis block.
        if (pindex->GetHeight() == 0)
            break;
        // Exponentially larger steps back, plus the genesis block.
        int nHeight = std::max(pindex->GetHeight() - nStep, 0);
        if (Contains(pindex)) {
            // Use O(1) CChain index if possible.
            pindex = (*this)[nHeight];
        } else {
            // Otherwise, use O(log n) skiplist.
            pindex = pindex->GetAncestor(nHeight);
        }
        if (vHave.size() > 10)
            nStep *= 2;
    }

    return CBlockLocator(vHave);
}

const CBlockIndex *CChain::FindFork(const CBlockIndex *pindex) const {
    if ( pindex == 0 )
        return(0);
    if (pindex->GetHeight() > Height())
        pindex = pindex->GetAncestor(Height());
    while (pindex && !Contains(pindex))
        pindex = pindex->pprev;
    return pindex;
}

bool CChain::GetBlockProof(ChainMerkleMountainView &view, CMMRProof &retProof, int index) const
{
    CBlockIndex *pindex = (index < 0 || index >= (int)vChain.size()) ? NULL : vChain[index];
    if (pindex)
    {
        retProof << pindex->BlockProofBridge();
        return view.GetProof(retProof, index);
    }
    else
    {
        return false;
    }
}

bool CChain::GetMerkleProof(ChainMerkleMountainView &view, CMMRProof &retProof, int index) const
{
    CBlockIndex *pindex = (index < 0 || index >= (int)vChain.size()) ? NULL : vChain[index];
    if (pindex)
    {
        retProof << pindex->MMRProofBridge();
        return view.GetProof(retProof, index);
    }
    else
    {
        return false;
    }
}

uint256 CChainPower::CompactChainPower() const
{
    arith_uint256 compactPower = (chainStake << 128) + chainWork;
    return ArithToUint256(compactPower);
}

CChainPower::CChainPower(CBlockIndex *pblockIndex)
{
     nHeight = pblockIndex->GetHeight();
     chainStake = arith_uint256(0);
     chainWork = arith_uint256(0);
}

CChainPower::CChainPower(CBlockIndex *pblockIndex, const arith_uint256 &stake, const arith_uint256 &work)
{
     nHeight = pblockIndex->GetHeight();
     chainStake = stake;
     chainWork = work;
}

bool operator==(const CChainPower &p1, const CChainPower &p2)
{
    arith_uint256 bigZero = arith_uint256(0);
    arith_uint256 workDivisor = p1.chainWork > p2.chainWork ? p1.chainWork : (p2.chainWork != bigZero ? p2.chainWork : 1);
    arith_uint256 stakeDivisor = p1.chainStake > p2.chainStake ? p1.chainStake : (p2.chainStake != bigZero ? p2.chainStake : 1);

    // use up 16 bits for precision
    return ((p1.chainWork << 16) / workDivisor + (p1.chainStake << 16) / stakeDivisor) ==
            ((p2.chainWork << 16) / workDivisor + (p2.chainStake << 16) / stakeDivisor);
}

bool operator<(const CChainPower &p1, const CChainPower &p2)
{
    arith_uint256 bigZero = arith_uint256(0);
    arith_uint256 workDivisor = p1.chainWork > p2.chainWork ? p1.chainWork : (p2.chainWork != bigZero ? p2.chainWork : 1);
    arith_uint256 stakeDivisor = p1.chainStake > p2.chainStake ? p1.chainStake : (p2.chainStake != bigZero ? p2.chainStake : 1);

    // use up 16 bits for precision
    return ((p1.chainWork << 16) / workDivisor + (p1.chainStake << 16) / stakeDivisor) <
            ((p2.chainWork << 16) / workDivisor + (p2.chainStake << 16) / stakeDivisor);
}

bool operator<=(const CChainPower &p1, const CChainPower &p2)
{
    arith_uint256 bigZero = arith_uint256(0);
    arith_uint256 workDivisor = p1.chainWork > p2.chainWork ? p1.chainWork : (p2.chainWork != bigZero ? p2.chainWork : 1);
    arith_uint256 stakeDivisor = p1.chainStake > p2.chainStake ? p1.chainStake : (p2.chainStake != bigZero ? p2.chainStake : 1);

    // use up 16 bits for precision
    return ((p1.chainWork << 16) / workDivisor + (p1.chainStake << 16) / stakeDivisor) <=
            ((p2.chainWork << 16) / workDivisor + (p2.chainStake << 16) / stakeDivisor);
}

CChainPower CChainPower::ExpandCompactPower(uint256 compactPower, uint32_t height)
{
    return CChainPower(height, UintToArith256(compactPower) >> 128, (UintToArith256(compactPower) << 128) >> 128);
}

/** Turn the lowest '1' bit in the binary representation of a number into a '0'. */
int static inline InvertLowestOne(int n) { return n & (n - 1); }

/** Compute what height to jump back to with the CBlockIndex::pskip pointer. */
int static inline GetSkipHeight(int height) {
    if (height < 2)
        return 0;

    // Determine which height to jump back to. Any number strictly lower than height is acceptable,
    // but the following expression seems to perform well in simulations (max 110 steps to go back
    // up to 2**18 blocks).
    return (height & 1) ? InvertLowestOne(InvertLowestOne(height - 1)) + 1 : InvertLowestOne(height);
}

CBlockIndex* CBlockIndex::GetAncestor(int height)
{
    if (height > GetHeight() || height < 0)
        return NULL;

    CBlockIndex* pindexWalk = this;
    int heightWalk = GetHeight();
    while ( heightWalk > height && pindexWalk != 0 )
    {
        int heightSkip = GetSkipHeight(heightWalk);
        int heightSkipPrev = GetSkipHeight(heightWalk - 1);
        if (pindexWalk->pskip != NULL &&
            (heightSkip == height ||
             (heightSkip > height && !(heightSkipPrev < heightSkip - 2 &&
                                       heightSkipPrev >= height)))) {
            // Only follow pskip if pprev->pskip isn't better than pskip->pprev.
            pindexWalk = pindexWalk->pskip;
            heightWalk = heightSkip;
        } else {
            assert(pindexWalk->pprev);
            pindexWalk = pindexWalk->pprev;
            heightWalk--;
        }
    }
    return pindexWalk;
}

const CBlockIndex* CBlockIndex::GetAncestor(int height) const
{
    return const_cast<CBlockIndex*>(this)->GetAncestor(height);
}

void CBlockIndex::BuildSkip()
{
    if (pprev)
    {
        //printf("building skip - current:\n%s\nprev:\n%s\n", ToString().c_str(), pprev->ToString().c_str());
        pskip = pprev->GetAncestor(GetSkipHeight(GetHeight()));
    }
}
