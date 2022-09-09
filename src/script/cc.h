#ifndef SCRIPT_CC_H
#define SCRIPT_CC_H

#include <memory>

#include "pubkey.h"
#include "script/script.h"
#include "cryptoconditions/include/cryptoconditions.h"


extern uint32_t ASSETCHAINS_CC;
bool IsCryptoConditionsEnabled();

// Limit acceptable condition types
// Prefix not enabled because no current use case, ambiguity on how to combine with secp256k1
// RSA not enabled because no current use case, not implemented
const int CCEnabledTypes = 1 << CC_Secp256k1 | \
                           1 << CC_Threshold | \
                           1 << CC_Eval | \
                           1 << CC_Preimage | \
                           1 << CC_Ed25519;

const int CCSigningNodes = 1 << CC_Ed25519 | 1 << CC_Secp256k1;

const int CCEvalNode = 1 << CC_Eval;

const int CCFirstEvalOnly = 2;
const int CCLastEvalOnly = 0x0d;

/*
 * Check if the server can accept the condition based on it's structure / types
 */
bool IsSupportedCryptoCondition(const CC *cond, int evalCode);


/*
 * Check if crypto condition is signed. Can only accept signed conditions.
 */
bool IsSignedCryptoCondition(const CC *cond);


/*
 * Construct crypto conditions
 */
CC* CCNewPreimage(std::vector<unsigned char> preimage);
CC* CCNewEval(std::vector<unsigned char> code);
CC* CCNewSecp256k1(CPubKey k);
CC* CCNewHashedSecp256k1(CKeyID keyID);
CC* CCNewThreshold(int t, std::vector<CC*> v);


/*
 * Turn a condition into a scriptPubKey or just the vector inside
 */
CScript CCPubKey(const CC *cond);
std::vector<unsigned char> CCPubKeyVec(const CC *cond);

/*
 * Turn a condition into a scriptSig
 *
 * Note: This will fail in undefined ways if the condition is missing signatures
 */
CScript CCSig(const CC *cond);

/*
 * Turn a condition into a scriptSig
 *
 * Note: This will fail in undefined ways if the condition is missing signatures
 */
std::vector<unsigned char> CCSigVec(const CC *cond);

/*
 * Turn a partial fulfillment that may still need more signatures into a scriptSig
 *
 */
std::vector<unsigned char> CCPartialSigVec(const CC *cond);

/*
 * Produces a string showing the structure of a CC condition
 */
std::string CCShowStructure(CC *cond);


/*
 * Take a signed CC, encode it, and decode it again. This has the effect
 * of removing branches unneccesary for fulfillment.
 */
CC* CCPrune(CC *cond);


/*
 * Get PUSHDATA from a script
 */
bool GetPushData(const CScript &sig, std::vector<unsigned char> &data);

/*
 * Get OP_RETURN data from a script
 */
bool GetOpReturnData(const CScript &sig, std::vector<unsigned char> &data);

#endif /* SCRIPT_CC_H */
