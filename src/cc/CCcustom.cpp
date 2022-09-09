/******************************************************************************
 * Copyright © 2014-2018 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

#include <univalue.h>
#include "key_io.h"
#include "CCinclude.h"
#include "CCassets.h"
#include "CCfaucet.h"
#include "CCrewards.h"
#include "CCdice.h"
#include "CCauction.h"
#include "CClotto.h"
#include "CCfsm.h"
#include "CCMofN.h"
#include "CCchannels.h"
#include "CCOracles.h"
#include "CCPrices.h"
#include "CCPegs.h"
#include "CCTriggers.h"
#include "CCPayments.h"
#include "CCGateways.h"
#include "StakeGuard.h"
#include "pbaas/crosschainrpc.h"
#include "pbaas/pbaas.h"
#include "pbaas/notarization.h"
#include "pbaas/identity.h"

/*
 CCcustom has most of the functions that need to be extended to create a new CC contract.
 
 A CC scriptPubKey can only be spent if it is properly signed and validated. By constraining the vins and vouts, it is possible to implement a variety of functionality. CC vouts have an otherwise non-standard form, but it is properly supported by the enhanced bitcoin protocol code as a "cryptoconditions" output and the same pubkey will create a different address.
 
 This allows creation of a special address(es) for each contract type, which has the privkey public. That allows anybody to properly sign and spend it, but with the constraints on what is allowed in the validation code, the contract functionality can be implemented.
 
 what needs to be done to add a new contract:
 1. add EVAL_CODE to eval.h
 2. initialize the variables in the CCinit function below
 3. write a Validate function to reject any unsanctioned usage of vin/vout
 4. make helper functions to create rawtx for RPC functions
 5. add rpc calls to rpcserver.cpp and rpcserver.h and in one of the rpc.cpp files
 6. add the new .cpp files to src/Makefile.am
 
 IMPORTANT: make sure that all CC inputs and CC outputs are properly accounted for and reconcile to the satoshi. The built in utxo management will enforce overall vin/vout constraints but it wont know anything about the CC constraints. That is what your Validate function needs to do.
 
 Generally speaking, there will be normal coins that change into CC outputs, CC outputs that go back to being normal coins, CC outputs that are spent to new CC outputs.
 
 Make sure both the CC coins and normal coins are preserved and follow the rules that make sense. It is a good idea to define specific roles for specific vins and vouts to reduce the complexity of validation.
 */

// to create a new CCaddr, add to rpcwallet the CCaddress and start with -pubkey= with the pubkey of the new address, with its wif already imported. set normaladdr and CChexstr. run CCaddress and it will print the privkey along with autocorrect the CCaddress. which should then update the CCaddr here

// StakeGuard - nothing at stake
std::string StakeGuardAddr = "RCG8KwJNDVwpUBcdoa6AoHqHVJsA1uMYMR";
std::string StakeGuardPubKey = "03166b7813a4855a88e9ef7340a692ef3c2decedfdc2c7563ec79537e89667d935";
std::string StakeGuardWIF = "Uw7vRYHGKjyi1FaJ8Lv1USSuj7ntUti8fAhSDiCdbzuV6yDagaTn";

// defines the blockchain parameters of a PBaaS blockchain
std::string PBaaSDefinitionAddr = "RP7id3CzCnwvzNUZesYJM6ekvsxpEzMqB1";
std::string PBaaSDefinitionPubKey = "02a0de91740d3d5a3a4a7990ae22315133d02f33716b339ebce88662d012224ef5";
std::string PBaaSDefinitionWIF = "UwhNWARAQTUvYUEqxGbRjM2BFUneGnFzmaMMiSqJQZFQZTku6xTW";

// Notary evidence output type
std::string NotaryEvidenceAddr = "RQWMeecjGFF3ZAVeSimRbyG9iMDUHPY5Ny";
std::string NotaryEvidencePubKey = "03e1894e9d487125be5a8c6657a8ce01bc81ba7816d698dbfcfb0483754eb5a2d9";
std::string NotaryEvidenceWIF = "Uw5dNvvgz7eyUJGtfi696hYbF9YPXHPHasgZFeQeDu8j4SapPBzd";

// Earned notarization type, created by miners and/or stakers
std::string EarnedNotarizationAddr = "RMYbaxFsCT1xfMmwLCCYAVf2DsxcDTtBmx";
std::string EarnedNotarizationPubKey = "03fb008879b37d644bef929576dda7f5ee31b352c76fc112b4a89838d5b61f52e2";
std::string EarnedNotarizationWIF = "UtzhFWXw24xS2Tf3gCDm9p2Ex7TUnCNt4DFA7r2f5cCKPhPknEqD";

// Accepted notarizations are validated notarizations and proofs of an alternate earned notarization -- these are for the Verus chain
std::string AcceptedNotarizationAddr = "RDTq9qn1Lthv7fvsdbWz36mGp8HK9XaruZ";
std::string AcceptedNotarizationPubKey = "02d85f078815b7a52faa92639c3691d2a640e26c4e06de54dd1490f0e93bcc11c3";
std::string AcceptedNotarizationWIF = "UtgbVEYs2PShTMffbkYh8bgo9DYsXr8JuqWVjAYHRt2ebGPeP5Mf";

// "Finalization" - output that can be spent when a notarization is effectively considered "final"
std::string FinalizeNotarizationAddr = "RRbKYitLH9EhQCvCo4bPZqJx3TWxASadxE";
std::string FinalizeNotarizationPubKey = "02e3154f8122ff442fbca3ff8ff4d4fb2d9285fd9f4d841d58fb8d6b7acefed60f";
std::string FinalizeNotarizationWIF = "UrN1b1hCQc6cUpcUdQD7DFTn2PJneDpKv5pmURPQzJ2zVp9UVM6E";

// Reserve output -- provides flexible Verus reserve currency transaction/utxo support on PBaaS chains only
std::string ReserveOutputAddr = "RMXeZGxxRuABFkT4uLSCeuJHLegBNGZq8D";
std::string ReserveOutputPubKey = "02d3e0f4c308c6e9786a5280ec96ea6d0e07505bae88d28b4b3156c309e2ae5515";
std::string ReserveOutputWIF = "UrCfRxuFKPg3b3HtPFhvL9X8iePfETRZpgymrxzdDZ3vpjSwHrxH";

// Identity advanced name reservation -- output with a versioned identity reservation that includes a parent to make IDs from a currency
std::string AdvancedNameReservationAddr = "REuGNkgunnw1J4Zx6Y9UCp8YHVZqYATe9D";
std::string AdvancedNameReservationPubKey = "02b68492c495d7d63d908fa641fb6215bc56a7de15fb438c78066ec4c173563527";
std::string AdvancedNameReservationWIF = "Uveq2qCQLjaJxdjXBAtBQQjhRDocomeSCtogifMHxwVsLNRCQgqX";

// Reserve transfer -- send reserves from a Verus chain to a PBaaS chain or back with optional conversion, works on Verus or PBaaS chains
std::string ReserveTransferAddr = "RTqQe58LSj2yr5CrwYFwcsAQ1edQwmrkUU";
std::string ReserveTransferPubKey = "0367add5577ca8f5f680ee0adf4cf802584c56ed14956efedd3e18656874614548";
std::string ReserveTransferWIF = "UtbtjjXtNtYroASwDrW63pEK7Fv3ehBRGDc2GRkPPr292DkRTmtB";

// Reserve deposit -- these outputs are spent into the cross chain import thread on the Verus chain when import transactions are created
std::string ReserveDepositAddr = "RFw9AVfgNKcHe2Vp2eyzHrX65aFD9Ky8df";
std::string ReserveDepositPubKey = "03b99d7cb946c5b1f8a54cde49b8d7e0a2a15a22639feb798009f82b519526c050";
std::string ReserveDepositWIF = "UtGtjeGBCUtQPGZp99bnDvQuxvURxdjGRFHuJ7oQyQgpNNCEyyqu";

// Cross chain export -- this is used on an aggregated cross chain export transaction and one unspent output defines the export thread
std::string CrossChainExportAddr = "RGkrs7SndcpsV61oKK2jYdMiU8PgkLU2qP";
std::string CrossChainExportPubKey = "02cbfe54fb371cfc89d35b46cafcad6ac3b7dc9b40546b0f30b2b29a4865ed3b4a";
std::string CrossChainExportWIF = "Uu9P8fa68e2ECar76z4MsSoKtbRV1Dny3WD6DTmMKmeimooeAyAz";

// Cross chain import -- this is used on a cross chain import transaction and one unspent output defines the import thread
std::string CrossChainImportAddr = "RKLN7wFhbrJFkPG8XkKteErAe5CjqoddTm";
std::string CrossChainImportPubKey = "038d259ec6175e192f8417914293dd09203885bc33039080f2a33f08a3fdddc818";
std::string CrossChainImportWIF = "UtAEFiEERMkuZ3cCzbi8DqXRM6fHNAuYcbXU2hy2dc14LgPpkxax";

// Currency state - coinbase output -- currently required on PBaaS chains only
std::string CurrencyStateAddr = "REU1HKkmdwdxKMpfD3QoxeERYd9tfMN6n9";
std::string CurrencyStatePubKey = "0219af977f9a6c3779f1185decee2b77da446040055b912b00e115a52d4786059c";
std::string CurrencyStateWIF = "Ur8YQJQ6guqmD6rXtrUtJ7fWxaEB5FaejCr3MxHAgMEwnjJnuGo5";

// identity primary output
std::string IdentityPrimaryAddr = "RS545EBdK5AzPTaGHNUg78wFuuAzBb74FB";
std::string IdentityPrimaryPubKey = "030b2c39fb8357ca54a56ca3b07a74a6b162addb4d31afaefc9c53bfc17aae052c";
std::string IdentityPrimaryWIF = "UtPq2QgtE9qcukeMA5grsHhr7eDzLo9BVwoN4QQRiv3coZn2ryXF";

// identity revoke output
std::string IdentityRevokeAddr = "RG6My2zwh9hBFSgUhZ5UmmUtxBap57aU4N";
std::string IdentityRevokePubKey = "03098d3fee3585ff42090c9cee5723a718dd27e7854761db4520eb70ade22a7802";
std::string IdentityRevokeWIF = "UuLt6xUQqG74M4Rgm96xEb672DjfkHYEukdUHWfAMBE4Tsc8cBvC";

// identity recover output
std::string IdentityRecoverAddr = "RRw9rJMPwdNqC1wgXn5vryJwMDyBgpXjYT";
std::string IdentityRecoverPubKey = "03a058410b33f893fe182f15336577f3941c28c8cadcfb0395b9c31dd5c07ccd11";
std::string IdentityRecoverWIF = "UuGtno91gaoJgy7nRgaBkWj6So3oBZ24fJWzULfU6LrsN4XZJckC";

// identity commitment output
std::string IdentityCommitmentAddr = "RCySaThHfVBcHZgjJGoBw3un4vcsRJNPYw";
std::string IdentityCommitmentPubKey = "03c4eac0982458644a87458eebe2fdc4e754e15c378b66f16fbd913ae2792d2cb0";
std::string IdentityCommitmentWIF = "Upfbmz3v16NM3zmQujmLSuaWeJ519fUKMqjusFwSDKgpBGMckWCr";

// identity reservation output
std::string IdentityReservationAddr = "RDbzJU8rEv4CkMABNUnKQoKDTfnikSm9fM";
std::string IdentityReservationPubKey = "03974e76f57409197870d4e5539380b2f8468465c2bd374e3610edf1282cd1a304";
std::string IdentityReservationWIF = "UqCXEj8oonBt6p9iDXbsAshCeFX7RsDpL6R62GUhTVRiSKDCQkYi";

// FinalizeExport
std::string FinalizeExportAddr = "REL7oLNeaeoQB1XauiHfcvjKMZC52Uj5xF";
std::string FinalizeExportPubKey = "0391fa230bd2509cbcc165c636c79ff540a8e3615993b16b8e366770bc4261bf10";
std::string FinalizeExportWIF = "UrRwoqyLMNddbASS7XV6rm3Q1JCBmMV9V5oPr92KEFmH5U8Evkf6";

// quantum resistant public key output to keep one copy of a public key and refer to it via its hash on the chain
std::string QuantumKeyOutAddr = "";
std::string QuantumKeyOutPubKey = "";
std::string QuantumKeyOutWIF = "";

// blockchain fee pool output
std::string FeePoolAddr = "RQ55dLQ7uGnLx8scXfkaFV6QS6qVBGyxAG";
std::string FeePoolPubKey = "0231dbadc511bcafdb557faf0b49bea1e2a4ccc0259aeae16c618e1cc4d38f2f4d";
std::string FeePoolWIF = "Ux4w6K5ptuQG4SUEQd1bRV8X1LwzcLrVirApbXvThKYfm6uXEafJ";

// atomic swap condition
std::string AtomicSwapConditionAddr = "";
std::string AtomicSwapConditionPubKey = "";
std::string AtomicSwapConditionWIF = "";

// condition to put time limits on a transaction output
std::string TimeLimitsAddr = "";
std::string TimeLimitsPubKey = "";
std::string TimeLimitsWIF = "";

// Assets, aka Tokens
#define FUNCNAME IsAssetsInput
#define EVALCODE EVAL_ASSETS
const char *AssetsCCaddr = "RGKRjeTBw4LYFotSDLT6RWzMHbhXri6BG6";
const char *AssetsNormaladdr = "RFYE2yL3KknWdHK6uNhvWacYsCUtwzjY3u";
char AssetsCChexstr[67] = { "02adf84e0e075cf90868bd4e3d34a03420e034719649c41f371fc70d8e33aa2702" };
uint8_t AssetsCCpriv[32] = { 0x9b, 0x17, 0x66, 0xe5, 0x82, 0x66, 0xac, 0xb6, 0xba, 0x43, 0x83, 0x74, 0xf7, 0x63, 0x11, 0x3b, 0xf0, 0xf3, 0x50, 0x6f, 0xd9, 0x6b, 0x67, 0x85, 0xf9, 0x7a, 0xf0, 0x54, 0x4d, 0xb1, 0x30, 0x77 };

#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// Faucet
#define FUNCNAME IsFaucetInput
#define EVALCODE EVAL_FAUCET
const char *FaucetCCaddr = "R9zHrofhRbub7ER77B7NrVch3A63R39GuC";
const char *FaucetNormaladdr = "RKQV4oYs4rvxAWx1J43VnT73rSTVtUeckk";
char FaucetCChexstr[67] = { "03682b255c40d0cde8faee381a1a50bbb89980ff24539cb8518e294d3a63cefe12" };
uint8_t FaucetCCpriv[32] = { 0xd4, 0x4f, 0xf2, 0x31, 0x71, 0x7d, 0x28, 0x02, 0x4b, 0xc7, 0xdd, 0x71, 0xa0, 0x39, 0xc4, 0xbe, 0x1a, 0xfe, 0xeb, 0xc2, 0x46, 0xda, 0x76, 0xf8, 0x07, 0x53, 0x3d, 0x96, 0xb4, 0xca, 0xa0, 0xe9 };

#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// Rewards
#define FUNCNAME IsRewardsInput
#define EVALCODE EVAL_REWARDS
const char *RewardsCCaddr = "RTsRBYL1HSvMoE3qtBJkyiswdVaWkm8YTK";
const char *RewardsNormaladdr = "RMgye9jeczNjQx9Uzq8no8pTLiCSwuHwkz";
char RewardsCChexstr[67] = { "03da60379d924c2c30ac290d2a86c2ead128cb7bd571f69211cb95356e2dcc5eb9" };
uint8_t RewardsCCpriv[32] = { 0x82, 0xf5, 0xd2, 0xe7, 0xd6, 0x99, 0x33, 0x77, 0xfb, 0x80, 0x00, 0x97, 0x23, 0x3d, 0x1e, 0x6f, 0x61, 0xa9, 0xb5, 0x2e, 0x5e, 0xb4, 0x96, 0x6f, 0xbc, 0xed, 0x6b, 0xe2, 0xbb, 0x7b, 0x4b, 0xb3 };
#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// Dice
#define FUNCNAME IsDiceInput
#define EVALCODE EVAL_DICE
const char *DiceCCaddr = "REabWB7KjFN5C3LFMZ5odExHPenYzHLtVw";
const char *DiceNormaladdr = "RLEe8f7Eg3TDuXii9BmNiiiaVGraHUt25c";
char DiceCChexstr[67] = { "039d966927cfdadab3ee6c56da63c21f17ea753dde4b3dfd41487103e24b27e94e" };
uint8_t DiceCCpriv[32] = { 0x0e, 0xe8, 0xf5, 0xb4, 0x3d, 0x25, 0xcc, 0x35, 0xd1, 0xf1, 0x2f, 0x04, 0x5f, 0x01, 0x26, 0xb8, 0xd1, 0xac, 0x3a, 0x5a, 0xea, 0xe0, 0x25, 0xa2, 0x8f, 0x2a, 0x8e, 0x0e, 0xf9, 0x34, 0xfa, 0x77 };
#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// Lotto
#define FUNCNAME IsLottoInput
#define EVALCODE EVAL_LOTTO
const char *LottoCCaddr = "RNXZxgyWSAE6XS3qGnTaf5dVNCxnYzhPrg";
const char *LottoNormaladdr = "RLW6hhRqBZZMBndnyPv29Yg3krh6iBYCyg";
char LottoCChexstr[67] = { "03f72d2c4db440df1e706502b09ca5fec73ffe954ea1883e4049e98da68690d98f" };
uint8_t LottoCCpriv[32] = { 0xb4, 0xac, 0xc2, 0xd9, 0x67, 0x34, 0xd7, 0x58, 0x80, 0x4e, 0x25, 0x55, 0xc0, 0x50, 0x66, 0x84, 0xbb, 0xa2, 0xe7, 0xc0, 0x39, 0x17, 0xb4, 0xc5, 0x07, 0xb7, 0x3f, 0xca, 0x07, 0xb0, 0x9a, 0xeb };
#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// Finite State Machine
#define FUNCNAME IsFSMInput
#define EVALCODE EVAL_FSM
const char *FSMCCaddr = "RUKTbLBeKgHkm3Ss4hKZP3ikuLW1xx7B2x";
const char *FSMNormaladdr = "RWSHRbxnJYLvDjpcQ2i8MekgP6h2ctTKaj";
char FSMCChexstr[67] = { "039b52d294b413b07f3643c1a28c5467901a76562d8b39a785910ae0a0f3043810" };
uint8_t FSMCCpriv[32] = { 0x11, 0xe1, 0xea, 0x3e, 0xdb, 0x36, 0xf0, 0xa8, 0xc6, 0x34, 0xe1, 0x21, 0xb8, 0x02, 0xb9, 0x4b, 0x12, 0x37, 0x8f, 0xa0, 0x86, 0x23, 0x50, 0xb2, 0x5f, 0xe4, 0xe7, 0x36, 0x0f, 0xda, 0xae, 0xfc };
#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// Auction
#define FUNCNAME IsAuctionInput
#define EVALCODE EVAL_AUCTION
const char *AuctionCCaddr = "RL4YPX7JYG3FnvoPqWF2pn3nQknH5NWEwx";
const char *AuctionNormaladdr = "RFtVDNmdTZBTNZdmFRbfBgJ6LitgTghikL";
char AuctionCChexstr[67] = { "037eefe050c14cb60ae65d5b2f69eaa1c9006826d729bc0957bdc3024e3ca1dbe6" };
uint8_t AuctionCCpriv[32] = { 0x8c, 0x1b, 0xb7, 0x8c, 0x02, 0xa3, 0x9d, 0x21, 0x28, 0x59, 0xf5, 0xea, 0xda, 0xec, 0x0d, 0x11, 0xcd, 0x38, 0x47, 0xac, 0x0b, 0x6f, 0x19, 0xc0, 0x24, 0x36, 0xbf, 0x1c, 0x0a, 0x06, 0x31, 0xfb };
#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// MofN
#define FUNCNAME IsMofNInput
#define EVALCODE EVAL_MOFN
const char *MofNCCaddr = "RDVHcSekmXgeYBqRupNTmqo3Rn8QRXNduy";
const char *MofNNormaladdr = "RTPwUjKYECcGn6Y4KYChLhgaht1RSU4jwf";
char MofNCChexstr[67] = { "03c91bef3d7cc59c3a89286833a3446b29e52a5e773f738a1ad2b09785e5f4179e" };
uint8_t MofNCCpriv[32] = { 0x9d, 0xa1, 0xf8, 0xf7, 0xba, 0x0a, 0x91, 0x36, 0x89, 0x9a, 0x86, 0x30, 0x63, 0x20, 0xd7, 0xdf, 0xaa, 0x35, 0xe3, 0x99, 0x32, 0x2b, 0x63, 0xc0, 0x66, 0x9c, 0x93, 0xc4, 0x5e, 0x9d, 0xb9, 0xce };
#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// Channels
#define FUNCNAME IsChannelsInput
#define EVALCODE EVAL_CHANNELS
const char *ChannelsCCaddr = "RQy3rwX8sP9oDm3c39vGKA6H315cgtPLfr";
const char *ChannelsNormaladdr = "RQUuT8zmkvDfXqECH4m3VD3SsHZAfnoh1v";
char ChannelsCChexstr[67] = { "035debdb19b1c98c615259339500511d6216a3ffbeb28ff5655a7ef5790a12ab0b" };
uint8_t ChannelsCCpriv[32] = { 0xec, 0x91, 0x36, 0x15, 0x2d, 0xd4, 0x48, 0x73, 0x22, 0x36, 0x4f, 0x6a, 0x34, 0x5c, 0x61, 0x0f, 0x01, 0xb4, 0x79, 0xe8, 0x1c, 0x2f, 0xa1, 0x1d, 0x4a, 0x0a, 0x21, 0x16, 0xea, 0x82, 0x84, 0x60 };
#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// Oracles
#define FUNCNAME IsOraclesInput
#define EVALCODE EVAL_ORACLES
const char *OraclesCCaddr = "REt2C4ZMnX8YYX1DRpffNA4hECZTFm39e3";
const char *OraclesNormaladdr = "RHkFKzn1csxA3fWzAsxsLWohoCgBbirXb5";
char OraclesCChexstr[67] = { "038c1d42db6a45a57eccb8981b078fb7857b9b496293fe299d2b8d120ac5b5691a" };
uint8_t OraclesCCpriv[32] = { 0xf7, 0x4b, 0x5b, 0xa2, 0x7a, 0x5e, 0x9c, 0xda, 0x89, 0xb1, 0xcb, 0xb9, 0xe6, 0x9c, 0x2c, 0x70, 0x85, 0x37, 0xdd, 0x00, 0x7a, 0x67, 0xff, 0x7c, 0x62, 0x1b, 0xe2, 0xfb, 0x04, 0x8f, 0x85, 0xbf };
#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// Prices
#define FUNCNAME IsPricesInput
#define EVALCODE EVAL_PRICES
const char *PricesCCaddr = "RAL5Vh8NXmFqEKJRKrk1KjKaUckK7mM1iS";
const char *PricesNormaladdr = "RBunXCsMHk5NPd6q8SQfmpgre3x133rSwZ";
char PricesCChexstr[67] = { "039894cb054c0032e99e65e715b03799607aa91212a16648d391b6fa2cc52ed0cf" };
uint8_t PricesCCpriv[32] = { 0x0a, 0x3b, 0xe7, 0x5d, 0xce, 0x06, 0xed, 0xb7, 0xc0, 0xb1, 0xbe, 0xe8, 0x7b, 0x5a, 0xd4, 0x99, 0xb8, 0x8d, 0xde, 0xac, 0xb2, 0x7e, 0x7a, 0x52, 0x96, 0x15, 0xd2, 0xa0, 0xc6, 0xb9, 0x89, 0x61 };
#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// Pegs
#define FUNCNAME IsPegsInput
#define EVALCODE EVAL_PEGS
const char *PegsCCaddr = "RHnkVb7vHuHnjEjhkCF1bS6xxLLNZPv5fd";
const char *PegsNormaladdr = "RMcCZtX6dHf1fz3gpLQhUEMQ8cVZ6Rzaro";
char PegsCChexstr[67] = { "03c75c1de29a35e41606363b430c08be1c2dd93cf7a468229a082cc79c7b77eece" };
uint8_t PegsCCpriv[32] = { 0x52, 0x56, 0x4c, 0x78, 0x87, 0xf7, 0xa2, 0x39, 0xb0, 0x90, 0xb7, 0xb8, 0x62, 0x80, 0x0f, 0x83, 0x18, 0x9d, 0xf4, 0xf4, 0xbd, 0x28, 0x09, 0xa9, 0x9b, 0x85, 0x54, 0x16, 0x0f, 0x3f, 0xfb, 0x65 };
#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// Triggers
#define FUNCNAME IsTriggersInput
#define EVALCODE EVAL_TRIGGERS
const char *TriggersCCaddr = "RGLSRDnUqTB43bYtRtNVgmwSSd1sun2te8";
const char *TriggersNormaladdr = "RMN25Tn8NNzcyQDiQNuMp8UmwLMFd9thYc";
char TriggersCChexstr[67] = { "03afc5be570d0ff419425cfcc580cc762ab82baad88c148f5b028d7db7bfeee61d" };
uint8_t TriggersCCpriv[32] = { 0x7c, 0x0b, 0x54, 0x9b, 0x65, 0xd4, 0x89, 0x57, 0xdf, 0x05, 0xfe, 0xa2, 0x62, 0x41, 0xa9, 0x09, 0x0f, 0x2a, 0x6b, 0x11, 0x2c, 0xbe, 0xbd, 0x06, 0x31, 0x8d, 0xc0, 0xb9, 0x96, 0x76, 0x3f, 0x24 };
#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// Payments
#define FUNCNAME IsPaymentsInput
#define EVALCODE EVAL_PAYMENTS
const char *PaymentsCCaddr = "REpyKi7avsVduqZ3eimncK4uKqSArLTGGK";
const char *PaymentsNormaladdr = "RHRX8RTMAh2STWe9DHqsvJbzS7ty6aZy3d";
char PaymentsCChexstr[67] = { "0358f1764f82c63abc7c7455555fd1d3184905e30e819e97667e247e5792b46856" };
uint8_t PaymentsCCpriv[32] = { 0x03, 0xc9, 0x73, 0xc2, 0xb8, 0x30, 0x3d, 0xbd, 0xc8, 0xd9, 0xbf, 0x02, 0x49, 0xd9, 0x65, 0x61, 0x45, 0xed, 0x9e, 0x93, 0x51, 0xab, 0x8b, 0x2e, 0xe7, 0xc7, 0x40, 0xf1, 0xc4, 0xd2, 0xc0, 0x5b };
#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

// Gateways
#define FUNCNAME IsGatewaysInput
#define EVALCODE EVAL_GATEWAYS
const char *GatewaysCCaddr = "RKWpoK6vTRtq5b9qrRBodLkCzeURHeEk33";
const char *GatewaysNormaladdr = "RGJKV97ZN1wBfunuMt1tebiiHENNEq73Yh";
char GatewaysCChexstr[67] = { "03ea9c062b9652d8eff34879b504eda0717895d27597aaeb60347d65eed96ccb40" };
uint8_t GatewaysCCpriv[32] = { 0xf7, 0x4b, 0x5b, 0xa2, 0x7a, 0x5e, 0x9c, 0xda, 0x89, 0xb1, 0xcb, 0xb9, 0xe6, 0x9c, 0x2c, 0x70, 0x85, 0x37, 0xdd, 0x00, 0x7a, 0x67, 0xff, 0x7c, 0x62, 0x1b, 0xe2, 0xfb, 0x04, 0x8f, 0x85, 0xbf };
#include "CCcustom.inc"
#undef FUNCNAME
#undef EVALCODE

struct CCcontract_info *CCinit(struct CCcontract_info *cp, uint8_t evalcode)
{
    cp->evalcode = evalcode;
    switch ( evalcode )
    {
        case EVAL_STAKEGUARD:
            strcpy(cp->unspendableCCaddr,StakeGuardAddr.c_str());
            strcpy(cp->normaladdr,StakeGuardAddr.c_str());
            strcpy(cp->CChexstr,StakeGuardPubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(StakeGuardWIF).begin(),32);
            cp->validate = StakeGuardValidate;
            cp->ismyvin = IsStakeGuardInput;  // TODO: these input functions are not useful for new CCs
            cp->contextualprecheck = PrecheckStakeGuardOutput;
            break;

        case EVAL_CURRENCY_DEFINITION:
            strcpy(cp->unspendableCCaddr,PBaaSDefinitionAddr.c_str());
            strcpy(cp->normaladdr,PBaaSDefinitionAddr.c_str());
            strcpy(cp->CChexstr,PBaaSDefinitionPubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(PBaaSDefinitionWIF).begin(),32);
            cp->validate = ValidateCurrencyDefinition;
            cp->ismyvin = IsCurrencyDefinitionInput;
            cp->contextualprecheck = PrecheckCurrencyDefinition;
            break;

        case EVAL_EARNEDNOTARIZATION:
            strcpy(cp->unspendableCCaddr,EarnedNotarizationAddr.c_str());
            strcpy(cp->normaladdr,EarnedNotarizationAddr.c_str());
            strcpy(cp->CChexstr,EarnedNotarizationPubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(EarnedNotarizationWIF).begin(),32);
            cp->validate = ValidateEarnedNotarization;
            cp->ismyvin = IsEarnedNotarizationInput;
            cp->contextualprecheck = PreCheckAcceptedOrEarnedNotarization;
            break;

        case EVAL_ACCEPTEDNOTARIZATION:
            strcpy(cp->unspendableCCaddr,AcceptedNotarizationAddr.c_str());
            strcpy(cp->normaladdr,AcceptedNotarizationAddr.c_str());
            strcpy(cp->CChexstr,AcceptedNotarizationPubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(AcceptedNotarizationWIF).begin(),32);
            cp->validate = ValidateAcceptedNotarization;
            cp->ismyvin = IsAcceptedNotarizationInput;
            cp->contextualprecheck = PreCheckAcceptedOrEarnedNotarization;
            break;

        case EVAL_FINALIZE_NOTARIZATION:
            strcpy(cp->unspendableCCaddr,FinalizeNotarizationAddr.c_str());
            strcpy(cp->normaladdr,FinalizeNotarizationAddr.c_str());
            strcpy(cp->CChexstr,FinalizeNotarizationPubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(FinalizeNotarizationWIF).begin(),32);
            cp->validate = ValidateFinalizeNotarization;
            cp->ismyvin = IsFinalizeNotarizationInput;
            cp->contextualprecheck = PreCheckFinalizeNotarization;
            break;

        case EVAL_NOTARY_EVIDENCE:
            strcpy(cp->unspendableCCaddr,NotaryEvidenceAddr.c_str());
            strcpy(cp->normaladdr,NotaryEvidenceAddr.c_str());
            strcpy(cp->CChexstr,NotaryEvidencePubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(NotaryEvidenceWIF).begin(),32);
            cp->validate = ValidateNotaryEvidence;
            cp->ismyvin = IsNotaryEvidenceInput;
            cp->contextualprecheck = DefaultCCContextualPreCheck;
            break;

        case EVAL_RESERVE_OUTPUT:
            strcpy(cp->unspendableCCaddr, ReserveOutputAddr.c_str());
            strcpy(cp->normaladdr, ReserveOutputAddr.c_str());
            strcpy(cp->CChexstr, ReserveOutputPubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(ReserveOutputWIF).begin(),32);
            cp->validate = ValidateReserveOutput;
            cp->ismyvin = IsReserveOutputInput;
            cp->contextualprecheck = DefaultCCContextualPreCheck;
            break;

        case EVAL_IDENTITY_ADVANCEDRESERVATION:
            strcpy(cp->unspendableCCaddr, AdvancedNameReservationAddr.c_str());
            strcpy(cp->normaladdr, AdvancedNameReservationAddr.c_str());
            strcpy(cp->CChexstr, AdvancedNameReservationPubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(AdvancedNameReservationWIF).begin(),32);
            cp->validate = ValidateAdvancedNameReservation;
            cp->ismyvin = IsIdentityInput;
            cp->contextualprecheck = PrecheckIdentityReservation;
            break;

        case EVAL_RESERVE_TRANSFER:
            strcpy(cp->unspendableCCaddr, ReserveTransferAddr.c_str());
            strcpy(cp->normaladdr, ReserveTransferAddr.c_str());
            strcpy(cp->CChexstr, ReserveTransferPubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(ReserveTransferWIF).begin(),32);
            cp->validate = ValidateReserveTransfer;
            cp->ismyvin = IsReserveTransferInput;
            cp->contextualprecheck = PrecheckReserveTransfer;
            break;

        case EVAL_RESERVE_DEPOSIT:
            strcpy(cp->unspendableCCaddr, ReserveDepositAddr.c_str());
            strcpy(cp->normaladdr, ReserveDepositAddr.c_str());
            strcpy(cp->CChexstr, ReserveDepositPubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(ReserveDepositWIF).begin(),32);
            cp->validate = ValidateReserveDeposit;
            cp->ismyvin = IsReserveDepositInput;
            cp->contextualprecheck = PrecheckReserveDeposit;
            break;

        case EVAL_CROSSCHAIN_IMPORT:
            strcpy(cp->unspendableCCaddr, CrossChainImportAddr.c_str());
            strcpy(cp->normaladdr, CrossChainImportAddr.c_str());
            strcpy(cp->CChexstr, CrossChainImportPubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(CrossChainImportWIF).begin(),32);
            cp->validate = ValidateCrossChainImport;
            cp->ismyvin = IsCrossChainImportInput;
            cp->contextualprecheck = PrecheckCrossChainImport;
            break;

        case EVAL_CROSSCHAIN_EXPORT:
            strcpy(cp->unspendableCCaddr, CrossChainExportAddr.c_str());
            strcpy(cp->normaladdr, CrossChainExportAddr.c_str());
            strcpy(cp->CChexstr, CrossChainExportPubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(CrossChainExportWIF).begin(),32);
            cp->validate = ValidateCrossChainExport;
            cp->ismyvin = IsCrossChainExportInput;
            cp->contextualprecheck = PrecheckCrossChainExport;
            break;

        case EVAL_CURRENCYSTATE:
            strcpy(cp->unspendableCCaddr,CurrencyStateAddr.c_str());
            strcpy(cp->normaladdr,CurrencyStateAddr.c_str());
            strcpy(cp->CChexstr, CurrencyStatePubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(CurrencyStateWIF).begin(),32);
            cp->validate = ValidateCurrencyState;
            cp->ismyvin = IsCurrencyStateInput;
            cp->contextualprecheck = DefaultCCContextualPreCheck;
            break;

        case EVAL_IDENTITY_PRIMARY:
            strcpy(cp->unspendableCCaddr, IdentityPrimaryAddr.c_str());
            strcpy(cp->normaladdr, IdentityPrimaryAddr.c_str());
            strcpy(cp->CChexstr, IdentityPrimaryPubKey.c_str());
            memcpy(cp->CCpriv, DecodeSecret(IdentityPrimaryWIF).begin(),32);
            cp->validate = ValidateIdentityPrimary;
            cp->ismyvin = IsIdentityInput;
            cp->contextualprecheck = &PrecheckIdentityPrimary;
            break;

        case EVAL_IDENTITY_REVOKE:
            strcpy(cp->unspendableCCaddr, IdentityRevokeAddr.c_str());
            strcpy(cp->normaladdr, IdentityRevokeAddr.c_str());
            strcpy(cp->CChexstr, IdentityRevokePubKey.c_str());
            memcpy(cp->CCpriv, DecodeSecret(IdentityRevokeWIF).begin(),32);
            cp->validate = ValidateIdentityRevoke;
            cp->ismyvin = IsIdentityInput;
            cp->contextualprecheck = DefaultCCContextualPreCheck;
            break;

        case EVAL_IDENTITY_RECOVER:
            strcpy(cp->unspendableCCaddr, IdentityRecoverAddr.c_str());
            strcpy(cp->normaladdr, IdentityRecoverAddr.c_str());
            strcpy(cp->CChexstr, IdentityRecoverPubKey.c_str());
            memcpy(cp->CCpriv, DecodeSecret(IdentityRecoverWIF).begin(),32);
            cp->validate = ValidateIdentityRecover;
            cp->ismyvin = IsIdentityInput;
            cp->contextualprecheck = DefaultCCContextualPreCheck;
            break;

        case EVAL_IDENTITY_COMMITMENT:
            strcpy(cp->unspendableCCaddr, IdentityCommitmentAddr.c_str());
            strcpy(cp->normaladdr, IdentityCommitmentAddr.c_str());
            strcpy(cp->CChexstr, IdentityCommitmentPubKey.c_str());
            memcpy(cp->CCpriv, DecodeSecret(IdentityCommitmentWIF).begin(),32);
            cp->validate = ValidateIdentityCommitment;
            cp->ismyvin = IsIdentityInput;
            cp->contextualprecheck = PrecheckIdentityCommitment;
            break;

        case EVAL_IDENTITY_RESERVATION:
            strcpy(cp->unspendableCCaddr, IdentityReservationAddr.c_str());
            strcpy(cp->normaladdr, IdentityReservationAddr.c_str());
            strcpy(cp->CChexstr, IdentityReservationPubKey.c_str());
            memcpy(cp->CCpriv, DecodeSecret(IdentityReservationWIF).begin(),32);
            cp->validate = ValidateIdentityReservation;
            cp->ismyvin = IsIdentityInput;
            cp->contextualprecheck = PrecheckIdentityReservation;
            break;

        case EVAL_FINALIZE_EXPORT:
            strcpy(cp->unspendableCCaddr,FinalizeExportAddr.c_str());
            strcpy(cp->normaladdr,FinalizeExportAddr.c_str());
            strcpy(cp->CChexstr,FinalizeExportPubKey.c_str());
            memcpy(cp->CCpriv,DecodeSecret(FinalizeExportWIF).begin(),32);
            cp->validate = ValidateFinalizeExport;
            cp->ismyvin = IsFinalizeExportInput;  // TODO: these input functions are not useful for new CCs
            cp->contextualprecheck = PreCheckFinalizeExport;
            break;

        case EVAL_FEE_POOL:
            strcpy(cp->unspendableCCaddr, FeePoolAddr.c_str());
            strcpy(cp->normaladdr, FeePoolAddr.c_str());
            strcpy(cp->CChexstr, FeePoolPubKey.c_str());
            memcpy(cp->CCpriv, DecodeSecret(FeePoolWIF).begin(),32);
            cp->validate = ValidateFeePool;
            cp->ismyvin = IsFeePoolInput;
            cp->contextualprecheck = PrecheckFeePool;
            break;

        case EVAL_QUANTUM_KEY:
            strcpy(cp->unspendableCCaddr, QuantumKeyOutAddr.c_str());
            strcpy(cp->normaladdr, QuantumKeyOutAddr.c_str());
            strcpy(cp->CChexstr, QuantumKeyOutPubKey.c_str());     // ironically, this does not need to be a quantum secure public key, since privkey is public
            memcpy(cp->CCpriv, DecodeSecret(QuantumKeyOutWIF).begin(),32);
            cp->validate = ValidateQuantumKeyOut;
            cp->ismyvin = IsQuantumKeyOutInput;
            cp->contextualprecheck = PrecheckQuantumKeyOut;
            break;

        // these are currently not used and should be triple checked if reenabled
        case EVAL_ASSETS:
            strcpy(cp->unspendableCCaddr,AssetsCCaddr);
            strcpy(cp->normaladdr,AssetsNormaladdr);
            strcpy(cp->CChexstr,AssetsCChexstr);
            memcpy(cp->CCpriv,AssetsCCpriv,32);
            cp->validate = AssetsValidate;
            cp->ismyvin = IsAssetsInput;
            break;
        case EVAL_FAUCET:
            strcpy(cp->unspendableCCaddr,FaucetCCaddr);
            strcpy(cp->normaladdr,FaucetNormaladdr);
            strcpy(cp->CChexstr,FaucetCChexstr);
            memcpy(cp->CCpriv,FaucetCCpriv,32);
            cp->validate = FaucetValidate;
            cp->ismyvin = IsFaucetInput;
            break;
        case EVAL_REWARDS:
            strcpy(cp->unspendableCCaddr,RewardsCCaddr);
            strcpy(cp->normaladdr,RewardsNormaladdr);
            strcpy(cp->CChexstr,RewardsCChexstr);
            memcpy(cp->CCpriv,RewardsCCpriv,32);
            cp->validate = RewardsValidate;
            cp->ismyvin = IsRewardsInput;
            break;
        case EVAL_DICE:
            strcpy(cp->unspendableCCaddr,DiceCCaddr);
            strcpy(cp->normaladdr,DiceNormaladdr);
            strcpy(cp->CChexstr,DiceCChexstr);
            memcpy(cp->CCpriv,DiceCCpriv,32);
            cp->validate = DiceValidate;
            cp->ismyvin = IsDiceInput;
            break;
        case EVAL_LOTTO:
            strcpy(cp->unspendableCCaddr,LottoCCaddr);
            strcpy(cp->normaladdr,LottoNormaladdr);
            strcpy(cp->CChexstr,LottoCChexstr);
            memcpy(cp->CCpriv,LottoCCpriv,32);
            cp->validate = LottoValidate;
            cp->ismyvin = IsLottoInput;
            break;
        case EVAL_FSM:
            strcpy(cp->unspendableCCaddr,FSMCCaddr);
            strcpy(cp->normaladdr,FSMNormaladdr);
            strcpy(cp->CChexstr,FSMCChexstr);
            memcpy(cp->CCpriv,FSMCCpriv,32);
            cp->validate = FSMValidate;
            cp->ismyvin = IsFSMInput;
            break;
        case EVAL_AUCTION:
            strcpy(cp->unspendableCCaddr,AuctionCCaddr);
            strcpy(cp->normaladdr,AuctionNormaladdr);
            strcpy(cp->CChexstr,AuctionCChexstr);
            memcpy(cp->CCpriv,AuctionCCpriv,32);
            cp->validate = AuctionValidate;
            cp->ismyvin = IsAuctionInput;
            break;
        case EVAL_MOFN:
            strcpy(cp->unspendableCCaddr,MofNCCaddr);
            strcpy(cp->normaladdr,MofNNormaladdr);
            strcpy(cp->CChexstr,MofNCChexstr);
            memcpy(cp->CCpriv,MofNCCpriv,32);
            cp->validate = MofNValidate;
            cp->ismyvin = IsMofNInput;
            break;
        case EVAL_CHANNELS:
            strcpy(cp->unspendableCCaddr,ChannelsCCaddr);
            strcpy(cp->normaladdr,ChannelsNormaladdr);
            strcpy(cp->CChexstr,ChannelsCChexstr);
            memcpy(cp->CCpriv,ChannelsCCpriv,32);
            cp->validate = ChannelsValidate;
            cp->ismyvin = IsChannelsInput;
            break;
        case EVAL_ORACLES:
            strcpy(cp->unspendableCCaddr,OraclesCCaddr);
            strcpy(cp->normaladdr,OraclesNormaladdr);
            strcpy(cp->CChexstr,OraclesCChexstr);
            memcpy(cp->CCpriv,OraclesCCpriv,32);
            cp->validate = OraclesValidate;
            cp->ismyvin = IsOraclesInput;
            break;
        case EVAL_PRICES:
            strcpy(cp->unspendableCCaddr,PricesCCaddr);
            strcpy(cp->normaladdr,PricesNormaladdr);
            strcpy(cp->CChexstr,PricesCChexstr);
            memcpy(cp->CCpriv,PricesCCpriv,32);
            cp->validate = PricesValidate;
            cp->ismyvin = IsPricesInput;
            break;
        case EVAL_PEGS:
            strcpy(cp->unspendableCCaddr,PegsCCaddr);
            strcpy(cp->normaladdr,PegsNormaladdr);
            strcpy(cp->CChexstr,PegsCChexstr);
            memcpy(cp->CCpriv,PegsCCpriv,32);
            cp->validate = PegsValidate;
            cp->ismyvin = IsPegsInput;
            break;
        case EVAL_TRIGGERS:
            strcpy(cp->unspendableCCaddr,TriggersCCaddr);
            strcpy(cp->normaladdr,TriggersNormaladdr);
            strcpy(cp->CChexstr,TriggersCChexstr);
            memcpy(cp->CCpriv,TriggersCCpriv,32);
            cp->validate = TriggersValidate;
            cp->ismyvin = IsTriggersInput;
            break;
        case EVAL_PAYMENTS:
            strcpy(cp->unspendableCCaddr,PaymentsCCaddr);
            strcpy(cp->normaladdr,PaymentsNormaladdr);
            strcpy(cp->CChexstr,PaymentsCChexstr);
            memcpy(cp->CCpriv,PaymentsCCpriv,32);
            cp->validate = PaymentsValidate;
            cp->ismyvin = IsPaymentsInput;
            break;
        case EVAL_GATEWAYS:
            strcpy(cp->unspendableCCaddr,GatewaysCCaddr);
            strcpy(cp->normaladdr,GatewaysNormaladdr);
            strcpy(cp->CChexstr,GatewaysCChexstr);
            memcpy(cp->CCpriv,GatewaysCCpriv,32);
            cp->validate = GatewaysValidate;
            cp->ismyvin = IsGatewaysInput;
            break;
    }
    return(cp);
}
