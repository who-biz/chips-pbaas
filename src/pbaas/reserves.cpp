/********************************************************************
 * (C) 2019 Michael Toutonghi
 * 
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 * 
 * This provides reserve currency functions, leveraging the multi-precision boost libraries to calculate reserve currency conversions.
 * 
 */

#include "main.h"
#include "pbaas/pbaas.h"
#include "pbaas/reserves.h"
#include "pbaas/notarization.h"
#include "rpc/pbaasrpc.h"
#include "rpc/server.h"
#include "key_io.h"
#include <random>


// calculate fees required in one currency to pay in another
CAmount CReserveTransfer::CalculateTransferFee(const CTransferDestination &destination, uint32_t flags)
{
    if (flags & FEE_OUTPUT)
    {
        return 0;
    }
    return (((CAmount)CReserveTransfer::DEFAULT_PER_STEP_FEE) << 1) + ((((CAmount)CReserveTransfer::DEFAULT_PER_STEP_FEE) << 1) * (destination.destination.size() / (int32_t)DESTINATION_BYTE_DIVISOR));
}

CAmount CReserveTransfer::CalculateTransferFee() const
{
    // determine fee for this send
    return CalculateTransferFee(destination, flags);
}

CCurrencyValueMap CReserveTransfer::TotalTransferFee() const
{
    CCurrencyValueMap retVal;
    CAmount transferFee = nFees;
    if (destination.HasGatewayLeg() && destination.fees)
    {
        transferFee += destination.fees;
    }
    retVal.valueMap[feeCurrencyID] += transferFee;
    return retVal;
}

CCurrencyValueMap CReserveTransfer::ConversionFee() const
{
    CCurrencyValueMap retVal;
    // add conversion fees in source currency for conversions or pre-conversions
    if (IsConversion() || IsPreConversion())
    {
        for (auto &oneCur : reserveValues.valueMap)
        {
            retVal.valueMap[oneCur.first] += CReserveTransactionDescriptor::CalculateConversionFee(oneCur.second);
        }
        if (IsReserveToReserve())
        {
            retVal = retVal * 2;
        }
    }
    return retVal;
}

CCurrencyValueMap CReserveTransfer::CalculateFee(uint32_t flags, CAmount transferTotal) const
{
    CCurrencyValueMap feeMap;

    feeMap.valueMap[feeCurrencyID] = CalculateTransferFee();

    // add conversion fees in source currency for conversions or pre-conversions
    if (IsConversion() || IsPreConversion())
    {
        for (auto &oneCur : reserveValues.valueMap)
        {
            feeMap.valueMap[oneCur.first] += CReserveTransactionDescriptor::CalculateConversionFee(oneCur.second);
        }
        if (IsReserveToReserve())
        {
            feeMap = feeMap * 2;
        }
    }

    // consider extra-leg pricing here

    return feeMap;
}

CCrossChainImport::CCrossChainImport(const CScript &script)
{
    COptCCParams p;
    if (IsPayToCryptoCondition(script, p) && p.IsValid())
    {
        // always take the first for now
        if (p.evalCode == EVAL_CROSSCHAIN_IMPORT && p.vData.size())
        {
            FromVector(p.vData[0], *this);
        }
    }
}

CCrossChainImport::CCrossChainImport(const CTransaction &tx, int32_t *pOutNum)
{
    for (int i = 0; i < tx.vout.size(); i++)
    {
        COptCCParams p;
        if (IsPayToCryptoCondition(tx.vout[i].scriptPubKey, p) && p.IsValid())
        {
            // always take the first for now
            if (p.evalCode == EVAL_CROSSCHAIN_IMPORT && p.vData.size())
            {
                FromVector(p.vData[0], *this);
                if (pOutNum)
                {
                    *pOutNum = i;
                }
                break;
            }
        }
    }
}

bool CCrossChainExport::GetExportInfo(const CTransaction &exportTx, 
                                      int numExportOut,
                                      int &primaryExportOutNumOut,
                                      int32_t &nextOutput,
                                      CPBaaSNotarization &exportNotarization,
                                      std::vector<CReserveTransfer> &reserveTransfers,
                                      CValidationState &state,
                                      CCurrencyDefinition::EProofProtocol hashType) const
{
    // we can assume that to get here, we have decoded the first output, which is the export output
    // specified in numExportOut, our "this" pointer

    // if this is called directly to get info, though it is a supplemental output, it is currently an error
    if (IsSupplemental())
    {
        return state.Error(strprintf("%s: cannot get export data directly from a supplemental data output. must be in context",__func__));
    }

    CNativeHashWriter hw(hashType);

    // this can be called passing either a system export or a normal currency export, and it will always
    // retrieve information from the same normal currency export in either case and return the primary output num
    int numOutput = IsSystemThreadExport() ? numExportOut - 1 : numExportOut;
    if (numOutput < 0)
    {
        return state.Error(strprintf("%s: invalid output index for export out or invalid export transaction",__func__));
    }
    primaryExportOutNumOut = numOutput;

    // if this export is from our system
    if (sourceSystemID == ASSETCHAINS_CHAINID)
    {
        // if we're exporting off-chain and not directly to the system currency,
        // the system currency is added as a system export output, which ensures export serialization from this system
        // to the other. the system export output will be after our currency export. if so skip it.
        if (destSystemID != sourceSystemID && destCurrencyID != destSystemID)
        {
            numOutput++;
        }

        // retrieve reserve transfers from export transaction inputs
        if (numInputs > 0)
        {
            for (int i = firstInput; i < (firstInput + numInputs); i++)
            {
                CTransaction rtTx;
                COptCCParams rtP;
                CReserveTransfer rt;
                uint256 hashBlk;
                if (!(myGetTransaction(exportTx.vin[i].prevout.hash, rtTx, hashBlk) &&
                        exportTx.vin[i].prevout.n < rtTx.vout.size() &&
                        rtTx.vout[exportTx.vin[i].prevout.n].scriptPubKey.IsPayToCryptoCondition(rtP) &&
                        rtP.IsValid() &&
                        rtP.evalCode == EVAL_RESERVE_TRANSFER &&
                        rtP.vData.size() &&
                        (rt = CReserveTransfer(rtP.vData[0])).IsValid()))
                {
                    return state.Error(strprintf("%s: invalid reserve transfer for export",__func__));
                }
                hw << rt;
                reserveTransfers.push_back(rt);
            }
        }
    }
    else
    {
        // this is coming from another chain or system.
        // the proof of this export must already have been checked, so we are
        // only interested in the reserve transfers for this and any supplements
        CCrossChainExport rtExport = *this;
        while (rtExport.IsValid())
        {
            COptCCParams p;
            for (auto &oneRt : rtExport.reserveTransfers)
            {
                hw << oneRt;
                reserveTransfers.push_back(oneRt);
            }
            numOutput++;
            if (!(exportTx.vout.size() > numOutput &&
                  exportTx.vout[numOutput].scriptPubKey.IsPayToCryptoCondition(p) &&
                  p.IsValid() &&
                  p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
                  p.vData.size() &&
                  (rtExport = CCrossChainExport(p.vData[0])).IsValid() &&
                  rtExport.IsSupplemental()))
            {
                numOutput--;
                rtExport = CCrossChainExport();
            }
        }
    }

    // now, we should have accurate reserve transfers
    uint256 rtHash;
    if (reserveTransfers.size())
    {
        rtHash = hw.GetHash();
    }
    if (rtHash != hashReserveTransfers)
    {
        return state.Error(strprintf("%s: reserve transfers do not match reserve transfer hash in export",__func__));
    }

    exportNotarization = CPBaaSNotarization();

    if (IsSameChain() && !IsChainDefinition())
    {
        // checking sourceHeightEnd being creater than 1 ensures that we can legitimately
        // expect an export finalization to follow
        // TODO: HARDENING - confirm that we leave no issue with an adversarially constructed export with sourceHeightEnd of 1
        if (IsClearLaunch() || (!IsPrelaunch() && sourceHeightEnd > 1))
        {
            numOutput++;
            COptCCParams p;
            // we have an export finalization to verify/skip
            if (!(exportTx.vout.size() > numOutput &&
                    exportTx.vout[numOutput].scriptPubKey.IsPayToCryptoCondition(p) &&
                    p.IsValid() &&
                    p.evalCode == EVAL_FINALIZE_EXPORT &&
                    p.vData.size() &&
                    (CObjectFinalization(p.vData[0])).IsValid()))
            {
                return state.Error(strprintf("%s: invalid export finalization",__func__));
            }
        }
        if ((IsPrelaunch() || IsClearLaunch()))
        {
            // in same chain before launch, we expect a notarization to follow
            numOutput++;
            COptCCParams p;
            if (!(exportTx.vout.size() > numOutput &&
                exportTx.vout[numOutput].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                (p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION) &&
                p.vData.size() &&
                (exportNotarization = CPBaaSNotarization(p.vData[0])).IsValid()))
            {
                return state.Error(strprintf("%s: invalid export notarization",__func__));
            }
        }
    }
    nextOutput = numOutput + 1;
    return true;
}

bool CCrossChainExport::GetExportInfo(const CTransaction &exportTx, 
                                    int numExportOut, 
                                    int &primaryExportOutNumOut,
                                    int32_t &nextOutput,
                                    CPBaaSNotarization &exportNotarization, 
                                    std::vector<CReserveTransfer> &reserveTransfers,
                                    CCurrencyDefinition::EProofProtocol hashType) const
{
    CValidationState state;
    return GetExportInfo(exportTx, numExportOut, primaryExportOutNumOut, nextOutput, exportNotarization, reserveTransfers, state, hashType);
}

bool GetNotarizationFromOutput(const CTransaction tx, int32_t outNum, CValidationState &state, CPBaaSNotarization &outNotarization)
{
    COptCCParams p;
    if (!(tx.vout.size() > outNum &&
          tx.vout[outNum].scriptPubKey.IsPayToCryptoCondition(p) &&
          p.IsValid() &&
          (p.evalCode == EVAL_ACCEPTEDNOTARIZATION || p.evalCode == EVAL_EARNEDNOTARIZATION) &&
          p.vData.size() &&
          (outNotarization = CPBaaSNotarization(p.vData[0])).IsValid()))
    {
        return state.Error(strprintf("%s: invalid import notarization for import",__func__));
    }
    return true;
}

bool CCrossChainImport::GetImportInfo(const CTransaction &importTx, 
                                      uint32_t nHeight,
                                      int numImportOut, 
                                      CCrossChainExport &ccx,
                                      CCrossChainImport &sysCCI,
                                      int32_t &sysCCIOut,
                                      CPBaaSNotarization &importNotarization,
                                      int32_t &importNotarizationOut,
                                      int32_t &evidenceOutStart,
                                      int32_t &evidenceOutEnd,
                                      std::vector<CReserveTransfer> &reserveTransfers,
                                      CValidationState &state) const
{
    // we can assume that to get here, we have decoded the first output, which is the import output
    // specified in numImportOut, our "this" pointer

    // following that, we should find in order:
    //
    // 1. Optional system import output, present only if we are importing to non-gateway, non-native currency from an external system or PBaaS chain
    //
    // 2. any necessary export proof for the import, present only if we are coming from an external system or PBaaS chain
    //
    // 3. if we are coming from an external system or PBaaS chain, following outputs will include the reserve transfers for the export proof
    //
    // 4. Notarization for import currency, only present if this is fractional currency or first launch of new PBaaS chain
    // 

    sysCCIOut = -1;
    evidenceOutStart = -1;
    evidenceOutEnd = -1;
    CCurrencyDefinition::EProofProtocol hashType = CCurrencyDefinition::EProofProtocol::PROOF_PBAASMMR;

    CCrossChainImport sysCCITemp;

    // we cannot assert that cs_main is held or take cs_main here due to the multi-threaded validation model, 
    // but we must either be holding the lock to enter here or in service of a smart transaction at this point.
    LOCK(mempool.cs);

    uint32_t solutionVersion = CConstVerusSolutionVector::GetVersionByHeight(nHeight);

    CCrossChainImport altImport;
    const CCrossChainImport *pBaseImport = this;

    // if this is a source system import, it comes after the actual import
    // that we can parse on a transaction
    if (pBaseImport->IsSourceSystemImport()) 
    {
        if (!(numImportOut-- > 0 &&
              (altImport = CCrossChainImport(importTx.vout[numImportOut].scriptPubKey)).IsValid() &&
              !(pBaseImport = &altImport)->IsSourceSystemImport()))
        {
            return state.Error(strprintf("%s: invalid import",__func__));
        }
    }

    bool isPBaaSDefinitionOrLaunch = (!IsVerusActive() && pBaseImport->IsInitialLaunchImport()) || 
                                     (pBaseImport->IsDefinitionImport() &&
                                      pBaseImport->sourceSystemID != ASSETCHAINS_CHAINID);

    importNotarizationOut = numImportOut + 1;

    if (pBaseImport->IsSameChain())
    {
        // reserve transfers are available via the inputs to the matching export
        CTransaction exportTx = pBaseImport->exportTxId.IsNull() ? importTx : CTransaction();
        uint256 hashBlk;
        COptCCParams p;

        if (!((pBaseImport->exportTxId.IsNull() ? true : myGetTransaction(pBaseImport->exportTxId, exportTx, hashBlk)) &&
              pBaseImport->IsDefinitionImport() ||
              (pBaseImport->exportTxOutNum >= 0 &&
              exportTx.vout.size() > pBaseImport->exportTxOutNum &&
              exportTx.vout[pBaseImport->exportTxOutNum].scriptPubKey.IsPayToCryptoCondition(p) &&
              p.IsValid() &&
              p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
              p.vData.size() &&
              (ccx = CCrossChainExport(p.vData[0])).IsValid())))
        {
            return state.Error(strprintf("%s: cannot retrieve export transaction for import",__func__));
        }

        // next output after import out is notarization
        if (!GetNotarizationFromOutput(importTx, importNotarizationOut, state, importNotarization))
        {
            // if error, state will be set
            return false;
        }

        if (!pBaseImport->IsDefinitionImport())
        {
            int32_t nextOutput;
            CPBaaSNotarization xNotarization;
            int primaryOutNumOut;
            if (!ccx.GetExportInfo(exportTx, pBaseImport->exportTxOutNum, primaryOutNumOut, nextOutput, xNotarization, reserveTransfers, state))
            {
                return false;
            }
        }
    }
    else
    {
        COptCCParams p;

        // PBaaS launch imports do not spend a separate sys import thread, since we are also importing 
        // system currency on the same tx and and the coinbase has no inputs anyhow
        if (!isPBaaSDefinitionOrLaunch && pBaseImport->sourceSystemID != pBaseImport->importCurrencyID)
        {
            // next output should be the import for the system from which this export comes
            uint256 hashBlk;
            sysCCIOut = numImportOut + 1;
            if (!(sysCCIOut >= 0 &&
                importTx.vout.size() > sysCCIOut &&
                importTx.vout[sysCCIOut].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
                p.vData.size() &&
                (sysCCITemp = CCrossChainImport(p.vData[0])).IsValid()))
            {
                return state.Error(strprintf("%s: cannot retrieve export evidence for import",__func__));
            }

            importNotarizationOut++;
        }

        if (!GetNotarizationFromOutput(importTx, importNotarizationOut, state, importNotarization))
        {
            // if error, state will be set
            return false;
        }

        // TODO: HARDENING - review to ensure that if this is skipped an error is thrown when appropriate
        if (!isPBaaSDefinitionOrLaunch &&
            (pBaseImport->importCurrencyID == ASSETCHAINS_CHAINID ||
             (!pBaseImport->importCurrencyID.IsNull() && pBaseImport->importCurrencyID == ConnectedChains.ThisChain().GatewayConverterID())))
        {
            // next output should be export in evidence output followed by supplemental reserve transfers for the export
            evidenceOutStart = importNotarizationOut + 1;
            int afterEvidence;
            CNotaryEvidence evidence(importTx, evidenceOutStart, afterEvidence, CNotaryEvidence::TYPE_IMPORT_PROOF);

            if (!evidence.IsValid())
            {
                // TODO: remove the line assigning evidence just below, as it is only for debugging
                evidence = CNotaryEvidence(importTx, evidenceOutStart, afterEvidence);

                return state.Error(strprintf("%s: cannot retrieve export evidence for import", __func__));
            }

            std::set<int> validEvidenceTypes;
            validEvidenceTypes.insert(CHAINOBJ_TRANSACTION_PROOF);
            CNotaryEvidence transactionProof(sysCCITemp.sourceSystemID, evidence.output, evidence.state, evidence.GetSelectEvidence(validEvidenceTypes), CNotaryEvidence::TYPE_IMPORT_PROOF);

            /*
            // reconstruct evidence if necessary 
            if (evidence.IsPartialTxProof() &&
                evidence.evidence.size())

            // reconstruct multipart evidence if necessary
            if (evidence.IsMultipartProof())
            {
                COptCCParams eP;
                CNotaryEvidence supplementalEvidence;
                while (importTx.vout.size() > (evidenceOutStart + 1) &&
                       importTx.vout[evidenceOutStart + 1].scriptPubKey.IsPayToCryptoCondition(eP) &&
                       eP.IsValid() &&
                       eP.evalCode == EVAL_NOTARY_EVIDENCE &&
                       eP.vData.size() &&
                       (supplementalEvidence = CNotaryEvidence(eP.vData[0])).IsValid() &&
                       supplementalEvidence.IsPartialTxProof() &&
                       supplementalEvidence.evidence.size() == 1)
                {
                    evidenceOutStart++;
                    evidence.evidence.push_back(supplementalEvidence.evidence[0]);
                }
                if (!eP.IsValid())
                {
                    return state.Error(strprintf("%s: cannot reconstruct export evidence for import", __func__));
                }
                evidence.evidence = std::vector<CPartialTransactionProof>({CPartialTransactionProof(evidence.evidence)});
            }
            */

            CTransaction exportTx;
            p = COptCCParams();
            if (!(transactionProof.evidence.chainObjects.size() &&
                  !((CChainObject<CPartialTransactionProof> *)transactionProof.evidence.chainObjects[0])->object.GetPartialTransaction(exportTx).IsNull() &&
                  ((CChainObject<CPartialTransactionProof> *)transactionProof.evidence.chainObjects[0])->object.TransactionHash() == pBaseImport->exportTxId &&
                  exportTx.vout.size() > pBaseImport->exportTxOutNum &&
                  exportTx.vout[pBaseImport->exportTxOutNum].scriptPubKey.IsPayToCryptoCondition(p) &&
                  p.IsValid() &&
                  p.evalCode == EVAL_CROSSCHAIN_EXPORT &&
                  p.vData.size() &&
                  (ccx = CCrossChainExport(p.vData[0])).IsValid()))
            {
                return state.Error(strprintf("%s: invalid export evidence for import", __func__));
            }

            uint160 externalSystemID = ccx.sourceSystemID == ASSETCHAINS_CHAINID ? 
                                       ((ccx.destSystemID == ASSETCHAINS_CHAINID) ? uint160() : ccx.destSystemID) : 
                                       ccx.sourceSystemID;

            std::map<uint160, CProofRoot>::iterator proofIt;
            if (!externalSystemID.IsNull() &&
                (proofIt = importNotarization.proofRoots.find(externalSystemID)) != importNotarization.proofRoots.end())
            {
                switch (proofIt->second.type)
                {
                    case CProofRoot::TYPE_ETHEREUM:
                    {
                        hashType = CCurrencyDefinition::EProofProtocol::PROOF_ETHNOTARIZATION;
                        break;
                    }
                }
            }
            else if (!externalSystemID.IsNull())
            {
                return state.Error(strprintf("%s: no proof root to validate export for external system %s", __func__, EncodeDestination(CIdentityID(externalSystemID)).c_str()));
            }

            int32_t nextOutput;
            CPBaaSNotarization xNotarization;
            int primaryOutNumOut;
            if (!ccx.GetExportInfo(importTx, evidenceOutStart, primaryOutNumOut, nextOutput, xNotarization, reserveTransfers, hashType))
            {
                //UniValue jsonTx(UniValue::VOBJ);
                //TxToUniv(importTx, uint256(), jsonTx);
                //printf("%s: importTx:\n%s\n", __func__, jsonTx.write(1,2).c_str());
                return state.Error(strprintf("%s: invalid export evidence for import 1",__func__));
            }

            // evidence out end points to the last evidence out, not beyond
            evidenceOutEnd = nextOutput - 1;
        }
    }

    // if we may have an arbitrage reserve transfer, look for it
    if (importNotarization.IsValid() &&
        importNotarization.IsLaunchComplete() &&
        !importNotarization.IsRefunding() &&
        importNotarization.currencyState.IsValid() &&
        importNotarization.currencyState.IsFractional() &&
        ccx.IsValid() &&
        hashReserveTransfers != ccx.hashReserveTransfers)
    {
        // if we don't have an arbitrage reserve transfer, this is an error that the hashes don't match
        // if we do, they cannot match, so get it
        CReserveTransfer arbitrageTransfer = GetArbitrageTransfer(importTx, numImportOut, state, nHeight);
        if (!arbitrageTransfer.IsValid())
        {
            return state.Error(strprintf("%s: export and import hash mismatch without valid arbitrage transfer",__func__));
        }
        reserveTransfers.push_back(arbitrageTransfer);
        CNativeHashWriter nhw1(hashType);
        CNativeHashWriter nhw2(hashType);
        for (int i = 0; i < reserveTransfers.size(); i++)
        {
            nhw1 << reserveTransfers[i];
            // if this is not the last, add it into the 2nd hash, which should then match the export
            if (i + 1 < reserveTransfers.size())
            {
                nhw2 << reserveTransfers[i];
            }
        }
        if (hashReserveTransfers != nhw1.GetHash() || ccx.hashReserveTransfers != nhw2.GetHash())
        {
            return state.Error(strprintf("%s: import hash of transfers does not match actual transfers with arbitrage",__func__));
        }
    }

    if (sysCCITemp.IsValid())
    {
        sysCCI = sysCCITemp;
    }
    else if (pBaseImport->sourceSystemID == pBaseImport->importCurrencyID)
    {
        sysCCI = *pBaseImport;
    }
    return true;
}

// returns a currency map that is the price in each currency for the target currency specified
// based on a given fractional currency state
int64_t CCoinbaseCurrencyState::TargetConversionPrice(const uint160 &sourceCurrencyID, const uint160 &targetCurrencyID) const
{
    if (!IsFractional())
    {
        return 0;
    }
    CCurrencyValueMap currencyMap(currencies, PricesInReserve());

    if ((sourceCurrencyID != GetID() && !currencyMap.valueMap.count(sourceCurrencyID)) ||
        (targetCurrencyID != GetID() && !currencyMap.valueMap.count(targetCurrencyID)))
    {
        return 0;
    }
    if (sourceCurrencyID == targetCurrencyID)
    {
        return SATOSHIDEN;
    }
    else if (targetCurrencyID == GetID())
    {
        return currencyMap.valueMap[sourceCurrencyID];
    }
    else if (sourceCurrencyID == GetID())
    {
        return ReserveToNativeRaw(SATOSHIDEN, currencyMap.valueMap[targetCurrencyID]);
    }
    else
    {
        // reserve to reserve in reverse
        return NativeToReserveRaw(ReserveToNativeRaw(SATOSHIDEN, currencyMap.valueMap[targetCurrencyID]), currencyMap.valueMap[sourceCurrencyID]);
    }
}

CCurrencyValueMap CCoinbaseCurrencyState::TargetConversionPrices(const uint160 &targetCurrencyID) const
{
    CCurrencyValueMap retVal(std::vector<uint160>({targetCurrencyID}), std::vector<int64_t>({SATOSHIDEN}));
    if (!IsFractional())
    {
        return retVal;
    }
    CCurrencyValueMap currencyMap(currencies, PricesInReserve());

    if (targetCurrencyID != GetID() && !currencyMap.valueMap.count(targetCurrencyID))
    {
        return retVal;
    }

    if (targetCurrencyID == GetID())
    {
        retVal = currencyMap;
        retVal.valueMap[GetID()] = SATOSHIDEN;
    }
    else
    {
        retVal.valueMap[GetID()] = NativeToReserveRaw(SATOSHIDEN, currencyMap.valueMap[targetCurrencyID]);

        for (auto &oneCur : currencies)
        {
            // reserve to reserve in reverse
            retVal.valueMap[oneCur] = oneCur == targetCurrencyID ?
                SATOSHIDEN :
                NativeToReserveRaw(ReserveToNativeRaw(SATOSHIDEN, currencyMap.valueMap[targetCurrencyID]), currencyMap.valueMap[oneCur]);
        }
    }
    return retVal;
}

CCurrencyValueMap CCoinbaseCurrencyState::TargetConversionPricesReverse(const uint160 &targetCurrencyID, bool addFeePct) const
{
    CAmount extraFeeAmount = addFeePct ? CReserveTransactionDescriptor::CalculateConversionFeeNoMin(SATOSHIDEN) : 0;

    CCurrencyValueMap retVal(std::vector<uint160>({targetCurrencyID}), std::vector<int64_t>({(int64_t)SATOSHIDEN - extraFeeAmount}));
    CCurrencyValueMap currencyMap(currencies, PricesInReserve(true));
    bool targetIsPrimary = targetCurrencyID == GetID();
    if (!IsFractional() || (!targetIsPrimary && !currencyMap.valueMap.count(targetCurrencyID)))
    {
        return retVal;
    }
    if (!targetIsPrimary)
    {
        if (!currencyMap.valueMap.count(targetCurrencyID))
        {
            return retVal;
        }
    }

    if (targetIsPrimary)
    {
        for (auto &onePrice : currencyMap.valueMap)
        {
            retVal.valueMap[onePrice.first] = ReserveToNativeRaw(SATOSHIDEN - extraFeeAmount, onePrice.second);
        }
    }
    else
    {
        retVal.valueMap[GetID()] = NativeToReserveRaw(SATOSHIDEN - extraFeeAmount, currencyMap.valueMap[targetCurrencyID]);
        extraFeeAmount <<= 1;

        for (auto &oneCur : currencies)
        {
            // reserve to reserve in reverse
            if (oneCur == targetCurrencyID)
            {
                retVal.valueMap[oneCur] = SATOSHIDEN - extraFeeAmount;
            }
            else
            {
                CAmount firstVal = NativeToReserveRaw(SATOSHIDEN - extraFeeAmount, currencyMap.valueMap[targetCurrencyID]);

                retVal.valueMap[oneCur] = ReserveToNativeRaw(
                    NativeToReserveRaw(SATOSHIDEN - extraFeeAmount, currencyMap.valueMap[targetCurrencyID]),
                    currencyMap.valueMap[oneCur]);
            }
        }
    }
    return retVal;
}

// returns the prior import from a given import
CReserveTransfer CCrossChainImport::GetArbitrageTransfer(const CTransaction &tx,
                                                         int32_t outNum,
                                                         CValidationState &state,
                                                         uint32_t height,
                                                         CTransaction *ppriorTx,
                                                         int32_t *ppriorOutNum,
                                                         uint256 *ppriorTxBlockHash) const
{
    // get the prior import
    CReserveTransfer rt;
    CCrossChainImport cci;
    int transferCount = 0;
    for (auto &oneIn : tx.vin)
    {
        CTransaction _priorTx;
        int32_t _priorOutNum;
        uint256 _priorTxBlockHash;
        CTransaction &priorTx = ppriorTx ? *ppriorTx : _priorTx;
        int32_t &priorOutNum = ppriorOutNum ? *ppriorOutNum : _priorOutNum;
        uint256 &priorTxBlockHash = ppriorTxBlockHash ? *ppriorTxBlockHash : _priorTxBlockHash;

        uint256 priorTxHash;
        COptCCParams p;
        if (!IsDefinitionImport() &&
            (myGetTransaction(oneIn.prevout.hash, _priorTx, priorTxBlockHash)))
        {
            if (cci.IsValid() &&
                _priorTx.vout.size() > oneIn.prevout.n &&
                _priorTx.vout[oneIn.prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_RESERVE_TRANSFER &&
                p.vData.size() &&
                (rt = CReserveTransfer(p.vData[0])).IsValid())
            {
                // only one allowed, even though we currently don't
                // loop after finding the first
                if (transferCount)
                {
                    rt = CReserveTransfer();
                    break;
                }
                transferCount++;
                priorTx = _priorTx;
                priorOutNum = oneIn.prevout.n;
                rt.SetArbitrageOnly();
                // TODO: right now, only one reserve transfer will be used for any import,
                // and any additional ones should be rejected as invalid spends, so ignore them here
                break;
            }
            else if (!cci.IsValid() &&
                     p.IsValid() &&
                     p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
                     p.vData.size())
            {
                cci = CCrossChainImport(p.vData[0]);
            }
            else if (cci.IsValid() &&
                     p.IsValid() &&
                     p.evalCode == EVAL_ACCEPTEDNOTARIZATION &&
                     p.vData.size())
            {
                // any reserve transfer should be after the import and before the notarization spend
                cci = CCrossChainImport();
                break;
            }
        }
    }
    return rt;
}

// returns the prior import from a given import
CCrossChainImport CCrossChainImport::GetPriorImport(const CTransaction &tx,
                                                    int32_t outNum,
                                                    CValidationState &state,
                                                    uint32_t height,
                                                    CTransaction *ppriorTx,
                                                    int32_t *ppriorOutNum,
                                                    uint256 *ppriorTxBlockHash) const
{
    // get the prior import
    CCrossChainImport cci;
    for (auto &oneIn : tx.vin)
    {
        CTransaction _priorTx;
        int32_t _priorOutNum;
        uint256 _priorTxBlockHash;
        CTransaction &priorTx = ppriorTx ? *ppriorTx : _priorTx;
        int32_t &priorOutNum = ppriorOutNum ? *ppriorOutNum : _priorOutNum;
        uint256 &priorTxBlockHash = ppriorTxBlockHash ? *ppriorTxBlockHash : _priorTxBlockHash;

        uint256 priorTxHash;
        COptCCParams p;
        if (!IsDefinitionImport() &&
            (myGetTransaction(oneIn.prevout.hash, _priorTx, priorTxBlockHash)))
        {
            if (_priorTx.vout.size() > oneIn.prevout.n &&
                _priorTx.vout[oneIn.prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
                p.vData.size() &&
                (cci = CCrossChainImport(p.vData[0])).IsValid() &&
                cci.importCurrencyID == importCurrencyID)
            {
                priorTx = _priorTx;
                priorOutNum = oneIn.prevout.n;
                break;
            }
            else
            {
                cci = CCrossChainImport();
            }
        }
    }
    return cci;
}

// returns the prior import from the same system as a given import. this enables export order checking to ensure
// that all exports from any system are imported in order.
CCrossChainImport CCrossChainImport::GetPriorImportFromSystem(const CTransaction &tx,
                                                              int32_t outNum,
                                                              CValidationState &state,
                                                              uint32_t height,
                                                              CTransaction *ppriorTx,
                                                              int32_t *ppriorOutNum,
                                                              uint256 *ppriorTxBlockHash) const
{
    // get the prior import
    CCrossChainImport cci;
    for (auto &oneIn : tx.vin)
    {
        CTransaction _priorTx;
        int32_t _priorOutNum;
        uint256 _priorTxBlockHash;
        CTransaction &priorTx = ppriorTx ? *ppriorTx : _priorTx;
        int32_t &priorOutNum = ppriorOutNum ? *ppriorOutNum : _priorOutNum;
        uint256 &priorTxBlockHash = ppriorTxBlockHash ? *ppriorTxBlockHash : _priorTxBlockHash;

        uint256 priorTxHash;
        COptCCParams p;
        if (!IsDefinitionImport() &&
            !(IsInitialLaunchImport() && cci.sourceSystemID != ASSETCHAINS_CHAINID) &&
            (myGetTransaction(oneIn.prevout.hash, _priorTx, priorTxBlockHash)))
        {
            if (_priorTx.vout.size() > oneIn.prevout.n &&
                _priorTx.vout[oneIn.prevout.n].scriptPubKey.IsPayToCryptoCondition(p) &&
                p.IsValid() &&
                p.evalCode == EVAL_CROSSCHAIN_IMPORT &&
                p.vData.size() &&
                (cci = CCrossChainImport(p.vData[0])).IsValid() &&
                cci.importCurrencyID == importCurrencyID)
            {
                priorTx = _priorTx;
                priorOutNum = oneIn.prevout.n;
                break;
            }
            else
            {
                cci = CCrossChainImport();
            }
        }
    }
    return cci;
}

// returns the best conversion prices for all currencies in a currency converter over a period of time to go from any currency in
// the converter to the fee currency.
//
// returns a map that is the aggregate best values for all conversions, with each currency being priced in the target currency, whether
// it is a straight or via conversion.
CCurrencyValueMap CCrossChainImport::GetBestPriorConversions(const CTransaction &tx, int32_t outNum, const uint160 &converterCurrencyID, const uint160 &targetCurrencyID, const CCoinbaseCurrencyState &converterState, CValidationState &state, uint32_t height, uint32_t minHeight, uint32_t maxHeight) const
{
    // get the prior import
    CCrossChainImport cci;
    CCurrencyValueMap retVal;
    CPBaaSNotarization importNot;

    CCrossChainImport priorImport, sysCCI;

    CTransaction lastTx = tx;
    int32_t lastOutNum = outNum;
    int32_t sysCCIOut, importNotarizationOut, eOutStart = -1, eOutEnd;
    CCrossChainExport ccx;
    CCoinbaseCurrencyState curState = converterState;
    std::vector<CReserveTransfer> reserveTransfers;

    uint160 fromSystem = sourceSystemID;

    if (!GetImportInfo(lastTx, height, lastOutNum, ccx, sysCCI, sysCCIOut, importNot, importNotarizationOut, eOutStart, eOutEnd, reserveTransfers))
    {
        return retVal;
    }

    // if this is from another chain, we need to get the actual notarization used for proof, validate the proof root, and get
    // prices from that, not the updated prices from the actual import
    if (fromSystem != ASSETCHAINS_CHAINID)
    {
        std::set<int> validEvidenceTypes;
        validEvidenceTypes.insert(CHAINOBJ_TRANSACTION_PROOF);
        validEvidenceTypes.insert(CHAINOBJ_EVIDENCEDATA);

        CNotaryEvidence evidence;
        CPBaaSNotarization altNot;
        COptCCParams p, q;
        CTransaction lastNotTx;
        uint256 blockHash;
        int eOutEndTmp;
        if (eOutStart > 0 &&
            (evidence = CNotaryEvidence(lastTx, eOutStart, eOutEndTmp)).IsValid() &&
            evidence.GetSelectEvidence(validEvidenceTypes).chainObjects.size() &&
            evidence.output.IsValid() &&
            !evidence.output.IsOnSameTransaction() &&
            myGetTransaction(evidence.output.hash, lastNotTx, blockHash) &&
            lastNotTx.vout.size() > evidence.output.n &&
            lastNotTx.vout[evidence.output.n].scriptPubKey.IsPayToCryptoCondition(q) &&
            q.IsValid() &&
            (q.evalCode == EVAL_EARNEDNOTARIZATION || q.evalCode == EVAL_ACCEPTEDNOTARIZATION) &&
            (altNot = CPBaaSNotarization(q.vData[0])).IsValid())
        {
            if (altNot.currencyID == converterCurrencyID)
            {
                curState = altNot.currencyState;
            }
            else if (altNot.currencyStates.count(converterCurrencyID))
            {
                curState = altNot.currencyStates[converterCurrencyID];
            }
        }
        else if (!cci.IsDefinitionImport() && height != 1)
        {
            return retVal;
        }
    }

    // go back until we get past the min height and get the lowest price of all currencies from all imports
    // the idea is that if the source system used a particular state as an import here, it would have had that one
    // as at least available for its calculation and if there is a more recent, better one available, it could have
    // that too

    // get best value according to the current converter
    if (converterState.IsPrelaunch() ||
        !converterState.IsValid() ||
        !converterState.IsFractional() ||
        !(retVal = curState.TargetConversionPrices(targetCurrencyID)).valueMap.size())
    {
        return retVal;
    }

    priorImport = *this;
    reserveTransfers.clear();
    while ((priorImport = priorImport.GetPriorImport(lastTx, lastOutNum, state, height, &lastTx, &lastOutNum)).IsValid() &&
           priorImport.GetImportInfo(lastTx, height, lastOutNum, ccx, sysCCI, sysCCIOut, importNot, importNotarizationOut, eOutStart, eOutEnd, reserveTransfers))
    {
        reserveTransfers.clear();

        std::set<int> validEvidenceTypes;
        validEvidenceTypes.insert(CHAINOBJ_TRANSACTION_PROOF);
        validEvidenceTypes.insert(CHAINOBJ_EVIDENCEDATA);

        // if this is an import from another system, it doesn't matter unless we only care about this one
        if (fromSystem != ASSETCHAINS_CHAINID)
        {
            CNotaryEvidence evidence;
            CPBaaSNotarization altNot;
            COptCCParams p, q;
            CTransaction lastNotTx;
            int eOutEndTmp;
            uint256 blockHash;
            if (priorImport.sourceSystemID == fromSystem &&
                eOutStart > 0 &&
                (evidence = CNotaryEvidence(lastTx, eOutStart, eOutEndTmp)).IsValid() &&
                evidence.GetSelectEvidence(validEvidenceTypes).chainObjects.size() &&
                evidence.output.IsValid() &&
                !evidence.output.IsOnSameTransaction() &&
                myGetTransaction(evidence.output.hash, lastNotTx, blockHash) &&
                lastNotTx.vout.size() > evidence.output.n &&
                lastNotTx.vout[evidence.output.n].scriptPubKey.IsPayToCryptoCondition(q) &&
                q.IsValid() &&
                (q.evalCode == EVAL_EARNEDNOTARIZATION || q.evalCode == EVAL_ACCEPTEDNOTARIZATION))
            {
                importNot = CPBaaSNotarization(q.vData[0]);
                if (!importNot.IsValid())
                {
                    break;
                }
            }
        }

        if (importNot.currencyID == converterCurrencyID)
        {
            curState = importNot.currencyState;
        }
        else if (importNot.currencyStates.count(converterCurrencyID))
        {
            curState = importNot.currencyStates[converterCurrencyID];
        }

        // if the target currency is another system, we need to check the proof information as the height
        uint32_t checkHeight = importNot.notarizationHeight;
        int checkedPrior = 0;
        if (checkHeight <= maxHeight &&
            (checkHeight >= minHeight || !checkedPrior++) &&
            (importNot.currencyState.currencyID == converterCurrencyID ||
            importNot.currencyStates.count(converterCurrencyID)))
        {
            // get final prices
            auto priorConversionMap = curState.TargetConversionPrices(targetCurrencyID);
            if (priorConversionMap.valueMap.size())
            {
                // get best prices
                for (auto &onePrice : priorConversionMap.valueMap)
                {
                    int64_t curVal = retVal.valueMap[onePrice.first];
                    if ((!curVal || curVal > onePrice.second) && onePrice.second)
                    {
                        retVal.valueMap[onePrice.first] = onePrice.second;
                    }
                }
            }
            continue;
        }
        else if (checkHeight < minHeight)
        {
            break;
        }
    }
    return retVal;
}

// Checks back on imports from the current system to ensure that there are no conflicts of either imported names or currencies that
// have not yet been confirmed, so are not yet on chain.
// first set is conflicting identities, second is conflicting currencies.
bool CCrossChainImport::UnconfirmedNameImports(const CTransaction &tx,
                                               int32_t outNum,
                                               CValidationState &state,
                                               uint32_t height,
                                               std::set<uint160> *pIDImports,
                                               std::set<uint160> *pCurrencyImports) const
{
    std::set<uint160> currencyRegistrations, idRegistrations, _IDImports, _CurrencyImports;

    std::set<uint160> &idImports = pIDImports ? *pIDImports : _IDImports;
    std::set<uint160> &currencyImports = pCurrencyImports ? *pCurrencyImports : _CurrencyImports;

    // get the prior import
    CCrossChainImport cci;
    CPBaaSNotarization importNot;

    CCrossChainImport priorImport, sysCCI;

    CTransaction lastTx = tx;
    int32_t lastOutNum = outNum;
    int32_t sysCCIOut, importNotarizationOut, eOutStart = -1, eOutEnd;
    CCrossChainExport ccx;
    std::vector<CReserveTransfer> reserveTransfers;

    uint160 fromSystem = sourceSystemID;

    if (!GetImportInfo(lastTx, height, lastOutNum, ccx, sysCCI, sysCCIOut, importNot, importNotarizationOut, eOutStart, eOutEnd, reserveTransfers))
    {
        return false;
    }

    uint256 priorTxBlockHash;
    for (priorImport = *this; (priorImport = GetPriorImport(lastTx, lastOutNum, state, height, &lastTx, &lastOutNum, &priorTxBlockHash)).IsValid(); )
    {
        // if lastTx is not confirmed, check for conflicts, otherwise, we're done
        if (!priorTxBlockHash.IsNull())
        {
            break;
        }
        if (!priorImport.GetImportInfo(lastTx, height, lastOutNum, ccx, sysCCI, sysCCIOut, importNot, importNotarizationOut, eOutStart, eOutEnd, reserveTransfers))
        {
            return state.Error(strprintf("%s: Cannot retrieve import details", __func__));
        }
        if (priorImport.sourceSystemID != ASSETCHAINS_CHAINID)
        {
            for (auto &oneTransfer : reserveTransfers)
            {
                if (oneTransfer.IsIdentityExport())
                {
                    idRegistrations.insert(GetDestinationID(TransferDestinationToDestination(oneTransfer.destination)));
                }
                else if (oneTransfer.IsCurrencyExport())
                {
                    CCurrencyDefinition curDef = CCurrencyDefinition(oneTransfer.destination.destination);
                    if (!curDef.IsValid())
                    {
                        return state.Error(strprintf("%s: Invalid currency import", __func__));
                    }
                    currencyRegistrations.insert(curDef.GetID());
                }
            }
        }
        priorTxBlockHash.SetNull();
    }
    return true;
}

// Checks back on imports from the current system to ensure that there are no conflicts of either imported names or currencies that
// have not yet been confirmed, so are not yet on chain.
// first set is conflicting identities, second is conflicting currencies.
bool CCrossChainImport::VerifyNameTransfers(const CTransaction &tx,
                                            int32_t outNum,
                                            CValidationState &state,
                                            uint32_t height,
                                            std::set<uint160> *pIDConflicts,
                                            std::set<uint160> *pCurrencyConflicts) const
{
    std::set<uint160> idsPresent, currenciesPresent;
    std::set<uint160> currencyRegistrations, idRegistrations;
    std::set<uint160> _IDConflicts, _CurrencyConflicts;
    std::set<uint160> &idConflicts = pIDConflicts ? *pIDConflicts : _IDConflicts;
    std::set<uint160> &currencyConflicts = pCurrencyConflicts ? *pCurrencyConflicts : _CurrencyConflicts;

    // get the prior import
    CCrossChainImport cci;
    CPBaaSNotarization importNot;

    CCrossChainImport priorImport, sysCCI;

    CTransaction lastTx = tx;
    int32_t lastOutNum = outNum;
    int32_t sysCCIOut, importNotarizationOut, eOutStart = -1, eOutEnd;
    CCrossChainExport ccx;
    std::vector<CReserveTransfer> reserveTransfers;

    if (!GetImportInfo(lastTx, height, lastOutNum, ccx, sysCCI, sysCCIOut, importNot, importNotarizationOut, eOutStart, eOutEnd, reserveTransfers))
    {
        return false;
    }

    for (auto &oneTransfer : reserveTransfers)
    {
        if (oneTransfer.IsIdentityExport())
        {
            idsPresent.insert(GetDestinationID(TransferDestinationToDestination(oneTransfer.destination)));
        }
        else if (oneTransfer.IsCurrencyExport())
        {
            CCurrencyDefinition curDef = CCurrencyDefinition(oneTransfer.destination.destination);
            if (!curDef.IsValid())
            {
                return state.Error(strprintf("%s: Invalid currency import", __func__));
            }
            currenciesPresent.insert(curDef.GetID());
        }
    }

    uint256 priorTxBlockHash;
    for (priorImport = *this; (priorImport = GetPriorImport(lastTx, lastOutNum, state, height, &lastTx, &lastOutNum, &priorTxBlockHash)).IsValid(); )
    {
        // if lastTx is not confirmed, check for conflicts, otherwise, we're done
        if (!priorTxBlockHash.IsNull())
        {
            break;
        }
        if (!priorImport.GetImportInfo(lastTx, height, lastOutNum, ccx, sysCCI, sysCCIOut, importNot, importNotarizationOut, eOutStart, eOutEnd, reserveTransfers))
        {
            return state.Error(strprintf("%s: Cannot retrieve import details", __func__));
        }
        if (priorImport.sourceSystemID != ASSETCHAINS_CHAINID)
        {
            for (auto &oneTransfer : reserveTransfers)
            {
                if (oneTransfer.IsIdentityExport())
                {
                    idRegistrations.insert(GetDestinationID(TransferDestinationToDestination(oneTransfer.destination)));
                }
                else if (oneTransfer.IsCurrencyExport())
                {
                    CCurrencyDefinition curDef = CCurrencyDefinition(oneTransfer.destination.destination);
                    if (!curDef.IsValid())
                    {
                        return state.Error(strprintf("%s: Invalid currency import", __func__));
                    }
                    currencyRegistrations.insert(curDef.GetID());
                }
            }
        }
        priorTxBlockHash.SetNull();
    }

    if (idsPresent.size() && idRegistrations.size())
    {
        auto &iterate = (idsPresent.size() < idRegistrations.size()) ? idsPresent : idRegistrations;
        auto &check = (idsPresent.size() < idRegistrations.size()) ? idRegistrations : idsPresent;
        for (auto &oneID : iterate)
        {
            if (check.count(oneID))
            {
                idConflicts.insert(oneID);
            }
        }
    }
    if (currenciesPresent.size() && currencyRegistrations.size())
    {
        auto &iterate = (currenciesPresent.size() < currencyRegistrations.size()) ? currenciesPresent : currencyRegistrations;
        auto &check = (currenciesPresent.size() < currencyRegistrations.size()) ? currencyRegistrations : currenciesPresent;
        for (auto &oneID : iterate)
        {
            if (check.count(oneID))
            {
                currencyConflicts.insert(oneID);
            }
        }
    }

    if (idConflicts.size() || currencyConflicts.size())
    {
        return state.Error(strprintf("%s: ID or currency registration conflict", __func__));
    }

    return true;
}

bool CCrossChainImport::GetImportInfo(const CTransaction &importTx, 
                                    uint32_t nHeight,
                                    int numImportOut, 
                                    CCrossChainExport &ccx,
                                    CCrossChainImport &sysCCI,
                                    int32_t &sysCCIOut,
                                    CPBaaSNotarization &importNotarization, 
                                    int32_t &importNotarizationOut,
                                    int32_t &evidenceOutStart,
                                    int32_t &evidenceOutEnd,
                                    std::vector<CReserveTransfer> &reserveTransfers) const
{
    CValidationState state;
    return GetImportInfo(importTx, 
                            nHeight,
                            numImportOut, 
                            ccx, 
                            sysCCI, 
                            sysCCIOut,
                            importNotarization, 
                            importNotarizationOut, 
                            evidenceOutStart,
                            evidenceOutEnd,
                            reserveTransfers, 
                            state);
}

bool CCrossChainImport::ValidateImport(const CTransaction &tx,
                                       int numImportin,
                                       int numImportOut,
                                       CCrossChainExport &ccx,
                                       CPBaaSNotarization &importNotarization,
                                       std::vector<CReserveTransfer> &reserveTransfers,
                                       CValidationState &state) const
{
    return true;
}

bool CCrossChainImport::ValidateImport(const CTransaction &tx,
                                        int numImportin,
                                        int numImportOut,
                                        CCrossChainExport &ccx,
                                        CPBaaSNotarization &importNotarization,
                                        std::vector<CReserveTransfer> &reserveTransfers) const
{
    CValidationState state;
    return ValidateImport(tx, numImportin, numImportOut, ccx, importNotarization, reserveTransfers, state);
}

CCurrencyState::CCurrencyState(const UniValue &obj)
{
    try
    {
        flags = uni_get_int(find_value(obj, "flags"));
        version = uni_get_int(find_value(obj, "version"), VERSION_CURRENT);

        std::string cIDStr = uni_get_str(find_value(obj, "currencyid"));
        if (cIDStr != "")
        {
            CTxDestination currencyDest = DecodeDestination(cIDStr);
            currencyID = GetDestinationID(currencyDest);
        }

        auto CurrenciesArr = IsFractional() ? find_value(obj, "reservecurrencies") : find_value(obj, "launchcurrencies");
        size_t numCurrencies = 0;

        if (IsFractional() &&
            (!CurrenciesArr.isArray() ||
             !(numCurrencies = CurrenciesArr.size())))
        {
            version = VERSION_INVALID;
            LogPrintf("%s: Failed to proplerly specify launch or reserve currencies in currency definition\n", __func__);
        }
        if (numCurrencies > MAX_RESERVE_CURRENCIES)
        {
            version = VERSION_INVALID;
            LogPrintf("%s: More than %d launch or reserve currencies in currency definition\n", __func__, MAX_RESERVE_CURRENCIES);
        }

        // store currencies, weights, and reserves
        if (CurrenciesArr.size())
        {
            try
            {
                for (int i = 0; i < CurrenciesArr.size(); i++)
                {
                    uint160 currencyID = GetDestinationID(DecodeDestination(uni_get_str(find_value(CurrenciesArr[i], "currencyid"))));
                    if (currencyID.IsNull())
                    {
                        LogPrintf("Invalid currency ID\n");
                        version = VERSION_INVALID;
                        break;
                    }
                    currencies.push_back(currencyID);
                    weights.push_back(AmountFromValueNoErr(find_value(CurrenciesArr[i], "weight")));
                    reserves.push_back(AmountFromValueNoErr(find_value(CurrenciesArr[i], "reserves")));
                }
            }
            catch (...)
            {
                version = VERSION_INVALID;
                LogPrintf("Invalid specification of currencies, weights, and/or reserves in initial definition of reserve currency\n");
            }
        }

        if (version == VERSION_INVALID)
        {
            printf("Invalid currency specification, see debug.log for reason other than invalid flags\n");
            LogPrintf("Invalid currency specification\n");
        }
        else
        {
            initialSupply = AmountFromValue(find_value(obj, "initialsupply"));
            emitted = AmountFromValue(find_value(obj, "emitted"));
            supply = AmountFromValue(find_value(obj, "supply"));
        }
    }
    catch (...)
    {
        printf("Invalid currency specification, see debug.log for reason other than invalid flags\n");
        LogPrintf("Invalid currency specification\n");
        version = VERSION_INVALID;
    }
}

CCoinbaseCurrencyState::CCoinbaseCurrencyState(const CTransaction &tx, int *pOutIdx)
{
    int localIdx;
    int &i = pOutIdx ? *pOutIdx : localIdx;
    for (i = 0; i < tx.vout.size(); i++)
    {
        COptCCParams p;
        if (IsPayToCryptoCondition(tx.vout[i].scriptPubKey, p))
        {
            if (p.evalCode == EVAL_CURRENCYSTATE && p.vData.size())
            {
                FromVector(p.vData[0], *this);
                break;
            }
        }
    }
}

std::vector<std::vector<CAmount>> ValueColumnsFromUniValue(const UniValue &uni,
                                                           const std::vector<std::string> &rowNames,
                                                           const std::vector<std::string> &columnNames)
{
    std::vector<std::vector<CAmount>> retVal;
    for (int i = 0; i < rowNames.size(); i++)
    {
        UniValue row = find_value(uni, rowNames[i]);
        if (row.isObject())
        {
            for (int j = 0; j < columnNames.size(); j++)
            {
                if (retVal.size() == j)
                {
                    retVal.emplace_back();
                }
                CAmount columnVal = 0;
                columnVal = AmountFromValueNoErr(find_value(row, columnNames[j]));
                retVal[j].push_back(columnVal);
            }
        }
    }
    return retVal;
}


CCoinbaseCurrencyState::CCoinbaseCurrencyState(const UniValue &obj) : CCurrencyState(obj)
{
    try
    {
        std::vector<std::vector<CAmount>> columnAmounts;

        std::vector<std::string> rowNames;
        auto currenciesValue = find_value(obj, "currencies");
        if (currenciesValue.isObject())
        {
            rowNames = currenciesValue.getKeys();
        }
        if (!currencies.size() && rowNames.size())
        {
            currencies.resize(rowNames.size());
            weights.resize(rowNames.size());
            reserves.resize(rowNames.size());
            for (int i = 0; i < rowNames.size(); i++)
            {
                currencies[i] = GetDestinationID(DecodeDestination(rowNames[i]));
            }
        }
        else if (currencies.size())
        {
            rowNames.resize(currencies.size());
            for (int i = 0; i < rowNames.size(); i++)
            {
                rowNames[i] = EncodeDestination(CIdentityID(currencies[i]));
            }
        }
        if (currencies.size() != rowNames.size())
        {
            LogPrintf("%s: mismatch currencies and reserve currencies\n", __func__);
            version = VERSION_INVALID;
            return;
        }
        std::vector<std::string> columnNames({"reservein", "primarycurrencyin", "reserveout", "lastconversionprice", "viaconversionprice", "fees", "conversionfees", "priorweights"});
        if (currenciesValue.isObject())
        {
            //printf("%s: currencies: %s\n", __func__, currenciesValue.write(1,2).c_str());
            columnAmounts = ValueColumnsFromUniValue(currenciesValue, rowNames, columnNames);
            if (columnAmounts.size() == columnNames.size())
            {
                reserveIn = columnAmounts[0];
                primaryCurrencyIn = columnAmounts[1];
                reserveOut = columnAmounts[2];
                conversionPrice = columnAmounts[3];
                viaConversionPrice = columnAmounts[4];
                fees = columnAmounts[5];
                conversionFees = columnAmounts[6];
                priorWeights.resize(0);
                for (auto oneColumnNum : columnAmounts[7])
                {
                    priorWeights.push_back(oneColumnNum);
                }
            }
        }
        primaryCurrencyFees = AmountFromValueNoErr(find_value(obj, "primarycurrencyfees"));
        primaryCurrencyConversionFees = AmountFromValueNoErr(find_value(obj, "primarycurrencyconversionfees"));
        primaryCurrencyOut = AmountFromValueNoErr(find_value(obj, "primarycurrencyout"));
        preConvertedOut = AmountFromValueNoErr(find_value(obj, "preconvertedout"));
    }
    catch(...)
    {
        version = VERSION_INVALID;
        LogPrintf("%s: exception reading json CCoinbaseCurrencyState\n", __func__);
    }
}

CAmount CalculateFractionalOut(CAmount NormalizedReserveIn, CAmount Supply, CAmount NormalizedReserve, int32_t reserveRatio)
{
    static cpp_dec_float_50 one("1");
    static cpp_dec_float_50 bigSatoshi("100000000");
    cpp_dec_float_50 reservein(std::to_string(NormalizedReserveIn));
    reservein = reservein / bigSatoshi;
    cpp_dec_float_50 supply(std::to_string((Supply ? Supply : 1)));
    supply = supply / bigSatoshi;
    cpp_dec_float_50 reserve(std::to_string(NormalizedReserve ? NormalizedReserve : 1));
    reserve = reserve / bigSatoshi;
    cpp_dec_float_50 ratio(std::to_string(reserveRatio));
    ratio = ratio / bigSatoshi;

    //printf("reservein: %s\nsupply: %s\nreserve: %s\nratio: %s\n\n", reservein.str().c_str(), supply.str().c_str(), reserve.str().c_str(), ratio.str().c_str());

    int64_t fractionalOut = 0;

    // first check if anything to buy
    if (NormalizedReserveIn)
    {
        cpp_dec_float_50 supplyout = bigSatoshi * (supply * (pow((reservein / reserve) + one, ratio) - one));
        //printf("supplyout: %s\n", supplyout.str(0, std::ios_base::fmtflags::_S_fixed).c_str());

        if (!CCurrencyState::to_int64(supplyout, fractionalOut))
        {
            return -1;
        }
    }
    return fractionalOut;
}

CAmount CalculateReserveOut(CAmount FractionalIn, CAmount Supply, CAmount NormalizedReserve, int32_t reserveRatio)
{
    static cpp_dec_float_50 one("1");
    static cpp_dec_float_50 bigSatoshi("100000000");
    cpp_dec_float_50 fractionalin(std::to_string(FractionalIn));
    fractionalin = fractionalin / bigSatoshi;
    cpp_dec_float_50 supply(std::to_string((Supply ? Supply : 1)));
    supply = supply / bigSatoshi;
    cpp_dec_float_50 reserve(std::to_string(NormalizedReserve ? NormalizedReserve : 1));
    reserve = reserve / bigSatoshi;
    cpp_dec_float_50 ratio(std::to_string(reserveRatio));
    ratio = ratio / bigSatoshi;

    //printf("fractionalin: %s\nsupply: %s\nreserve: %s\nratio: %s\n\n", fractionalin.str().c_str(), supply.str().c_str(), reserve.str().c_str(), ratio.str().c_str());

    int64_t reserveOut = 0;

    // first check if anything to buy
    if (FractionalIn)
    {
        cpp_dec_float_50 reserveout = bigSatoshi * (reserve * (one - pow(one - (fractionalin / supply), (one / ratio))));
        //printf("reserveout: %s\n", reserveout.str(0, std::ios_base::fmtflags::_S_fixed).c_str());

        if (!CCurrencyState::to_int64(reserveout, reserveOut))
        {
            assert(false);
        }
    }
    return reserveOut;
}

// This can handle multiple aggregated, bidirectional conversions in one block of transactions. To determine the conversion price, it 
// takes both input amounts of any number of reserves and the fractional currencies targeting those reserves to merge the conversion into one 
// merged calculation with the same price across currencies for all transactions in the block. It returns the newly calculated 
// conversion prices of the fractional reserve in the reserve currency.
std::vector<CAmount> CCurrencyState::ConvertAmounts(const std::vector<CAmount> &_inputReserves,
                                                    const std::vector<CAmount> &_inputFractional,
                                                    CCurrencyState &_newState,
                                                    std::vector<std::vector<CAmount>> const *pCrossConversions,
                                                    std::vector<CAmount> *pViaPrices) const
{
    static arith_uint256 bigSatoshi(SATOSHIDEN);

    int32_t numCurrencies = currencies.size();
    std::vector<CAmount> inputReserves = _inputReserves;
    std::vector<CAmount> inputFractional = _inputFractional;

    CCurrencyState newState = *this;
    std::vector<CAmount> rates(numCurrencies);
    std::vector<CAmount> initialRates = PricesInReserve();

    bool haveConversion = false;

    if (inputReserves.size() == inputFractional.size() && inputReserves.size() == numCurrencies && 
        (!pCrossConversions || pCrossConversions->size() == numCurrencies))
    {
        int i;
        for (i = 0; i < numCurrencies; i++)
        {
            if (!pCrossConversions || (*pCrossConversions)[i].size() != numCurrencies)
            {
                break;
            }
        }
        if (!pCrossConversions || i == numCurrencies)
        {
            for (auto oneIn : inputReserves)
            {
                if (oneIn)
                {
                    haveConversion = true;
                    break;
                }
            }
            if (!haveConversion)
            {
                for (auto oneIn : inputFractional)
                {
                    if (oneIn)
                    {
                        haveConversion = true;
                        break;
                    }
                }
            }
        }
    }
    else
    {
        printf("%s: invalid parameters\n", __func__);
        LogPrintf("%s: invalid parameters\n", __func__);
        return initialRates;
    }
    
    if (!haveConversion)
    {
        // not considered an error
        _newState = newState;
        return initialRates;
    }

    // generally an overflow will cause a fail, which will result in leaving the _newState parameter untouched, making it
    // possible to check if it is invalid as an overflow or formula failure check
    bool failed = false;

    for (auto oneIn : inputReserves)
    {
        if (oneIn < 0)
        {
            failed = true;
            printf("%s: invalid reserve input amount for conversion %ld\n", __func__, oneIn);
            LogPrintf("%s: invalid reserve input amount for conversion %ld\n", __func__, oneIn);
            break;
        }
    }
    for (auto oneIn : inputFractional)
    {
        if (oneIn < 0)
        {
            failed = true;
            printf("%s: invalid fractional input amount for conversion %ld\n", __func__, oneIn);
            LogPrintf("%s: invalid fractional input amount for conversion %ld\n", __func__, oneIn);
            break;
        }
    }

    if (failed)
    {
        return initialRates;
    }

    // Create corresponding fractions of the supply for each currency to be used as starting calculation of that currency's value
    // Determine the equivalent amount of input and output based on current values. Balance each such that each currency has only
    // input or output, denominated in supply at the starting value.
    //
    // For each currency in either direction, sell to reserve or buy aggregate, we convert to a contribution of amount at the reserve
    // percent value. For example, consider 4 currencies, r1...r4, which are all 25% reserves of currency fr1. For simplicity of example,
    // assume 1000 reserve of each reserve currency, where all currencies are equal in value to each other at the outset, and a supply of
    // 4000, where each fr1 is equal in value to 1 of each component reserve. 
    // Now, consider the following cases:
    //
    // 1. purchase fr1 with 100 r1
    //      This is treated as a single 25% fractional purchase with respect to amount purchased, ending price, and supply change
    // 2. purchase fr1 with 100 r1, 100 r2, 100 r3, 100 r4
    //      This is treated as a common layer of purchase across 4 x 25% currencies, resulting in 100% fractional purchase divided 4 ways
    // 3. purchase fr1 with 100 r1, 50 r2, 25 r3
    //      This is treated as 3 separate purchases in order:
    //          a. one of 25 units across 3 currencies (3 x 25%), making a 75% fractional purchase of 75 units divided equally across 3 currencies
    //          b. one of 25 units across 2 currencies (2 x 25%), making a 50% fractional purchase of 50 units divided equally between r1 and r2
    //          c. one purchase of 50 units in r1 at 25% fractional purchase
    // 4. purchase fr1 with 100 r1, sell 100 fr1 to r2
    //          a. one fractional purchase of 100 units at 25%
    //          b. one fractional sell of 100 units at 25%
    //          c. do each in forward and reverse order and set conversion at mean between each
    // 5. purchase fr1 with 100 r1, 50 r2, sell 100 fr1 to r3, 50 to r4
    //          This consists of one composite (multi-layer) buy and one composite sell
    //          a. Compose one two layer purchase of 50 r1 + 50 r2 at 50% and 50 r1 at 25%
    //          b. Compose one two layer sell of 50 r3 + 50 r4 at 50% and 50 r3 at 25%
    //          c. execute each operation of a and b in forward and reverse order and set conversion at mean between results
    //

    std::multimap<CAmount, std::pair<CAmount, uint160>> fractionalIn, fractionalOut;

    // aggregate amounts of ins and outs across all currencies expressed in fractional values in both directions first buy/sell, then sell/buy
    std::map<uint160, std::pair<CAmount, CAmount>> fractionalInMap, fractionalOutMap;

    arith_uint256 bigSupply(supply);

    int32_t totalReserveWeight = 0;
    int32_t maxReserveRatio = 0;

    for (auto weight : weights)
    {
        maxReserveRatio = weight > maxReserveRatio ? weight : maxReserveRatio;
        totalReserveWeight += weight;
        if (!weight)
        {
            LogPrintf("%s: invalid, zero weight currency for conversion\n", __func__);
            return initialRates;
        }
    }

    if (!maxReserveRatio)
    {
        LogPrintf("%s: attempting to convert amounts on non-fractional currency\n", __func__);
        return initialRates;
    }

    // it is currently an error to have > 100% reserve ratio currency
    if (totalReserveWeight > bigSatoshi)
    {
        LogPrintf("%s: total currency backing weight exceeds 100%\n", __func__);
        return initialRates;
    }

    arith_uint256 bigMaxReserveRatio = arith_uint256(maxReserveRatio);
    arith_uint256 bigTotalReserveWeight = arith_uint256(totalReserveWeight);

    // reduce each currency change to a net inflow or outflow of fractional currency and
    // store both negative and positive in structures sorted by the net amount, adjusted
    // by the difference of the ratio between the weights of each currency
    for (int64_t i = 0; i < numCurrencies; i++)
    {
        arith_uint256 weight(weights[i]);
        //printf("%s: %ld\n", __func__, ReserveToNative(inputReserves[i], i));
        CAmount asNative = ReserveToNative(inputReserves[i], i);
        // if overflow
        if (asNative < 0)
        {
            failed = true;
            break;
        }
        CAmount netFractional = inputFractional[i] - asNative;
        int64_t deltaRatio;
        arith_uint256 bigDeltaRatio;
        if (netFractional > 0)
        {
            bigDeltaRatio = ((arith_uint256(netFractional) * bigMaxReserveRatio) / weight);
            if (bigDeltaRatio > INT64_MAX)
            {
                failed = true;
                break;
            }
            deltaRatio = bigDeltaRatio.GetLow64();
            fractionalIn.insert(std::make_pair(deltaRatio, std::make_pair(netFractional, currencies[i])));
        }
        else if (netFractional < 0)
        {
            netFractional = -netFractional;
            bigDeltaRatio = ((arith_uint256(netFractional) * bigMaxReserveRatio) / weight);
            if (bigDeltaRatio > INT64_MAX)
            {
                failed = true;
                break;
            }
            deltaRatio = bigDeltaRatio.GetLow64();
            fractionalOut.insert(std::make_pair(deltaRatio, std::make_pair(netFractional, currencies[i])));
        }
    }

    if (failed)
    {
        LogPrintf("%s: OVERFLOW in calculating changes in currency\n", __func__);
        return initialRates;
    }

    // create "layers" of equivalent value at different fractional percentages
    // across currencies going in or out at the same time, enabling their effect on the aggregate
    // to be represented by a larger fractional percent impact of "normalized reserve" on the currency, 
    // which results in accurate pricing impact simulating a basket of currencies.
    //
    // since we have all values sorted, the lowest non-zero value determines the first common layer, then next lowest, the next, etc.
    std::vector<std::pair<int32_t, std::pair<CAmount, std::vector<uint160>>>> fractionalLayersIn, fractionalLayersOut;
    auto reserveMap = GetReserveMap();

    CAmount layerAmount = 0;
    CAmount layerStart;

    for (auto inFIT = fractionalIn.upper_bound(layerAmount); inFIT != fractionalIn.end(); inFIT = fractionalIn.upper_bound(layerAmount))
    {
        // make a common layer out of all entries from here until the end
        int frIdx = fractionalLayersIn.size();
        layerStart = layerAmount;
        layerAmount = inFIT->first;
        CAmount layerHeight = layerAmount - layerStart;
        fractionalLayersIn.emplace_back(std::make_pair(0, std::make_pair(0, std::vector<uint160>())));
        for (auto it = inFIT; it != fractionalIn.end(); it++)
        {
            // reverse the calculation from layer height to amount for this currency, based on currency weight
            int32_t weight = weights[reserveMap[it->second.second]];
            CAmount curAmt = ((arith_uint256(layerHeight) * arith_uint256(weight) / bigMaxReserveRatio)).GetLow64();
            it->second.first -= curAmt;

            if (it->second.first < 0)
            {
                LogPrintf("%s: UNDERFLOW in calculating changes in currency\n", __func__);
                return initialRates;
            }

            fractionalLayersIn[frIdx].first += weight;
            fractionalLayersIn[frIdx].second.first += curAmt;
            fractionalLayersIn[frIdx].second.second.push_back(it->second.second);
        }
    }

    layerAmount = 0;
    for (auto outFIT = fractionalOut.upper_bound(layerAmount); outFIT != fractionalOut.end(); outFIT = fractionalOut.upper_bound(layerAmount))
    {
        int frIdx = fractionalLayersOut.size();
        layerStart = layerAmount;
        layerAmount = outFIT->first;
        CAmount layerHeight = layerAmount - layerStart;
        fractionalLayersOut.emplace_back(std::make_pair(0, std::make_pair(0, std::vector<uint160>())));
        for (auto it = outFIT; it != fractionalOut.end(); it++)
        {
            int32_t weight = weights[reserveMap[it->second.second]];
            arith_uint256 bigCurAmt = ((arith_uint256(layerHeight) * arith_uint256(weight) / bigMaxReserveRatio));
            if (bigCurAmt > INT64_MAX)
            {
                LogPrintf("%s: OVERFLOW in calculating changes in currency\n", __func__);
                return initialRates;
            }
            CAmount curAmt = bigCurAmt.GetLow64();
            it->second.first -= curAmt;
            assert(it->second.first >= 0);

            fractionalLayersOut[frIdx].first += weight;
            fractionalLayersOut[frIdx].second.first += curAmt;
            fractionalLayersOut[frIdx].second.second.push_back(it->second.second);
        }
    }    

    int64_t supplyAfterBuy = 0, supplyAfterBuySell = 0, supplyAfterSell = 0, supplyAfterSellBuy = 0;
    int64_t reserveAfterBuy = 0, reserveAfterBuySell = 0, reserveAfterSell = 0, reserveAfterSellBuy = 0;

    // first, loop through all buys layer by layer. calculate and divide the proceeds between currencies
    // in each participating layer, in accordance with each currency's relative percentage
    CAmount addSupply = 0;
    CAmount addNormalizedReserves = 0;
    for (auto &layer : fractionalLayersOut)
    {
        // each layer has a fractional percentage/weight and a total amount, determined by the total of all weights for that layer
        // and net amounts across all currencies in that layer. each layer also includes a list of all currencies.
        //
        // calculate a fractional buy at the total layer ratio for the amount specified
        // and divide the value according to the relative weight of each currency, adding to each entry of fractionalOutMap
        arith_uint256 bigLayerWeight = arith_uint256(layer.first);
        CAmount totalLayerReserves = ((bigSupply * bigLayerWeight) / bigSatoshi).GetLow64() + addNormalizedReserves;
        addNormalizedReserves += layer.second.first;
        CAmount newSupply = CalculateFractionalOut(layer.second.first, supply + addSupply, totalLayerReserves, layer.first);
        if (newSupply < 0)
        {
            LogPrintf("%s: currency supply OVERFLOW\n", __func__);
            return initialRates;
        }
        arith_uint256 bigNewSupply(newSupply);
        addSupply += newSupply;
        for (auto &id : layer.second.second)
        {
            auto idIT = fractionalOutMap.find(id);
            CAmount newSupplyForCurrency = ((bigNewSupply * weights[reserveMap[id]]) / bigLayerWeight).GetLow64();

            // initialize or add to the new supply for this currency
            if (idIT == fractionalOutMap.end())
            {
                fractionalOutMap[id] = std::make_pair(newSupplyForCurrency, int64_t(0));
            }
            else
            {
                idIT->second.first += newSupplyForCurrency;
            }
        }
    }

    supplyAfterBuy = supply + addSupply;
    assert(supplyAfterBuy >= 0);

    reserveAfterBuy = supply + addNormalizedReserves;
    assert(reserveAfterBuy >= 0);

    addSupply = 0;
    addNormalizedReserves = 0;
    CAmount addNormalizedReservesBB = 0, addNormalizedReservesAB = 0;

    // calculate sell both before and after buy through this loop
    for (auto &layer : fractionalLayersIn)
    {
        // first calculate sell before-buy, then after-buy
        arith_uint256 bigLayerWeight(layer.first);

        // before-buy starting point
        CAmount totalLayerReservesBB = ((bigSupply * bigLayerWeight) / bigSatoshi).GetLow64() + addNormalizedReservesBB;
        CAmount totalLayerReservesAB = ((arith_uint256(supplyAfterBuy) * bigLayerWeight) / bigSatoshi).GetLow64() + addNormalizedReservesAB;

        CAmount newNormalizedReserveBB = CalculateReserveOut(layer.second.first, supply + addSupply, totalLayerReservesBB + addNormalizedReservesBB, layer.first);
        CAmount newNormalizedReserveAB = CalculateReserveOut(layer.second.first, supplyAfterBuy + addSupply, totalLayerReservesAB + addNormalizedReservesAB, layer.first);

        // input fractional is burned and output reserves are removed from reserves
        addSupply -= layer.second.first;
        addNormalizedReservesBB -= newNormalizedReserveBB;
        addNormalizedReservesAB -= newNormalizedReserveAB;

        for (auto &id : layer.second.second)
        {
            auto idIT = fractionalInMap.find(id);
            CAmount newReservesForCurrencyBB = ((arith_uint256(newNormalizedReserveBB) * arith_uint256(weights[reserveMap[id]])) / bigLayerWeight).GetLow64();
            CAmount newReservesForCurrencyAB = ((arith_uint256(newNormalizedReserveAB) * arith_uint256(weights[reserveMap[id]])) / bigLayerWeight).GetLow64();

            // initialize or add to the new supply for this currency
            if (idIT == fractionalInMap.end())
            {
                fractionalInMap[id] = std::make_pair(newReservesForCurrencyBB, newReservesForCurrencyAB);
            }
            else
            {
                idIT->second.first += newReservesForCurrencyBB;
                idIT->second.second += newReservesForCurrencyAB;
            }
        }
    }

    supplyAfterSell = supply + addSupply;
    assert(supplyAfterSell >= 0);

    supplyAfterBuySell = supplyAfterBuy + addSupply;
    assert(supplyAfterBuySell >= 0);

    reserveAfterSell = supply + addNormalizedReservesBB;
    assert(reserveAfterSell >= 0);

    reserveAfterBuySell = reserveAfterBuy + addNormalizedReservesAB;
    assert(reserveAfterBuySell >= 0);

    addSupply = 0;
    addNormalizedReserves = 0;

    // now calculate buy after sell
    for (auto &layer : fractionalLayersOut)
    {
        arith_uint256 bigLayerWeight = arith_uint256(layer.first);
        CAmount totalLayerReserves = ((arith_uint256(supplyAfterSell) * bigLayerWeight) / bigSatoshi).GetLow64() + addNormalizedReserves;
        addNormalizedReserves += layer.second.first;
        CAmount newSupply = CalculateFractionalOut(layer.second.first, supplyAfterSell + addSupply, totalLayerReserves, layer.first);
        arith_uint256 bigNewSupply(newSupply);
        addSupply += newSupply;
        for (auto &id : layer.second.second)
        {
            auto idIT = fractionalOutMap.find(id);

            assert(idIT != fractionalOutMap.end());

            idIT->second.second += ((bigNewSupply * weights[reserveMap[id]]) / bigLayerWeight).GetLow64();
        }
    }

    // now loop through all currencies, calculate conversion rates for each based on mean of all prices that we calculate for
    // buy before sell and sell before buy
    std::vector<int64_t> fractionalSizes(numCurrencies,0);
    std::vector<int64_t> reserveSizes(numCurrencies,0);

    for (int i = 0; i < numCurrencies; i++)
    {
        // each coin has an amount of reserve in, an amount of fractional in, and potentially two delta amounts in one of the
        // fractionalInMap or fractionalOutMap maps, one for buy before sell and one for sell before buy.
        // add the mean of the delta amounts to the appropriate side of the equation and calculate a price for each
        // currency.
        auto fractionalOutIT = fractionalOutMap.find(currencies[i]);
        auto fractionalInIT = fractionalInMap.find(currencies[i]);

        auto inputReserve = inputReserves[i];
        auto inputFraction = inputFractional[i];
        reserveSizes[i] = inputReserve;
        fractionalSizes[i] = inputFraction;

        CAmount fractionDelta = 0, reserveDelta = 0;

        if (fractionalOutIT != fractionalOutMap.end())
        {
            arith_uint256 bigFractionDelta(fractionalOutIT->second.first);
            fractionDelta = ((bigFractionDelta + arith_uint256(fractionalOutIT->second.second)) >> 1).GetLow64();
            assert(inputFraction + fractionDelta > 0);

            fractionalSizes[i] += fractionDelta;
            rates[i] = ((arith_uint256(inputReserve) * bigSatoshi) / arith_uint256(fractionalSizes[i])).GetLow64();

            // add the new reserve and supply to the currency
            newState.supply += fractionDelta;

            // all reserves have been calculated using a substituted value, which was 1:1 for native initially
            newState.reserves[i] += inputFractional[i] ? NativeToReserveRaw(fractionDelta, rates[i]) : inputReserves[i];
        }
        else if (fractionalInIT != fractionalInMap.end())
        {
            arith_uint256 bigReserveDelta(fractionalInIT->second.first);
            CAmount adjustedReserveDelta = NativeToReserve(((bigReserveDelta + arith_uint256(fractionalInIT->second.second)) >> 1).GetLow64(), i);
            reserveSizes[i] += adjustedReserveDelta;
            assert(inputFraction > 0);

            rates[i] = ((arith_uint256(reserveSizes[i]) * bigSatoshi) / arith_uint256(inputFraction)).GetLow64();

            // subtract the fractional and reserve that has left the currency
            newState.supply -= inputFraction;
            newState.reserves[i] -= adjustedReserveDelta;
        }
    }

    // if we have cross conversions, complete a final conversion with the updated currency, including all of the
    // cross conversion outputs to their final currency destinations
    if (pCrossConversions)
    {
        bool convertRToR = false;
        std::vector<CAmount> reservesRToR(numCurrencies, 0);    // keep track of reserve inputs to convert to the fractional currency

        // now add all cross conversions, determine how much of the converted fractional should be converted back to each
        // reserve currency. after adding all together, convert all to each reserve and average the price again
        for (int i = 0; i < numCurrencies; i++)
        {
            // add up all conversion amounts for each fractional to each reserve-to-reserve conversion
            for (int j = 0; j < numCurrencies; j++)
            {
                // convert this much of currency indexed by i into currency indexed by j
                // figure out how much fractional the amount of currency represents and add it to the total 
                // fractionalIn for the currency indexed by j
                if ((*pCrossConversions)[i][j])
                {
                    convertRToR = true;
                    reservesRToR[i] += (*pCrossConversions)[i][j];
                }
            }
        }

        if (convertRToR)
        {
            std::vector<CAmount> scratchValues(numCurrencies, 0);
            std::vector<CAmount> fractionsToConvert(numCurrencies, 0);

            // add fractional created to be converted to its destination
            for (int i = 0; i < reservesRToR.size(); i++)
            {
                if (reservesRToR[i])
                {
                    for (int j = 0; j < (*pCrossConversions)[i].size(); j++)
                    {
                        if ((*pCrossConversions)[i][j])
                        {
                            fractionsToConvert[j] += ReserveToNativeRaw((*pCrossConversions)[i][j], rates[i]);
                        }
                    }
                }
            }

            std::vector<CAmount> _viaPrices;
            std::vector<CAmount> &viaPrices(pViaPrices ? *pViaPrices : _viaPrices);
            CCurrencyState intermediateState = newState;
            viaPrices = intermediateState.ConvertAmounts(scratchValues, fractionsToConvert, newState);
        }
    }

    if (!failed)
    {
        _newState = newState;
    }

    for (int i = 0; i < rates.size(); i++)
    {
        if (!rates[i])
        {
            rates[i] = PriceInReserve(i);
        }
    }
    return rates;
}

CAmount CCurrencyState::ConvertAmounts(CAmount inputReserve, CAmount inputFraction, CCurrencyState &newState, int32_t reserveIndex) const
{
    int32_t numCurrencies = currencies.size();
    if (reserveIndex >= numCurrencies)
    {
        printf("%s: reserve index out of range\n", __func__);
        return 0;
    }
    std::vector<CAmount> inputReserves(numCurrencies);
    inputReserves[reserveIndex] = inputReserve;
    std::vector<CAmount> inputFractional(numCurrencies);
    inputFractional[reserveIndex] = inputFraction;
    std::vector<CAmount> retVal = ConvertAmounts(inputReserves,
                                                 inputFractional,
                                                 newState);
    return retVal[reserveIndex];
}

UniValue CReserveInOuts::ToUniValue() const
{
    UniValue retVal(UniValue::VOBJ);
    retVal.push_back(Pair("reservein", reserveIn));
    retVal.push_back(Pair("reserveout", reserveOut));
    retVal.push_back(Pair("reserveoutconverted", reserveOutConverted));
    retVal.push_back(Pair("nativeoutconverted", nativeOutConverted));
    retVal.push_back(Pair("reserveconversionfees", reserveConversionFees));
    return retVal;
}

UniValue CReserveTransactionDescriptor::ToUniValue() const
{
    UniValue retVal(UniValue::VOBJ);
    UniValue inOuts(UniValue::VARR);
    for (auto &oneInOut : currencies)
    {
        UniValue oneIOUni(UniValue::VOBJ);
        oneIOUni.push_back(Pair("currency", EncodeDestination(CIdentityID(oneInOut.first))));
        oneIOUni.push_back(Pair("inouts", oneInOut.second.ToUniValue()));
        inOuts.push_back(oneIOUni);
    }
    retVal.push_back(Pair("inouts", inOuts));
    retVal.push_back(Pair("nativein", nativeIn));
    retVal.push_back(Pair("nativeout", nativeOut));
    retVal.push_back(Pair("nativeconversionfees", nativeConversionFees));
    return retVal;
}

void CReserveTransactionDescriptor::AddReserveInput(const uint160 &currency, CAmount value)
{
    //printf("adding %ld:%s reserve input\n", value, EncodeDestination(CIdentityID(currency)).c_str());
    currencies[currency].reserveIn += value;
}

void CReserveTransactionDescriptor::AddReserveOutput(const uint160 &currency, CAmount value)
{
    //printf("adding %ld:%s reserve output\n", value, EncodeDestination(CIdentityID(currency)).c_str());
    currencies[currency].reserveOut += value;
}

void CReserveTransactionDescriptor::AddReserveOutConverted(const uint160 &currency, CAmount value)
{
    currencies[currency].reserveOutConverted += value;
}

void CReserveTransactionDescriptor::AddNativeOutConverted(const uint160 &currency, CAmount value)
{
    currencies[currency].nativeOutConverted += value;
}

void CReserveTransactionDescriptor::AddReserveConversionFees(const uint160 &currency, CAmount value)
{
    currencies[currency].reserveConversionFees += value;
}

void CReserveTransactionDescriptor::AddReserveOutput(const CTokenOutput &ro)
{
    flags |= IS_RESERVE;
    for (auto &oneCur : ro.reserveValues.valueMap)
    {
        if (oneCur.first != ASSETCHAINS_CHAINID && oneCur.second)
        {
            AddReserveOutput(oneCur.first, oneCur.second);
        }
    }
}

void CReserveTransactionDescriptor::AddReserveTransfer(const CReserveTransfer &rt)
{
    flags |= IS_RESERVE;
    for (auto &oneCur : rt.TotalCurrencyOut().valueMap)
    {
        if (oneCur.first != ASSETCHAINS_CHAINID && oneCur.second)
        {
            AddReserveOutput(oneCur.first, oneCur.second);
        }
    }
}

CAmount CReserveTransactionDescriptor::AllFeesAsNative(const CCurrencyState &currencyState) const
{
    CAmount nativeFees = NativeFees();
    CCurrencyValueMap reserveFees = ReserveFees();
    for (int i = 0; i < currencyState.currencies.size(); i++)
    {
        auto it = reserveFees.valueMap.find(currencyState.currencies[i]);
        if (it != reserveFees.valueMap.end())
        {
            nativeFees += currencyState.ReserveToNative(it->second, i);
        }
    }
    return nativeFees;
}

CAmount CReserveTransactionDescriptor::AllFeesAsNative(const CCurrencyState &currencyState, const std::vector<CAmount> &exchangeRates) const
{
    assert(exchangeRates.size() == currencyState.currencies.size());
    CAmount nativeFees = NativeFees();
    CCurrencyValueMap reserveFees = ReserveFees();
    for (int i = 0; i < currencyState.currencies.size(); i++)
    {
        auto it = reserveFees.valueMap.find(currencyState.currencies[i]);
        if (it != reserveFees.valueMap.end())
        {
            nativeFees += currencyState.ReserveToNativeRaw(it->second, exchangeRates[i]);
        }
    }
    return nativeFees;
}

CCurrencyValueMap CReserveTransactionDescriptor::ReserveFees(const uint160 &nativeID) const
{
    uint160 id = nativeID.IsNull() ? ASSETCHAINS_CHAINID : nativeID;
    CCurrencyValueMap retFees;
    for (auto &one : currencies)
    {
        // skip native
        if (one.first != id)
        {
            CAmount oneFee = one.second.reserveIn - (one.second.reserveOut - one.second.reserveOutConverted);
            if (oneFee)
            {
                retFees.valueMap[one.first] = oneFee;
            }
        }
    }
    return retFees;
}

CAmount CReserveTransactionDescriptor::NativeFees() const
{
    return nativeIn - nativeOut;
}

CCurrencyValueMap CReserveTransactionDescriptor::AllFeesAsReserve(const CCurrencyState &currencyState, int defaultReserve) const
{
    CCurrencyValueMap reserveFees = ReserveFees();

    auto it = reserveFees.valueMap.find(currencyState.currencies[defaultReserve]);
    if (it != reserveFees.valueMap.end())
    {
        it->second += currencyState.NativeToReserve(NativeFees(), defaultReserve);
    }
    else
    {
        reserveFees.valueMap[currencyState.currencies[defaultReserve]] = NativeFees();
    }
    return reserveFees;
}

CCurrencyValueMap CReserveTransactionDescriptor::AllFeesAsReserve(const CCurrencyState &currencyState, const std::vector<CAmount> &exchangeRates, int defaultReserve) const
{
    CCurrencyValueMap reserveFees = ReserveFees();

    auto it = reserveFees.valueMap.find(currencyState.currencies[defaultReserve]);
    if (it != reserveFees.valueMap.end())
    {
        it->second += currencyState.NativeToReserveRaw(NativeFees(), exchangeRates[defaultReserve]);
    }
    else
    {
        reserveFees.valueMap[currencyState.currencies[defaultReserve]] = NativeFees();
    }
    return reserveFees;
}

/*
 * Checks all structural aspects of the reserve part of a transaction that may have reserve inputs and/or outputs
 */
CReserveTransactionDescriptor::CReserveTransactionDescriptor(const CTransaction &tx, const CCoinsViewCache &view, int32_t nHeight) :
        flags(0),
        ptx(NULL),
        numBuys(0),
        numSells(0),
        numTransfers(0),
        nativeIn(0),
        nativeOut(0),
        nativeConversionFees(0)
{
    // market conversions can have any number of both buy and sell conversion outputs, this is used to make efficient, aggregated
    // reserve transfer operations with conversion

    // limit conversion outputs may have multiple outputs with different input amounts and destinations, 
    // but they must not be mixed in a transaction with any dissimilar set of conditions on the output, 
    // including mixing with market orders, parity of buy or sell, limit value and validbefore values, 
    // or the transaction is considered invalid

    // no inputs are valid at height 0
    if (!nHeight)
    {
        flags |= IS_REJECT;
        return;
    }

    int32_t solutionVersion = CConstVerusSolutionVector::activationHeight.ActiveVersion(nHeight);

    // reserve descriptor transactions cannot run until identity activates
    if (!chainActive.LastTip() || solutionVersion < CConstVerusSolutionVector::activationHeight.ACTIVATE_IDENTITY)
    {
        return;
    }

    bool isPBaaS = solutionVersion >= CActivationHeight::ACTIVATE_PBAAS;
    bool isPBaaSActivation = CConstVerusSolutionVector::activationHeight.IsActivationHeight(CActivationHeight::ACTIVATE_PBAAS, nHeight);
    bool loadedCurrencies = false;

    bool reservationValid = false;
    bool advancedReservationValid = false;
    CNameReservation nr;
    CAdvancedNameReservation anr;
    CIdentity identity;

    std::vector<CPBaaSNotarization> notarizations;
    CCurrencyValueMap importGeneratedCurrency;

    flags |= IS_VALID;

    for (int i = 0; i < tx.vout.size(); i++)
    {
        COptCCParams p;

        if (tx.vout[i].scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid())
        {
            switch (p.evalCode)
            {
                case EVAL_IDENTITY_RESERVATION:
                case EVAL_IDENTITY_ADVANCEDRESERVATION:
                {
                    // one name reservation per transaction
                    if (p.version < p.VERSION_V3 || !p.vData.size() || reservationValid || 
                        !((p.evalCode == EVAL_IDENTITY_ADVANCEDRESERVATION && (anr = CAdvancedNameReservation(p.vData[0])).IsValid()) || 
                          (p.evalCode == EVAL_IDENTITY_RESERVATION && (nr = CNameReservation(p.vData[0])).IsValid())))
                    {
                        flags &= ~IS_VALID;
                        flags |= IS_REJECT;
                        return;
                    }
                    if (identity.IsValid())
                    {
                        if (p.evalCode == EVAL_IDENTITY_ADVANCEDRESERVATION && identity.name == anr.name && identity.parent == anr.parent)
                        {
                            // TDOD: HARDENING potentially finish validating the fees according to the currency
                            flags |= IS_IDENTITY_DEFINITION + IS_HIGH_FEE;
                            reservationValid = advancedReservationValid = true;
                        }
                        else if (p.evalCode == EVAL_IDENTITY_RESERVATION && identity.name == nr.name)
                        {
                            flags |= IS_IDENTITY_DEFINITION + IS_HIGH_FEE;
                            reservationValid = true;
                        }
                        else
                        {
                            flags &= ~IS_VALID;
                            flags |= IS_REJECT;
                            return;
                        }
                    }
                }
                break;

                case EVAL_IDENTITY_PRIMARY:
                {
                    // one identity per transaction, unless we are first block coinbase on a PBaaS chain
                    // or import
                    if (p.version < p.VERSION_V3 ||
                        !p.vData.size() ||
                        (solutionVersion < CActivationHeight::ACTIVATE_VERUSVAULT && identity.IsValid()) ||
                        !(identity = CIdentity(p.vData[0])).IsValid())
                    {
                        flags &= ~IS_VALID;
                        flags |= IS_REJECT;
                        return;
                    }
                    flags |= IS_IDENTITY;
                    if (reservationValid)
                    {
                        if (advancedReservationValid && identity.name == anr.name)
                        {
                            flags |= IS_IDENTITY_DEFINITION + IS_HIGH_FEE;
                        }
                        else if (identity.name == nr.name)
                        {
                            flags |= IS_IDENTITY_DEFINITION + IS_HIGH_FEE;
                        }
                        else
                        {
                            flags &= ~IS_VALID;
                            flags |= IS_REJECT;
                            return;
                        }
                    }
                }
                break;

                case EVAL_RESERVE_DEPOSIT:
                {
                    CReserveDeposit rd;
                    if (!p.vData.size() || !(rd = CReserveDeposit(p.vData[0])).IsValid())
                    {
                        flags &= ~IS_VALID;
                        flags |= IS_REJECT;
                        return;
                    }
                    for (auto &oneCur : rd.reserveValues.valueMap)
                    {
                        if (oneCur.first != ASSETCHAINS_CHAINID)
                        {
                            AddReserveOutput(oneCur.first, oneCur.second);
                        }
                    }
                }
                break;

                case EVAL_RESERVE_OUTPUT:
                {
                    CTokenOutput ro;
                    if (!p.vData.size() || !(ro = CTokenOutput(p.vData[0])).IsValid())
                    {
                        flags &= ~IS_VALID;
                        flags |= IS_REJECT;
                        return;
                    }
                    for (auto &oneCur : ro.reserveValues.valueMap)
                    {
                        if (oneCur.first != ASSETCHAINS_CHAINID && oneCur.second)
                        {
                            AddReserveOutput(oneCur.first, oneCur.second);
                        }
                    }
                }
                break;

                case EVAL_RESERVE_TRANSFER:
                {
                    CReserveTransfer rt;
                    if (!p.vData.size() || !(rt = CReserveTransfer(p.vData[0])).IsValid())
                    {
                        flags &= ~IS_VALID;
                        flags |= IS_REJECT;
                        return;
                    }
                    flags |= IS_RESERVETRANSFER;
                    AddReserveTransfer(rt);
                }
                break;

                case EVAL_CROSSCHAIN_IMPORT:
                {
                    if (isPBaaS &&
                        nHeight == 1 &&
                        tx.IsCoinBase() &&
                        !loadedCurrencies)
                    {
                        // load currencies
                        //UniValue jsonTx(UniValue::VOBJ);
                        //TxToUniv(tx, uint256(), jsonTx);
                        //printf("%s: Coinbase transaction:\n%s\n", __func__, jsonTx.write(1,2).c_str());
                        CCurrencyDefinition oneCurDef;
                        COptCCParams tempP;
                        for (int j = 0; j < tx.vout.size(); j++)
                        {
                            if (tx.vout[j].scriptPubKey.IsPayToCryptoCondition(tempP) &&
                                tempP.IsValid() &&
                                tempP.evalCode == EVAL_CURRENCY_DEFINITION &&
                                tempP.vData.size() &&
                                (oneCurDef = CCurrencyDefinition(tempP.vData[0])).IsValid())
                            {
                                //printf("%s: Adding currency:\n%s\n", __func__, oneCurDef.ToUniValue().write(1,2).c_str());
                                ConnectedChains.currencyDefCache.insert(std::make_pair(oneCurDef.GetID(), oneCurDef));
                            }
                        }
                        loadedCurrencies = true;
                    }

                    CCrossChainImport cci, sysCCI;

                    // if this is an import, add the amount imported to the reserve input and the amount of reserve output as
                    // the amount available to take from this transaction in reserve as an import fee
                    if (!p.vData.size() || !(cci = CCrossChainImport(p.vData[0])).IsValid())
                    {
                        flags &= ~IS_VALID;
                        flags |= IS_REJECT;
                        return;
                    }

                    flags |= (IS_IMPORT + IS_HIGH_FEE);

                    CCurrencyDefinition importCurrencyDef, sourceSystemDef;
                    CCrossChainExport ccx;
                    int32_t sysCCIOut;
                    notarizations.push_back(CPBaaSNotarization());
                    CPBaaSNotarization &importNotarization = notarizations.back();

                    int32_t importNotarizationOut;
                    int32_t eOutStart, eOutEnd;
                    std::vector<CReserveTransfer> importTransfers;

                    // if this is the source system for a cci that we already processed, skip it
                    if ((cci.flags & cci.FLAG_SOURCESYSTEM) || (cci.flags & cci.FLAG_DEFINITIONIMPORT))
                    {
                        break;
                    }

                    if (!cci.IsDefinitionImport())
                    {
                        if (!cci.GetImportInfo(tx, nHeight, i, ccx, sysCCI, sysCCIOut, importNotarization, importNotarizationOut, eOutStart, eOutEnd, importTransfers))
                        {
                            flags &= ~IS_VALID;
                            flags |= IS_REJECT;
                            return;
                        }

                        importCurrencyDef = ConnectedChains.GetCachedCurrency(cci.importCurrencyID);
                        sourceSystemDef = ConnectedChains.GetCachedCurrency(cci.sourceSystemID);

                        if (!sourceSystemDef.IsValid() || !importCurrencyDef.IsValid())
                        {
                            flags &= ~IS_VALID;
                            flags |= IS_REJECT;
                            return;
                        }

                        std::vector<CTxOut> checkOutputs;
                        CCurrencyValueMap importedCurrency, gatewayDeposits, spentCurrencyOut;

                        CCoinbaseCurrencyState checkState = importNotarization.currencyState;
                        CCoinbaseCurrencyState newState;

                        /* if (tx.IsCoinBase())
                        {
                            printf("%s: currency state before revert: %s\n", __func__, checkState.ToUniValue().write(1,2).c_str());
                        }*/

                        checkState.RevertReservesAndSupply();
                        if (!cci.IsPostLaunch() && cci.IsInitialLaunchImport())
                        {
                            checkState.SetLaunchClear();
                        }

                        /*if (tx.IsCoinBase())
                        {
                            printf("%s: currency state after revert: %s\n", __func__, checkState.ToUniValue().write(1,2).c_str());
                        }*/

                        CReserveTransactionDescriptor rtxd;
                        // if clear launch, don't set launch complete beforehand to match outputs
                        if (ccx.IsClearLaunch() && ccx.sourceSystemID == importCurrencyDef.launchSystemID)
                        {
                            checkState.SetLaunchCompleteMarker(false);
                        }

                        if (!rtxd.AddReserveTransferImportOutputs(sourceSystemDef,
                                                                  ConnectedChains.thisChain,
                                                                  importCurrencyDef,
                                                                  checkState,
                                                                  importTransfers,
                                                                  nHeight,
                                                                  checkOutputs,
                                                                  importedCurrency,
                                                                  gatewayDeposits,
                                                                  spentCurrencyOut,
                                                                  &newState,
                                                                  ccx.exporter,
                                                                  importNotarization.proposer,
                                                                  importNotarization.proofRoots.count(cci.sourceSystemID) ?
                                                                    importNotarization.proofRoots.find(cci.sourceSystemID)->second.stateRoot :
                                                                    uint256()))
                        {
                            flags &= ~IS_VALID;
                            flags |= IS_REJECT;
                            return;
                        }

                        // validate that all outputs match calculated outputs
                        if (!cci.IsDefinitionImport() &&
                            !cci.IsSourceSystemImport())
                        {
                            int startingOutput = importNotarizationOut + 1;
                            if (eOutEnd > 0)
                            {
                                startingOutput = eOutEnd + 1;
                            }
                            if (startingOutput < 0 ||
                                checkOutputs.size() > cci.numOutputs ||
                                (startingOutput + checkOutputs.size()) > tx.vout.size())
                            {
                                LogPrint("importtransactions", "%s: import outputs would index beyond import transaction\n", __func__);
                                flags &= ~IS_VALID;
                                flags |= IS_REJECT;
                                return;
                            }

                            // TODO: HARDENING - this check skips checking imported IDs, as it cannot verify whether they have been skipped
                            // because they are in the mem pool on the same transaction, as we have not
                            // completed making the transaction yet. we need to confirm that imported IDs are valid 
                            // from the importing system and not duplicate.

                            int idCheckOffset = 0;
                            for (int loop = 0; loop < checkOutputs.size(); loop++)
                            {
                                if (checkOutputs[loop] != tx.vout[loop + startingOutput + idCheckOffset])
                                {
                                    COptCCParams idImportCheckP;
                                    if (!(tx.vout[loop + startingOutput + idCheckOffset].scriptPubKey.IsPayToCryptoCondition(idImportCheckP) &&
                                          idImportCheckP.IsValid() &&
                                          idImportCheckP.evalCode == EVAL_IDENTITY_PRIMARY &&
                                          checkOutputs[loop] == tx.vout[loop + startingOutput + ++idCheckOffset]))
                                    {
                                        if (LogAcceptCategory("crosschain") || LogAcceptCategory("defi"))
                                        {
                                            LogPrintf("%s: calculated outputs do not match outputs on import transaction\n", __func__);
                                            UniValue scriptJson1(UniValue::VOBJ), scriptJson2(UniValue::VOBJ);
                                            ScriptPubKeyToUniv(checkOutputs[loop].scriptPubKey, scriptJson1, false, false);
                                            ScriptPubKeyToUniv(tx.vout[loop + startingOutput + ++idCheckOffset].scriptPubKey, scriptJson2, false, false);
                                            LogPrintf("pre currency state: %s\n", checkState.ToUniValue().write(1,2).c_str());
                                            LogPrintf("post currency state: %s\n", newState.ToUniValue().write(1,2).c_str());
                                            LogPrintf("output 1:\n%s\nnativeout: %ld\nexpected:\n%s\nnativeout: %ld\n", scriptJson1.write(1,2).c_str(), checkOutputs[loop].nValue, scriptJson2.write(1,2).c_str(), tx.vout[loop + startingOutput + ++idCheckOffset].nValue);
                                        }
                                        //LogPrint("importtransactions", "%s: calculated outputs do not match outputs on import transaction\n", __func__);
                                        //flags &= ~IS_VALID;
                                        //flags |= IS_REJECT;
                                        //return;
                                    }
                                }
                            }
                        }

                        /*if (tx.IsCoinBase())
                        {
                            printf("%s: currency state after import: %s\n", __func__, newState.ToUniValue().write(1,2).c_str());
                            printf("%s: coinbase rtxd: %s\n", __func__, rtxd.ToUniValue().write(1,2).c_str());
                        }*/

                        importGeneratedCurrency += importedCurrency;
                        if (newState.primaryCurrencyOut)
                        {
                            importGeneratedCurrency.valueMap[cci.importCurrencyID] = newState.primaryCurrencyOut;
                        }
                        if (nHeight == 1 && cci.importCurrencyID == ASSETCHAINS_CHAINID)
                        {
                            importGeneratedCurrency.valueMap[ASSETCHAINS_CHAINID] += gatewayDeposits.valueMap[ASSETCHAINS_CHAINID];
                        }

                        /*
                        printf("%s: importGeneratedCurrency:\n%s\nnewState:\n%s\n", 
                                __func__, 
                                importGeneratedCurrency.ToUniValue().write(1,2).c_str(), 
                                newState.ToUniValue().write(1,2).c_str());
                        */

                        for (auto &oneOutCur : cci.totalReserveOutMap.valueMap)
                        {
                            AddReserveOutput(oneOutCur.first, oneOutCur.second);
                        }
                    }
                }
                break;

                // this check will need to be made complete by preventing mixing both here and where the others
                // are seen
                case EVAL_CROSSCHAIN_EXPORT:
                {
                    CCrossChainExport ccx;
                    if (!p.vData.size() ||
                        !(ccx = CCrossChainExport(p.vData[0])).IsValid())
                    {
                        flags &= ~IS_VALID;
                        flags |= IS_REJECT;
                        return;
                    }
                    //printf("%s: ccx: %s\n", __func__, ccx.ToUniValue().write(1,2).c_str());
                    importGeneratedCurrency -= ccx.totalBurned;
                    flags |= IS_EXPORT;
                }
                break;

                case EVAL_CURRENCY_DEFINITION:
                {
                    CCurrencyDefinition cDef;
                    if (!p.vData.size() ||
                        !(cDef = CCurrencyDefinition(p.vData[0])).IsValid())
                    {
                        flags &= ~IS_VALID;
                        flags |= IS_REJECT;
                        return;
                    }
                    flags |= IS_CURRENCY_DEFINITION;
                }
                break;

                case EVAL_FINALIZE_NOTARIZATION:
                {
                    CObjectFinalization of;
                    if (!p.vData.size() ||
                        !(of = CObjectFinalization(p.vData[0])).IsValid())
                    {
                        flags &= ~IS_VALID;
                        flags |= IS_REJECT;
                        return;
                    }
                    if (ConnectedChains.notarySystems.count(of.currencyID))
                    {
                        flags |= IS_CHAIN_NOTARIZATION;
                    }
                }
                break;

                case EVAL_EARNEDNOTARIZATION:
                {
                    // this is only used on the chain earning notarizations
                    flags |= IS_CHAIN_NOTARIZATION;
                }
                case EVAL_ACCEPTEDNOTARIZATION:
                {
                    CPBaaSNotarization onePBN;
                    if (!p.vData.size() ||
                        !(onePBN = CPBaaSNotarization(p.vData[0])).IsValid())
                    {
                        flags &= ~IS_VALID;
                        flags |= IS_REJECT;
                        return;
                    }
                    // verify
                    // if this is the notaries that can finalize this chain, store notarization
                }
                break;

                default:
                {
                    CCurrencyValueMap output = tx.vout[i].scriptPubKey.ReserveOutValue();
                    output.valueMap.erase(ASSETCHAINS_CHAINID);
                    for (auto &oneOutCur : output.valueMap)
                    {
                        AddReserveOutput(oneOutCur.first, oneOutCur.second);
                    }
                }
            }
        }
        /*if (flags & IS_IMPORT)
        {
            printf("currencies after proccessing code %d:\n", p.evalCode);
            for (auto &oneInOut : currencies)
            {
                printf("{\"currency\":\"%s\",\"nativeOutConverted\":\"%ld\",\"reserveConversionFees\":\"%ld\",\"reserveIn\":\"%ld\",\"reserveOut\":\"%ld\",\"reserveOutConverted\":\"%ld\"}\n",
                        EncodeDestination(CIdentityID(oneInOut.first)).c_str(), 
                        oneInOut.second.nativeOutConverted,
                        oneInOut.second.reserveConversionFees,
                        oneInOut.second.reserveIn,
                        oneInOut.second.reserveOut,
                        oneInOut.second.reserveOutConverted);
            }
        }*/
    }

    // we have all inputs, outputs, and fees, if check inputs, we can check all for consistency
    // inputs may be in the memory pool or on the blockchain
    CAmount dummyInterest;
    nativeOut = tx.GetValueOut();
    nativeIn = view.GetValueIn(nHeight, &dummyInterest, tx);

    if (importGeneratedCurrency.valueMap.count(ASSETCHAINS_CHAINID))
    {
        nativeIn += importGeneratedCurrency.valueMap[ASSETCHAINS_CHAINID];
        importGeneratedCurrency.valueMap.erase(ASSETCHAINS_CHAINID);
    }

    // if it is a conversion to reserve, the amount in is accurate, since it is from the native coin, if converting to
    // the native PBaaS coin, the amount input is a sum of all the reserve token values of all of the inputs
    auto reservesIn = (view.GetReserveValueIn(nHeight, tx) + importGeneratedCurrency).CanonicalMap();

    /* if (flags & IS_IMPORT || flags & IS_EXPORT)
    {
        printf("%s: importGeneratedCurrency:\n%s\nreservesIn:\n%s\n", __func__, importGeneratedCurrency.ToUniValue().write(1,2).c_str(),
                                                                          reservesIn.ToUniValue().write(1,2).c_str());
    } */

    for (auto &oneCur : currencies)
    {
        oneCur.second.reserveIn = 0;
    }
    if (reservesIn.valueMap.size())
    {
        flags |= IS_RESERVE;
        for (auto &oneCur : reservesIn.valueMap)
        {
            currencies[oneCur.first].reserveIn = oneCur.second;
        }
    }
    
    if (!IsReserve() && ReserveOutputMap().valueMap.size())
    {
        flags |= IS_RESERVE;
    }

    ptx = &tx;
}

// this is only valid when used after AddReserveTransferImportOutputs on an empty CReserveTransactionDwescriptor
CCurrencyValueMap CReserveTransactionDescriptor::GeneratedImportCurrency(const uint160 &fromSystemID, const uint160 &importSystemID, const uint160 &importCurrencyID) const
{
    // only currencies that are controlled by the exporting chain or created in conversion by the importing currency
    // can be created from nothing
    // add newly created currency here that meets those criteria
    CCurrencyValueMap retVal;
    for (auto one : currencies)
    {
        bool isImportCurrency = one.first == importCurrencyID;
        if ((one.second.nativeOutConverted && isImportCurrency) || 
              (one.second.reserveIn && fromSystemID != ASSETCHAINS_CHAINID && ConnectedChains.GetCachedCurrency(one.first).systemID == fromSystemID))
        {
            retVal.valueMap[one.first] = isImportCurrency ? one.second.nativeOutConverted : one.second.reserveIn;
        }
    }
    return retVal;
}

CReserveTransfer CReserveTransfer::GetRefundTransfer(bool clearCrossSystem) const
{
    CReserveTransfer rt = *this;
    uint160 newDest;

    if (rt.IsImportToSource())
    {
        newDest = rt.FirstCurrency();
    }
    else
    {
        newDest = rt.destCurrencyID;
    }

    // turn it into a normal transfer, which will create an unconverted output
    rt.flags &= ~(DOUBLE_SEND | PRECONVERT | CONVERT);

    if (clearCrossSystem)
    {
        rt.flags &= ~CROSS_SYSTEM;
        rt.destSystemID.SetNull();
        // convert full ID destinations to normal ID outputs, since it's refund, full ID will be on this chain already
        if (rt.destination.type == CTransferDestination::DEST_FULLID)
        {
            CIdentity(rt.destination.destination);
            rt.destination = CTransferDestination(CTransferDestination::DEST_ID, rt.destination.destination);
        }
    }

    if (rt.IsMint())
    {
        rt.flags &= ~MINT_CURRENCY;
        rt.reserveValues.valueMap.begin()->second = 0;
    }

    // with the refund flag, we won't import new currency, so we don't set it for cross system refunds
    // due to a failure
    if (!rt.IsCrossSystem())
    {
        rt.flags |= REFUND;
    }

    rt.destCurrencyID = newDest;
    return rt;
}

bool CReserveTransfer::GetTxOut(const CCurrencyDefinition &sourceSystem,
                                const CCurrencyDefinition &destSystem,
                                const CCurrencyDefinition &destCurrency,
                                const CCoinbaseCurrencyState &curState,
                                CCurrencyValueMap reserves,
                                int64_t nativeAmount,
                                CTxOut &txOut,
                                std::vector<CTxOut> &txOutputs,
                                uint32_t height) const
{
    bool makeNormalOutput = true;
    CTxDestination dest = TransferDestinationToDestination(destination);
    CCurrencyDefinition exportCurDef;
    if (HasNextLeg())
    {
        makeNormalOutput = false;
        CReserveTransfer nextLegTransfer = CReserveTransfer(CReserveTransfer::VERSION_INVALID);

        // if we have a nested transfer, use it
        if (destination.TypeNoFlags() == destination.DEST_NESTEDTRANSFER)
        {
            printf("%s: Nested currency transfers not yet supported\n", __func__);
            return false;
            // get the reserve transfer from the raw data and
            CReserveTransfer rt(destination.destination);
            if (rt.IsValid())
            {
                // input currency, not fees, come from the output of the
                // last leg. fees are converted and transfered independently.
                rt.reserveValues = reserves;
                rt.feeCurrencyID = destination.gatewayID;
                rt.destination.fees = destination.fees;
                nextLegTransfer = rt;
            }
        }
        else
        {
            // make an output to the gateway ID, which should be another system, since there is
            // no reserve transfer left for instructions to do anything else worth another leg
            // we need to have correct fees in the destination currency available
            CTransferDestination lastLegDest = CTransferDestination(destination);
            lastLegDest.ClearGatewayLeg();

            uint32_t newFlags = CReserveTransfer::VALID;

            CCurrencyDefinition nextDest = destination.gatewayID == ASSETCHAINS_CHAINID ?
                ConnectedChains.ThisChain() :
                ConnectedChains.GetCachedCurrency(destination.gatewayID);

            // if this is a currency export, make the export
            if (IsCurrencyExport())
            {
                exportCurDef = ConnectedChains.GetCachedCurrency(FirstCurrency());
                if (exportCurDef.IsValid() &&
                    nextDest.IsMultiCurrency() &&
                    destination.gatewayID != ASSETCHAINS_CHAINID &&
                    CCurrencyDefinition::IsValidDefinitionImport(sourceSystem, destSystem, exportCurDef.parent.IsNull() ? VERUS_CHAINID : exportCurDef.parent, height))
                {
                    if (!IsValidExportCurrency(nextDest, FirstCurrency(), height))
                    {
                        lastLegDest.type = lastLegDest.DEST_REGISTERCURRENCY;
                        lastLegDest.destination = ::AsVector(exportCurDef);
                        newFlags |= CURRENCY_EXPORT;
                    }
                }
                else
                {
                    printf("%s: Invalid currency export to system: %s\n", __func__, EncodeDestination(CIdentityID(nextDest.GetID())).c_str());
                    LogPrintf("%s: Invalid currency export to system: %s\n", __func__, EncodeDestination(CIdentityID(nextDest.GetID())).c_str());
                    return false;
                }
            }
            // if we're supposed to export the destination identity, do so
            // by adding the full ID to this transfer destination
            else if (IsIdentityExport())
            {
                CTxDestination dest = TransferDestinationToDestination(destination);
                CIdentity fullID;
                if (dest.which() != COptCCParams::ADDRTYPE_ID ||
                    !(fullID = CIdentity::LookupIdentity(GetDestinationID(dest))).IsValid() ||
                    destination.gatewayID == ASSETCHAINS_CHAINID ||
                    !CCurrencyDefinition::IsValidDefinitionImport(sourceSystem, destSystem, fullID.parent.IsNull() ? VERUS_CHAINID : fullID.parent, height))
                {
                    // TODO: HARDENING - ensure this cannot be exploited by a cross-chain transfer
                    printf("%s: Invalid export identity or identity not found for %s\n", __func__, EncodeDestination(dest).c_str());
                    LogPrintf("%s: Invalid export identity or identity not found for %s\n", __func__, EncodeDestination(dest).c_str());
                    return false;
                }
                lastLegDest.type = lastLegDest.DEST_FULLID;
                lastLegDest.destination = ::AsVector(fullID);
            }

            if (destination.gatewayID != destSystem.GetID())
            {
                newFlags |= CReserveTransfer::CROSS_SYSTEM;
                CCurrencyValueMap newReserves = reserves;
                // if there is no value, we will add zero in source currency
                if (nativeAmount || !newReserves.valueMap.size())
                {
                    newReserves.valueMap[ASSETCHAINS_CHAINID] = nativeAmount;
                }
                nextLegTransfer = CReserveTransfer(newFlags,
                                                   newReserves,
                                                   destination.gatewayID,
                                                   destination.fees,
                                                   destination.gatewayID,
                                                   lastLegDest,
                                                   uint160(),
                                                   destination.gatewayID);

                // make sure we have enough fee to make a valid cross chain transfer
                // or refund before we make it
                //
                // if headed to a system with incompatible addresses, we need to get the source address
                // for refund

                // TODO: HARDENING - for now, insufficient fee would only be refunded when there is a compatible
                // output address for refund. we need to add a check on the second leg fee in reserve transfer
                // or risk this blocking the bridge due to fee liquidity + slow processing
                // commented check below

                /* if ((nextLegTransfer.IsCurrencyExport() && destination.fees < nextDest.GetCurrencyImportFee()) ||
                    (nextLegTransfer.IsIdentityExport() && destination.fees < nextDest.IDImportFee()) ||
                    (!(nextLegTransfer.IsCurrencyExport() || nextLegTransfer.IsIdentityExport()) && destination.fees < nextDest.GetTransactionImportFee()))
                {
                    // for now, we refund only if we have a valid output for this chain, otherwise
                    // put output in fees
                    nextLegTransfer = CReserveTransfer();
                    makeNormalOutput = true;
                    reserves += CCurrencyValueMap(std::vector<uint160>({destination.gatewayID}), std::vector<int64_t>({destination.fees}));
                    if (!(dest.which() == COptCCParams::ADDRTYPE_ID || 
                         dest.which() == COptCCParams::ADDRTYPE_PK ||
                         dest.which() == COptCCParams::ADDRTYPE_PKH ||
                         dest.which() == COptCCParams::ADDRTYPE_SH))
                    {
                        // TODO: HARDENING - here, if we have too little fee and no
                        // compatible destination address, we are eating the value and making it
                        // available to the first spender. Instead, we should look back and have
                        // a refund address
                        CCcontract_info CC;
                        CCcontract_info *cp;
                        cp = CCinit(&CC, EVAL_RESERVE_OUTPUT);
                        dest = CPubKey(ParseHex(CC.CChexstr));
                    }
                } // */
            }
            else
            {
                // if our destination is here, add unused fees to native output and drop through to make normal output
                // TODO: right now, a next leg that is local is a normal output. we should support local next legs
                // that have function.
                nativeAmount += destination.fees;
                makeNormalOutput = true;
            }
        }
        if (nextLegTransfer.IsValid())
        {
            // if we don't have enough for a transaction import fee to the next destination,
            // we need to drop out here and send to the recipient, or if they have an incompatible
            // destination address, to the last compatible one we have
            CCurrencyDefinition nextSys = destination.gatewayID != ASSETCHAINS_CHAINID ?
                                    ConnectedChains.GetCachedCurrency(destination.gatewayID) :
                                    ConnectedChains.ThisChain();
            if (!nextSys.IsValid() ||
                (destination.gatewayID != ASSETCHAINS_CHAINID &&
                 (nextLegTransfer.feeCurrencyID != nextSys.GetID())))
            {
                printf("%s: Invalid fee currency for next leg of transfer %s\n", __func__, nextLegTransfer.ToUniValue().write(1,2).c_str());
                LogPrintf("%s: Invalid fee currency for next leg of transfer %s\n", __func__, nextLegTransfer.ToUniValue().write(1,2).c_str());
            }
            else if (nextLegTransfer.nFees < nextSys.GetTransactionImportFee() ||
                     (IsCurrencyExport() && nextLegTransfer.nFees < nextSys.GetCurrencyImportFee(exportCurDef.ChainOptions() & exportCurDef.OPTION_NFT_TOKEN)) ||
                     (IsIdentityExport() && nextLegTransfer.nFees < nextSys.IDImportFee()))
            {
                LogPrintf("%s: Insufficient fee currency for next leg of transfer %s\n", __func__, nextLegTransfer.ToUniValue().write(1,2).c_str());
            }
            else
            {
                // emit a reserve transfer output
                CCcontract_info CC;
                CCcontract_info *cp;
                cp = CCinit(&CC, EVAL_RESERVE_TRANSFER);
                CPubKey pk = CPubKey(ParseHex(CC.CChexstr));

                // transfer it back to the source chain and to our address
                std::vector<CTxDestination> dests = std::vector<CTxDestination>({pk.GetID()});
                txOut = CTxOut(nativeAmount, MakeMofNCCScript(CConditionObj<CReserveTransfer>(EVAL_RESERVE_TRANSFER, dests, 1, &nextLegTransfer)));
                return true;
            }
            if (dest.which() == COptCCParams::ADDRTYPE_INVALID || dest.which() == COptCCParams::ADDRTYPE_INDEX)
            {
                dest = GetCompatibleAuxDestination(destination, (CCurrencyDefinition::EProofProtocol)nextSys.proofProtocol);
                if (dest.which() == COptCCParams::ADDRTYPE_INVALID)
                {
                    // TODO: HARDENING - provide a model for users to add funds to allow the send to resume
                    // for example, send to an address controlled by an app that can accept payment to retry
                    // or a type of output that parks, waiting for more fees that can be
                    // contributed by anyone to continue, possibly a parked transaction similar to a market offer
                    // that can be accepted by anyone to enable resumption.
                    dest = DecodeDestination("vrsctest@");
                    LogPrintf("Invalid or missing alternative destination. Value sent to %s on chain %s\n", "vrsctest@", EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID)).c_str());
                }
                else
                {
                    LogPrintf("Value refunded to alternatiive destination on chain %s\n", EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID)).c_str());
                }
            }
            else
            {
                LogPrintf("Value emitted to recipient on chain %s\n", EncodeDestination(CIdentityID(ASSETCHAINS_CHAINID)).c_str());
            }
            if (!reserves.valueMap.size() && nativeAmount)
            {
                txOut = CTxOut(nativeAmount, GetScriptForDestination(dest));
            }
            else
            {
                std::vector<CTxDestination> dests = std::vector<CTxDestination>({dest});
                CTokenOutput ro = CTokenOutput(reserves);
                txOut = CTxOut(nativeAmount, MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, dests, 1, &ro)));
            }
            return true;
        }
    }
    if (makeNormalOutput)
    {
        // if this is a currency registration, make the currency output
        if (destination.TypeNoFlags() == destination.DEST_REGISTERCURRENCY)
        {
            CCurrencyDefinition registeredCurrency(destination.destination);
            if (!registeredCurrency.IsValid() ||
                !IsCurrencyExport() ||
                FirstCurrency() != registeredCurrency.GetID() ||
                FirstValue() != 0 ||
                IsConversion())
            {
                std::string qualifiedName = ConnectedChains.GetFriendlyCurrencyName(FirstCurrency());
                printf("%s: Invalid currency export of %s from %s\n", __func__, ConnectedChains.GetFriendlyCurrencyName(FirstCurrency()).c_str(), sourceSystem.name.c_str());
                LogPrintf("%s: Invalid currency export of %s from %s\n", __func__, ConnectedChains.GetFriendlyCurrencyName(FirstCurrency()).c_str(), sourceSystem.name.c_str());
                return false;
            }

            CCurrencyDefinition preExistingCur;
            int32_t curHeight;

            // if on this chain, not enough fees or currency is already registered, don't define
            // if not on this chain, it is a simulation, and allow it
            if (destSystem.GetID() == ASSETCHAINS_CHAINID &&
                (GetCurrencyDefinition(FirstCurrency(), preExistingCur, &curHeight, false) &&
                curHeight < height))
            {
                std::string qualifiedName = ConnectedChains.GetFriendlyCurrencyName(FirstCurrency());
                LogPrint("crosschain", "%s: Currency already registered for %s\n", __func__, qualifiedName.c_str());

                // drop through and make an output that will not be added
                nativeAmount = -1;
            }
            txOut = CTxOut(nativeAmount, MakeMofNCCScript(CConditionObj<CCurrencyDefinition>(EVAL_CURRENCY_DEFINITION, std::vector<CTxDestination>({dest}), 1, &registeredCurrency)));
            return true;
        }
        // if we are supposed to make an imported ID registration output, check to see if the ID exists, and if not, make it
        else if (destination.TypeNoFlags() == destination.DEST_FULLID)
        {
            CIdentity importedID(destination.destination);

            if (!importedID.IsValid())
            {
                // cannot accept an invalid identity
                return false;
            }

            // lookup ID and if not present, make an ID output

            // TODO: HARDENING - confirm/audit that we can only mint IDs from systems that are able to mint them
            CIdentity preexistingID = CIdentity::LookupIdentity(importedID.GetID());

            // if we have a collision present, sound an alarm and make no output
            if (preexistingID.IsValid() &&
                (boost::to_lower_copy(importedID.name) != boost::to_lower_copy(preexistingID.name) ||
                 importedID.parent != preexistingID.parent))
            {
                printf("WARNING!: Imported identity collides with pre-existing identity of another name.\n"
                        "The only likely reason for this occurance is a hash-collision attack, targeted specifically at\n"
                        "either the %s or the %s identities. As a result, this transaction is undeliverable.\n"
                        "Full identity outputs:\n%s\n%s\n",
                        importedID.name.c_str(), preexistingID.name.c_str(),
                        importedID.ToUniValue().write(1,2).c_str(), preexistingID.ToUniValue().write(1,2).c_str());
                LogPrintf("WARNING!: Imported identity collides with pre-existing identity of another name.\n"
                        "The only likely reason for this occurance is a hash-collision attack, targeted specifically at\n"
                        "either the %s or the %s identities. As a result, this transaction is undeliverable.\n"
                        "Full identity outputs:\n%s\n%s\n",
                        importedID.name.c_str(), preexistingID.name.c_str(),
                        importedID.ToUniValue().write(1,2).c_str(), preexistingID.ToUniValue().write(1,2).c_str());

                // TODO: HARDENING
                // the current best option for this case is to make an output to
                // the first primary address controlling the ID
                // consider any others before removing this TODO
                // check below for one more of this same issue
                dest = importedID.primaryAddresses[0];

                // if we are sending no value, make an output that will not be added
                if (reserves.CanonicalMap() == CCurrencyValueMap() && !nativeAmount)
                {
                    txOut = CTxOut(-1, GetScriptForDestination(dest));
                    return true;
                }
            }
            else if (!preexistingID.IsValid())
            {
                LOCK(mempool.cs);
                // check mempool for collision, and if none, make the ID output
                uint160 identityKeyID(CCrossChainRPCData::GetConditionID(importedID.GetID(), EVAL_IDENTITY_PRIMARY));
                std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta>> memIndex;

                bool foundMemDup = false;
                if (mempool.getAddressIndex(std::vector<std::pair<uint160, int32_t>>({{identityKeyID, CScript::P2IDX}}), memIndex))
                {
                    // TODO: HARDENING - ensure that if we find an in-memory duplicate, that it is
                    // from the same export as this one, otherwise we can't make an output
                    // this may already be achieved by ensuring that all identity outputs are either unique
                    // on-chain new, spend the prior, or are invalid, but before removing this comment,
                    // it must be verified

                    // if there is any conflicting entry, we have an issue, otherwise, we are fine
                    foundMemDup = memIndex.size() > 0;
                    for (auto &oneIdxEntry : memIndex)
                    {
                        const CTransaction &identityTx = mempool.mapTx.find(oneIdxEntry.first.txhash)->GetTx();
                        preexistingID = CIdentity(identityTx.vout[oneIdxEntry.first.index].scriptPubKey);
                        if (!preexistingID.IsValid() ||
                            boost::to_lower_copy(importedID.name) != boost::to_lower_copy(preexistingID.name) ||
                            importedID.parent != preexistingID.parent)
                        {
                            printf("WARNING!: Imported identity collides with pre-existing identity of another name in mempool.\n"
                                "The only likely reason for this occurance is a hash-collision attack, targeted specifically at\n"
                                "either the %s or the %s identities. As a result, this transaction is undeliverable.\n"
                                "Full identity outputs:\n%s\n%s\n",
                                importedID.name.c_str(), preexistingID.name.c_str(),
                                importedID.ToUniValue().write(1,2).c_str(), preexistingID.ToUniValue().write(1,2).c_str());
                            LogPrintf("WARNING!: Imported identity collides with pre-existing identity of another name in mempool.\n"
                                "The only likely reason for this occurance is a hash-collision attack, targeted specifically at\n"
                                "either the %s or the %s identities. As a result, this transaction is undeliverable.\n"
                                "Full identity outputs:\n%s\n%s\n",
                                importedID.name.c_str(), preexistingID.name.c_str(),
                                importedID.ToUniValue().write(1,2).c_str(), preexistingID.ToUniValue().write(1,2).c_str());

                            dest = GetCompatibleAuxDestination(destination, (CCurrencyDefinition::EProofProtocol)destSystem.proofProtocol);
                            if (dest.which() == COptCCParams::ADDRTYPE_INVALID)
                            {
                                dest = importedID.primaryAddresses[0];
                            }

                            // this is not just a mem dup
                            foundMemDup = false;
                        }
                    }
                }
                // if the ID is already in the mempool, we don't need to make an ID output, otherwise, we do
                if (!memIndex.size() || foundMemDup)
                {
                    // if we are sending no value, make one output for the ID and return
                    if (reserves.CanonicalMap() == CCurrencyValueMap() && !nativeAmount)
                    {
                        txOut = CTxOut(0, importedID.IdentityUpdateOutputScript(height));
                        return true;
                    }
                    txOutputs.push_back(CTxOut(0, importedID.IdentityUpdateOutputScript(height)));
                }
                else if (reserves.CanonicalMap() == CCurrencyValueMap() && !nativeAmount)
                {
                    txOut = CTxOut(-1, GetScriptForDestination(dest));
                    return true;
                }
            }

            // as long as the ID sent to us is the same as the ID on chain, we accept the ID
            // destination, but cannot replace the existing ID definition, so we don't try and pass through
        }

        // make normal output to the destination, which must be valid
        // if destination is not valid, and we are supposed to make an output
        // to an ETH address, make a nested output instead
        if (dest.which() == COptCCParams::ADDRTYPE_INVALID && destination.TypeNoFlags() == destination.DEST_ETH)
        {
            // we make an unspendable P2SH output with the ETH address as the P2SH value
            CKeyID unspendableP2SH;
            bool success = false;
            ::FromVector(destination.destination, unspendableP2SH, &success);
            if (success)
            {
                dest = CTxDestination(CKeyID(unspendableP2SH));
            }
        }
        if (!reserves.valueMap.size() && nativeAmount)
        {
            if (dest.which() == COptCCParams::ADDRTYPE_ID || 
                dest.which() == COptCCParams::ADDRTYPE_PK ||
                dest.which() == COptCCParams::ADDRTYPE_PKH ||
                dest.which() == COptCCParams::ADDRTYPE_SH)
            {
                txOut = CTxOut(nativeAmount, GetScriptForDestination(dest));
                return true;
            }
        }
        else
        {
            if (dest.which() == COptCCParams::ADDRTYPE_ID ||
                dest.which() == COptCCParams::ADDRTYPE_PK ||
                dest.which() == COptCCParams::ADDRTYPE_PKH)
            {
                std::vector<CTxDestination> dests = std::vector<CTxDestination>({dest});
                CTokenOutput ro = CTokenOutput(reserves);
                txOut = CTxOut(nativeAmount, MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, dests, 1, &ro)));
                return true;
            }
        }
    }
    return false;
}

CReserveTransfer RefundExport(const CBaseChainObject *objPtr)
{
    if (objPtr->objectType == CHAINOBJ_RESERVETRANSFER)
    {
        return ((CChainObject<CReserveTransfer> *)objPtr)->object.GetRefundTransfer();
    }
    return CReserveTransfer();
}

// the source currency indicates the system from which the import comes, but the imports may contain additional
// currencies that are supported in that system and are not limited to the native currency. Fees are assumed to
// be covered by the native currency of the source or source currency, if this is a reserve conversion. That 
// means that all explicit fees are assumed to be in the currency of the source.
bool CReserveTransactionDescriptor::AddReserveTransferImportOutputs(const CCurrencyDefinition &systemSource, 
                                                                    const CCurrencyDefinition &systemDest, 
                                                                    const CCurrencyDefinition &importCurrencyDef, 
                                                                    const CCoinbaseCurrencyState &importCurrencyState,
                                                                    const std::vector<CReserveTransfer> &exportObjects, 
                                                                    uint32_t height,
                                                                    std::vector<CTxOut> &vOutputs,
                                                                    CCurrencyValueMap &importedCurrency,
                                                                    CCurrencyValueMap &gatewayDepositsIn,
                                                                    CCurrencyValueMap &spentCurrencyOut,
                                                                    CCoinbaseCurrencyState *pNewCurrencyState,
                                                                    const CTransferDestination &feeRecipient,
                                                                    const CTransferDestination &blockNotarizer,
                                                                    const uint256 &entropy)
{
    // easy way to refer to return currency state or a dummy without conditionals
    CCoinbaseCurrencyState _newCurrencyState;
    if (!pNewCurrencyState)
    {
        pNewCurrencyState = &_newCurrencyState;
    }
    CCoinbaseCurrencyState &newCurrencyState = *pNewCurrencyState;

    // prepare to update ins, outs, emissions, and last pricing
    newCurrencyState = importCurrencyState;
    newCurrencyState.ClearForNextBlock();

    bool isFractional = importCurrencyDef.IsFractional();

    int arbitrageCount = 0;

    // reserve currency amounts converted to fractional
    CCurrencyValueMap reserveConverted;

    // fractional currency amount and the reserve it is converted to
    CCurrencyValueMap fractionalConverted;

    CCurrencyValueMap newConvertedReservePool;

    std::map<uint160, int32_t> currencyIndexMap = importCurrencyDef.GetCurrenciesMap();

    uint160 systemSourceID = systemSource.GetID();
    uint160 systemDestID = importCurrencyDef.IsGateway() && systemSourceID != importCurrencyDef.GetID() ? 
                                importCurrencyDef.GetID() : 
                                systemDest.GetID();  // native on destination system

    uint160 importCurrencyID = importCurrencyDef.GetID();

    // this matrix tracks n-way currency conversion
    // each entry contains the original amount of the row's (dim 0) currency to be converted to the currency position of its column
    int32_t numCurrencies = importCurrencyDef.currencies.size();
    std::vector<std::vector<CAmount>> crossConversions(numCurrencies, std::vector<CAmount>(numCurrencies, 0));

    // used to keep track of burned fractional currency. this currency is subtracted from the
    // currency supply, but not converted. In doing so, it can either raise the price of the fractional
    // currency in all other currencies, or increase the reserve ratio of all currencies by some amount.
    CAmount burnedChangePrice = 0;
    CAmount burnedChangeWeight = 0;
    CCurrencyValueMap burnedReserves;

    // this is cached here, but only used for pre-conversions
    CCurrencyValueMap preConvertedOutput;
    CCurrencyValueMap preConvertedReserves;
    CAmount preAllocTotal = 0;

    // determine if we are importing from a gateway currency
    // if so, we can use it to mint gateway currencies via the gateway, and deal with fees and conversions on
    // our converter currency
    uint160 nativeSourceCurrencyID = systemSource.IsGateway() ? systemSource.gatewayID : systemSource.systemID;
    uint160 nativeDestCurrencyID = systemDest.IsGateway() ? systemDest.gatewayID : systemDest.systemID;
    int32_t systemDestIdx = currencyIndexMap.count(systemDestID) ? currencyIndexMap[systemDestID] : -1;

    if (nativeSourceCurrencyID != systemSourceID)
    {
        printf("%s: systemSource import %s is not from either gateway, PBaaS chain, or other system level currency\n", __func__, systemSource.name.c_str());
        LogPrintf("%s: systemSource import %s is not from either gateway, PBaaS chain, or other system level currency\n", __func__, systemSource.name.c_str());
        return false;
    }
    bool isCrossSystemImport = nativeSourceCurrencyID != nativeDestCurrencyID;

    nativeIn = 0;
    numTransfers = 0;
    for (auto &oneInOut : currencies)
    {
        oneInOut.second.reserveIn = 0;
        oneInOut.second.reserveOut = 0;
    }

    CCcontract_info CC;
    CCcontract_info *cp;

    CCurrencyValueMap transferFees;                     // calculated fees based on all transfers/conversions, etc.
    CCurrencyValueMap convertedFees;                    // post conversion transfer fees
    CCurrencyValueMap liquidityFees;                    // for fractionals, this value is added to the currency itself

    bool feeOutputStart = false;                        // fee outputs must come after all others, this indicates they have started
    int nFeeOutputs = 0;                                // number of fee outputs

    int32_t totalCarveOut = importCurrencyDef.GetTotalCarveOut();
    CCurrencyValueMap totalCarveOuts;
    CAmount totalMinted = 0;
    CAmount currencyRegistrationFee = 0;
    CAmount totalNativeFee = 0;
    CAmount totalVerusFee = 0;

    for (int i = 0; i <= exportObjects.size(); i++)
    {
        CReserveTransfer curTransfer;

        if (i == exportObjects.size())
        {
            // this will be the primary fee output
            curTransfer = CReserveTransfer(CReserveTransfer::VALID + CReserveTransfer::FEE_OUTPUT,
                                           nativeDestCurrencyID,
                                           0,
                                           nativeDestCurrencyID,
                                           0,
                                           importCurrencyID,
                                           feeRecipient);
        }
        else if (importCurrencyState.IsRefunding() ||
                 exportObjects[i].FirstCurrency() == exportObjects[i].destCurrencyID ||
                 (exportObjects[i].IsPreConversion() && importCurrencyState.IsLaunchCompleteMarker()) ||
                 (exportObjects[i].IsConversion() && !exportObjects[i].IsPreConversion() && !importCurrencyState.IsLaunchCompleteMarker()))
        {
            // TODO: HARDENING - ensure that we reject every invalid combination of flags as an explicit part of the
            // protocol, so that a bridge with such a failure would block until it was fixed.
            curTransfer = exportObjects[i].GetRefundTransfer(!(systemSourceID != systemDestID && exportObjects[i].IsCrossSystem()));
        }
        else
        {
            curTransfer = exportObjects[i];
        }

        if (((importCurrencyID != curTransfer.FirstCurrency()) && curTransfer.IsImportToSource()) ||
            ((importCurrencyID != curTransfer.destCurrencyID) && !curTransfer.IsImportToSource()))
        {
            printf("%s: Importing to source currency w/o flag or importing to destination w/source flag:\n%s\n", __func__, curTransfer.ToUniValue().write(1,2).c_str());
            LogPrintf("%s: Importing to source currency without flag or importing to destination with source flag\n", __func__);
            return false;
        }

        //printf("currency transfer #%d:\n%s\n", i, curTransfer.ToUniValue().write(1,2).c_str());
        CCurrencyDefinition _currencyDest;
        const CCurrencyDefinition &currencyDest = curTransfer.IsRefund() ?
                                                    (_currencyDest = ConnectedChains.GetCachedCurrency(curTransfer.FirstCurrency())) :
                                                    (importCurrencyID == curTransfer.destCurrencyID) ?
                                                    importCurrencyDef :
                                                    (_currencyDest = ConnectedChains.GetCachedCurrency(curTransfer.destCurrencyID));

        if (!currencyDest.IsValid())
        {
            printf("%s: invalid currency or currency not found %s\n", __func__, curTransfer.ToUniValue().write(1,2).c_str());
            LogPrintf("%s: invalid currency or currency not found %s\n", __func__, EncodeDestination(CIdentityID(curTransfer.destCurrencyID)).c_str());
            return false;
        }

        //printf("%s: transferFees: %s\n", __func__, transferFees.ToUniValue().write(1,2).c_str());

        if (i == exportObjects.size() || curTransfer.IsValid())
        {
            CTxOut newOut;

            // at the end, make our fee outputs
            if (i == exportObjects.size())
            {
                // only tokens release pre-allocations here
                // PBaaS chain pre-allocations and initial pre-conversion
                // supply come out of the coinbase, since we don't mint
                // native currency out of a non-coinbase import
                if (importCurrencyState.IsLaunchClear())
                {
                    // we need to pay 1/2 of the launch cost for the launch system in launch fees
                    // remainder was paid when the currency is defined
                    currencyRegistrationFee = systemSource.LaunchFeeImportShare(importCurrencyDef.options);
                    transferFees.valueMap[importCurrencyDef.launchSystemID] += currencyRegistrationFee;
                    if (importCurrencyDef.launchSystemID != systemDestID)
                    {
                        // this fee input was injected into the currency at definition
                        importedCurrency.valueMap[importCurrencyDef.launchSystemID] += currencyRegistrationFee;
                        AddReserveInput(importCurrencyDef.launchSystemID, currencyRegistrationFee);
                    }
                    else
                    {
                        if (importCurrencyDef.systemID != systemDestID && importCurrencyState.IsRefunding())
                        {
                            gatewayDepositsIn.valueMap[systemDestID] += currencyRegistrationFee;
                        }
                        nativeIn += currencyRegistrationFee;
                    }

                    if (importCurrencyState.IsLaunchConfirmed())
                    {
                        if (importCurrencyState.IsPrelaunch())
                        {
                            // first time with launch clear on prelaunch, start supply at initial supply
                            newCurrencyState.supply = newCurrencyState.initialSupply;
                        }

                        // if we have finished importing all pre-launch exports, create all pre-allocation outputs
                        for (auto &onePreAlloc : importCurrencyDef.preAllocation)
                        {
                            // we need to make one output for each pre-allocation
                            AddNativeOutConverted(importCurrencyID, onePreAlloc.second);
                            if (importCurrencyID != systemDestID)
                            {
                                AddReserveOutConverted(importCurrencyID, onePreAlloc.second);
                            }
                            
                            preAllocTotal += onePreAlloc.second;

                            std::vector<CTxDestination> dests;
                            if (onePreAlloc.first.IsNull())
                            {
                                // if pre-alloc/pre-mine goes to NULL, send it to fee recipient who mines the final export
                                dests = std::vector<CTxDestination>({TransferDestinationToDestination(curTransfer.destination)});
                            }
                            else
                            {
                                dests = std::vector<CTxDestination>({CTxDestination(CIdentityID(onePreAlloc.first))});
                            }

                            if (importCurrencyID == systemDestID)
                            {
                                vOutputs.push_back(CTxOut(onePreAlloc.second, GetScriptForDestination(dests[0])));
                                nativeOut += onePreAlloc.second;
                            }
                            else
                            {
                                AddReserveOutput(importCurrencyID, onePreAlloc.second);
                                CTokenOutput ro = CTokenOutput(importCurrencyID, onePreAlloc.second);
                                vOutputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, dests, 1, &ro))));
                            }
                        }
                        if (importCurrencyDef.gatewayConverterIssuance)
                        {
                            if (importCurrencyDef.IsPBaaSChain())
                            {
                                preAllocTotal += importCurrencyDef.gatewayConverterIssuance;
                                AddNativeOutConverted(importCurrencyID, importCurrencyDef.gatewayConverterIssuance);
                                nativeOut += importCurrencyDef.gatewayConverterIssuance;
                            }
                        }
                    }
                }

                // convert all fees to the system currency of the import
                // fees that started in fractional are already converted, so not considered
                CCurrencyValueMap conversionFees = ReserveConversionFeesMap().CanonicalMap();

                newCurrencyState.fees = transferFees.AsCurrencyVector(newCurrencyState.currencies);
                newCurrencyState.conversionFees = conversionFees.AsCurrencyVector(newCurrencyState.currencies);
                newCurrencyState.primaryCurrencyFees = transferFees.valueMap.count(importCurrencyID) ? transferFees.valueMap[importCurrencyID] : 0;
                newCurrencyState.primaryCurrencyConversionFees = 
                    conversionFees.valueMap.count(importCurrencyID) ? transferFees.valueMap[importCurrencyID] : 0;

                CCurrencyValueMap exporterReserveFees;

                if (importCurrencyState.IsLaunchConfirmed() &&
                    isFractional &&
                    importCurrencyState.reserves[systemDestIdx])
                {
                    // 1/2 of all conversion fees go directly into the fractional currency itself
                    liquidityFees = conversionFees / 2;
                    transferFees -= liquidityFees;

                    // setup conversion matrix for fees that are converted to
                    // native (or launch currency of a PBaaS chain) from another reserve
                    std::vector<std::pair<std::pair<uint160,CAmount>, std::pair<uint160,CAmount>>> feeConversions;

                    // printf("%s: transferFees: %s\nreserveConverted: %s\nliquidityFees: %s\n", __func__, transferFees.ToUniValue().write(1,2).c_str(), reserveConverted.ToUniValue().write(1,2).c_str(), liquidityFees.ToUniValue().write(1,2).c_str());
                    for (auto &oneFee : transferFees.valueMap)
                    {
                        // only convert through "via" if we are going from one reserve to the system ID
                        if (oneFee.first != importCurrencyID && oneFee.first != systemDestID)
                        {
                            auto curIt = currencyIndexMap.find(oneFee.first);
                            if (curIt == currencyIndexMap.end())
                            {
                                printf("%s: Invalid fee currency for %s\n", __func__, curTransfer.ToUniValue().write(1,2).c_str());
                                LogPrintf("%s: Invalid fee currency for %s\n", __func__, curTransfer.ToUniValue().write(1,2).c_str());
                                return false;
                            }
                            int curIdx = curIt->second;

                            // printf("%s: *this 1: %s\n", __func__, ToUniValue().write(1,2).c_str());

                            CAmount oneFeeValue = 0;
                            reserveConverted.valueMap[oneFee.first] += oneFee.second;
                            crossConversions[curIdx][systemDestIdx] += oneFee.second;
                            CAmount conversionPrice = importCurrencyState.IsLaunchCompleteMarker() ? 
                                                        importCurrencyState.conversionPrice[curIdx] :
                                                        importCurrencyState.viaConversionPrice[curIdx];
                            oneFeeValue = importCurrencyState.ReserveToNativeRaw(oneFee.second, conversionPrice);

                            if (systemDestID == importCurrencyID)
                            {
                                AddNativeOutConverted(oneFee.first, oneFeeValue);
                            }
                            else
                            {
                                // if fractional currency is not native, one more conversion to native
                                oneFeeValue = 
                                    CCurrencyState::NativeToReserveRaw(oneFeeValue, importCurrencyState.viaConversionPrice[systemDestIdx]);
                                newConvertedReservePool.valueMap[systemDestID] += oneFeeValue;
                                AddReserveOutConverted(systemDestID, oneFeeValue);
                            }

                            feeConversions.push_back(std::make_pair(std::make_pair(oneFee.first, oneFee.second), 
                                                                    std::make_pair(systemDestID, oneFeeValue)));
                            // printf("%s: *this 2: %s\n", __func__, ToUniValue().write(1,2).c_str());
                        }
                        else if (oneFee.first == importCurrencyID)
                        {
                            // convert from fractional to system ID in the first, non-via stage, since this was
                            // already fractional to begin with
                            fractionalConverted.valueMap[systemDestID] += oneFee.second;
                            AddNativeOutConverted(oneFee.first, -oneFee.second);

                            CAmount convertedFractionalFee = CCurrencyState::NativeToReserveRaw(oneFee.second, importCurrencyState.conversionPrice[systemDestIdx]);
                            newConvertedReservePool.valueMap[systemDestID] += convertedFractionalFee;
                            AddReserveOutConverted(systemDestID, convertedFractionalFee);
                            feeConversions.push_back(std::make_pair(std::make_pair(oneFee.first, oneFee.second), 
                                                                    std::make_pair(systemDestID, convertedFractionalFee)));
                        }
                    }
                    // loop through, subtract "from" and add "to"
                    convertedFees = transferFees;
                    if (feeConversions.size())
                    {
                        for (auto &conversionPairs : feeConversions)
                        {
                            convertedFees.valueMap[conversionPairs.first.first] -= conversionPairs.first.second;
                            convertedFees.valueMap[conversionPairs.second.first] += conversionPairs.second.second;
                        }
                        convertedFees = convertedFees.CanonicalMap();
                    }
                    auto nativeFeeIt = convertedFees.valueMap.find(systemDestID);
                    totalNativeFee = nativeFeeIt == convertedFees.valueMap.end() ? 0 : nativeFeeIt->second;
                    totalVerusFee = !importCurrencyState.IsLaunchConfirmed() || systemDest.launchSystemID.IsNull() || !convertedFees.valueMap.count(systemDest.launchSystemID) ? 
                                        0 : 
                                        convertedFees.valueMap[systemDest.launchSystemID];
                }
                else
                {
                    // since there is no support for taking reserves as fees, split any available 
                    // reserves fee from the launch chain, for example, between us and the exporter
                    std::vector<CTxDestination> dests({TransferDestinationToDestination(feeRecipient)});
                    for (auto &oneFee : transferFees.valueMap)
                    {
                        if (oneFee.first != systemDestID && oneFee.first != VERUS_CHAINID && oneFee.second)
                        {
                            exporterReserveFees.valueMap[oneFee.first] += oneFee.second;
                        }
                        else if (oneFee.second)
                        {
                            if (oneFee.first == systemDestID)
                            {
                                totalNativeFee += oneFee.second;
                            }
                            else if (importCurrencyState.IsLaunchConfirmed() && oneFee.first == VERUS_CHAINID)
                            {
                                totalVerusFee += oneFee.second;
                            }
                        }
                    }
                    convertedFees = transferFees;
                }

                // export fee is added to the fee pool of the receiving
                // system, exporter reward goes directly to the exporter
                CAmount exportFee = CCrossChainExport::CalculateExportFeeRaw(totalNativeFee, numTransfers);
                CAmount exporterReward = CCrossChainExport::ExportReward(systemDest, exportFee);
                CAmount notaryReward = 0;

                if (isCrossSystemImport && !importCurrencyState.IsLaunchClear() && (exportFee - exporterReward) > exporterReward)
                {
                    notaryReward = std::min((exportFee - exporterReward) >> 1, exporterReward);
                    if (notaryReward < systemDest.GetTransactionTransferFee())
                    {
                        notaryReward = 0;
                    }
                }

                for (auto &oneFee : convertedFees.valueMap)
                {
                    if (oneFee.first == systemDestID)
                    {
                        nativeOut += oneFee.second;
                    }
                    else
                    {
                        AddReserveOutput(oneFee.first, oneFee.second);
                    }
                }

                if (!exporterReward)
                {
                    break;
                }

                curTransfer.reserveValues.valueMap[systemDestID] = exporterReward;

                // if there is any launch system currency in the fees, share it with the exporter
                static arith_uint256 bigSatoshi(SATOSHIDEN);
                int64_t rewardRatio = (int64_t)((arith_uint256(exporterReward) * bigSatoshi) / exportFee).GetLow64();
                CCurrencyValueMap exporterReserves;
                if (totalVerusFee)
                {
                    exporterReserves.valueMap[systemDest.launchSystemID] = CCurrencyDefinition::CalculateRatioOfValue(totalVerusFee, rewardRatio);
                }

                CTxDestination exporterDest = TransferDestinationToDestination(curTransfer.destination);

                if (notaryReward)
                {
                    CCurrencyValueMap notaryReserves;
                    int64_t notaryRewardRatio = (int64_t)((arith_uint256(notaryReward) * bigSatoshi) / exportFee).GetLow64();
                    if (totalVerusFee)
                    {
                        notaryReserves.valueMap[systemDest.launchSystemID] = CCurrencyDefinition::CalculateRatioOfValue(totalVerusFee, notaryRewardRatio);
                    }

                    CTxDestination blockNotarizerDest = TransferDestinationToDestination(blockNotarizer);
                    if (blockNotarizerDest.which() == COptCCParams::ADDRTYPE_PK ||
                        blockNotarizerDest.which() == COptCCParams::ADDRTYPE_PKH ||
                        blockNotarizerDest.which() == COptCCParams::ADDRTYPE_ID)
                    {
                        CScript outScript;
                        if (notaryReserves > CCurrencyValueMap())
                        {
                            CTokenOutput ro = CTokenOutput(notaryReserves);
                            outScript = MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, std::vector<CTxDestination>({blockNotarizerDest}), 1, &ro));
                        }
                        else
                        {
                            outScript = GetScriptForDestination(blockNotarizerDest);
                        }
                        
                        vOutputs.push_back(CTxOut(notaryReward, outScript));
                    }

                    // no valid payee, so select from the chain notaries based on a hash of the
                    // notarization proposer and export fee recipient
                    CTxDestination notaryPayeeDest;
                    const std::vector<uint160> *pNotaries = nullptr;

                    if (systemDest.parent == systemSourceID)
                    {
                        pNotaries = &systemDest.notaries;
                    }
                    else if (systemSource.parent == systemDestID)
                    {
                        pNotaries = &systemSource.notaries;
                    }
                    else
                    {
                        LogPrintf("%s: Invalid import/export relationship between source and destination %s : %s\n", __func__, EncodeDestination(CIdentityID(systemSourceID)).c_str(), EncodeDestination(CIdentityID(systemDestID)).c_str());
                        return false;
                    }
                    
                    if (pNotaries->size())
                    {
                        uint64_t intermediate = (UintToArith256(uint256S(GetDestinationID(exporterDest).GetHex())) ^
                                                        UintToArith256(uint256S(GetDestinationID(blockNotarizerDest).GetHex())) ^
                                                        UintToArith256(entropy)).GetLow64();
                        notaryPayeeDest = CIdentityID((*pNotaries)[(intermediate % pNotaries->size())]);
                    }

                    if (notaryPayeeDest.which() == COptCCParams::ADDRTYPE_PK ||
                        notaryPayeeDest.which() == COptCCParams::ADDRTYPE_PKH ||
                        notaryPayeeDest.which() == COptCCParams::ADDRTYPE_ID)
                    {
                        CScript outScript;
                        if (notaryReserves > CCurrencyValueMap())
                        {
                            CTokenOutput ro = CTokenOutput(notaryReserves);
                            outScript = MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, std::vector<CTxDestination>({notaryPayeeDest}), 1, &ro));
                        }
                        else
                        {
                            outScript = GetScriptForDestination(notaryPayeeDest);
                        }
                        
                        vOutputs.push_back(CTxOut(notaryReward, outScript));
                    }
                }

                if (exporterDest.which() == COptCCParams::ADDRTYPE_PK ||
                    exporterDest.which() == COptCCParams::ADDRTYPE_PKH ||
                    exporterDest.which() == COptCCParams::ADDRTYPE_ID)
                {
                    CScript outScript;
                    if (exporterReserves > CCurrencyValueMap())
                    {
                        CTokenOutput ro = CTokenOutput(exporterReserves);
                        CScript outScript = MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, std::vector<CTxDestination>({exporterDest}), 1, &ro));                        
                    }
                    else
                    {
                        outScript = GetScriptForDestination(exporterDest);
                    }
                    vOutputs.push_back(CTxOut(exporterReward, outScript));
                }
                break;
            }
            else
            {
                numTransfers++;

                // ensure that in the import, we precheck the reserve transfer added here as well
                // we can only have one arbitrage transfer per import
                if (curTransfer.IsArbitrageOnly())
                {
                    if (!importCurrencyState.IsLaunchCompleteMarker())
                    {
                        printf("%s: arbitrage transactions invalid until after currency launch is complete for %s\n", __func__, importCurrencyDef.name.c_str());
                        LogPrint("reservetransfers", "%s: arbitrage transactions invalid until after currency launch is complete for %s\n", __func__, importCurrencyDef.name.c_str());
                        return false;
                    }
                    if (arbitrageCount++)
                    {
                        printf("%s: only one arbitrage transaction is allowed on an import for %s\n", __func__, importCurrencyDef.name.c_str());
                        LogPrint("reservetransfers", "%s: only one arbitrage transaction is allowed on an import for %s\n", __func__, importCurrencyDef.name.c_str());
                        return false;
                    }
                    if (curTransfer.IsCurrencyExport() ||
                        curTransfer.IsIdentityExport() ||
                        curTransfer.IsPreConversion() ||
                        !curTransfer.IsConversion())
                    {
                        printf("%s: invalid arbitrage transaction for %s\n", __func__, importCurrencyDef.name.c_str());
                        LogPrint("reservetransfers", "%s: invalid arbitrage transaction for %s\n", __func__, importCurrencyDef.name.c_str());
                        return false;
                    }
                    // TODO: HARDENING - ensure that the reserve transfers coming from an export cannot contain arbitrage
                    // transfers, which may be checked on GetExportInfo. they are only allowed on imports and only one conversion.
                    // note is here, but to resolve this, add the check on getexportinfo
                }

                // enforce maximum if there is one
                if (curTransfer.IsPreConversion() && importCurrencyDef.maxPreconvert.size())
                {
                    // check if it exceeds pre-conversion maximums, and refund if so
                    CCurrencyValueMap newReserveIn = CCurrencyValueMap(std::vector<uint160>({curTransfer.FirstCurrency()}), 
                                                                    std::vector<int64_t>({curTransfer.FirstValue() - CReserveTransactionDescriptor::CalculateConversionFee(curTransfer.FirstValue())}));
                    CCurrencyValueMap newTotalReserves = CCurrencyValueMap(importCurrencyState.currencies, importCurrencyState.primaryCurrencyIn) + newReserveIn + preConvertedReserves;

                    if (newTotalReserves > CCurrencyValueMap(importCurrencyDef.currencies, importCurrencyDef.maxPreconvert))
                    {
                        LogPrint("defi", "%s: refunding pre-conversion over maximum\n", __func__);
                        curTransfer = curTransfer.GetRefundTransfer();
                    }
                }

                CAmount explicitFees = curTransfer.nFees;
                transferFees.valueMap[curTransfer.feeCurrencyID] += explicitFees;

                // see if our destination is for a gateway or other blockchain and see if we are reserving some
                // fees for additional routing. if so, add those fees to the pass-through fees, which will get converted
                // to the target native currency and subtracted from this leg
                if (curTransfer.destination.HasGatewayLeg() && curTransfer.destination.fees)
                {
                    // we keep the destination fees in the same currency as the normal transfer fee, but
                    // convert it as we move through systems and only use it for delivery to the system
                    // of the destination.
                    if (curTransfer.destination.fees)
                    {
                        explicitFees += curTransfer.destination.fees;
                    }

                    // convert fees to next destination native, if necessary/possible
                    CCurrencyDefinition curNextDest = ConnectedChains.GetCachedCurrency(curTransfer.destination.gatewayID);
                    uint160 nextDestSysID = curNextDest.IsGateway() ? curNextDest.gatewayID : curNextDest.systemID;

                    // if it's already in the correct currency, nothing to do, otherwise convert if we can
                    if (curTransfer.feeCurrencyID != nextDestSysID)
                    {
                        if (!isFractional ||
                            (!currencyIndexMap.count(nextDestSysID) &&
                             !currencyIndexMap.count(curTransfer.feeCurrencyID) &&
                             curTransfer.feeCurrencyID != importCurrencyID))
                        {
                            printf("%s: next leg fee currency %s unavailable for conversion using %s\n", __func__, curNextDest.name.c_str(), importCurrencyDef.name.c_str());
                            LogPrintf("%s: next leg fee currency %s unavailable for conversion using %s\n", __func__, curNextDest.name.c_str(), importCurrencyDef.name.c_str());
                            return false;
                        }
                        // now, convert next leg fees, which are currently in the fee currency, to the next destination system ID, 
                        // adjust curTransfer values to reflect the new state, and continue
                        // while we won't change the fee currency ID in the curTransfer, all pass through fees are assumed to be in
                        // the next leg's system currency by the time it is ready to produce an output

                        int feeCurIdx = currencyIndexMap[curTransfer.feeCurrencyID];
                        int nextDestIdx = currencyIndexMap[nextDestSysID];

                        // either fractional to reserve or reserve-to-reserve fee for the conversion
                        CAmount passThroughFee = CalculateConversionFeeNoMin(curTransfer.destination.fees);
                        if (curTransfer.feeCurrencyID != importCurrencyID)
                        {
                            passThroughFee <<= 1;
                        }
                        curTransfer.destination.fees -= passThroughFee;

                        AddReserveConversionFees(curTransfer.feeCurrencyID, passThroughFee);
                        transferFees.valueMap[curTransfer.feeCurrencyID] += passThroughFee;

                        // one more conversion to destination native
                        CAmount finalReserveAmount = 0;

                        if (curTransfer.feeCurrencyID == importCurrencyID)
                        {
                            // convert from fractional to system ID in the first, non-via stage, since this was
                            // already fractional to begin with
                            fractionalConverted.valueMap[nextDestSysID] += curTransfer.destination.fees;
                            AddNativeOutConverted(importCurrencyID, -curTransfer.destination.fees);

                            finalReserveAmount = 
                                CCurrencyState::NativeToReserveRaw(curTransfer.destination.fees, importCurrencyState.conversionPrice[currencyIndexMap[nextDestSysID]]);
                        }
                        else
                        {
                            CAmount oneFeeValue = 0;

                            reserveConverted.valueMap[curTransfer.feeCurrencyID] += curTransfer.destination.fees;
                            crossConversions[feeCurIdx][nextDestIdx] += curTransfer.destination.fees;
                            oneFeeValue = importCurrencyState.ReserveToNativeRaw(curTransfer.destination.fees,
                                                                                importCurrencyState.IsLaunchCompleteMarker() ?
                                                                                importCurrencyState.conversionPrice[feeCurIdx] :
                                                                                importCurrencyState.viaConversionPrice[feeCurIdx]);
                            // one more conversion to destination native
                            finalReserveAmount = CCurrencyState::NativeToReserveRaw(oneFeeValue, importCurrencyState.viaConversionPrice[nextDestIdx]);
                        }

                        curTransfer.destination.fees = finalReserveAmount;
                        newConvertedReservePool.valueMap[nextDestSysID] += finalReserveAmount;

                        AddReserveOutput(nextDestSysID, finalReserveAmount);
                        AddReserveOutConverted(nextDestSysID, finalReserveAmount);
                    } else
                    {
                        if (curTransfer.feeCurrencyID == systemDestID)
                        {
                            nativeOut = curTransfer.destination.fees;
                        }
                        else
                        {
                            AddReserveOutput(nextDestSysID, curTransfer.destination.fees);
                        }
                    }
                }

                // if it's from a gateway and not an arbitrage transaction, 
                // make sure that the currency it is importing is valid for the current chain
                // all pre-conversions
                if (!curTransfer.IsArbitrageOnly() &&
                    (isCrossSystemImport || (importCurrencyDef.SystemOrGatewayID() != systemDestID && importCurrencyState.IsRefunding())))
                {
                    // We may import:
                    //  fee currency
                    //  primary currency
                    //  identity
                    //  currency definition
                    //
                    // Each of these imports may be imported/minted, iff the imported currency or ID is 
                    // NOT a descendant of the destination system and IS a descendent of the source system
                    //
                    std::set<uint160> mustBeAsDeposit;
                    CCurrencyValueMap importExportCurrencies(std::vector<uint160>({curTransfer.feeCurrencyID}), std::vector<int64_t>({explicitFees}));
                    if (curTransfer.IsCurrencyExport() &&
                        curTransfer.destination.TypeNoFlags() == curTransfer.destination.DEST_REGISTERCURRENCY &&
                        !curTransfer.IsImportToSource())
                    {
                        // ensure that the destination is a valid currency, that the currency is not already exported, and
                        // that its parents have been
                        CCurrencyDefinition curToExport(curTransfer.destination.destination);
                        uint160 curToExportID;
                        if (!curToExport.IsValid() ||
                            (curToExportID = curToExport.GetID()) == systemDestID ||
                            curToExportID == systemSourceID)
                        {
                            printf("%s: invalid currency export from system: %s\n", __func__, systemSource.name.c_str());
                            LogPrintf("%s: invalid currency export from system: %s\n", __func__, systemSource.name.c_str());
                            return false;
                        }

                        if (!CCurrencyDefinition::IsValidDefinitionImport(systemSource, systemDest, curToExport.parent, height))
                        {
                            printf("%s: invalid currency export from system: %s\n", __func__, systemSource.name.c_str());
                            LogPrintf("%s: invalid currency export from system: %s\n", __func__, systemSource.name.c_str());
                            return false;
                        }
                    }
                    else if (curTransfer.destination.TypeNoFlags() == curTransfer.destination.DEST_REGISTERCURRENCY || curTransfer.IsCurrencyExport())
                    {
                        printf("%s: invalid currency import from system: %s\n", __func__, systemSource.name.c_str());
                        LogPrintf("%s: invalid currency import from system: %s\n", __func__, systemSource.name.c_str());
                        return false;
                    }
                    else if (curTransfer.IsIdentityExport())
                    {
                        CIdentity identityToExport(curTransfer.destination.destination);
                        uint160 identityToExportID;
                        if (!identityToExport.IsValid() ||
                            (identityToExportID = identityToExport.GetID()) == systemDestID)
                        {
                            printf("%s: invalid identity export from system: %s\n", __func__, systemSource.name.c_str());
                            LogPrintf("%s: invalid identity export from system: %s\n", __func__, systemSource.name.c_str());
                            return false;
                        }

                        if (!CCurrencyDefinition::IsValidDefinitionImport(systemSource, systemDest, identityToExport.parent, height))
                        {
                            printf("%s: invalid identity export from gateway: %s\n", __func__, systemSource.name.c_str());
                            LogPrintf("%s: invalid identity export from gateway: %s\n", __func__, systemSource.name.c_str());
                            return false;
                        }
                    }

                    if (curTransfer.IsMint())
                    {
                        printf("%s: Invalid mint operation from %s\n", __func__, curTransfer.ToUniValue().write().c_str());
                        return false;
                    }

                    // mustBeAsDeposit entries are new to the destination and not
                    // to the source. all parent currencies must have already been imported
                    // because of this, the parent of any currency being exported or imported
                    // is what represents the import or export

                    if (!curTransfer.IsCurrencyExport())
                    {
                        importExportCurrencies.valueMap[curTransfer.FirstCurrency()] += curTransfer.FirstValue();
                    }

                    CCurrencyValueMap newDepositCurrencies, newGatewayDeposits;
                    if (!ConnectedChains.CurrencyExportStatus(importExportCurrencies,
                                                              importCurrencyState.IsRefunding() ? importCurrencyDef.systemID : systemSourceID,
                                                              systemDestID,
                                                              newDepositCurrencies,
                                                              newGatewayDeposits))
                    {
                        printf("%s: invalid exports from system: %s\n", __func__, systemSource.name.c_str());
                        LogPrintf("%s: invalid exports from system: %s\n", __func__, systemSource.name.c_str());
                        return false;
                    }

                    // make sure all IDs and currencies are valid
                    for (auto &oneCurID : mustBeAsDeposit)
                    {
                        if (!newDepositCurrencies.valueMap.count(oneCurID))
                        {
                            printf("%s: invalid export (%s) from system: %s\n", __func__, oneCurID.GetHex().c_str(), systemSource.name.c_str());
                            LogPrintf("%s: invalid export (%s) from system: %s\n", __func__, oneCurID.GetHex().c_str(), systemSource.name.c_str());
                            return false;
                        }
                    }

                    newGatewayDeposits = newGatewayDeposits.CanonicalMap();
                    newDepositCurrencies = newDepositCurrencies.CanonicalMap();

                    for (auto &oneCur : newGatewayDeposits.valueMap)
                    {
                        if (oneCur.first == systemDestID)
                        {
                            nativeIn += oneCur.second;
                        }
                        else
                        {
                            // if the input will go into our currency as reserves, we only record it once on export/pre-launch
                            AddReserveInput(oneCur.first, oneCur.second);
                        }
                    }

                    for (auto &oneCur : newDepositCurrencies.valueMap)
                    {
                        if (oneCur.first == systemDestID)
                        {
                            nativeIn += oneCur.second;
                        }
                        else
                        {
                            // if the input will go into our currency as reserves, we only record it once on export/pre-launch
                            AddReserveInput(oneCur.first, oneCur.second);
                        }
                    }

                    gatewayDepositsIn += newGatewayDeposits;
                    importedCurrency += newDepositCurrencies;

                    // if this currency is under control of the gateway, it is minted on the way in, otherwise, it will be
                    // on the gateway's reserve deposits, which can be spent by imports from the gateway's converter

                    // source system currency is imported, dest system must come from deposits
                    if (curTransfer.feeCurrencyID == systemSourceID)
                    {
                        // if it's not a reserve of this currency, we can't process this transfer's fee
                        if (!((isFractional &&
                               currencyIndexMap.count(systemSourceID)) ||
                             (systemSourceID == importCurrencyDef.launchSystemID)))
                        {
                            printf("%s: currency transfer fees invalid for receiving system\n", __func__);
                            LogPrintf("%s: currency transfer fees invalid for receiving system\n", __func__);
                            return false;
                        }
                    }
                    else if (curTransfer.feeCurrencyID != systemDestID &&
                             !(curTransfer.feeCurrencyID == curTransfer.FirstCurrency() && 
                               isFractional && 
                               currencyIndexMap.count(curTransfer.feeCurrencyID) &&
                               importCurrencyState.IsLaunchConfirmed()))
                    {
                        printf("%s: pass-through fees invalid\n", __func__);
                        LogPrintf("%s: pass-through fees invalid\n", __func__);
                        return false;
                    }
                }
                else 
                {
                    if (curTransfer.feeCurrencyID == systemDestID)
                    {
                        nativeIn += explicitFees;
                    }
                    else
                    {
                        // if the input will go into our currency as reserves, we only record it once on export/pre-launch
                        AddReserveInput(curTransfer.feeCurrencyID, explicitFees);
                    }

                    // now, fees are either in the destination native currency, or this is a fractional currency, and
                    // we convert to see if we meet fee minimums
                    CAmount feeEquivalent;
                    uint160 feeCurrency;
                    if (curTransfer.IsConversion() && !curTransfer.IsPreConversion())
                    {
                        feeCurrency = curTransfer.nFees ? curTransfer.feeCurrencyID : curTransfer.FirstCurrency();
                        feeEquivalent = CReserveTransactionDescriptor::CalculateConversionFee(curTransfer.FirstValue()) + curTransfer.nFees;
                    }
                    else
                    {
                        feeCurrency = curTransfer.feeCurrencyID;
                        feeEquivalent = curTransfer.nFees;
                    }

                    if (feeCurrency != systemDestID)
                    { 
                        if (!importCurrencyDef.IsFractional() || !(currencyIndexMap.count(feeCurrency) || feeCurrency == importCurrencyID))
                        {
                            printf("%s: Invalid fee currency for transfer %s\n", __func__, curTransfer.ToUniValue().write().c_str());
                            LogPrintf("%s: Invalid fee currency for transfer %s\n", __func__, curTransfer.ToUniValue().write().c_str());
                            return false;
                        }
                        if (curTransfer.feeCurrencyID != importCurrencyID)
                        {
                            feeEquivalent = importCurrencyState.ReserveToNativeRaw(feeEquivalent, importCurrencyState.conversionPrice[currencyIndexMap[feeCurrency]]);
                        }
                        feeEquivalent = importCurrencyState.NativeToReserveRaw(feeEquivalent, importCurrencyState.viaConversionPrice[systemDestIdx]);
                    }

                    /* if (!systemDest.IsGateway() && feeEquivalent < curTransfer.CalculateTransferFee())
                    {
                        // TODO: HARDENING - this refund check is only here because there was an issue in preconversions being sent without
                        // having a base transfer fee, both on the same chain and cross chain
                        if (!curTransfer.IsRefund())
                        {
                            printf("%s: Incorrect fee sent with export %s\n", __func__, curTransfer.ToUniValue().write().c_str());
                            LogPrintf("%s: Incorrect fee sent with export %s\n", __func__, curTransfer.ToUniValue().write().c_str());
                            return false;
                        }
                    } // */

                    if (curTransfer.FirstCurrency() == systemDestID && !curTransfer.IsMint())
                    {
                        nativeIn += curTransfer.FirstValue();
                    }
                    else
                    {
                        if (curTransfer.IsMint())
                        {
                            AddReserveInput(curTransfer.destCurrencyID, curTransfer.FirstValue());
                        }
                        else
                        {
                            AddReserveInput(curTransfer.FirstCurrency(), curTransfer.FirstValue());
                        }
                    }
                }
            }

            if (curTransfer.IsPreConversion())
            {
                // pre-conversions can only come from our launch system
                if (importCurrencyDef.launchSystemID != systemSourceID)
                {
                    printf("%s: Invalid source system for preconversion %s\n", __func__, curTransfer.ToUniValue().write().c_str());
                    LogPrintf("%s: Invalid source system for preconversion %s\n", __func__, curTransfer.ToUniValue().write().c_str());
                    return false;
                }

                if (importCurrencyState.IsLaunchCompleteMarker())
                {
                    printf("%s: Invalid preconversion after launch %s\n", __func__, curTransfer.ToUniValue().write().c_str());
                    LogPrintf("%s: Invalid preconversion after launch %s\n", __func__, curTransfer.ToUniValue().write().c_str());
                    return false;
                }

                uint160 convertFromID = curTransfer.FirstCurrency();

                // either the destination currency must be fractional or the source currency
                // must be native
                if (!isFractional && convertFromID != importCurrencyDef.launchSystemID)
                {
                    printf("%s: Invalid conversion %s. Source must be launch system native or destinaton must be fractional.\n", __func__, curTransfer.ToUniValue().write().c_str());
                    LogPrintf("%s: Invalid conversion %s. Source must be launch system native or destinaton must be fractional\n", __func__, curTransfer.ToUniValue().write().c_str());
                    return false;
                }

                // get currency index
                auto curIndexIt = currencyIndexMap.find(convertFromID);
                if (curIndexIt == currencyIndexMap.end())
                {
                    printf("%s: Invalid currency for conversion %s\n", __func__, curTransfer.ToUniValue().write().c_str());
                    LogPrintf("%s: Invalid currency for conversion %s\n", __func__, curTransfer.ToUniValue().write().c_str());
                    return false;
                }
                int curIdx = curIndexIt->second;

                // output the converted amount, minus fees, and generate a normal output that spends the net input of the import as native
                // difference between all potential value out and what was taken unconverted as a fee in our fee output
                CAmount preConversionFee = 0;
                CAmount newCurrencyConverted = 0;
                CAmount valueOut = curTransfer.FirstValue();

                preConversionFee = CalculateConversionFee(curTransfer.FirstValue());
                if (preConversionFee > curTransfer.FirstValue())
                {
                    preConversionFee = curTransfer.FirstValue();
                }

                valueOut -= preConversionFee;

                AddReserveConversionFees(curTransfer.FirstCurrency(), preConversionFee);
                transferFees.valueMap[curTransfer.FirstCurrency()] +=  preConversionFee;

                newCurrencyConverted = importCurrencyState.ReserveToNativeRaw(valueOut, importCurrencyState.conversionPrice[curIdx]);

                if (newCurrencyConverted == -1)
                {
                    // if we have an overflow, this isn't going to work
                    newCurrencyConverted = 0;
                }

                if (newCurrencyConverted)
                {
                    uint160 firstCurID = curTransfer.FirstCurrency();
                    reserveConverted.valueMap[firstCurID] += valueOut;
                    preConvertedReserves.valueMap[firstCurID] += valueOut;
                    if (isFractional && isCrossSystemImport && importedCurrency.valueMap.count(firstCurID))
                    {
                        // TODO: look into 100% rollup of launch fees and resolution at launch.
                        // Right now, only fees are imported after the first coinbase
                        // reserves in the currency are already on chain as of block 1 and fees come in 
                        // and get converted with imports
                        importedCurrency.valueMap[firstCurID] -= valueOut;
                    }

                    if (totalCarveOut > 0 && totalCarveOut < SATOSHIDEN)
                    {
                        CAmount newReserveIn = CCurrencyState::NativeToReserveRaw(valueOut, SATOSHIDEN - totalCarveOut);
                        totalCarveOuts.valueMap[curTransfer.FirstCurrency()] += valueOut - newReserveIn;
                        valueOut = newReserveIn;
                    }

                    if (curTransfer.FirstCurrency() != systemDestID)
                    {
                        // if this is a fractional currency, everything but fees and carveouts stay in reserve deposit
                        // else all that would be reserves is sent to chain ID
                        if (!isFractional)
                        {
                            AddReserveOutput(curTransfer.FirstCurrency(), valueOut);
                            std::vector<CTxDestination> dests({CIdentityID(importCurrencyID)});
                            CTokenOutput ro = CTokenOutput(curTransfer.FirstCurrency(), valueOut);
                            vOutputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, dests, 1, &ro))));
                        }
                    }
                    else
                    {
                        // if it is not fractional, send proceeds to currency ID, else leave it in reserve deposit
                        if (!isFractional)
                        {
                            nativeOut += valueOut;
                            vOutputs.push_back(CTxOut(valueOut, GetScriptForDestination(CIdentityID(importCurrencyID))));
                        }
                    }

                    preConvertedOutput.valueMap[curTransfer.FirstCurrency()] += newCurrencyConverted;
                    AddNativeOutConverted(curTransfer.FirstCurrency(), newCurrencyConverted);
                    AddNativeOutConverted(curTransfer.destCurrencyID, newCurrencyConverted);
                    if (curTransfer.destCurrencyID == systemDestID)
                    {
                        nativeOut += newCurrencyConverted;
                        if (!importCurrencyState.IsLaunchConfirmed())
                        {
                            nativeIn += newCurrencyConverted;
                        }
                        curTransfer.GetTxOut(systemSource, 
                                             systemDest, 
                                             importCurrencyDef, 
                                             importCurrencyState,
                                             CCurrencyValueMap(),
                                             newCurrencyConverted,
                                             newOut,
                                             vOutputs,
                                             height);
                    }
                    else // all conversions are to primary currency
                    {
                        AddReserveOutConverted(curTransfer.destCurrencyID, newCurrencyConverted);
                        AddReserveOutput(curTransfer.destCurrencyID, newCurrencyConverted);
                        if (!importCurrencyState.IsLaunchConfirmed())
                        {
                            AddReserveInput(curTransfer.destCurrencyID, newCurrencyConverted);
                        }
                        curTransfer.GetTxOut(systemSource, 
                                             systemDest, 
                                             importCurrencyDef, 
                                             importCurrencyState,
                                             CCurrencyValueMap(std::vector<uint160>({curTransfer.destCurrencyID}),
                                             std::vector<int64_t>({newCurrencyConverted})), 
                                             0, newOut, vOutputs, height);
                    }
                }
            }
            else if (curTransfer.IsConversion())
            {
                if (curTransfer.FirstCurrency() == curTransfer.destCurrencyID)
                {
                    printf("%s: Conversion does not specify two currencies\n", __func__);
                    LogPrintf("%s: Conversion does not specify two currencies\n", __func__);
                    // TODO: HARDENING - we may allow this, but we need to make sure that we charge enough of a fee
                    // on all conversions.
                    //return false;
                }

                // either the source or destination must be a reserve currency of the other fractional currency
                // if destination is a fractional currency of a reserve, we will mint currency
                // if not, we will burn currency
                bool toFractional = importCurrencyID == curTransfer.destCurrencyID &&
                                    currencyDest.IsFractional() && 
                                    currencyIndexMap.count(curTransfer.FirstCurrency());

                CCurrencyDefinition sourceCurrency = ConnectedChains.GetCachedCurrency(curTransfer.FirstCurrency());

                if (!sourceCurrency.IsValid())
                {
                    printf("%s: Currency specified for conversion not found\n", __func__);
                    LogPrintf("%s: Currency specified for conversion not found\n", __func__);
                    return false;
                }

                if (!(toFractional || 
                    (importCurrencyID == curTransfer.FirstCurrency() &&
                        sourceCurrency.IsFractional() &&
                        currencyIndexMap.count(curTransfer.destCurrencyID))))
                {
                    printf("%s: Conversion must be between a fractional currency and one of its reserves\n", __func__);
                    LogPrintf("%s: Conversion must be between a fractional currency and one of its reserves\n", __func__);
                    return false;
                }

                if (curTransfer.IsReserveToReserve() &&
                    (!toFractional ||
                        curTransfer.secondReserveID.IsNull() ||
                        curTransfer.secondReserveID == curTransfer.FirstCurrency() ||
                        !currencyIndexMap.count(curTransfer.secondReserveID)))
                {
                    printf("%s: Invalid reserve to reserve transaction %s\n", __func__, curTransfer.ToUniValue().write().c_str());
                    LogPrintf("%s: Invalid reserve to reserve transaction %s\n", __func__, curTransfer.ToUniValue().write().c_str());
                    return false;
                }

                const CCurrencyDefinition &fractionalCurrency = toFractional ? currencyDest : sourceCurrency;
                const CCurrencyDefinition &reserveCurrency = toFractional ? sourceCurrency : currencyDest;
                int reserveIdx = currencyIndexMap[reserveCurrency.GetID()];

                assert(fractionalCurrency.IsValid() && 
                        reserveCurrency.IsValid() && 
                        fractionalCurrency.currencies[reserveIdx] == reserveCurrency.GetID());

                // now, we know that we are converting from the source currency to the
                // destination currency and also that one of them is a reserve of the other
                // we convert using the provided currency state, and we update the currency 
                // state to include newly minted or burned currencies.
                CAmount valueOut = curTransfer.FirstValue();
                CAmount oneConversionFee = 0;
                CAmount newCurrencyConverted = 0;

                if (!curTransfer.IsFeeOutput())
                {
                    oneConversionFee = CalculateConversionFee(curTransfer.FirstValue());
                    if (curTransfer.IsReserveToReserve())
                    {
                        oneConversionFee <<= 1;
                    }
                    if (oneConversionFee > curTransfer.FirstValue())
                    {
                        oneConversionFee = curTransfer.FirstValue();
                    }
                    valueOut -= oneConversionFee;
                    AddReserveConversionFees(curTransfer.FirstCurrency(), oneConversionFee);
                    transferFees.valueMap[curTransfer.FirstCurrency()] += oneConversionFee;
                }

                if (toFractional)
                {
                    reserveConverted.valueMap[curTransfer.FirstCurrency()] += valueOut;
                    newCurrencyConverted = importCurrencyState.ReserveToNativeRaw(valueOut, importCurrencyState.conversionPrice[reserveIdx]);
                }
                else
                {
                    fractionalConverted.valueMap[curTransfer.destCurrencyID] += valueOut;
                    newCurrencyConverted = importCurrencyState.NativeToReserveRaw(valueOut, importCurrencyState.conversionPrice[reserveIdx]);
                }

                if (newCurrencyConverted)
                {
                    uint160 outputCurrencyID;

                    if (curTransfer.IsReserveToReserve())
                    {
                        // we need to convert once more from fractional to a reserve currency
                        // we burn 0.025% of the fractional that was converted, and convert the rest to
                        // the specified reserve. since the burn depends on the first conversion, which
                        // it is not involved in, it is tracked separately and applied after the first conversion
                        outputCurrencyID = curTransfer.secondReserveID;
                        int32_t outputCurrencyIdx = currencyIndexMap[outputCurrencyID];
                        newCurrencyConverted = CCurrencyState::NativeToReserveRaw(newCurrencyConverted, importCurrencyState.viaConversionPrice[outputCurrencyIdx]);
                        crossConversions[reserveIdx][outputCurrencyIdx] += valueOut;
                    }
                    else
                    {
                        outputCurrencyID = curTransfer.destCurrencyID;
                    }

                    if (toFractional && !curTransfer.IsReserveToReserve())
                    {
                        AddNativeOutConverted(curTransfer.FirstCurrency(), newCurrencyConverted);
                        AddNativeOutConverted(curTransfer.destCurrencyID, newCurrencyConverted);
                        if (curTransfer.destCurrencyID == systemDestID)
                        {
                            nativeOut += newCurrencyConverted;
                        }
                        else
                        {
                            AddReserveOutConverted(curTransfer.destCurrencyID, newCurrencyConverted);
                            AddReserveOutput(curTransfer.destCurrencyID, newCurrencyConverted);
                        }
                    }
                    else
                    {
                        AddReserveOutConverted(outputCurrencyID, newCurrencyConverted);
                        newConvertedReservePool.valueMap[outputCurrencyID] += newCurrencyConverted;
                        if (outputCurrencyID == systemDestID)
                        {
                            nativeOut += newCurrencyConverted;
                        }
                        else
                        {
                            AddReserveOutput(outputCurrencyID, newCurrencyConverted);
                        }

                        // if this originated as input fractional, burn the input currency
                        // if it was reserve to reserve, it was never added, and it's fee 
                        // value is left behind in the currency
                        if (!toFractional && !curTransfer.IsReserveToReserve())
                        {
                            AddNativeOutConverted(importCurrencyID, -valueOut);
                        }
                    }

                    if (outputCurrencyID == systemDestID)
                    {
                        curTransfer.GetTxOut(systemSource, 
                                             systemDest, 
                                             importCurrencyDef, 
                                             importCurrencyState,
                                             CCurrencyValueMap(),
                                             newCurrencyConverted,
                                             newOut,
                                             vOutputs,
                                             height);
                    }
                    else
                    {
                        curTransfer.GetTxOut(systemSource, 
                                             systemDest, 
                                             importCurrencyDef, 
                                             importCurrencyState,
                                             CCurrencyValueMap(std::vector<uint160>({outputCurrencyID}),
                                                               std::vector<int64_t>({newCurrencyConverted})), 
                                             0, newOut, vOutputs, height);
                    }
                }
            }
            else
            {
                // if we are supposed to burn a currency, it must be the import currency, and it
                // is removed from the supply, which either changes calculations for price or weight, burnweight is only allowed
                // as an operation by the currency controller
                if (curTransfer.IsBurn())
                {
                    // if the source is fractional currency or one of its reserves and not burn change weight, it is burned or added to reserves
                    if ((curTransfer.FirstCurrency() != importCurrencyID &&
                         (!isFractional || curTransfer.IsBurnChangeWeight() || !importCurrencyDef.GetCurrenciesMap().count(curTransfer.FirstCurrency()))) ||
                         !(isFractional || importCurrencyDef.IsToken()))
                    {
                        CCurrencyDefinition sourceCurrency = ConnectedChains.GetCachedCurrency(curTransfer.FirstCurrency());
                        printf("%s: Attempting to burn %s, which is either not a token or fractional currency or not the import currency %s\n", __func__, sourceCurrency.name.c_str(), importCurrencyDef.name.c_str());
                        LogPrintf("%s: Attempting to burn %s, which is either not a token or fractional currency or not the import currency %s\n", __func__, sourceCurrency.name.c_str(), importCurrencyDef.name.c_str());
                        return false;
                    }
                    // if this is burning the import currency, reduce supply, otherwise, the currency has been entered, and we
                    // simply leave it in the reserves
                    if (curTransfer.FirstCurrency() == importCurrencyID)
                    {
                        AddNativeOutConverted(curTransfer.FirstCurrency(), -curTransfer.FirstValue());
                        if (curTransfer.IsBurnChangeWeight())
                        {
                            burnedChangeWeight += curTransfer.FirstValue();
                        }
                        else
                        {
                            burnedChangePrice += curTransfer.FirstValue();
                        }
                    }
                    else
                    {
                        burnedReserves.valueMap[curTransfer.FirstCurrency()] += curTransfer.FirstValue();
                    }
                }
                else if (!curTransfer.IsMint() && systemDestID == curTransfer.FirstCurrency())
                {
                    nativeOut += curTransfer.FirstValue();
                    if (!curTransfer.GetTxOut(systemSource, 
                                             systemDest, 
                                             importCurrencyDef, 
                                             importCurrencyState,
                                             CCurrencyValueMap(),
                                             curTransfer.FirstValue(),
                                             newOut,
                                             vOutputs,
                                             height))
                    {
                        printf("%s: invalid transfer %s\n", __func__, curTransfer.ToUniValue().write(1,2).c_str());
                        LogPrintf("%s: invalid transfer %s\n", __func__, curTransfer.ToUniValue().write().c_str());
                        return false;
                    }
                }
                else
                {
                    // if this is a minting of currency
                    // this is used for both pre-allocation and also centrally, algorithmically, or externally controlled currencies
                    uint160 destCurID = curTransfer.destCurrencyID;
                    if (curTransfer.IsMint() && destCurID == importCurrencyID)
                    {
                        // minting is emitted in new currency state
                        totalMinted += curTransfer.FirstValue();
                        AddNativeOutConverted(destCurID, curTransfer.FirstValue());
                        if (destCurID != systemDestID)
                        {
                            AddReserveOutConverted(destCurID, curTransfer.FirstValue());
                        }
                    }
                    else
                    {
                        destCurID = curTransfer.FirstCurrency();
                    }
                    AddReserveOutput(destCurID, curTransfer.FirstValue());
                    curTransfer.GetTxOut(systemSource, 
                                         systemDest, 
                                         importCurrencyDef, 
                                         importCurrencyState,
                                         CCurrencyValueMap(std::vector<uint160>({destCurID}), std::vector<int64_t>({curTransfer.FirstValue()})), 
                                         0, newOut, vOutputs, height);
                }
            }
            if (newOut.nValue < 0)
            {
                // if we get here, we have absorbed the entire transfer
                LogPrintf("%s: skip creating output for import to %s\n", __func__, currencyDest.name.c_str());
            }
            else
            {
                vOutputs.push_back(newOut);
            }
        }
        else
        {
            if (!curTransfer.destination.IsValid())
            {
                printf("%s: Invalid destination for reserve transfer\n", __func__);
            }
            printf("%s: Invalid reserve transfer on transfer %s\n", __func__, curTransfer.ToUniValue().write(1,2).c_str());
            LogPrintf("%s: Invalid reserve transfer on export %s\n", __func__);
            return false;
        }
    }

    if (importCurrencyState.IsRefunding())
    {
        importedCurrency = CCurrencyValueMap();
    }
    else if ((totalCarveOuts = totalCarveOuts.CanonicalMap()).valueMap.size())
    {
        // add carveout outputs
        for (auto &oneCur : totalCarveOuts.valueMap)
        {
            // if we are creating a reserve import for native currency, it must be spent from native inputs on the destination system
            if (oneCur.first == systemDestID)
            {
                nativeOut += oneCur.second;
                vOutputs.push_back(CTxOut(oneCur.second, GetScriptForDestination(CIdentityID(importCurrencyID))));
            }
            else
            {
                // generate a reserve output of the amount indicated, less fees
                // we will send using a reserve output, fee will be paid through coinbase by converting from reserve or not, depending on currency settings
                std::vector<CTxDestination> dests = std::vector<CTxDestination>({CIdentityID(importCurrencyID)});
                CTokenOutput ro = CTokenOutput(oneCur.first, oneCur.second);
                AddReserveOutput(oneCur.first, oneCur.second);
                vOutputs.push_back(CTxOut(0, MakeMofNCCScript(CConditionObj<CTokenOutput>(EVAL_RESERVE_OUTPUT, dests, 1, &ro))));
            }
        }
    }

    // input of primary currency is sources in and output is sinks
    CAmount netPrimaryIn = 0;
    CAmount netPrimaryOut = 0;
    spentCurrencyOut.valueMap.clear();
    CCurrencyValueMap ReserveInputs;

    // remove burned currency from supply
    //
    // check to see if liquidity fees include currency that was burned and remove from output if so
    if (liquidityFees.valueMap.count(importCurrencyID))
    {
        CAmount primaryLiquidityFees = liquidityFees.valueMap[importCurrencyID];
        newCurrencyState.primaryCurrencyOut -= primaryLiquidityFees;
        liquidityFees.valueMap.erase(importCurrencyID);
    }

    // burn both change price and weight
    if (burnedChangePrice > 0 || burnedChangeWeight > 0 || burnedReserves > CCurrencyValueMap())
    {
        if ((burnedChangePrice + burnedChangeWeight) > newCurrencyState.supply)
        {
            printf("%s: Invalid burn amount %ld\n", __func__, burnedChangePrice + burnedChangeWeight);
            LogPrintf("%s: Invalid burn amount %ld\n", __func__, burnedChangePrice + burnedChangeWeight);
            return false;
        }

        if (burnedReserves.HasNegative())
        {
            printf("%s: Invalid burn amount %s\n", __func__, burnedReserves.ToUniValue().write(1,2).c_str());
            LogPrintf("%s: Invalid burn amount %s\n", __func__, burnedReserves.ToUniValue().write(1,2).c_str());
            return false;
        }

        // TODO: HARDENING - if we remove the supply entirely, we need to output any remaining reserves

        if (burnedChangePrice > 0)
        {
            newCurrencyState.supply -= burnedChangePrice;
        }

        // if we burned reserves, they go straight into reserves in the currency
        if (burnedReserves > CCurrencyValueMap())
        {
            newCurrencyState.reserves = CCoinbaseCurrencyState::AddVectors(newCurrencyState.reserves, burnedReserves.AsCurrencyVector(newCurrencyState.currencies));
        }

        // if we burn to change the weight, update weights
        if (burnedChangeWeight > 0)
        {
            newCurrencyState.UpdateWithEmission(-burnedChangeWeight);
        }
    }

    CCurrencyValueMap adjustedReserveConverted = reserveConverted - preConvertedReserves;

    int32_t issuedWeight = 0;
    CAmount totalRatio = 0;
    bool fractionalLaunchClearConfirm = false;

    if (isFractional && importCurrencyState.IsLaunchConfirmed())
    {
        CCoinbaseCurrencyState scratchCurrencyState = importCurrencyState;

        if (burnedChangePrice > 0)
        {
            scratchCurrencyState.supply -= burnedChangePrice;
        }

        // if we burned reserves, they go straight into reserves in the currency
        if (burnedReserves > CCurrencyValueMap())
        {
            scratchCurrencyState.reserves = CCoinbaseCurrencyState::AddVectors(scratchCurrencyState.reserves, burnedReserves.AsCurrencyVector(scratchCurrencyState.currencies));
        }

        // if we burned to change the weight, update weights
        if (burnedChangeWeight > 0)
        {
            scratchCurrencyState.UpdateWithEmission(-burnedChangeWeight);
        }

        if (scratchCurrencyState.IsPrelaunch() && preConvertedReserves > CCurrencyValueMap())
        {
            // add all pre-converted reserves before calculating pricing for fee conversions
            for (auto &oneReserve : preConvertedReserves.valueMap)
            {
                if (oneReserve.second)
                {
                    scratchCurrencyState.reserves[currencyIndexMap[oneReserve.first]] += oneReserve.second;
                }
            }
        }

        if (importCurrencyState.IsLaunchClear())
        {
            fractionalLaunchClearConfirm = true;

            for (auto weight : importCurrencyDef.weights)
            {
                totalRatio += weight;
            }

            CAmount tempIssuedWeight = 
                issuedWeight = 
                    importCurrencyDef.gatewayConverterIssuance ? importCurrencyState.weights[currencyIndexMap[importCurrencyDef.systemID]] : 0;

            if (totalCarveOut)
            {
                if (tempIssuedWeight < totalCarveOut)
                {
                    scratchCurrencyState.ApplyCarveouts(totalCarveOut - tempIssuedWeight);
                    tempIssuedWeight = 0;
                }
                else
                {
                    tempIssuedWeight -= totalCarveOut;
                }
            }
            if (importCurrencyDef.preLaunchDiscount)
            {
                if (tempIssuedWeight <= importCurrencyDef.preLaunchDiscount)
                {
                    scratchCurrencyState.ApplyCarveouts(importCurrencyDef.preLaunchDiscount - tempIssuedWeight);
                }
            }
        }

        if (adjustedReserveConverted.CanonicalMap().valueMap.size() || fractionalConverted.CanonicalMap().valueMap.size())
        {
            CCurrencyState dummyCurState;
            std::vector<int64_t> newPrices =
                scratchCurrencyState.ConvertAmounts(adjustedReserveConverted.AsCurrencyVector(importCurrencyState.currencies),
                                                    fractionalConverted.AsCurrencyVector(importCurrencyState.currencies),
                                                    dummyCurState,
                                                    &crossConversions,
                                                    &newCurrencyState.viaConversionPrice);
            if (!dummyCurState.IsValid())
            {
                printf("%s: Invalid currency conversions for import to %s : %s\n", __func__, importCurrencyDef.name.c_str(), EncodeDestination(CIdentityID(importCurrencyDef.GetID())).c_str());
                LogPrintf("%s: Invalid currency conversions for import to %s : %s\n", __func__, importCurrencyDef.name.c_str(), EncodeDestination(CIdentityID(importCurrencyDef.GetID())).c_str());
                return false;
            }
            if (!newCurrencyState.IsLaunchCompleteMarker())
            {
                // make viaconversion prices the dynamic prices and conversion prices remain initial pricing
                for (int i = 0; i < newPrices.size(); i++)
                {
                    if (i != systemDestIdx)
                    {
                        newCurrencyState.viaConversionPrice[i] = newPrices[i];
                    }
                }
            }
            else
            {
                newCurrencyState.conversionPrice = newPrices;
            }
        }
    }

    if (newCurrencyState.IsPrelaunch())
    {
        adjustedReserveConverted = reserveConverted;
    }

    newCurrencyState.preConvertedOut = 0;
    if (!newCurrencyState.IsRefunding())
    {
        for (auto &oneVal : preConvertedOutput.valueMap)
        {
            newCurrencyState.preConvertedOut += oneVal.second;
            if (!isFractional &&
                newCurrencyState.IsLaunchConfirmed() &&
                !(importCurrencyDef.IsPBaaSChain() && !newCurrencyState.IsLaunchClear()))
            {
                newCurrencyState.supply += oneVal.second;
            }
        }
    }

    std::vector<CAmount> vResConverted;
    std::vector<CAmount> vResOutConverted;
    std::vector<CAmount> vFracConverted;
    std::vector<CAmount> vFracOutConverted;

    CCurrencyValueMap reserveBalanceInMap;

    // liquidity fees that are in the import currency are burned above
    std::vector<CAmount> vLiquidityFees = liquidityFees.AsCurrencyVector(newCurrencyState.currencies);

    if (newCurrencyState.IsLaunchConfirmed())
    {
        vResConverted = adjustedReserveConverted.AsCurrencyVector(newCurrencyState.currencies);
        vResOutConverted = (ReserveOutConvertedMap(importCurrencyID) + totalCarveOuts).AsCurrencyVector(newCurrencyState.currencies);
        vFracConverted = fractionalConverted.AsCurrencyVector(newCurrencyState.currencies);
        vFracOutConverted = (NativeOutConvertedMap() - preConvertedOutput).AsCurrencyVector(newCurrencyState.currencies);
        CAmount totalNewFrac = 0;
        for (int i = 0; i < newCurrencyState.currencies.size(); i++)
        {
            newCurrencyState.reserveIn[i] = vResConverted[i] + vLiquidityFees[i];
            newCurrencyState.reserveOut[i] = vResOutConverted[i];
            CAmount newReservesIn = isFractional ? (vResConverted[i] - vResOutConverted[i]) + vLiquidityFees[i] : 0;
            newCurrencyState.reserves[i] += newReservesIn;
            if (newReservesIn)
            {
                reserveBalanceInMap.valueMap[newCurrencyState.currencies[i]] = newReservesIn;
            }
            netPrimaryIn += (newCurrencyState.primaryCurrencyIn[i] = vFracConverted[i]);
            netPrimaryOut += vFracOutConverted[i];
            totalNewFrac += vFracOutConverted[i];

            auto cIT = burnedReserves.valueMap.find(newCurrencyState.currencies[i]);
            if (cIT != burnedReserves.valueMap.end())
            {
                newCurrencyState.reserveIn[i] += cIT->second;
            }
        }
        newCurrencyState.supply += (netPrimaryOut - netPrimaryIn);
        netPrimaryIn += totalNewFrac;
    }
    else
    {
        vResConverted = adjustedReserveConverted.AsCurrencyVector(newCurrencyState.currencies);
        vResOutConverted = ReserveOutConvertedMap(importCurrencyID).AsCurrencyVector(newCurrencyState.currencies);
        vFracConverted = fractionalConverted.AsCurrencyVector(newCurrencyState.currencies);
        vFracOutConverted = preConvertedOutput.AsCurrencyVector(newCurrencyState.currencies);
        for (int i = 0; i < newCurrencyState.currencies.size(); i++)
        {
            newCurrencyState.reserveIn[i] = vResConverted[i] + vLiquidityFees[i];
            if (isFractional)
            {
                newCurrencyState.reserves[i] += (vResConverted[i] - vResOutConverted[i]) + vLiquidityFees[i];
            }
            else
            {
                CAmount newPrimaryOut = vFracOutConverted[i] - vFracConverted[i];
                newCurrencyState.supply += newPrimaryOut;
                netPrimaryIn += newPrimaryOut;
                netPrimaryOut += newPrimaryOut;
            }
        }
    }

    // launch clear or not confirmed, we have straight prices, fees get formula based conversion, but
    // price is not recorded in state so that initial currency always has initial prices
    if (!newCurrencyState.IsLaunchCompleteMarker())
    {
        if (isFractional)
        {
            if (newCurrencyState.IsLaunchConfirmed())
            {
                // calculate launch prices and ensure that conversion prices remain constant until
                // launch is complete
                if (newCurrencyState.IsLaunchClear() && newCurrencyState.IsPrelaunch())
                {
                    CCoinbaseCurrencyState tempCurrencyState = importCurrencyState;

                    if (preConvertedReserves > CCurrencyValueMap())
                    {
                        tempCurrencyState.reserves = 
                            (CCurrencyValueMap(
                                tempCurrencyState.currencies, tempCurrencyState.reserves) + preConvertedReserves).AsCurrencyVector(tempCurrencyState.currencies);
                    }

                    /* printf("%s: importCurrencyState:\n%s\nnewCurrencyState:\n%s\nrevertedState:\n%s\n", 
                        __func__, 
                        importCurrencyState.ToUniValue().write(1,2).c_str(), 
                        newCurrencyState.ToUniValue().write(1,2).c_str(), 
                        tempCurrencyState.ToUniValue().write(1,2).c_str());
                    printf("%s: liquidityfees:\n%s\n", __func__, liquidityFees.ToUniValue().write(1,2).c_str());
                    printf("%s: preConvertedReserves:\n%s\n", __func__, preConvertedReserves.ToUniValue().write(1,2).c_str()); */

                    tempCurrencyState.supply = importCurrencyDef.initialFractionalSupply;

                    if (importCurrencyDef.launchSystemID == importCurrencyDef.systemID)
                    {
                        newCurrencyState.conversionPrice = tempCurrencyState.PricesInReserve(true);
                    }
                    else
                    {
                        CAmount systemDestPrice = tempCurrencyState.PriceInReserve(systemDestIdx);
                        tempCurrencyState.currencies.erase(tempCurrencyState.currencies.begin() + systemDestIdx);
                        tempCurrencyState.reserves.erase(tempCurrencyState.reserves.begin() + systemDestIdx);
                        int32_t sysWeight = tempCurrencyState.weights[systemDestIdx];
                        tempCurrencyState.weights.erase(tempCurrencyState.weights.begin() + systemDestIdx);
                        int32_t oneExtraWeight = sysWeight / tempCurrencyState.weights.size();
                        int32_t weightRemainder = sysWeight % tempCurrencyState.weights.size();
                        for (auto &oneWeight : tempCurrencyState.weights)
                        {
                            oneWeight += oneExtraWeight;
                            if (weightRemainder)
                            {
                                oneWeight++;
                                weightRemainder--;
                            }
                        }
                        std::vector<CAmount> launchPrices = tempCurrencyState.PricesInReserve(true);
                        launchPrices.insert(launchPrices.begin() + systemDestIdx, systemDestPrice);
                        newCurrencyState.conversionPrice = launchPrices;
                    }
                }
                else
                {
                    newCurrencyState.conversionPrice = importCurrencyState.conversionPrice;
                }
            }
            else if (importCurrencyState.IsPrelaunch() && !importCurrencyState.IsRefunding())
            {
                newCurrencyState.viaConversionPrice = newCurrencyState.PricesInReserve(true);
                CCoinbaseCurrencyState tempCurrencyState = newCurrencyState;
                // via prices are used for fees on launch clear and include the converter issued currency
                // normal prices on launch clear for a gateway or PBaaS converter do not include the new native
                // currency until after pre-conversions are processed
                if (importCurrencyDef.launchSystemID == importCurrencyDef.systemID)
                {
                    newCurrencyState.conversionPrice = tempCurrencyState.PricesInReserve(true);
                }
                else
                {
                    tempCurrencyState.currencies.erase(tempCurrencyState.currencies.begin() + systemDestIdx);
                    tempCurrencyState.reserves.erase(tempCurrencyState.reserves.begin() + systemDestIdx);
                    int32_t sysWeight = tempCurrencyState.weights[systemDestIdx];
                    tempCurrencyState.weights.erase(tempCurrencyState.weights.begin() + systemDestIdx);
                    int32_t oneExtraWeight = sysWeight / tempCurrencyState.weights.size();
                    int32_t weightRemainder = sysWeight % tempCurrencyState.weights.size();
                    for (auto &oneWeight : tempCurrencyState.weights)
                    {
                        oneWeight += oneExtraWeight;
                        if (weightRemainder)
                        {
                            oneWeight++;
                            weightRemainder--;
                        }
                    }
                    std::vector<CAmount> launchPrices = tempCurrencyState.PricesInReserve(true);
                    launchPrices.insert(launchPrices.begin() + systemDestIdx, newCurrencyState.viaConversionPrice[systemDestIdx]);
                    newCurrencyState.conversionPrice = launchPrices;
                }
            }
        }
    }

    // if this is a PBaaS launch, mint all required preconversion along with preallocation
    CAmount extraPreconverted = 0;
    if (importCurrencyDef.IsPBaaSChain() && newCurrencyState.IsLaunchClear() && newCurrencyState.IsLaunchConfirmed())
    {
        if (importCurrencyState.IsPrelaunch())
        {
            extraPreconverted = newCurrencyState.preConvertedOut;
            // if this is our launch currency issue any necessary pre-converted supply and add it to reserve deposits
            if (importCurrencyID == ASSETCHAINS_CHAINID &&
                importCurrencyState.reserveIn.size())
            {
                for (int i = 0; i < importCurrencyState.reserveIn.size(); i++)
                {
                    // add new native currency to reserve deposits for imports
                    // total converted in this import should be added to the total from before
                    CAmount oldReservesIn = importCurrencyState.reserveIn[i] - newCurrencyState.reserveIn[i];
                    extraPreconverted += newCurrencyState.ReserveToNativeRaw(oldReservesIn, newCurrencyState.conversionPrice[i]);
                }
                newCurrencyState.preConvertedOut = extraPreconverted;
            }
        }
        else
        {
            extraPreconverted = importCurrencyState.preConvertedOut - newCurrencyState.preConvertedOut;
        }
    }

    if (newCurrencyState.IsRefunding())
    {
        preAllocTotal = 0;
        totalMinted = 0;
        extraPreconverted = 0;
    }

    if (fractionalLaunchClearConfirm)
    {
        if (totalCarveOut)
        {
            if (issuedWeight < totalCarveOut)
            {
                newCurrencyState.ApplyCarveouts(totalCarveOut - issuedWeight);
                issuedWeight = 0;
            }
            else
            {
                issuedWeight -= totalCarveOut;
            }
        }
        if (importCurrencyDef.preLaunchDiscount)
        {
            if (issuedWeight <= importCurrencyDef.preLaunchDiscount)
            {
                newCurrencyState.ApplyCarveouts(importCurrencyDef.preLaunchDiscount - issuedWeight);
                issuedWeight = 0;
            }
            else
            {
                issuedWeight -= importCurrencyDef.preLaunchDiscount;
            }
        }

        //printf("new currency state: %s\n", newCurrencyState.ToUniValue().write(1,2).c_str());
    }

    if (totalMinted || preAllocTotal)
    {
        if (preAllocTotal)
        {
            newCurrencyState.UpdateWithEmission(preAllocTotal, issuedWeight);
        }
        if (totalMinted)
        {
            newCurrencyState.UpdateWithEmission(totalMinted);
        }
        netPrimaryOut += (totalMinted + preAllocTotal);
        netPrimaryIn += (totalMinted + preAllocTotal);
    }

    if (newCurrencyState.IsLaunchConfirmed())
    {
        netPrimaryOut += newCurrencyState.preConvertedOut;
        netPrimaryIn += newCurrencyState.preConvertedOut + extraPreconverted;
    }

    if (extraPreconverted)
    {
        gatewayDepositsIn.valueMap[importCurrencyID] += extraPreconverted;
    }

    // double check that the export fee taken as the fee output matches the export fee that should have been taken
    CAmount systemOutConverted = 0;

    //printf("%s currencies: %s\n", __func__, ToUniValue().write(1,2).c_str());

    if (netPrimaryIn)
    {
        ReserveInputs.valueMap[importCurrencyID] += netPrimaryIn;
    }

    if (netPrimaryOut)
    {
        spentCurrencyOut.valueMap[importCurrencyID] += netPrimaryOut;
    }

    newCurrencyState.primaryCurrencyOut = netPrimaryOut - (burnedChangePrice + burnedChangeWeight);

    if (importCurrencyDef.IsPBaaSChain() && importCurrencyState.IsLaunchConfirmed())
    {
        // pre-conversions should already be on this chain as gateway deposits on behalf of the
        // launching chain
        if (!importCurrencyState.IsLaunchClear())
        {
            newCurrencyState.primaryCurrencyOut -= newCurrencyState.preConvertedOut;
            gatewayDepositsIn.valueMap[importCurrencyID] += newCurrencyState.preConvertedOut;
            importedCurrency = (importedCurrency - preConvertedReserves).CanonicalMap();
            gatewayDepositsIn += preConvertedReserves;
        }
        else if (!newCurrencyState.IsPrelaunch())
        {
            // adjust gateway deposits for launch
            newCurrencyState.reserveIn = importCurrencyState.reserveIn; // reserve in must be the same
            CAmount newLaunchNative = newCurrencyState.ReserveToNative(CCurrencyValueMap(newCurrencyState.currencies, newCurrencyState.reserveIn));
            gatewayDepositsIn.valueMap[importCurrencyID] -= newLaunchNative;
            newCurrencyState.primaryCurrencyOut += newLaunchNative;
            newCurrencyState.preConvertedOut += newLaunchNative;
        }
        else
        {
            newCurrencyState.supply += importCurrencyState.supply - newCurrencyState.emitted;
            newCurrencyState.preConvertedOut += importCurrencyState.preConvertedOut;
            newCurrencyState.primaryCurrencyOut += importCurrencyState.primaryCurrencyOut;
        }
    }

    for (auto &oneInOut : currencies)
    {
        if (oneInOut.first == importCurrencyID)
        {
            if (oneInOut.first == systemDestID)
            {
                systemOutConverted += oneInOut.second.nativeOutConverted;
            }
            else
            {
                if (oneInOut.second.reserveIn)
                {
                    ReserveInputs.valueMap[oneInOut.first] += oneInOut.second.reserveIn;
                }
                if (oneInOut.second.reserveOut)
                {
                    spentCurrencyOut.valueMap[oneInOut.first] += oneInOut.second.reserveOut - oneInOut.second.reserveOutConverted;
                }
            }
        }
        else
        {
            if (oneInOut.first == systemDestID)
            {
                systemOutConverted += oneInOut.second.reserveOutConverted;
            }
            if (oneInOut.second.reserveIn)
            {
                ReserveInputs.valueMap[oneInOut.first] += oneInOut.second.reserveIn;
            }
            if (liquidityFees.valueMap.count(oneInOut.first))
            {
                ReserveInputs.valueMap[oneInOut.first] += liquidityFees.valueMap[oneInOut.first];
            }
            if (oneInOut.first != systemDestID)
            {
                if (oneInOut.second.reserveOut)
                {
                    spentCurrencyOut.valueMap[oneInOut.first] += oneInOut.second.reserveOut;
                }
            }
        }
    }

    if (nativeIn)
    {
        if (importCurrencyID == systemDestID)
        {
            ReserveInputs.valueMap[systemDestID] += (nativeIn - netPrimaryIn);
        }
        else
        {
            ReserveInputs.valueMap[systemDestID] += nativeIn;
        }
    }
    if (nativeOut)
    {
        if (importCurrencyID == systemDestID)
        {
            spentCurrencyOut.valueMap[systemDestID] += (nativeOut - netPrimaryOut);
        }
        else
        {
            spentCurrencyOut.valueMap[systemDestID] += nativeOut;
        }
    }

    if (systemOutConverted && importCurrencyID != systemDestID)
    {
        // this does not have meaning besides a store of the system currency output that was converted
        currencies[importCurrencyID].reserveOutConverted = systemOutConverted;
    }

    CCurrencyValueMap checkAgainstInputs(spentCurrencyOut);

    if (((ReserveInputs + newConvertedReservePool) - checkAgainstInputs).HasNegative())
    {
        printf("importCurrencyState: %s\nnewCurrencyState: %s\n", importCurrencyState.ToUniValue().write(1,2).c_str(), newCurrencyState.ToUniValue().write(1,2).c_str());
        printf("newConvertedReservePool: %s\n", newConvertedReservePool.ToUniValue().write(1,2).c_str());
        printf("ReserveInputs: %s\nspentCurrencyOut: %s\nReserveInputs - spentCurrencyOut: %s\ncheckAgainstInputs: %s\nreserveBalanceInMap: %s\ntotalNativeFee: %ld, totalVerusFee: %ld\n", 
            ReserveInputs.ToUniValue().write(1,2).c_str(), 
            spentCurrencyOut.ToUniValue().write(1,2).c_str(), 
            (ReserveInputs - spentCurrencyOut).ToUniValue().write(1,2).c_str(), 
            checkAgainstInputs.ToUniValue().write(1,2).c_str(),
            reserveBalanceInMap.ToUniValue().write(1,2).c_str(),
            totalNativeFee,
            totalVerusFee);
        //*/

        /*UniValue jsonTx(UniValue::VOBJ);
        CMutableTransaction mtx;
        mtx.vout = vOutputs;
        TxToUniv(mtx, uint256(), jsonTx);
        printf("%s: outputsOnTx:\n%s\n", __func__, jsonTx.write(1,2).c_str());
        //*/

        printf("%s: Too much fee taken by export, ReserveInputs: %s\nReserveOutputs: %s\n", __func__,
                ReserveInputs.ToUniValue().write(1,2).c_str(), 
                spentCurrencyOut.ToUniValue().write(1,2).c_str());
        LogPrintf("%s: Too much fee taken by export, ReserveInputs: %s\nReserveOutputs: %s\n", __func__,
                ReserveInputs.ToUniValue().write(1,2).c_str(), 
                spentCurrencyOut.ToUniValue().write(1,2).c_str());
        return false;
    }
    return true;
}

CCurrencyValueMap CReserveTransactionDescriptor::ReserveInputMap(const uint160 &nativeID) const
{
    CCurrencyValueMap retVal;
    uint160 id = nativeID.IsNull() ? ASSETCHAINS_CHAINID : nativeID;
    for (auto &oneInOut : currencies)
    {
        // skip native
        if (oneInOut.first != id)
        {
            if (oneInOut.second.reserveIn)
            {
                retVal.valueMap[oneInOut.first] = oneInOut.second.reserveIn;
            }
        }
        if (oneInOut.second.nativeOutConverted)
        {
            retVal.valueMap[oneInOut.first] = oneInOut.second.nativeOutConverted;
        }
    }
    return retVal;
}

CCurrencyValueMap CReserveTransactionDescriptor::ReserveOutputMap(const uint160 &nativeID) const
{
    CCurrencyValueMap retVal;
    uint160 id = nativeID.IsNull() ? ASSETCHAINS_CHAINID : nativeID;
    for (auto &oneInOut : currencies)
    {
        // skip native
        if (oneInOut.first != id)
        {
            if (oneInOut.second.reserveOut)
            {
                retVal.valueMap[oneInOut.first] = oneInOut.second.reserveOut;
            }
        }
    }
    return retVal;
}

CCurrencyValueMap CReserveTransactionDescriptor::ReserveOutConvertedMap(const uint160 &nativeID) const
{
    CCurrencyValueMap retVal;
    uint160 id = nativeID.IsNull() ? ASSETCHAINS_CHAINID : nativeID;
    for (auto &oneInOut : currencies)
    {
        // skip native
        if (oneInOut.first != id)
        {
            if (oneInOut.second.reserveOutConverted)
            {
                retVal.valueMap[oneInOut.first] = oneInOut.second.reserveOutConverted;
            }
        }
    }
    return retVal;
}

CCurrencyValueMap CReserveTransactionDescriptor::NativeOutConvertedMap() const
{
    CCurrencyValueMap retVal;
    for (auto &oneInOut : currencies)
    {
        if (oneInOut.second.nativeOutConverted)
        {
            retVal.valueMap[oneInOut.first] = oneInOut.second.nativeOutConverted;
        }
    }
    return retVal;
}

CCurrencyValueMap CReserveTransactionDescriptor::ReserveConversionFeesMap() const
{
    CCurrencyValueMap retVal;
    for (auto &oneInOut : currencies)
    {
        if (oneInOut.second.reserveConversionFees)
        {
            retVal.valueMap[oneInOut.first] = oneInOut.second.reserveConversionFees;
        }
    }
    return retVal;
}

std::vector<CAmount> CReserveTransactionDescriptor::ReserveInputVec(const CCurrencyState &cState) const
{
    std::vector<CAmount> retVal(cState.currencies.size());
    std::map<uint160, int> curMap = cState.GetReserveMap();
    for (auto &oneInOut : currencies)
    {
        retVal[curMap[oneInOut.first]] = oneInOut.second.reserveIn;
    }
    return retVal;
}

std::vector<CAmount> CReserveTransactionDescriptor::ReserveOutputVec(const CCurrencyState &cState) const
{
    std::vector<CAmount> retVal(cState.currencies.size());
    std::map<uint160, int> curMap = cState.GetReserveMap();
    for (auto &oneInOut : currencies)
    {
        retVal[curMap[oneInOut.first]] = oneInOut.second.reserveOut;
    }
    return retVal;
}

std::vector<CAmount> CReserveTransactionDescriptor::ReserveOutConvertedVec(const CCurrencyState &cState) const
{
    std::vector<CAmount> retVal(cState.currencies.size());
    std::map<uint160, int> curMap = cState.GetReserveMap();
    for (auto &oneInOut : currencies)
    {
        retVal[curMap[oneInOut.first]] = oneInOut.second.reserveOutConverted;
    }
    return retVal;
}

std::vector<CAmount> CReserveTransactionDescriptor::NativeOutConvertedVec(const CCurrencyState &cState) const
{
    std::vector<CAmount> retVal(cState.currencies.size());
    std::map<uint160, int> curMap = cState.GetReserveMap();
    for (auto &oneInOut : currencies)
    {
        retVal[curMap[oneInOut.first]] = oneInOut.second.nativeOutConverted;
    }
    return retVal;
}

std::vector<CAmount> CReserveTransactionDescriptor::ReserveConversionFeesVec(const CCurrencyState &cState) const
{
    std::vector<CAmount> retVal(cState.currencies.size());
    std::map<uint160, int> curMap = cState.GetReserveMap();
    for (auto &oneInOut : currencies)
    {
        retVal[curMap[oneInOut.first]] = oneInOut.second.reserveConversionFees;
    }
    return retVal;
}

// this should be done no more than once to prepare a currency state to be updated to the next state
// emission occurs for a block before any conversion or exchange and that impact on the currency state is calculated
CCoinbaseCurrencyState &CCoinbaseCurrencyState::UpdateWithEmission(CAmount toEmit, int32_t excessRatio)
{
    emitted = 0;

    // if supply is 0, reserve must be zero, and we cannot function as a reserve currency
    if (!IsFractional() || supply <= 0 || CCurrencyValueMap(currencies, reserves) <= CCurrencyValueMap())
    {
        if (supply <= 0)
        {
            emitted = supply = toEmit;
        }
        else
        {
            emitted = toEmit;
            supply += toEmit;
        }
        return *this;
    }

    if (toEmit)
    {
        // first determine current ratio by adding up all currency weights
        CAmount InitialRatio = 0;
        for (auto weight : weights)
        {
            InitialRatio += weight;
        }

        // to balance rounding with truncation, we statistically add a satoshi to the initial ratio
        static arith_uint256 bigSatoshi(SATOSHIDEN);
        arith_uint256 bigInitial(InitialRatio);
        arith_uint256 bigEmission(std::abs(toEmit));
        arith_uint256 bigSupply(supply);

        arith_uint256 bigScratch = (toEmit < 0) && (supply + toEmit) <= 0 ?
                                    arith_uint256(SATOSHIDEN) * arith_uint256(SATOSHIDEN) :
                                    (bigInitial * bigSupply * bigSatoshi) / (toEmit < 0 ? (bigSupply - bigEmission) : (bigSupply + bigEmission));

        arith_uint256 bigRatio = bigScratch / bigSatoshi;

        // cap ratio at 1
        if (bigRatio >= bigSatoshi)
        {
            bigScratch = arith_uint256(SATOSHIDEN) * arith_uint256(SATOSHIDEN);
            bigRatio = bigSatoshi;
        }

        int64_t newRatio = bigRatio.GetLow64();
        int64_t remainder = (bigScratch - (bigRatio * SATOSHIDEN)).GetLow64();
        // form of bankers rounding, if odd, round up at half, if even, round down at half
        if (remainder > (SATOSHIDEN >> 1) || (remainder == (SATOSHIDEN >> 1) && newRatio & 1))
        {
            newRatio += 1;
        }

        // now, we must update all weights accordingly, based on the new, total ratio, by dividing the total among all the
        // weights, according to their current relative weight. because this also can be a source of rounding error, we will
        // distribute any modulus excess deterministically pseudorandomly among the currencies
        std::vector<CAmount> extraWeight(currencies.size());
        arith_uint256 bigRatioDelta(InitialRatio - newRatio);

        // adjust the ratio adjustment if we have a non-zero excessRatio
        if (excessRatio > 0)
        {
            CAmount adjustedRatioDelta = InitialRatio - newRatio;
            if (excessRatio < adjustedRatioDelta)
            {
                bigRatioDelta = arith_uint256(adjustedRatioDelta - excessRatio);
                newRatio += excessRatio;
            }
            else
            {
                bigRatioDelta = 0;
                newRatio = InitialRatio;
            }
        }

        CAmount totalUpdates = 0;

        for (auto &weight : weights)
        {
            CAmount weightDelta = (bigRatioDelta * arith_uint256(weight) / bigSatoshi).GetLow64();
            weight -= weightDelta;
            totalUpdates += weightDelta;
        }

        CAmount updateExtra = (InitialRatio - newRatio) - totalUpdates;

        // if we have any extra, distribute it evenly and any mod, both deterministically and pseudorandomly
        if (updateExtra)
        {
            CAmount forAll = updateExtra / currencies.size();
            CAmount forSome = updateExtra % currencies.size();

            // get deterministic seed for linear congruential pseudorandom number for shuffle
            uint32_t seed = (uint32_t)((uint64_t)(supply + forAll + forSome)) & 0xffffffff;
            auto prandom = std::minstd_rand0(seed);

            for (int i = 0; i < extraWeight.size(); i++)
            {
                extraWeight[i] = forAll;
                if (forSome)
                {
                    extraWeight[i]++;
                    forSome--;
                }
            }

            // distribute the extra as evenly as possible
            std::shuffle(extraWeight.begin(), extraWeight.end(), prandom);
            for (int i = 0; i < weights.size(); i++)
            {
                weights[i] -= extraWeight[i];
            }
        }

        // update initial supply from what we currently have
        emitted = toEmit;
        supply += emitted;
    }
    return *this; 
}

CCoinbaseCurrencyState &CCoinbaseCurrencyState::ApplyCarveouts(int32_t carveOut)
{
    if (carveOut && carveOut < SATOSHIDEN)
    {
        // first determine current ratio by adding up all currency weights
        CAmount InitialRatio = 0;
        for (auto weight : weights)
        {
            InitialRatio += weight;
        }

        static arith_uint256 bigSatoshi(SATOSHIDEN);
        arith_uint256 bigInitial(InitialRatio);
        arith_uint256 bigCarveOut((int64_t)carveOut);
        arith_uint256 bigScratch = (bigInitial * (bigSatoshi - bigCarveOut));
        arith_uint256 bigNewRatio = bigScratch / bigSatoshi;

        int64_t newRatio = bigNewRatio.GetLow64();

        int64_t remainder = (bigScratch - (bigNewRatio * bigSatoshi)).GetLow64();
        // form of bankers rounding, if odd, round up at half, if even, round down at half
        if (remainder > (SATOSHIDEN >> 1) || (remainder == (SATOSHIDEN >> 1) && newRatio & 1))
        {
            if (newRatio < SATOSHIDEN)
            {
                newRatio += 1;
            }
        }

        // now, we must update all weights accordingly, based on the new, total ratio, by dividing the total among all the
        // weights, according to their current relative weight. because this also can be a source of rounding error, we will
        // distribute any modulus excess randomly among the currencies
        std::vector<CAmount> extraWeight(currencies.size());
        arith_uint256 bigRatioDelta(InitialRatio - newRatio);
        CAmount totalUpdates = 0;

        for (auto &weight : weights)
        {
            CAmount weightDelta = (bigRatioDelta * arith_uint256(weight) / bigSatoshi).GetLow64();
            weight -= weightDelta;
            totalUpdates += weightDelta;
        }

        CAmount updateExtra = (InitialRatio - newRatio) - totalUpdates;

        // if we have any extra, distribute it evenly and any mod, both deterministically and pseudorandomly
        if (updateExtra)
        {
            CAmount forAll = updateExtra / currencies.size();
            CAmount forSome = updateExtra % currencies.size();

            // get deterministic seed for linear congruential pseudorandom number for shuffle
            uint32_t seed = (uint32_t)((uint64_t)(supply + forAll + forSome)) & 0xffffffff;
            auto prandom = std::minstd_rand0(seed);

            for (int i = 0; i < extraWeight.size(); i++)
            {
                extraWeight[i] = forAll;
                if (forSome)
                {
                    extraWeight[i]++;
                    forSome--;
                }
            }
            // distribute the extra weight loss as evenly as possible
            std::shuffle(extraWeight.begin(), extraWeight.end(), prandom);
            for (int i = 0; i < weights.size(); i++)
            {
                weights[i] -= extraWeight[i];
            }
        }
    }
    return *this; 
}


void CCoinbaseCurrencyState::RevertFees(const std::vector<CAmount> &normalConversionPrice,
                                        const std::vector<CAmount> &outgoingConversionPrice,
                                        const uint160 &systemID)
{
    auto reserveIndexMap = GetReserveMap();
    if (IsFractional() && reserveIndexMap.count(systemID) && reserveIndexMap.find(systemID)->second)
    {
        // undo fees
        // all liquidity fees except blockchain native currency go into the reserves for conversion
        // native currency gets burned
        CCurrencyValueMap allConvertedFees(currencies, fees);
        if (primaryCurrencyFees)
        {
            allConvertedFees.valueMap[GetID()] = primaryCurrencyFees;
        }

        CCurrencyValueMap liquidityFees(CCurrencyValueMap(currencies, conversionFees));
        if (primaryCurrencyConversionFees)
        {
            liquidityFees.valueMap[systemID] = primaryCurrencyConversionFees;
        }

        liquidityFees = liquidityFees / 2;

        //printf("%s: liquidityfees/2:\n%s\n", __func__, liquidityFees.ToUniValue().write(1,2).c_str());

        for (auto &oneLiquidityFee : liquidityFees.valueMap)
        {
            // importCurrency as liquidity fee will have gotten burned, so add it back to supply
            if (oneLiquidityFee.first == GetID())
            {
                supply += oneLiquidityFee.second;
            }
            else
            {
                // otherwise, the currency went in to reserves, so remove it
                reserves[reserveIndexMap[oneLiquidityFee.first]] -= oneLiquidityFee.second;
            }
        }

        // the rest of the fees should have been converted to native and paid out
        // from native. calculate an exact amount of converted native fee by converting 
        // according to the prices supplied. The rest of the fees are transfer fees or
        // something else that does not affect currency reserves.
        allConvertedFees -= liquidityFees;
        CAmount totalConvertedNativeFee = 0;
        int systemDestIdx = reserveIndexMap[systemID];
        for (auto &oneFee : allConvertedFees.valueMap)
        {
            // fees are not converted from the system currency, only to it
            // for that reason, skip system in the loop and calculate the amount
            // that was converted to it to determine the amount to replenish
            if (oneFee.first != systemID)
            {
                if (reserveIndexMap.count(oneFee.first))
                {
                    reserves[reserveIndexMap[oneFee.first]] -= oneFee.second;
                    totalConvertedNativeFee +=
                        NativeToReserveRaw(ReserveToNativeRaw(oneFee.second, normalConversionPrice[reserveIndexMap[oneFee.first]]),
                                        outgoingConversionPrice[systemDestIdx]);
                }
                else if (oneFee.first == GetID())
                {
                    totalConvertedNativeFee +=
                        NativeToReserveRaw(oneFee.second, normalConversionPrice[systemDestIdx]);
                }
            }
        }
        reserves[systemDestIdx] += totalConvertedNativeFee;

        //printf("%s: currencyState:\n%s\n", __func__, ToUniValue().write(1,2).c_str());
    }
}

CCurrencyValueMap CCoinbaseCurrencyState::CalculateConvertedFees(const std::vector<CAmount> &normalConversionPrice,
                                                                 const std::vector<CAmount> &outgoingConversionPrice,
                                                                 const uint160 &systemID,
                                                                 bool &feesConverted,
                                                                 CCurrencyValueMap &liquidityFees,
                                                                 CCurrencyValueMap &convertedFees) const
{
    CCurrencyValueMap originalFees(currencies, fees);
    auto reserveIndexMap = GetReserveMap();
    feesConverted = false;
    if (IsFractional() && reserveIndexMap.count(systemID) && reserveIndexMap.find(systemID)->second)
    {
        feesConverted = true;

        CCurrencyValueMap allConvertedFees(currencies, fees);
        if (primaryCurrencyFees)
        {
            allConvertedFees.valueMap[GetID()] = primaryCurrencyFees;
        }

        liquidityFees = CCurrencyValueMap(CCurrencyValueMap(currencies, conversionFees));
        if (primaryCurrencyConversionFees)
        {
            liquidityFees.valueMap[systemID] = primaryCurrencyConversionFees;
        }

        liquidityFees = liquidityFees / 2;

        allConvertedFees -= liquidityFees;
        CAmount totalNativeFee = 0;
        if (allConvertedFees.valueMap.count(systemID))
        {
            totalNativeFee += allConvertedFees.valueMap[systemID];
        }
        int systemDestIdx = reserveIndexMap[systemID];
        for (auto &oneFee : allConvertedFees.valueMap)
        {
            // fees are not converted from the system currency, only to it
            // for that reason, skip system in the loop and calculate the amount
            // that was converted to it to determine the amount to replenish
            if (oneFee.first != systemID)
            {
                if (reserveIndexMap.count(oneFee.first))
                {
                    totalNativeFee +=
                        NativeToReserveRaw(ReserveToNativeRaw(oneFee.second, normalConversionPrice[reserveIndexMap[oneFee.first]]),
                                        outgoingConversionPrice[systemDestIdx]);
                }
                else if (oneFee.first == GetID())
                {
                    totalNativeFee +=
                        NativeToReserveRaw(oneFee.second, normalConversionPrice[systemDestIdx]);
                }
            }
        }
        convertedFees.valueMap[systemID] += totalNativeFee;
    }
    //printf("%s: liquidityfees:\n%s\n", __func__, liquidityFees.ToUniValue().write(1,2).c_str());
    //printf("%s: allConvertedFees:\n%s\n", __func__, allConvertedFees.ToUniValue().write(1,2).c_str());
    //printf("%s: convertedFees:\n%s\n", __func__, convertedFees.ToUniValue().write(1,2).c_str());
    return originalFees;
}

void CCoinbaseCurrencyState::RevertReservesAndSupply()
{
    bool processingPreconverts = !IsLaunchCompleteMarker() && !IsPrelaunch();
    if (IsFractional())
    {
        // between prelaunch and postlaunch, we only revert fees since preConversions are accounted for differently
        auto reserveMap = GetReserveMap();
        if (IsLaunchClear() && !IsPrelaunch() && reserveMap.count(ASSETCHAINS_CHAINID) && reserves[reserveMap[ASSETCHAINS_CHAINID]])
        {
            // leave all currencies in
            // revert only fees at launch pricing
            RevertFees(viaConversionPrice, viaConversionPrice, ASSETCHAINS_CHAINID);
        }
        else
        {
            // reverse last changes
            auto currencyMap = GetReserveMap();

            // revert changes in reserves and supply to pre conversion state, add reserve outs and subtract reserve ins
            for (auto &oneCur : currencyMap)
            {
                if (processingPreconverts)
                {
                    reserves[oneCur.second] += reserveOut[oneCur.second];
                }
                else
                {
                    reserves[oneCur.second] += (reserveOut[oneCur.second] - reserveIn[oneCur.second]);
                }

                if (IsLaunchCompleteMarker())
                {
                    supply += primaryCurrencyIn[oneCur.second];
                }
                else
                {
                    CCurrencyValueMap negativePreReserves(currencies, reserveIn);
                    negativePreReserves = negativePreReserves * -1;

                    if (!IsPrelaunch())
                    {
                        primaryCurrencyIn = AddVectors(primaryCurrencyIn, negativePreReserves.AsCurrencyVector(currencies));
                        for (auto &oneVal : reserveIn)
                        {
                            oneVal = 0;
                        }
                    }
                }
            }
        }
    }
    // between prelaunch and launch complete phases, we have accumulation of reserves
    else if (processingPreconverts)
    {
        CCurrencyValueMap negativePreReserves(currencies, reserveIn);
        negativePreReserves = negativePreReserves * -1;
        primaryCurrencyIn = AddVectors(primaryCurrencyIn, negativePreReserves.AsCurrencyVector(currencies));
        for (auto &oneVal : reserveIn)
        {
            oneVal = 0;
        }
    }

    // if this is the last launch clear pre-launch, it will emit and create the correct supply starting
    // from the initial supply, which was more for display. reset to initial supply as a starting point
    if (IsPrelaunch())
    {
        supply -= primaryCurrencyOut;
    }
    else
    {
        supply -= (primaryCurrencyOut - preConvertedOut);
    }
    weights = priorWeights;
}

CAmount CCurrencyState::CalculateConversionFee(CAmount inputAmount, bool convertToNative, int currencyIndex) const
{
    arith_uint256 bigAmount(inputAmount);
    arith_uint256 bigSatoshi(SATOSHIDEN);

    // we need to calculate a fee based either on the amount to convert or the last price
    // times the reserve
    if (convertToNative)
    {
        int64_t price;
        cpp_dec_float_50 priceInReserve = PriceInReserveDecFloat50(currencyIndex);
        if (!to_int64(priceInReserve, price))
        {
            assert(false);
        }
        bigAmount = price ? (bigAmount * bigSatoshi) / arith_uint256(price) : 0;
    }

    CAmount fee = 0;
    fee = ((bigAmount * arith_uint256(CReserveTransfer::SUCCESS_FEE)) / bigSatoshi).GetLow64();
    if (fee < CReserveTransfer::MIN_SUCCESS_FEE)
    {
        fee = CReserveTransfer::MIN_SUCCESS_FEE;
    }
    return fee;
}

CAmount CReserveTransactionDescriptor::CalculateConversionFeeNoMin(CAmount inputAmount)
{
    arith_uint256 bigAmount(inputAmount);
    arith_uint256 bigSatoshi(SATOSHIDEN);
    return ((bigAmount * arith_uint256(CReserveTransfer::SUCCESS_FEE)) / bigSatoshi).GetLow64();
}

CAmount CReserveTransactionDescriptor::CalculateConversionFee(CAmount inputAmount)
{
    CAmount fee = CalculateConversionFeeNoMin(inputAmount);
    if (fee < CReserveTransfer::MIN_SUCCESS_FEE)
    {
        fee = CReserveTransfer::MIN_SUCCESS_FEE;
    }
    return fee;
}

// this calculates a fee that will be added to an amount and result in the same percentage as above,
// such that a total of the inputAmount + this returned fee, if passed to CalculateConversionFee, would return
// the same amount
CAmount CReserveTransactionDescriptor::CalculateAdditionalConversionFee(CAmount inputAmount)
{
    arith_uint256 bigAmount(inputAmount);
    arith_uint256 bigSatoshi(SATOSHIDEN);
    arith_uint256 conversionFee(CReserveTransfer::SUCCESS_FEE);

    CAmount newAmount = ((bigAmount * bigSatoshi) / (bigSatoshi - conversionFee)).GetLow64();
    if (newAmount - inputAmount < CReserveTransfer::MIN_SUCCESS_FEE)
    {
        newAmount = inputAmount + CReserveTransfer::MIN_SUCCESS_FEE;
    }
    CAmount fee = CalculateConversionFee(newAmount);
    newAmount = inputAmount + fee;
    fee = CalculateConversionFee(newAmount);            // again to account for minimum fee
    fee += inputAmount - (newAmount - fee);             // add any additional difference
    return fee;
}

bool CFeePool::GetCoinbaseFeePool(CFeePool &feePool, uint32_t height)
{
    CBlock block;
    CTransaction coinbaseTx;
    feePool.SetInvalid();
    if (!height || chainActive.Height() < height)
    {
        height = chainActive.Height();
    }
    if (!height)
    {
        return true;
    }
    if (ReadBlockFromDisk(block, chainActive[height], Params().GetConsensus()))
    {
        coinbaseTx = block.vtx[0];
    }
    else
    {
        return false;
    }
    
    for (auto &txOut : coinbaseTx.vout)
    {
        COptCCParams p;
        if (txOut.scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode == EVAL_FEE_POOL && p.vData.size())
        {
            feePool = CFeePool(p.vData[0]);
        }
    }
    return true;
}

CFeePool::CFeePool(const CTransaction &coinbaseTx)
{
    nVersion = VERSION_INVALID;
    if (coinbaseTx.IsCoinBase())
    {
        for (auto &txOut : coinbaseTx.vout)
        {
            COptCCParams p;
            if (txOut.scriptPubKey.IsPayToCryptoCondition(p) && p.IsValid() && p.evalCode == EVAL_FEE_POOL && p.vData.size())
            {
                ::FromVector(p.vData[0], *this);
            }
        }
    }
}

bool ValidateFeePool(struct CCcontract_info *cp, Eval* eval, const CTransaction &tx, uint32_t nIn, bool fulfilled)
{
    // fee pool output is unspendable
    return false;
}

bool IsFeePoolInput(const CScript &scriptSig)
{
    return false;
}

bool PrecheckFeePool(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    return true;
}

bool PrecheckReserveDeposit(const CTransaction &tx, int32_t outNum, CValidationState &state, uint32_t height)
{
    // do a basic sanity check that this reserve transfer's values are consistent
    COptCCParams p;
    CReserveDeposit rd;
    return (tx.vout[outNum].scriptPubKey.IsPayToCryptoCondition(p) &&
            p.IsValid() &&
            p.evalCode == EVAL_RESERVE_DEPOSIT &&
            p.vData.size() &&
            (rd = CReserveDeposit(p.vData[0])).IsValid() &&
            rd.reserveValues.valueMap[ASSETCHAINS_CHAINID] == tx.vout[outNum].nValue);
}
