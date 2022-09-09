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

#include "asn/Condition.h"
#include "asn/Fulfillment.h"
#include "asn/EvalFulfillment.h"
#include "asn/OCTET_STRING.h"
#include "cryptoconditions.h"
#include "internal.h"
#include "include/cJSON.h"


struct CCType CC_EvalType;


static unsigned char *evalFingerprint(const CC *cond) {
    unsigned char *hash = calloc(1, 32);
    //fprintf(stderr,"evalfingerprint %p %p\n",hash,cond->code);
    sha256(cond->code, cond->codeLength, hash);
    return hash;
}


static unsigned long evalCost(const CC *cond) {
    return 1048576;  // Pretty high
}


static CC *evalFromJSON(const cJSON *params, char *err) {
    size_t codeLength;
    unsigned char *code = 0;

    if (!jsonGetBase64(params, "code", err, &code, &codeLength)) {
        return NULL;
    }

    CC *cond = cc_new(CC_Eval);
    cond->code = code;
    cond->codeLength = codeLength;
    return cond;
}


static void evalToJSON(const CC *cond, cJSON *code) {

    // add code
    unsigned char *b64 = base64_encode(cond->code, cond->codeLength);
    cJSON_AddItemToObject(code, "code", cJSON_CreateString(b64));
    free(b64);
}


static CC *evalFromFulfillment(const Fulfillment_t *ffill) {
    CC *cond = cc_new(CC_Eval);

    EvalFulfillment_t *eval = &ffill->choice.evalSha256;

    OCTET_STRING_t octets = eval->code;
    cond->codeLength = octets.size;
    cond->code = calloc(1,octets.size);
    memcpy(cond->code, octets.buf, octets.size);

    return cond;
}


static Fulfillment_t *evalToFulfillment(const CC *cond) {
    Fulfillment_t *ffill = calloc(1, sizeof(Fulfillment_t));
    ffill->present = Fulfillment_PR_evalSha256;
    EvalFulfillment_t *eval = &ffill->choice.evalSha256;
    OCTET_STRING_fromBuf(&eval->code, cond->code, cond->codeLength);
    return ffill;
}


int evalIsFulfilled(const CC *cond) {
    return 1;
}


static void evalFree(CC *cond) {
    free(cond->code);
}


static uint32_t evalSubtypes(const CC *cond) {
    return 0;
}


/*
 * The JSON api doesn't contain custom verifiers, so a stub method is provided suitable for testing
 */
int jsonVerifyEval(CC *cond, void *context, int fulfilled) {
    if (cond->codeLength == 5 && 0 == memcmp(cond->code, "TEST", 4)) {
        return cond->code[5];
    }
    fprintf(stderr, "Cannot verify eval; user function unknown\n");
    return 0;
}


typedef struct CCEvalVerifyData {
    VerifyEval verify;
    void *context;
} CCEvalVerifyData;


void cc_setEvalVisitorFulfilled(CCVisitor *visitor, int fulfilled)
{
    const uint8_t *fulfilledStr = "1";
    const uint8_t *notFulfilledStr = "0";
    if (visitor->msgLength == 0)
    {
        visitor->msgLength = 1;
    }
    visitor->msg = fulfilled ? fulfilledStr : notFulfilledStr;
}

int cc_isEvalVisitorFulfilled(CCVisitor *visitor)
{
    return (visitor->msgLength == 1 && visitor->msg[0] == '1');
}

int evalVisit(CC *cond, CCVisitor visitor) {
    if (cond->type->typeId != CC_Eval) return 1;
    CCEvalVerifyData *evalData = visitor.context;
    return evalData->verify(cond, evalData->context, cc_isEvalVisitorFulfilled(&visitor));
}

int evalCountVisits(CC *cond, CCVisitor visitor) {
    if (cond->type->typeId != CC_Eval) return 1;
    *((int *)(visitor.context)) += 1;
    return 1;
}

int cc_countEvals(const CC *cond) {
    int evalCount = 0;
    // assume fulfilled if not modified
    CCVisitor visitor = {&evalCountVisits, "", 0, &evalCount};
    cc_visit(cond, visitor);
    return evalCount;
}

int cc_isEvalVisitor(CCVisitor *visitor)
{
    if (visitor->visit == &evalVisit)
        return 1;
    else
        return 0;
}

int cc_verifyEval(const CC *cond, VerifyEval verify, void *context) {
    CCEvalVerifyData evalData = {verify, context};
    // assume fulfilled if not modified
    CCVisitor visitor = {&evalVisit, "1", 1, &evalData};
    return cc_visit(cond, visitor);
}

struct CCType CC_EvalType = { 15, "eval-sha-256", Condition_PR_evalSha256, 0, &evalFingerprint, &evalCost, &evalSubtypes, &evalFromJSON, &evalToJSON, &evalFromFulfillment, &evalToFulfillment, &evalFromFulfillment, &evalToFulfillment, &evalIsFulfilled, &evalFree };
