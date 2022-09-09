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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include "cJSON.c"

char hexbyte(int32_t c)
{
    c &= 0xf;
    if ( c < 10 )
        return('0'+c);
    else if ( c < 16 )
        return('a'+c-10);
    else return(0);
}

int32_t _unhex(char c)
{
    if ( c >= '0' && c <= '9' )
        return(c - '0');
    else if ( c >= 'a' && c <= 'f' )
        return(c - 'a' + 10);
    else if ( c >= 'A' && c <= 'F' )
        return(c - 'A' + 10);
    return(-1);
}

int32_t is_hexstr(char *str,int32_t n)
{
    int32_t i;
    if ( str == 0 || str[0] == 0 )
        return(0);
    for (i=0; str[i]!=0; i++)
    {
        if ( n > 0 && i >= n )
            break;
        if ( _unhex(str[i]) < 0 )
            break;
    }
    if ( n == 0 )
        return(i);
    return(i == n);
}

int32_t unhex(char c)
{
    int32_t hex;
    if ( (hex= _unhex(c)) < 0 )
    {
        //printf("unhex: illegal hexchar.(%c)\n",c);
    }
    return(hex);
}

unsigned char _decode_hex(char *hex) { return((unhex(hex[0])<<4) | unhex(hex[1])); }

int32_t decode_hex(unsigned char *bytes,int32_t n,char *hex)
{
    int32_t adjust,i = 0;
    //printf("decode.(%s)\n",hex);
    if ( is_hexstr(hex,n) <= 0 )
    {
        memset(bytes,0,n);
        return(n);
    }
    if ( hex[n-1] == '\n' || hex[n-1] == '\r' )
        hex[--n] = 0;
    if ( hex[n-1] == '\n' || hex[n-1] == '\r' )
        hex[--n] = 0;
    if ( n == 0 || (hex[n*2+1] == 0 && hex[n*2] != 0) )
    {
        if ( n > 0 )
        {
            bytes[0] = unhex(hex[0]);
            printf("decode_hex n.%d hex[0] (%c) -> %d hex.(%s) [n*2+1: %d] [n*2: %d %c] len.%ld\n",n,hex[0],bytes[0],hex,hex[n*2+1],hex[n*2],hex[n*2],(long)strlen(hex));
        }
        bytes++;
        hex++;
        adjust = 1;
    } else adjust = 0;
    if ( n > 0 )
    {
        for (i=0; i<n; i++)
            bytes[i] = _decode_hex(&hex[i*2]);
    }
    //bytes[i] = 0;
    return(n + adjust);
}

int32_t init_hexbytes_noT(char *hexbytes,unsigned char *message,long len)
{
    int32_t i;
    if ( len <= 0 )
    {
        hexbytes[0] = 0;
        return(1);
    }
    for (i=0; i<len; i++)
    {
        hexbytes[i*2] = hexbyte((message[i]>>4) & 0xf);
        hexbytes[i*2 + 1] = hexbyte(message[i] & 0xf);
        //printf("i.%d (%02x) [%c%c]\n",i,message[i],hexbytes[i*2],hexbytes[i*2+1]);
    }
    hexbytes[len*2] = 0;
    //printf("len.%ld\n",len*2+1);
    return((int32_t)len*2+1);
}

long _stripwhite(char *buf,int accept)
{
    int32_t i,j,c;
    if ( buf == 0 || buf[0] == 0 )
        return(0);
    for (i=j=0; buf[i]!=0; i++)
    {
        buf[j] = c = buf[i];
        if ( c == accept || (c != ' ' && c != '\n' && c != '\r' && c != '\t' && c != '\b') )
            j++;
    }
    buf[j] = 0;
    return(j);
}

char *clonestr(char *str)
{
    char *clone;
    if ( str == 0 || str[0] == 0 )
    {
        printf("warning cloning nullstr.%p\n",str);
        //#ifdef __APPLE__
        //        while ( 1 ) sleep(1);
        //#endif
        str = (char *)"<nullstr>";
    }
    clone = (char *)malloc(strlen(str)+16);
    strcpy(clone,str);
    return(clone);
}

int32_t safecopy(char *dest,char *src,long len)
{
    int32_t i = -1;
    if ( src != 0 && dest != 0 && src != dest )
    {
        if ( dest != 0 )
            memset(dest,0,len);
        for (i=0; i<len&&src[i]!=0; i++)
            dest[i] = src[i];
        if ( i == len )
        {
            printf("safecopy: %s too long %ld\n",src,len);
            //printf("divide by zero! %d\n",1/zeroval());
#ifdef __APPLE__
            //getchar();
#endif
            return(-1);
        }
        dest[i] = 0;
    }
    return(i);
}

char *bits256_str(char hexstr[65],bits256 x)
{
    init_hexbytes_noT(hexstr,x.bytes,sizeof(x));
    return(hexstr);
}

int64_t conv_floatstr(char *numstr)
{
    double val,corr;
    val = atof(numstr);
    corr = (val < 0.) ? -0.50000000001 : 0.50000000001;
    return((int64_t)(val * SATOSHIDEN + corr));
}

char *nonportable_path(char *str)
{
    int32_t i;
    for (i=0; str[i]!=0; i++)
        if ( str[i] == '/' )
            str[i] = '\\';
    return(str);
}

char *portable_path(char *str)
{
#ifdef _WIN32
    return(nonportable_path(str));
#else
#ifdef __PNACL
    /*int32_t i,n;
     if ( str[0] == '/' )
     return(str);
     else
     {
     n = (int32_t)strlen(str);
     for (i=n; i>0; i--)
     str[i] = str[i-1];
     str[0] = '/';
     str[n+1] = 0;
     }*/
#endif
    return(str);
#endif
}

void *loadfile(char *fname,uint8_t **bufp,long *lenp,long *allocsizep)
{
    FILE *fp;
    long  filesize,buflen = *allocsizep;
    uint8_t *buf = *bufp;
    *lenp = 0;
    if ( (fp= fopen(portable_path(fname),"rb")) != 0 )
    {
        fseek(fp,0,SEEK_END);
        filesize = ftell(fp);
        if ( filesize == 0 )
        {
            fclose(fp);
            *lenp = 0;
            printf("loadfile null size.(%s)\n",fname);
            return(0);
        }
        if ( filesize > buflen )
        {
            *allocsizep = filesize;
            *bufp = buf = (uint8_t *)realloc(buf,(long)*allocsizep+64);
        }
        rewind(fp);
        if ( buf == 0 )
            printf("Null buf ???\n");
        else
        {
            if ( fread(buf,1,(long)filesize,fp) != (unsigned long)filesize )
                printf("error reading filesize.%ld\n",(long)filesize);
            buf[filesize] = 0;
        }
        fclose(fp);
        *lenp = filesize;
        //printf("loaded.(%s)\n",buf);
    } //else printf("OS_loadfile couldnt load.(%s)\n",fname);
    return(buf);
}

void *filestr(long *allocsizep,char *_fname)
{
    long filesize = 0; char *fname,*buf = 0; void *retptr;
    *allocsizep = 0;
    fname = malloc(strlen(_fname)+1);
    strcpy(fname,_fname);
    retptr = loadfile(fname,(uint8_t **)&buf,&filesize,allocsizep);
    free(fname);
    return(retptr);
}

char *send_curl(char *url,char *fname)
{
    long fsize; char curlstr[1024];
    sprintf(curlstr,"curl --url \"%s\" > %s",url,fname);
    system(curlstr);
    return(filestr(&fsize,fname));
}

cJSON *get_urljson(char *url,char *fname)
{
    char *jsonstr; cJSON *json = 0;
    if ( (jsonstr= send_curl(url,fname)) != 0 )
    {
        //printf("(%s) -> (%s)\n",url,jsonstr);
        json = cJSON_Parse(jsonstr);
        free(jsonstr);
    }
    return(json);
}

//////////////////////////////////////////////
// start of dapp
//////////////////////////////////////////////

uint64_t get_btcusd()
{
    cJSON *pjson,*bpi,*usd; uint64_t btcusd = 0;
    if ( (pjson= get_urljson("http://api.coindesk.com/v1/bpi/currentprice.json","/tmp/oraclefeed.json")) != 0 )
    {
        if ( (bpi= jobj(pjson,"bpi")) != 0 && (usd= jobj(bpi,"USD")) != 0 )
        {
            btcusd = jdouble(usd,"rate_float") * SATOSHIDEN;
            printf("BTC/USD %.4f\n",dstr(btcusd));
        }
        free_json(pjson);
    }
    return(btcusd);
}

cJSON *get_komodocli(char **retstrp,char *acname,char *method,char *arg0,char *arg1,char *arg2)
{
    long fsize; cJSON *retjson = 0; char cmdstr[32768],*jsonstr,fname[256];
    sprintf(fname,"/tmp/oraclefeed.%s",method);
    if ( acname[0] != 0 )
        sprintf(cmdstr,"./komodo-cli -ac_name=%s %s %s %s %s > %s\n",acname,method,arg0,arg1,arg2,fname);
    else sprintf(cmdstr,"./komodo-cli %s %s %s %s > %s\n",method,arg0,arg1,arg2,fname);
    system(cmdstr);
    *retstrp = 0;
    if ( (jsonstr= filestr(&fsize,fname)) != 0 )
    {
        //fprintf(stderr,"%s -> jsonstr.(%s)\n",cmdstr,jsonstr);
        if ( (jsonstr[0] != '{' && jsonstr[0] != '[') || (retjson= cJSON_Parse(jsonstr)) == 0 )
            *retstrp = jsonstr;
        else free(jsonstr);
    }
    return(retjson);
}

bits256 komodobroadcast(char *acname,cJSON *hexjson)
{
    char *hexstr,*retstr,str[65]; cJSON *retjson; bits256 txid;
    memset(txid.bytes,0,sizeof(txid));
    if ( (hexstr= jstr(hexjson,"hex")) != 0 )
    {
        if ( (retjson= get_komodocli(&retstr,acname,"sendrawtransaction",hexstr,"","")) != 0 )
        {
            //fprintf(stderr,"broadcast.(%s)\n",jprint(retjson,0));
            free_json(retjson);
        }
        else if ( retstr != 0 )
        {
            if ( strlen(retstr) >= 64 )
            {
                retstr[64] = 0;
                decode_hex(txid.bytes,32,retstr);
            }
            fprintf(stderr,"broadcast %s txid.(%s)\n",acname,bits256_str(str,txid));
            free(retstr);
        }
    }
    return(txid);
}

bits256 sendtoaddress(char *acname,char *destaddr,int64_t satoshis)
{
    char numstr[32],*retstr,str[65]; cJSON *retjson; bits256 txid;
    memset(txid.bytes,0,sizeof(txid));
    sprintf(numstr,"%.8f",(double)satoshis/SATOSHIDEN);
    if ( (retjson= get_komodocli(&retstr,acname,"sendtoaddress",destaddr,numstr,"")) != 0 )
    {
        fprintf(stderr,"unexpected sendrawtransaction json.(%s)\n",jprint(retjson,0));
        free_json(retjson);
    }
    else if ( retstr != 0 )
    {
        if ( strlen(retstr) >= 64 )
        {
            retstr[64] = 0;
            decode_hex(txid.bytes,32,retstr);
        }
        fprintf(stderr,"sendtoaddress %s %.8f txid.(%s)\n",destaddr,(double)satoshis/SATOSHIDEN,bits256_str(str,txid));
        free(retstr);
    }
    return(txid);
}

int32_t get_KMDheight(char *acname)
{
    cJSON *retjson; char *retstr; int32_t height=0;
    if ( (retjson= get_komodocli(&retstr,acname,"getinfo","","","")) != 0 )
    {
        height = jint(retjson,"blocks");
        //fprintf(stderr,"%s height.%d\n",acname[0]!=0?acname:"KMD",height);
        free_json(retjson);
    }
    else if ( retstr != 0 )
    {
        fprintf(stderr,"get_KMDheight.(%s) error.(%s)\n",acname,retstr);
        free(retstr);
    }
    return(height);
}

bits256 get_KMDblockhash(int32_t height)
{
    cJSON *retjson; char *retstr,heightstr[32]; bits256 hash;
    memset(hash.bytes,0,sizeof(hash));
    sprintf(heightstr,"%d",height);
    if ( (retjson= get_komodocli(&retstr,"","getblockhash",heightstr,"","")) != 0 )
    {
        fprintf(stderr,"unexpected blockhash json.(%s)\n",jprint(retjson,0));
        free_json(retjson);
    }
    else if ( retstr != 0 )
    {
        //fprintf(stderr,"get_KMDblockhash.(%s) %d\n",retstr,(int32_t)strlen(retstr));
        if ( strlen(retstr) >= 64 )
        {
            retstr[64] = 0;
            decode_hex(hash.bytes,32,retstr);
        }
        free(retstr);
    }
    return(hash);
}

bits256 get_KMDmerkleroot(bits256 blockhash)
{
    cJSON *retjson; char *retstr,str[65]; bits256 merkleroot;
    memset(merkleroot.bytes,0,sizeof(merkleroot));
    if ( (retjson= get_komodocli(&retstr,"","getblockheader",bits256_str(str,blockhash),"","")) != 0 )
    {
        merkleroot = jbits256(retjson,"merkleroot");
        //fprintf(stderr,"got merkleroot.(%s)\n",bits256_str(str,merkleroot));
        free_json(retjson);
    }
    else if ( retstr != 0 )
    {
        fprintf(stderr,"get_KMDmerkleroot error.(%s)\n",retstr);
        free(retstr);
    }
    return(merkleroot);
}

int32_t get_KMDheader(bits256 *blockhashp,bits256 *merklerootp,int32_t prevheight)
{
    int32_t height = 0; char str[65];
    if ( prevheight == 0 )
        height = get_KMDheight("") - 20;
    else height = prevheight + 1;
    if ( height > 0 )
    {
        *blockhashp = get_KMDblockhash(height);
        if ( bits256_nonz(*blockhashp) != 0 )
        {
            *merklerootp = get_KMDmerkleroot(*blockhashp);
            if ( bits256_nonz(*merklerootp) != 0 )
                return(height);
        }
    }
    memset(blockhashp,0,sizeof(*blockhashp));
    memset(merklerootp,0,sizeof(*merklerootp));
    return(0);
}

cJSON *get_gatewayspending(char *acname,char *oraclestxidstr,char *coin)
{
    cJSON *retjson; char *retstr;
    if ( (retjson= get_komodocli(&retstr,acname,"gatewayspending",oraclestxidstr,coin,"")) != 0 )
    {
        //printf("pending.(%s)\n",jprint(retjson,0));
        return(retjson);
    }
    else if ( retstr != 0 )
    {
        fprintf(stderr,"get_gatewayspending.(%s) error.(%s)\n",acname,retstr);
        free(retstr);
    }
    return(0);
}

cJSON *get_rawmempool(char *acname)
{
    cJSON *retjson; char *retstr;
    if ( (retjson= get_komodocli(&retstr,acname,"getrawmempool","","","")) != 0 )
    {
        //printf("mempool.(%s)\n",jprint(retjson,0));
        return(retjson);
    }
    else if ( retstr != 0 )
    {
        fprintf(stderr,"get_rawmempool.(%s) error.(%s)\n",acname,retstr);
        free(retstr);
    }
    return(0);
}

cJSON *get_addressutxos(char *acname,char *coinaddr)
{
    cJSON *retjson; char *retstr,jsonbuf[256];
    sprintf(jsonbuf,"{\\\"addresses\\\":[\\\"%s\\\"]}",coinaddr);
    if ( (retjson= get_komodocli(&retstr,acname,"getaddressutxos",jsonbuf,"","")) != 0 )
    {
        //printf("addressutxos.(%s)\n",jprint(retjson,0));
        return(retjson);
    }
    else if ( retstr != 0 )
    {
        fprintf(stderr,"get_addressutxos.(%s) error.(%s)\n",acname,retstr);
        free(retstr);
    }
    return(0);
}

cJSON *get_rawtransaction(char *acname,bits256 txid)
{
    cJSON *retjson; char *retstr,str[65];
    if ( (retjson= get_komodocli(&retstr,acname,"getrawtransaction",bits256_str(str,txid),"1","")) != 0 )
    {
        return(retjson);
    }
    else if ( retstr != 0 )
    {
        fprintf(stderr,"get_rawtransaction.(%s) error.(%s)\n",acname,retstr);
        free(retstr);
    }
    return(0);
}

void gatewaysmarkdone(char *acname,bits256 txid)
{
    char str[65],*retstr; cJSON *retjson;
    printf("spend %s %s/v2 as marker\n",acname,bits256_str(str,txid));
    if ( (retjson= get_komodocli(&retstr,acname,"gatewaysmarkdone",bits256_str(str,txid),"","")) != 0 )
    {
        komodobroadcast(acname,retjson);
        free_json(retjson);
    }
    else if ( retstr != 0 )
    {
        printf("error parsing gatewaysmarkdone.(%s)\n",retstr);
        free(retstr);
    }
}

int32_t tx_has_voutaddress(char *acname,bits256 txid,char *coinaddr)
{
    cJSON *txobj,*vouts,*vout,*sobj,*addresses; char *addr,str[65]; int32_t i,j,n,numvouts,retval = 0;
    if ( (txobj= get_rawtransaction(acname,txid)) != 0 )
    {
        if ( (vouts= jarray(&numvouts,txobj,"vout")) != 0 )
        {
            for (i=0; i<numvouts; i++)
            {
                vout = jitem(vouts,i);
                if ( (sobj= jobj(vout,"scriptPubKey")) != 0 )
                {
                    if ( (addresses= jarray(&n,sobj,"addresses")) != 0 )
                    {
                        for (j=0; j<n; j++)
                        {
                            addr = jstri(addresses,j);
                            if ( strcmp(addr,coinaddr) == 0 )
                            {
                                //fprintf(stderr,"found %s in %s v%d\n",coinaddr,bits256_str(str,txid),i);
                                retval = 1;
                            }
                        }
                    }
                }
            }
        }
        free_json(txobj);
    }
    return(retval);
}

int32_t coinaddrexists(char *acname,char *coinaddr)
{
    cJSON *array; bits256 txid; int32_t i,n,num=0;
    if ( (array= get_addressutxos(acname,coinaddr)) != 0 )
    {
        num = cJSON_GetArraySize(array);
        free_json(array);
    } else return(-1);
    if ( num == 0 )
    {
        if ( (array= get_rawmempool(acname)) != 0 )
        {
            if ( (n= cJSON_GetArraySize(array)) != 0 )
            {
                for (i=0; i<n; i++)
                {
                    txid = jbits256i(array,i);
                    if ( tx_has_voutaddress(acname,txid,coinaddr) > 0 )
                    {
                        num = 1;
                        break;
                    }
                }
            }
            free_json(array);
        } else return(-1);
    }
    return(num);
}

void update_gatewayspending(char *acname,char *oraclestxidstr,char *coin)
{
    // check queue to prevent duplicate
    // check KMD chain and mempool for txidaddr
    // if txidaddr exists properly, spend the marker (txid.2)
    // create withdraw tx and sign it
    /// if enough sigs, sendrawtransaction and when it confirms spend marker (txid.2)
    /// if not enough sigs, post partially signed to acname with marker2
    // monitor marker2, for the partially signed withdraws
    cJSON *retjson,*pending,*item; char str[65],*coinstr,*txidaddr,*signeraddr,*withdrawaddr; int32_t i,n,retval,processed = 0; bits256 txid,withtxid,origtxid; int64_t satoshis;
    if ( (retjson= get_gatewayspending(acname,oraclestxidstr,coin)) != 0 )
    {
        if ( jint(retjson,"queueflag") != 0 && (coinstr= jstr(retjson,"coin")) != 0 && strcmp(coinstr,coin) == 0 )
        {
            if ( (pending= jarray(&n,retjson,"pending")) != 0 )
            {
                for (i=0; i<n; i++)
                {
                    if ( processed != 0 ) // avoid out of utxo conditions
                        break;
                    item = jitem(pending,i);
                    origtxid = jbits256(item,"txid");
                    //process item.0 {"txid":"10ec8f4dad6903df6b249b361b879ac77b0617caad7629b97e10f29fa7e99a9b","txidaddr":"RMbite4TGugVmkGmu76ytPHDEQZQGSUjxz","withdrawaddr":"RNJmgYaFF5DbnrNUX6pMYz9rcnDKC2tuAc","amount":"1.00000000","depositaddr":"RHV2As4rox97BuE3LK96vMeNY8VsGRTmBj","signeraddr":"RHV2As4rox97BuE3LK96vMeNY8VsGRTmBj"}
                    if ( (txidaddr= jstr(item,"txidaddr")) != 0 && (withdrawaddr= jstr(item,"withdrawaddr")) != 0 && (signeraddr= jstr(item,"signeraddr")) != 0 )
                    {
                        if ( (satoshis= jdouble(item,"amount")*SATOSHIDEN) != 0 && (retval= coinaddrexists(acname,txidaddr)) == 0 )
                        {
                            // this is less errors but more expensive: ./komodo-cli z_sendmany "signeraddr" '[{"address":"<txidaddr>","amount":0.0001},{"address":"<withdrawaddr>","amount":<withamount>}]'
                            txid = sendtoaddress(acname,txidaddr,10000);
                            if ( bits256_nonz(txid) != 0 && coinaddrexists(acname,txidaddr) > 0 )
                            {
                                // the actual withdraw
                                withtxid = sendtoaddress(strcmp("KMD",coin)==0?"":coin,withdrawaddr,satoshis);
                                if ( bits256_nonz(withtxid) != 0 )
                                {
                                    fprintf(stderr,"withdraw %s %s %s %.8f processed\n",coin,bits256_str(str,withtxid),withdrawaddr,(double)satoshis/SATOSHIDEN);
                                    gatewaysmarkdone(acname,origtxid);
                                    processed++;
                                }
                                else
                                {
                                    fprintf(stderr,"ERROR withdraw %s %s %s %.8f processed\n",coin,bits256_str(str,withtxid),withdrawaddr,(double)satoshis/SATOSHIDEN);
                                }
                            } else fprintf(stderr,"error sending %s txidaddr.%s -> %s exists.%d\n",acname,txidaddr,bits256_str(str,txid),coinaddrexists(acname,txidaddr));
                        }
                        else if ( retval > 0 )
                        {
                            fprintf(stderr,"already did withdraw %s %s %.8f processed\n",coin,withdrawaddr,(double)satoshis/SATOSHIDEN);
                            gatewaysmarkdone(acname,origtxid);
                        }
                    }
                }
            }
        }
        free_json(retjson);
    }
}

int32_t get_oracledata(int32_t prevheight,char *hexstr,int32_t maxsize,char *format)
{
    int32_t i; uint32_t height; uint64_t price; bits256 blockhash,merkleroot;
    hexstr[0] = 0;
    if ( format[0] == 'L' || format[0] == 'l' )
    {
        if ( (price= get_btcusd()) != 0 )
        {
            for (i=0; i<8; i++)
                sprintf(&hexstr[i*2],"%02x",(uint8_t)((price >> (i*8)) & 0xff));
            hexstr[16] = 0;
            return(16);
        }
    }
    else if ( strcmp(format,"Ihh") == 0 )
    {
        if ( (height= get_KMDheader(&blockhash,&merkleroot,prevheight)) > prevheight )
        {
            for (i=0; i<4; i++)
                sprintf(&hexstr[i*2],"%02x",(uint8_t)((height >> (i*8)) & 0xff));
            for (i=31; i>=0; i--)
                sprintf(&hexstr[8 + (31-i)*2],"%02x",blockhash.bytes[i]);
            for (i=31; i>=0; i--)
                sprintf(&hexstr[8 + 64 + (31-i)*2],"%02x",merkleroot.bytes[i]);
            hexstr[8 + 64*2] = 0;
            return(height);
        }
    }
    return(0);
}

/*
 oraclescreate "BTCUSD" "coindeskpricedata" "L" -> 4895f631316a649e216153aee7a574bd281686265dc4e8d37597f72353facac3
 oraclesregister 4895f631316a649e216153aee7a574bd281686265dc4e8d37597f72353facac3 1000000 -> 11c54d4ab17293217276396e27d86f714576ff55a3300dac34417047825edf93
 oraclessubscribe 4895f631316a649e216153aee7a574bd281686265dc4e8d37597f72353facac3 02ebc786cb83de8dc3922ab83c21f3f8a2f3216940c3bf9da43ce39e2a3a882c92 1.5 -> ce4e4afa53765b11a74543dacbd3174a93f33f12bb94cdc080c2c023726b5838
 oraclesdata 4895f631316a649e216153aee7a574bd281686265dc4e8d37597f72353facac3 000000ff00000000 -> e8a8c897e97389dcac31d81b617ab73a829110bd5c6f99f9f533b9c0e22700d0
 oraclessamples 4895f631316a649e216153aee7a574bd281686265dc4e8d37597f72353facac3 90ff8813a93b5b2615ec43974ff4fc91e4373dfd672d995676c43ff2dcda1010 10 ->
{
"result": "success",
"samples": [
            [
             "4278190080"
             ]
            ]
}
 
oraclescreate test testsformat s -> 17a841a919c284cea8a676f34e793da002e606f19a9258a3190bed12d5aaa3ff
oraclesregister -> 7825ad75ba854ab12868f7d2e06b4061903687fe93f41a2a99202a6b9ca3c029
oraclessubscribe 17a841a919c284cea8a676f34e793da002e606f19a9258a3190bed12d5aaa3ff 02ebc786cb83de8dc3922ab83c21f3f8a2f3216940c3bf9da43ce39e2a3a882c92 1.5 -> faf8a6676f6389abad9e7f397015d200395c9f8a24c4ded291d83e6265b2f4d1
oraclesdata 17a841a919c284cea8a676f34e793da002e606f19a9258a3190bed12d5aaa3ff 03404040 -> e8a8c897e97389dcac31d81b617ab73a829110bd5c6f99f9f533b9c0e22700d0

*/

// ./a.out AT5 1f1aefcca2bdea8196cfd77337fb21de22d200ddea977c2f9e8742c55829d808 02ebc786cb83de8dc3922ab83c21f3f8a2f3216940c3bf9da43ce39e2a3a882c92 Ihh e6c99f79d4afb216aa8063658b4222edb773dd24bb0f8e91bd4ef341f3e47e5e

int32_t main(int32_t argc,char **argv)
{
    cJSON *clijson,*clijson2,*regjson,*item; int32_t acheight,i,retval,n,height,prevheight = 0; char *format,*acname,*oraclestr,*bindtxidstr,*pkstr,*pubstr,*retstr,*retstr2,hexstr[4096]; uint64_t price; bits256 txid;
    if ( argc != 6 )
    {
        printf("usage: oraclefeed $ACNAME $ORACLETXID $MYPUBKEY $FORMAT $BINDTXID\nPowered by CoinDesk (%s) %.8f\n","https://www.coindesk.com/price/",dstr(get_btcusd()));
        return(-1);
    }
    acname = argv[1];
    oraclestr = argv[2];
    pkstr = argv[3];
    format = argv[4];
    bindtxidstr = argv[5];
    if ( strncmp(format,"Ihh",3) != 0 && format[0] != 'L' )
    {
        printf("only formats of L and Ihh are supported now\n");
        return(-1);
    }
    acheight = 0;
    while ( 1 )
    {
        retstr = 0;
        if ( prevheight < (get_KMDheight("") - 10) && (clijson= get_komodocli(&retstr,acname,"oraclesinfo",oraclestr,"","")) != 0 )
        {
            if ( (regjson= jarray(&n,clijson,"registered")) != 0 )
            {
                for (i=0; i<n; i++)
                {
                    item = jitem(regjson,i);
                    if ( (pubstr= jstr(item,"publisher")) != 0 && strcmp(pkstr,pubstr) == 0 )
                    {
                        if ( (height= get_oracledata(prevheight,hexstr,sizeof(hexstr),"Ihh")) != 0 )
                        {
                            if ( (clijson2= get_komodocli(&retstr2,acname,"oraclesdata",oraclestr,hexstr,"")) != 0 )
                            {
                                //printf("data.(%s)\n",jprint(clijson2,0));
                                txid = komodobroadcast(acname,clijson2);
                                if ( bits256_nonz(txid) != 0 )
                                {
                                    prevheight = height;
                                    acheight = get_KMDheight(acname);
                                    printf("ht.%d <- %s\n",height,hexstr);
                                    update_gatewayspending(acname,bindtxidstr,"KMD");
                                }
                                free_json(clijson2);
                            }
                            else if ( retstr2 != 0 )
                            {
                                printf("error parsing oraclesdata.(%s)\n",retstr2);
                                free(retstr2);
                            }
                        }
                        break;
                    }
                }
            }
            free_json(clijson);
        }
        if ( retstr != 0 )
        {
            printf("got json parse error.(%s)\n",retstr);
            free(retstr);
        }
        sleep(10);
        // best check is for txid to not be in mempool, ie confirmed
    }
    return(0);
}
