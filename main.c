#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include "sigv4.h"

#define SUPER_BIG        1000U
#
#define PATH             "/"
#define QUERY            "Action=ListUsers&Version=2010-05-08"
#define QUERY_LENGTH     ( sizeof( QUERY ) - 1U )
#define ACCESS_KEY_ID    "AKIAIOSFODNN7EXAMPLE"
#define DATE             "20150830T123600Z"
#define REGION           "us-east-1"
#define SERVICE          "iam"
#define HEADERS          "Host: iam.amazonaws.com\r\nContent-Type:       application/x-www-form-urlencoded;         charset=utf-8\r\nX-Amz-Date: 20150830T123600Z\r\n\r\n"
#define HEADERS_LENGTH     ( sizeof( HEADERS ) - 1U )

void sha256_string( char * string,
                    char outputBuffer[ 65 ],
                    SHA256_CTX * sha256 )
{
    unsigned char hash[ SHA256_DIGEST_LENGTH ];

    SHA256_Init( sha256 );
    SHA256_Update( sha256, string, strlen( string ) );
    SHA256_Final( hash, sha256 );
    int i = 0;

    for( i = 0; i < SHA256_DIGEST_LENGTH; i++ )
    {
        sprintf( outputBuffer + ( i * 2 ), "%02x", hash[ i ] );
    }

    outputBuffer[ 64 ] = 0;
}

static int32_t sha256_init( void * pHashContext )
{
    if( SHA256_Init( ( SHA256_CTX * ) pHashContext ) == 1 )
    {
        return 0;
    }

    return -1;
}

static int32_t sha256_update( void * pHashContext,
                           const char * pInput,
                           size_t inputLen )
{
    if( SHA256_Update( ( SHA256_CTX * ) pHashContext, pInput, inputLen ) )
    {
        return 0;
    }

    return -1;
}

static int32_t sha256_final( void * pHashContext,
                          char * pOutput,
                          size_t outputLen )
{
    if( SHA256_Final( pOutput, ( SHA256_CTX * ) pHashContext ) )
    {
        return 0;
    }

    return -1;
}

int main()
{
    SigV4Parameters_t params;
    SigV4HttpParameters_t httpParams;

    httpParams.pHttpMethod = "GET";
    httpParams.httpMethodLen = 3;
    httpParams.pPath = PATH;
    httpParams.pathLen = sizeof( PATH ) - 1U;
    httpParams.pQuery = QUERY;
    httpParams.queryLen = QUERY_LENGTH;
    httpParams.flags = 0;
    httpParams.pHeaders = HEADERS;
    httpParams.headersLen = HEADERS_LENGTH;
    httpParams.pPayload = NULL;
    httpParams.payloadLen = 0U;
    params.pHttpParameters = &httpParams;
    SigV4Credentials_t creds;
    creds.pAccessKeyId = ACCESS_KEY_ID;
    creds.accessKeyIdLen = sizeof( ACCESS_KEY_ID ) - 1U;
    creds.pSecretAccessKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    creds.secretAccessKeyLen = sizeof("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY") - 1U;
    params.pAlgorithm = NULL;
    params.pCredentials = &creds;
    params.pDateIso8601 = DATE;
    params.pRegion = REGION;
    params.regionLen = sizeof( REGION ) - 1U;
    params.pService = SERVICE;
    params.serviceLen = sizeof( SERVICE ) - 1U;
    char authBuf[ SUPER_BIG ];
    size_t authBufLen = SUPER_BIG;
    char * signature;
    size_t signatureLen;
    SigV4CryptoInterface_t cryptoInterface;
    SHA256_CTX sha256;
    cryptoInterface.pHashContext = &sha256;
    cryptoInterface.hashInit = sha256_init;
    cryptoInterface.hashUpdate = sha256_update;
    cryptoInterface.hashFinal = sha256_final;
    cryptoInterface.hashBlockLen = SIGV4_HASH_MAX_BLOCK_LENGTH;
    cryptoInterface.hashDigestLen = SIGV4_HASH_MAX_DIGEST_LENGTH;
    params.pCryptoInterface = &cryptoInterface;

    printf( "%d", SigV4_GenerateHTTPAuthorization( &params, authBuf, &authBufLen, &signature, &signatureLen ) );
    printf( "%.*s", authBufLen, authBuf);

    return 0;
}
