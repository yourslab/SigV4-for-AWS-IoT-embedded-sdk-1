/*
 * SigV4 Utility Library v1.0.0
 * Copyright (C) 2021 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * @file sigv4.c
 * @brief Implements the user-facing functions in sigv4.h
 */

#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "sigv4.h"
#include "sigv4_internal.h"

/*-----------------------------------------------------------*/

#if ( SIGV4_USE_CANONICAL_SUPPORT == 1 )

/**
 * @brief Interpret string parameters into standardized SigV4String_t structs to
 * assist in sorting and canonicalization.
 *
 * @param[in, out] pSigV4Value The SigV4 standardized struct to populate.
 * @param[in] pInput String containing sorting parameters.
 * @param[in] lenInput Length of string @pInput.
 */
    static void stringToSigV4Value( SigV4String_t * pSigV4Value,
                                    const char * pInput,
                                    size_t lenInput );

/**
 * @brief Verifies if a SigV4 string value is empty.
 *
 * @param[in] pInput The SigV4 string value struct to verify.
 *
 * @return Returns 'true' if @pInput is empty, and 'false' otherwise.
 */
    static bool emptySigV4String( SigV4String_t * pInput );

/**
 * @brief Normalize a URI string according to RFC 3986 and fill destination
 * buffer with the formatted string.
 *
 * @param[in] pUri The URI string to encode.
 * @param[in] uriLen Length of pUri.
 * @param[out] pCanonicalURI The resulting canonicalized URI.
 * @param[in, out] canonicalURILen input: the length of pCanonicalURI,
 * output: the length of the generated canonical URI.
 * @param[in] encodeSlash Option to indicate if slashes should be encoded.
 * @param[in] doubleEncodeEquals Option to indicate if equals should be double-encoded.
 */
    static SigV4Status_t encodeURI( const char * pUri,
                                    size_t uriLen,
                                    char * pCanonicalURI,
                                    size_t * canonicalURILen,
                                    bool encodeSlash,
                                    bool doubleEncodeEquals );

/**
 * @brief Canonicalize the full URI path. The input URI starts after the
 * HTTP host and ends at the question mark character ("?") that begins the
 * query string parameters (if any). Example: folder/subfolder/item.txt"
 *
 * @param[in] pUri HTTP request URI, also known that the request absolute
 * path.
 * @param[in] uriLen Length of pUri.
 * @param[in] encodeTwice Service-dependent option to indicate whether
 * encoding should be done twice. For example, S3 requires that the
 * URI is encoded only once, while other services encode twice.
 * @param[in, out] canonicalRequest Struct to maintain intermediary buffer
 * and state of canonicalization.
 */
    static SigV4Status_t generateCanonicalURI( const char * pUri,
                                               size_t uriLen,
                                               bool encodeTwice,
                                               CanonicalContext_t * canonicalRequest );

/**
 * @brief Canonicalize the query string HTTP URL, beginning (but not
 * including) at the "?" character. Does not include "/".
 *
 * @param[in] pQuery HTTP request query.
 * @param[in] queryLen Length of pQuery.
 * @param[in, out] canonicalRequest Struct to maintain intermediary buffer
 * and state of canonicalization.
 */
    static SigV4Status_t generateCanonicalQuery( const char * pQuery,
                                                 size_t queryLen,
                                                 CanonicalContext_t * canonicalRequest );

    static SigV4Status_t generateCanonicalRequest( CanonicalContext_t * canonicalRequest );

/**
 * @brief Compare two SigV4 data structures lexicographically, without case-sensitivity.
 *
 * @param[in] pFirstVal SigV4 key value data structure to sort.
 * @param[in] pSecondVal SigV4 key value data structure to sort.
 *
 * @return Returns a value less than 0 if @pFirstVal < @pSecondVal, or
 * a value greater than 0 if @pSecondVal < @pFirstVal. 0 is never returned in
 * order to provide stability to qSort() calls.
 */
    static int cmpKey( const void * pFirstVal,
                       const void * pSecondVal );

#endif /* #if (SIGV4_USE_CANONICAL_SUPPORT == 1) */

/**
 * @brief Converts an integer value to its ASCII representation, and stores the
 * result in the provided buffer.
 *
 * @param[in] value The value to convert to ASCII.
 * @param[in, out] pBuffer The starting location of the buffer on input, and the
 * ending location on output.
 * @param[in] bufferLen Width of value to write (padded with leading 0s if
 * necessary).
 */
static void intToAscii( int32_t value,
                        char ** pBuffer,
                        size_t bufferLen );

/**
 * @brief Format the credential scope of the authorization header using the access key ID,
 * date, region, and service parameters found in #SigV4Parameters_t and ends with the
 * "aws4_request" terminator.
 *
 * @param[in] pSigV4Params The application parameters defining the credential's scope.
 * @param[in, out] pCredScope The credential scope in the V4 required format.
 *
 * @return SigV4InsufficientMemory if the length of `pCredScope` was insufficient to
 * fit the actual credential scope, SigV4Success otherwise.
 */
static SigV4Status_t generateCredentialScope( const SigV4Parameters_t * pSigV4Params,
                                              SigV4String_t * pCredScope );

/**
 * @brief Check if the date represents a valid leap year day.
 *
 * @param[in] pDateElements The date representation to be verified.
 *
 * @return #SigV4Success if the date corresponds to a valid leap year,
 * #SigV4ISOFormattingError otherwise.
 */
static SigV4Status_t checkLeap( const SigV4DateTime_t * pDateElements );

/**
 * @brief Verify the date stored in a SigV4DateTime_t date representation.
 *
 * @param[in] pDateElements The date representation to be verified.
 *
 * @return #SigV4Success if the date is valid, and #SigV4ISOFormattingError if
 * any member of SigV4DateTime_t is invalid or represents an out-of-range date.
 */
static SigV4Status_t validateDateTime( const SigV4DateTime_t * pDateElements );

/**
 * @brief Append the value of a date element to the internal date representation
 * structure.
 *
 * @param[in] formatChar The specifier identifying the struct member to fill.
 * @param[in] result The value to assign to the specified struct member.
 * @param[out] pDateElements The date representation structure to modify.
 */
static void addToDate( const char formatChar,
                       int32_t result,
                       SigV4DateTime_t * pDateElements );

/**
 * @brief Interpret the value of the specified characters in date, based on the
 * format specifier, and append to the internal date representation.
 *
 * @param[in] pDate The date to be parsed.
 * @param[in] formatChar The format specifier used to interpret characters.
 * @param[in] readLoc The index of pDate to read from.
 * @param[in] lenToRead The number of characters to read.
 * @param[out] pDateElements The date representation to modify.
 *
 * @return #SigV4Success if parsing succeeded, #SigV4ISOFormattingError if the
 * characters read did not match the format specifier.
 */
static SigV4Status_t scanValue( const char * pDate,
                                const char formatChar,
                                size_t readLoc,
                                size_t lenToRead,
                                SigV4DateTime_t * pDateElements );

/**
 * @brief Parses date according to format string parameter, and populates date
 * representation struct SigV4DateTime_t with its elements.
 *
 * @param[in] pDate The date to be parsed.
 * @param[in] dateLen Length of pDate, the date to be formatted.
 * @param[in] pFormat The format string used to extract date pDateElements from
 * pDate. This string, among other characters, may contain specifiers of the
 * form "%LV", where L is the number of characters to be read, and V is one of
 * {Y, M, D, h, m, s, *}, representing a year, month, day, hour, minute, second,
 * or skipped (un-parsed) value, respectively.
 * @param[in] formatLen Length of the format string pFormat.
 * @param[out] pDateElements The deconstructed date representation of pDate.
 *
 * @return #SigV4Success if all format specifiers were matched successfully,
 * #SigV4ISOFormattingError otherwise.
 */
static SigV4Status_t parseDate( const char * pDate,
                                size_t dateLen,
                                const char * pFormat,
                                size_t formatLen,
                                SigV4DateTime_t * pDateElements );

/**
 * @brief Verify @p pParams and its sub-members.
 *
 * @param[in] pParams Complete SigV4 configurations passed by application.
 *
 * @return #SigV4Success if successful, #SigV4InvalidParameter otherwise.
 */
static SigV4Status_t verifySigV4Parameters( const SigV4Parameters_t * pParams );

/**
 * @brief Hex digest of provided string parameter.
 *
 * @param[in] pInputStr String to encode.
 * @param[out] pHexOutput Hex representation of @p pInputStr.
 */
static SigV4Status_t lowercaseHexEncode( const SigV4String_t * pInputStr,
                                         SigV4String_t * pHexOutput );

/*-----------------------------------------------------------*/

static void intToAscii( int32_t value,
                        char ** pBuffer,
                        size_t bufferLen )
{
    int32_t currentVal = value;
    size_t lenRemaining = bufferLen;

    assert( pBuffer != NULL );
    assert( bufferLen > 0U );

    /* Write base-10 remainder in its ASCII representation, and fill any
     * remaining width with '0' characters. */
    while( lenRemaining > 0U )
    {
        lenRemaining--;
        ( *pBuffer )[ lenRemaining ] = ( char ) ( ( currentVal % 10 ) + '0' );
        currentVal /= 10;
    }

    /* Move pointer to follow last written character. */
    *pBuffer += bufferLen;
}

/*-----------------------------------------------------------*/

static SigV4Status_t checkLeap( const SigV4DateTime_t * pDateElements )
{
    SigV4Status_t returnStatus = SigV4ISOFormattingError;

    assert( pDateElements != NULL );

    /* If the date represents a leap day, verify that the leap year is valid. */
    if( ( pDateElements->tm_mon == 2 ) && ( pDateElements->tm_mday == 29 ) )
    {
        if( ( ( pDateElements->tm_year % 400 ) != 0 ) &&
            ( ( ( pDateElements->tm_year % 4 ) != 0 ) ||
              ( ( pDateElements->tm_year % 100 ) == 0 ) ) )
        {
            LogError( ( "%ld is not a valid leap year.",
                        ( long int ) pDateElements->tm_year ) );
        }
        else
        {
            returnStatus = SigV4Success;
        }
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static SigV4Status_t validateDateTime( const SigV4DateTime_t * pDateElements )
{
    SigV4Status_t returnStatus = SigV4Success;
    const int32_t daysPerMonth[] = MONTH_DAYS;

    assert( pDateElements != NULL );

    if( pDateElements->tm_year < YEAR_MIN )
    {
        LogError( ( "Invalid 'year' value parsed from date string. "
                    "Expected an integer %ld or greater, received: %ld",
                    ( long int ) YEAR_MIN,
                    ( long int ) pDateElements->tm_year ) );
        returnStatus = SigV4ISOFormattingError;
    }

    if( ( pDateElements->tm_mon < 1 ) || ( pDateElements->tm_mon > 12 ) )
    {
        LogError( ( "Invalid 'month' value parsed from date string. "
                    "Expected an integer between 1 and 12, received: %ld",
                    ( long int ) pDateElements->tm_mon ) );
        returnStatus = SigV4ISOFormattingError;
    }

    /* Ensure that the day of the month is valid for the relevant month. */
    if( ( returnStatus != SigV4ISOFormattingError ) &&
        ( ( pDateElements->tm_mday < 1 ) ||
          ( pDateElements->tm_mday > daysPerMonth[ pDateElements->tm_mon - 1 ] ) ) )
    {
        /* Check if the date is a valid leap year day. */
        returnStatus = checkLeap( pDateElements );

        if( returnStatus == SigV4ISOFormattingError )
        {
            LogError( ( "Invalid 'day' value parsed from date string. "
                        "Expected an integer between 1 and %ld, received: %ld",
                        ( long int ) daysPerMonth[ pDateElements->tm_mon - 1 ],
                        ( long int ) pDateElements->tm_mday ) );
        }
    }

    /* SigV4DateTime_t values are asserted to be non-negative before they are
     * assigned in function addToDate(). Therefore, we only verify logical upper
     * bounds for the following values. */
    if( pDateElements->tm_hour > 23 )
    {
        LogError( ( "Invalid 'hour' value parsed from date string. "
                    "Expected an integer between 0 and 23, received: %ld",
                    ( long int ) pDateElements->tm_hour ) );
        returnStatus = SigV4ISOFormattingError;
    }

    if( pDateElements->tm_min > 59 )
    {
        LogError( ( "Invalid 'minute' value parsed from date string. "
                    "Expected an integer between 0 and 59, received: %ld",
                    ( long int ) pDateElements->tm_min ) );
        returnStatus = SigV4ISOFormattingError;
    }

    /* An upper limit of 60 accounts for the occasional leap second UTC
     * adjustment. */
    if( pDateElements->tm_sec > 60 )
    {
        LogError( ( "Invalid 'second' value parsed from date string. "
                    "Expected an integer between 0 and 60, received: %ld",
                    ( long int ) pDateElements->tm_sec ) );
        returnStatus = SigV4ISOFormattingError;
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static void addToDate( const char formatChar,
                       int32_t result,
                       SigV4DateTime_t * pDateElements )
{
    assert( pDateElements != NULL );
    assert( result >= 0 );

    switch( formatChar )
    {
        case 'Y':
            pDateElements->tm_year = result;
            break;

        case 'M':
            pDateElements->tm_mon = result;
            break;

        case 'D':
            pDateElements->tm_mday = result;
            break;

        case 'h':
            pDateElements->tm_hour = result;
            break;

        case 'm':
            pDateElements->tm_min = result;
            break;

        case 's':
            pDateElements->tm_sec = result;
            break;

        default:

            /* Do not assign values for skipped characters ('*'), or
             * unrecognized format specifiers. */
            break;
    }
}

/*-----------------------------------------------------------*/

static SigV4Status_t scanValue( const char * pDate,
                                const char formatChar,
                                size_t readLoc,
                                size_t lenToRead,
                                SigV4DateTime_t * pDateElements )
{
    SigV4Status_t returnStatus = SigV4InvalidParameter;
    const char * pMonthNames[] = MONTH_NAMES;
    const char * pLoc = pDate + readLoc;
    size_t remainingLenToRead = lenToRead;
    int32_t result = 0;

    assert( pDate != NULL );
    assert( pDateElements != NULL );

    if( formatChar == '*' )
    {
        remainingLenToRead = 0U;
    }

    /* Determine if month value is non-numeric. */
    if( ( formatChar == 'M' ) && ( remainingLenToRead == MONTH_ASCII_LEN ) )
    {
        while( result++ < 12 )
        {
            /* Search month array for parsed string. */
            if( strncmp( pMonthNames[ result - 1 ], pLoc, MONTH_ASCII_LEN ) == 0 )
            {
                returnStatus = SigV4Success;
                break;
            }
        }

        if( returnStatus != SigV4Success )
        {
            LogError( ( "Unable to match string '%.3s' to a month value.",
                        pLoc ) );
            returnStatus = SigV4ISOFormattingError;
        }

        remainingLenToRead = 0U;
    }

    /* Interpret integer value of numeric representation. */
    while( ( remainingLenToRead > 0U ) && ( *pLoc >= '0' ) && ( *pLoc <= '9' ) )
    {
        result = ( result * 10 ) + ( int32_t ) ( *pLoc - '0' );
        remainingLenToRead--;
        pLoc += 1;
    }

    if( remainingLenToRead != 0U )
    {
        LogError( ( "Parsing Error: Expected numerical string of type '%%%d%c', "
                    "but received '%.*s'.",
                    ( int ) lenToRead,
                    formatChar,
                    ( int ) lenToRead,
                    pLoc ) );
        returnStatus = SigV4ISOFormattingError;
    }

    if( returnStatus != SigV4ISOFormattingError )
    {
        addToDate( formatChar,
                   result,
                   pDateElements );
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static SigV4Status_t parseDate( const char * pDate,
                                size_t dateLen,
                                const char * pFormat,
                                size_t formatLen,
                                SigV4DateTime_t * pDateElements )
{
    SigV4Status_t returnStatus = SigV4InvalidParameter;
    size_t readLoc = 0U, lenToRead = 0U, formatIndex = 0U;

    assert( pDate != NULL );
    assert( pFormat != NULL );
    assert( pDateElements != NULL );
    ( void ) dateLen;

    /* Loop through the format string. */
    while( ( formatIndex < formatLen ) && ( returnStatus != SigV4ISOFormattingError ) )
    {
        if( pFormat[ formatIndex ] == '%' )
        {
            /* '%' must be followed by a length and type specification. */
            assert( formatIndex < formatLen - 2 );
            formatIndex++;

            /* Numerical value of length specifier character. */
            lenToRead = ( ( uint32_t ) pFormat[ formatIndex ] - ( uint32_t ) '0' );
            formatIndex++;

            /* Ensure read is within buffer bounds. */
            assert( readLoc + lenToRead - 1 < dateLen );
            returnStatus = scanValue( pDate,
                                      pFormat[ formatIndex ],
                                      readLoc,
                                      lenToRead,
                                      pDateElements );

            readLoc += lenToRead;
        }
        else if( pDate[ readLoc ] != pFormat[ formatIndex ] )
        {
            LogError( ( "Parsing error: Expected character '%c', "
                        "but received '%c'.",
                        pFormat[ formatIndex ], pDate[ readLoc ] ) );
            returnStatus = SigV4ISOFormattingError;
        }
        else
        {
            readLoc++;
            LogDebug( ( "Successfully matched character '%c' found in format string.",
                        pDate[ readLoc - 1 ] ) );
        }

        formatIndex++;
    }

    if( ( returnStatus != SigV4ISOFormattingError ) )
    {
        returnStatus = SigV4Success;
    }
    else
    {
        LogError( ( "Parsing Error: Date did not match expected string format." ) );
        returnStatus = SigV4ISOFormattingError;
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

/* Hex digest of provided parameter string. */
static SigV4Status_t lowercaseHexEncode( const SigV4String_t * pInputStr,
                                         SigV4String_t * pHexOutput )
{
    SigV4Status_t returnStatus = SigV4Success;
    static const char digitArr[] = "0123456789abcdef";
    char * hex = NULL;
    size_t i = 0U;

    assert( pInputStr != NULL );
    assert( pHexOutput != NULL );
    assert( pInputStr->pData != NULL );
    assert( pHexOutput->pData != NULL );

    hex = pHexOutput->pData;

    if( pHexOutput->dataLen < pInputStr->dataLen * 2 )
    {
        returnStatus = SigV4InsufficientMemory;
    }

    if( returnStatus == SigV4Success )
    {
        for( i = 0; i < pInputStr->dataLen; i++ )
        {
            *hex = digitArr[ ( pInputStr->pData[ i ] & 0xF0 ) >> 4 ];
            hex++;
            *hex = digitArr[ ( pInputStr->pData[ i ] & 0x0F ) ];
            hex++;
        }

        pHexOutput->dataLen = pInputStr->dataLen * 2;
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static size_t sizeNeededForCredentialScope( const SigV4Parameters_t * pSigV4Params )
{
    return ISO_DATE_SCOPE_LEN +                                               \
           CREDENTIAL_SCOPE_SEPARATOR_LEN + pSigV4Params->regionLen +         \
           CREDENTIAL_SCOPE_SEPARATOR_LEN + pSigV4Params->serviceLen +        \
           CREDENTIAL_SCOPE_SEPARATOR_LEN + CREDENTIAL_SCOPE_TERMINATOR_LEN + \
           LINEFEED_CHAR_LEN;
}

static SigV4Status_t generateCredentialScope( const SigV4Parameters_t * pSigV4Params,
                                              SigV4String_t * pCredScope )
{
    SigV4Status_t returnStatus = SigV4Success;
    char * pBufWrite = NULL;
    size_t sizeNeeded = 0U;

    assert( pSigV4Params != NULL );
    assert( pSigV4Params->pCredentials != NULL );
    assert( pSigV4Params->pRegion != NULL );
    assert( pSigV4Params->pService != NULL );
    assert( pCredScope != NULL );
    assert( pCredScope->pData != NULL );

    sizeNeeded = sizeNeededForCredentialScope( pSigV4Params );

    pBufWrite = pCredScope->pData;

    if( pCredScope->dataLen < sizeNeeded )
    {
        returnStatus = SigV4InsufficientMemory;
        LogError( ( "Insufficient memory provided to write the credential scope, bytesExceeded=%zu",
                    sizeNeeded - pCredScope->dataLen ) );
    }

    /* Each concatenated component is separated by a '/' character. */
    if( returnStatus == SigV4Success )
    {
        /* Concatenate first 8 characters from the provided ISO 8601 string (YYYYMMDD). */
        ( void ) memcpy( pBufWrite, pSigV4Params->pDateIso8601, ISO_DATE_SCOPE_LEN );
        pBufWrite += ISO_DATE_SCOPE_LEN;

        *pBufWrite = CREDENTIAL_SCOPE_SEPARATOR;
        pBufWrite += CREDENTIAL_SCOPE_SEPARATOR_LEN;

        /* Concatenate AWS region. */
        ( void ) memcpy( pBufWrite, pSigV4Params->pRegion, pSigV4Params->regionLen );
        pBufWrite += pSigV4Params->regionLen;

        *pBufWrite = CREDENTIAL_SCOPE_SEPARATOR;
        pBufWrite += CREDENTIAL_SCOPE_SEPARATOR_LEN;

        /* Concatenate AWS service. */
        ( void ) memcpy( pBufWrite, pSigV4Params->pService, pSigV4Params->serviceLen );
        pBufWrite += pSigV4Params->serviceLen;

        *pBufWrite = CREDENTIAL_SCOPE_SEPARATOR;
        pBufWrite += CREDENTIAL_SCOPE_SEPARATOR_LEN;

        /* Concatenate terminator. */
        ( void ) memcpy( pBufWrite, CREDENTIAL_SCOPE_TERMINATOR, CREDENTIAL_SCOPE_TERMINATOR_LEN );
        pBufWrite += CREDENTIAL_SCOPE_TERMINATOR_LEN;

        /* Concatenate linefeed character. */
        *pBufWrite = LINEFEED_CHAR;
        pBufWrite += LINEFEED_CHAR_LEN;

        pCredScope->dataLen = sizeNeeded;
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

#if ( SIGV4_USE_CANONICAL_SUPPORT == 1 )

    static void stringToSigV4Value( SigV4String_t * pSigV4Value,
                                    const char * pInput,
                                    size_t lenInput )
    {
        assert( pSigV4Value != NULL );
        assert( pInput != NULL );
        assert( lenInput > 0U );

        pSigV4Value->pData = ( char * ) pInput;
        pSigV4Value->dataLen = ( size_t ) lenInput;
    }

/*-----------------------------------------------------------*/

    static bool emptySigV4String( SigV4String_t * pInput )
    {
        bool returnVal = true;

        assert( pInput != NULL );

        return ( pInput->pData == NULL || pInput->dataLen == 0 ) ? returnVal : !returnVal;
    }

/*-----------------------------------------------------------*/

    static int cmpKeyValue( const void * pFirstVal,
                            const void * pSecondVal )
    {
        SigV4KeyValuePair_t * pFirst, * pSecond = NULL;
        size_t lenSmall = 0U;

        assert( pFirstVal != NULL );
        assert( pSecondVal != NULL );

        pFirst = ( SigV4KeyValuePair_t * ) pFirstVal;
        pSecond = ( SigV4KeyValuePair_t * ) pSecondVal;

        assert( !emptySigV4String( &pFirst->key ) );
        assert( !emptySigV4String( &pSecond->key ) );

        if( pFirst->key.dataLen <= pSecond->key.dataLen )
        {
            lenSmall = pFirst->key.dataLen;
        }
        else
        {
            lenSmall = pSecond->key.dataLen;
        }

        return strncmp( ( char * ) pFirst->key.pData,
                        ( char * ) pSecond->key.pData,
                        lenSmall );
    }

/*-----------------------------------------------------------*/

    static int cmpQueryFieldValue( const void * pFirstVal,
                                   const void * pSecondVal )
    {
        SigV4KeyValuePair_t * pFirst, * pSecond = NULL;
        size_t lenSmall = 0U;
        int32_t compResult = -1;

        assert( pFirstVal != NULL );
        assert( pSecondVal != NULL );

        pFirst = ( SigV4KeyValuePair_t * ) pFirstVal;
        pSecond = ( SigV4KeyValuePair_t * ) pSecondVal;

        assert( !emptySigV4String( &pFirst->key ) );
        assert( !emptySigV4String( &pSecond->key ) );

        lenSmall = ( pFirst->key.dataLen < pSecond->key.dataLen ) ? pFirst->key.dataLen : pSecond->key.dataLen;
        compResult = ( int32_t ) strncmp( ( char * ) pFirst->key.pData,
                                          ( char * ) pSecond->key.pData,
                                          lenSmall );

        if( compResult == 0 )
        {
            if( pFirst->key.dataLen == pSecond->key.dataLen )
            {
                /* The fields are equal, so sorting must be done by value. */
                lenSmall = ( pFirst->value.dataLen < pSecond->value.dataLen ) ? pFirst->value.dataLen : pSecond->value.dataLen;
                compResult = ( int32_t ) strncmp( ( char * ) pFirst->value.pData,
                                                  ( char * ) pSecond->value.pData,
                                                  lenSmall );
            }
            else
            {
                /* Fields share a common prefix, so the shorter one should come first. */
                compResult = ( pFirst->key.dataLen < pSecond->key.dataLen ) ? -1 : 1;
            }
        }

        if( ( compResult == 0 ) && ( pFirst->value.dataLen != pSecond->value.dataLen ) )
        {
            /* Values share a common prefix, so the shorter one should come first. */
            compResult = ( pFirst->value.dataLen < pSecond->value.dataLen ) ? -1 : 1;
        }

        return compResult;
    }

/*-----------------------------------------------------------*/

    static char toUpperHexChar( const char value )
    {
        char hexChar;

        assert( value < 16 );

        if( value < 10 )
        {
            hexChar = '0' + value;
        }
        else
        {
            hexChar = ( 'A' + value ) - 10;
        }

        return hexChar;
    }

    static SigV4Status_t encodeURI( const char * pUri,
                                    size_t uriLen,
                                    char * pCanonicalURI,
                                    size_t * canonicalURILen,
                                    bool encodeSlash,
                                    bool doubleEncodeEquals )
    {
        const char * pUriLoc = NULL;
        char * pBufLoc = NULL;
        size_t i = 0U, bytesConsumed = 0U;
        SigV4Status_t returnStatus = SigV4Success;

        assert( pUri != NULL );
        assert( pCanonicalURI != NULL );
        assert( canonicalURILen != NULL );
        assert( *canonicalURILen > 0U );

        pUriLoc = pUri;
        pBufLoc = pCanonicalURI;

        while( i++ < uriLen && *pUriLoc )
        {
            if( returnStatus != SigV4Success )
            {
                break;
            }
            else if( doubleEncodeEquals && ( *pUriLoc == '=' ) )
            {
                if( ( bytesConsumed > SIZE_MAX - 5U ) || ( bytesConsumed + 5U > *canonicalURILen ) )
                {
                    returnStatus = SigV4InsufficientMemory;
                }
                else
                {
                    *pBufLoc = '%';
                    ++pBufLoc;
                    *pBufLoc = '2';
                    ++pBufLoc;
                    *pBufLoc = '5';
                    ++pBufLoc;
                    *pBufLoc = '3';
                    ++pBufLoc;
                    *pBufLoc = 'D';
                    ++pBufLoc;

                    bytesConsumed += 5;
                }
            }
            else if( isalnum( *pUriLoc ) || ( *pUriLoc == '-' ) || ( *pUriLoc == '_' ) || ( *pUriLoc == '.' ) || ( *pUriLoc == '~' ) ||
                     ( ( *pUriLoc == '/' ) && !encodeSlash ) )
            {
                *pBufLoc = *pUriLoc;
                ++pBufLoc;
                ++bytesConsumed;
            }
            else
            {
                if( ( bytesConsumed > SIZE_MAX - 3U ) || ( bytesConsumed + 3U > *canonicalURILen ) )
                {
                    returnStatus = SigV4InsufficientMemory;
                }
                else
                {
                    *pBufLoc = '%';
                    ++pBufLoc;
                    *pBufLoc = toUpperHexChar( *pUriLoc >> 4 );
                    ++pBufLoc;
                    *pBufLoc = toUpperHexChar( *pUriLoc & 0x0F );
                    ++pBufLoc;

                    bytesConsumed += 3;
                }
            }

            if( bytesConsumed > *canonicalURILen )
            {
                returnStatus = SigV4InsufficientMemory;
            }

            pUriLoc++;
        }

        *canonicalURILen = bytesConsumed;

        return returnStatus;
    }

/*-----------------------------------------------------------*/

    static SigV4Status_t generateCanonicalURI( const char * pUri,
                                               size_t uriLen,
                                               bool encodeTwice,
                                               CanonicalContext_t * pCanonicalRequest )
    {
        SigV4Status_t returnStatus = SigV4Success;
        char * pBufLoc = NULL;
        size_t encodedLen = 0U;

        assert( pUri != NULL );
        assert( pCanonicalRequest != NULL );
        assert( pCanonicalRequest->pBufCur != NULL );

        pBufLoc = pCanonicalRequest->pBufCur;
        encodedLen = pCanonicalRequest->bufRemaining;
        returnStatus = encodeURI( pUri, uriLen, pBufLoc, &encodedLen, false, false );

        if( returnStatus == SigV4Success )
        {
            if( encodeTwice )
            {
                size_t doubleEncodedLen = pCanonicalRequest->bufRemaining - encodedLen;

                /* Note that encoding is not done in place. */
                returnStatus = encodeURI( pBufLoc,
                                          encodedLen,
                                          pBufLoc + encodedLen,
                                          &doubleEncodedLen,
                                          false,
                                          false );

                if( returnStatus == SigV4Success )
                {
                    ( void ) memcpy( pBufLoc, pBufLoc + encodedLen, doubleEncodedLen );
                    pBufLoc += doubleEncodedLen;
                    pCanonicalRequest->bufRemaining -= doubleEncodedLen;
                }
            }
            else
            {
                pBufLoc += encodedLen;
                pCanonicalRequest->bufRemaining -= encodedLen;
            }
        }

        if( returnStatus == SigV4Success )
        {
            if( pCanonicalRequest->bufRemaining < 1U )
            {
                returnStatus = SigV4InsufficientMemory;
            }
            else
            {
                *pBufLoc = LINEFEED_CHAR;
                pCanonicalRequest->pBufCur = pBufLoc + LINEFEED_CHAR_LEN;
                pCanonicalRequest->bufRemaining -= LINEFEED_CHAR_LEN;
            }
        }

        return returnStatus;
    }

/*-----------------------------------------------------------*/

    static void setQueryStringFieldsAndValues( char * pQuery,
                                               size_t queryLen,
                                               size_t * pNumberOfParameters,
                                               CanonicalContext_t * pCanonicalRequest )
    {
        size_t numberOfParameters = 0U, i = 0U, startOfFieldOrValue = 0U;
        uint8_t fieldHasValue = 0U;

        /* Set cursors to each field and value in the query string. */
        for( i = 0U; i < queryLen; i++ )
        {
            if( ( pQuery[ i ] == '=' ) && !fieldHasValue )
            {
                pCanonicalRequest->pQueryLoc[ numberOfParameters ].key.pData = &pQuery[ startOfFieldOrValue ];
                pCanonicalRequest->pQueryLoc[ numberOfParameters ].key.dataLen = i - startOfFieldOrValue;
                startOfFieldOrValue = i + 1U;
                fieldHasValue = 1U;
            }
            else if( ( i == queryLen - 1U ) || ( ( pQuery[ i ] == '&' ) && ( i != 0U ) ) )
            {
                /* Adjust for the length of the last query parameter. */
                if( i == queryLen - 1U )
                {
                    i++;
                }

                if( i - startOfFieldOrValue == 0U )
                {
                    /* A field should never be empty, but a value can be empty
                     * provided a field was specified first. */
                }
                else if( !fieldHasValue )
                {
                    pCanonicalRequest->pQueryLoc[ numberOfParameters ].key.pData = &pQuery[ startOfFieldOrValue ];
                    pCanonicalRequest->pQueryLoc[ numberOfParameters ].key.dataLen = i - startOfFieldOrValue;
                    /* The previous field did not have a value set for it, so set its value to NULL. */
                    pCanonicalRequest->pQueryLoc[ numberOfParameters ].value.pData = NULL;
                    pCanonicalRequest->pQueryLoc[ numberOfParameters ].value.dataLen = 0U;
                    startOfFieldOrValue = i + 1U;
                    numberOfParameters++;
                }
                else
                {
                    /* End of value reached, so store a pointer to the previously set value. */
                    pCanonicalRequest->pQueryLoc[ numberOfParameters ].value.pData = &pQuery[ startOfFieldOrValue ];
                    pCanonicalRequest->pQueryLoc[ numberOfParameters ].value.dataLen = i - startOfFieldOrValue;
                    fieldHasValue = 0U;
                    startOfFieldOrValue = i + 1U;
                    numberOfParameters++;
                }
            }
            else
            {
                /* Empty else. */
            }

            if( numberOfParameters > SIGV4_MAX_QUERY_PAIR_COUNT )
            {
                break;
            }
        }

        *pNumberOfParameters = numberOfParameters;
    }

    static SigV4Status_t writeCanonicalQueryParameters( CanonicalContext_t * pCanonicalRequest,
                                                        size_t numberOfParameters )
    {
        SigV4Status_t returnStatus = SigV4Success;
        char * pBufLoc = NULL;
        size_t encodedLen = 0U, remainingLen = 0U, i = 0U;

        assert( pCanonicalRequest != NULL );
        assert( pCanonicalRequest->pBufCur != NULL );
        assert( pCanonicalRequest->pQueryLoc != NULL );

        pBufLoc = pCanonicalRequest->pBufCur;
        remainingLen = pCanonicalRequest->bufRemaining;

        for( i = 0U; i < numberOfParameters; i++ )
        {
            assert( pCanonicalRequest->pQueryLoc[ i ].key.pData != NULL );
            assert( pCanonicalRequest->pQueryLoc[ i ].key.dataLen > 0U );

            encodedLen = remainingLen;
            returnStatus = encodeURI( pCanonicalRequest->pQueryLoc[ i ].key.pData,
                                      pCanonicalRequest->pQueryLoc[ i ].key.dataLen,
                                      pBufLoc,
                                      &encodedLen,
                                      true,
                                      false );

            if( returnStatus == SigV4Success )
            {
                pBufLoc += encodedLen;
                remainingLen -= encodedLen;
                encodedLen = remainingLen;

                /* An empty value corresponds to an empty string. */
                if( ( pCanonicalRequest->pQueryLoc[ i ].value.dataLen > 0U ) &&
                    ( pCanonicalRequest->pQueryLoc[ i ].value.pData != NULL ) )
                {
                    if( encodedLen < 1U )
                    {
                        returnStatus = SigV4InsufficientMemory;
                    }
                    else
                    {
                        *pBufLoc = '=';
                        ++pBufLoc;
                        remainingLen -= 1;
                        encodedLen = remainingLen;
                        returnStatus = encodeURI( pCanonicalRequest->pQueryLoc[ i ].value.pData,
                                                  pCanonicalRequest->pQueryLoc[ i ].value.dataLen,
                                                  pBufLoc,
                                                  &encodedLen,
                                                  true,
                                                  true );
                    }

                    if( returnStatus == SigV4Success )
                    {
                        pBufLoc += encodedLen;
                        remainingLen -= encodedLen;
                    }
                }
            }

            if( ( remainingLen < 1U ) && ( numberOfParameters != i + 1 ) )
            {
                returnStatus = SigV4InsufficientMemory;
            }
            else if( ( numberOfParameters != i + 1 ) && ( returnStatus == SigV4Success ) )
            {
                *pBufLoc = '&';
                ++pBufLoc;
                remainingLen -= 1;
            }
            else
            {
                /* Empty else. */
            }

            if( returnStatus != SigV4Success )
            {
                break;
            }
            else
            {
                pCanonicalRequest->pBufCur = pBufLoc;
                pCanonicalRequest->bufRemaining = remainingLen;
            }
        }

        return returnStatus;
    }

    static SigV4Status_t generateCanonicalQuery( const char * pQuery,
                                                 size_t queryLen,
                                                 CanonicalContext_t * pCanonicalContext )
    {
        SigV4Status_t returnStatus = SigV4Success;
        size_t numberOfParameters;

        assert( pQuery != NULL );
        assert( queryLen > 0U );
        assert( pCanonicalContext != NULL );
        assert( pCanonicalContext->pBufCur != NULL );

        /* Note: Cast is used to remove the const with the assumption that #setQueryStringFieldsAndValues
         * never updates #pQuery.  */
        setQueryStringFieldsAndValues( ( char * ) pQuery, queryLen, &numberOfParameters, pCanonicalContext );

        if( numberOfParameters > SIGV4_MAX_QUERY_PAIR_COUNT )
        {
            LogError( ( "Number of parameters in the query string has exceeded the maximum of %u.", SIGV4_MAX_QUERY_PAIR_COUNT ) );
            returnStatus = SigV4MaxQueryPairCountExceeded;
        }

        if( returnStatus == SigV4Success )
        {
            /* Sort the parameter names by character code point in ascending order.
             * Parameters with duplicate names should be sorted by value. */
            qsort( pCanonicalContext->pQueryLoc, numberOfParameters, sizeof( SigV4KeyValuePair_t ), cmpQueryFieldValue );

            /* URI-encode each parameter name and value according to the following rules specified for SigV4:
             *  - Do not URI-encode any of the unreserved characters that RFC 3986 defines:
             *      A-Z, a-z, 0-9, hyphen ( - ), underscore ( _ ), period ( . ), and tilde ( ~ ).
             *  - Percent-encode all other characters with %XY, where X and Y are hexadecimal characters (0-9 and uppercase A-F).
             *  - Double-encode any equals ( = ) characters in parameter values.
             */
            returnStatus = writeCanonicalQueryParameters( pCanonicalContext, numberOfParameters );
        }

        if( returnStatus == SigV4Success )
        {
            /* Append a linefeed at the end. */
            *pCanonicalContext->pBufCur = LINEFEED_CHAR;
            pCanonicalContext->pBufCur += LINEFEED_CHAR_LEN;
            pCanonicalContext->bufRemaining -= LINEFEED_CHAR_LEN;
        }

        return returnStatus;
    }

#endif /* #if ( SIGV4_USE_CANONICAL_SUPPORT == 1 ) */

/*-----------------------------------------------------------*/

static SigV4Status_t verifySigV4Parameters( const SigV4Parameters_t * pParams )
{
    SigV4Status_t returnStatus = SigV4Success;

    /* Check for NULL members of struct pParams */
    if( pParams == NULL )
    {
        LogError( ( "Parameter check failed: pParams is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pCredentials == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pCredentials is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pCredentials->pAccessKeyId == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pCredentials->pAccessKeyId is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pCredentials->pSecretAccessKey == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pCredentials->pSecretAccessKey is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pCredentials->pSecurityToken == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pCredentials->pSecurityToken is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pCredentials->pExpiration == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pCredentials->pExpiration is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pDateIso8601 == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pDateIso8601 is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pRegion == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pRegion is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pService == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pService is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pCryptoInterface == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pCryptoInterface is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pCryptoInterface->pHashContext == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pCryptoInterface->pHashContext is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pHttpParameters == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pHttpParameters is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pHttpParameters->pHttpMethod == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pHttpParameters->pHttpMethod is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pHttpParameters->pQuery == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pHttpParameters->pQuery is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }
    else if( pParams->pHttpParameters->pHeaders == NULL )
    {
        LogError( ( "Parameter check failed: pParams->pHttpParameters->pHeaders is NULL." ) );
        returnStatus = SigV4InvalidParameter;
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

static int32_t completeHash( const char * pInput,
                             size_t inputLen,
                             char * pOutput,
                             size_t outputLen,
                             const SigV4CryptoInterface_t * pCryptoInterface )
{
    int32_t hashStatus = -1;

    hashStatus = pCryptoInterface->hashInit( pCryptoInterface->pHashContext );

    if( hashStatus == 0 )
    {
        hashStatus = pCryptoInterface->hashUpdate( pCryptoInterface->pHashContext,
                                                   pInput, inputLen );
    }

    if( hashStatus == 0 )
    {
        hashStatus = pCryptoInterface->hashFinal( pCryptoInterface->pHashContext,
                                                  pOutput, outputLen );
    }

    return hashStatus;
}

/*-----------------------------------------------------------*/

static SigV4Status_t completeHashAndHexEncode( const char * pInput,
                                               size_t inputLen,
                                               char * pOutput,
                                               size_t * pOutputLen,
                                               const SigV4CryptoInterface_t * pCryptoInterface )
{
    SigV4Status_t returnStatus = SigV4Success;
    /* Used to store the hash of the request payload. */
    char hashedPayload[ SIGV4_HASH_MAX_DIGEST_LENGTH ];
    SigV4String_t originalHash;
    SigV4String_t hexEncodedHash;

    assert( pOutput != NULL );
    assert( pOutputLen != NULL );
    assert( pCryptoInterface != NULL );

    originalHash.pData = hashedPayload;
    originalHash.dataLen = pCryptoInterface->hashDigestLen;
    hexEncodedHash.pData = pOutput;
    hexEncodedHash.dataLen = *pOutputLen;

    if( completeHash( pInput,
                      inputLen,
                      hashedPayload,
                      pCryptoInterface->hashDigestLen,
                      pCryptoInterface ) != 0 )
    {
        returnStatus = SigV4HashError;
    }

    if( returnStatus == SigV4Success )
    {
        /* Hex-encode the request payload. */
        returnStatus = lowercaseHexEncode( &originalHash,
                                           &hexEncodedHash );
    }

    if( returnStatus == SigV4Success )
    {
        *pOutputLen = hexEncodedHash.dataLen;
    }

    return returnStatus;
}

int32_t hmacKey( HmacContext_t * pHmacContext,
                 const char * pKey,
                 size_t keyLen )
{
    int32_t returnStatus = 0;
    const SigV4CryptoInterface_t * pCryptoInterface = NULL;

    assert( pHmacContext != NULL );
    assert( pHmacContext->key != NULL );
    assert( pHmacContext->pCryptoInterface != NULL );
    assert( pHmacContext->pCryptoInterface->hashInit != NULL );
    assert( pHmacContext->pCryptoInterface->hashUpdate != NULL );
    assert( pHmacContext->pCryptoInterface->hashFinal != NULL );

    pCryptoInterface = pHmacContext->pCryptoInterface;

    if( pHmacContext->keyLen + keyLen <= pCryptoInterface->hashBlockLen )
    {
        /* The key fits into the block so just append it. */
        ( void ) memcpy( pHmacContext->key + pHmacContext->keyLen, pKey, keyLen );
    }
    else
    {
        /* Initialize the hash context and hash existing key data. */
        if( pHmacContext->keyLen <= pCryptoInterface->hashBlockLen )
        {
            returnStatus = pCryptoInterface->hashInit( pCryptoInterface->pHashContext );

            if( returnStatus == 0 )
            {
                returnStatus = pCryptoInterface->hashUpdate( pCryptoInterface->pHashContext,
                                                             pHmacContext->key,
                                                             pHmacContext->keyLen );
            }
        }

        /* Hash down the key in order to create a block-sized derived key. */
        if( returnStatus == 0 )
        {
            returnStatus = pCryptoInterface->hashUpdate( pCryptoInterface->pHashContext,
                                                         pKey,
                                                         keyLen );
        }
    }

    pHmacContext->keyLen += keyLen;

    return returnStatus;
}

/*-----------------------------------------------------------*/

int32_t hmacData( HmacContext_t * pHmacContext,
                  const char * pData,
                  size_t dataLen )
{
    int32_t returnStatus = 0;
    size_t i = 0U;
    const SigV4CryptoInterface_t * pCryptoInterface = NULL;

    assert( pHmacContext != NULL );
    assert( pHmacContext->key != NULL );
    assert( pHmacContext->pCryptoInterface != NULL );
    assert( pHmacContext->pCryptoInterface->hashInit != NULL );
    assert( pHmacContext->pCryptoInterface->hashUpdate != NULL );
    assert( pHmacContext->pCryptoInterface->hashFinal != NULL );

    pCryptoInterface = pHmacContext->pCryptoInterface;

    if( pHmacContext->keyLen > pCryptoInterface->hashBlockLen )
    {
        /* Store the final block-sized derived key. */
        returnStatus = pCryptoInterface->hashFinal( pCryptoInterface->pHashContext,
                                                    pHmacContext->key,
                                                    pCryptoInterface->hashBlockLen );
        pHmacContext->keyLen = pCryptoInterface->hashDigestLen;
    }

    assert( pCryptoInterface->hashBlockLen >= pHmacContext->keyLen );

    if( returnStatus == 0 )
    {
        /* Zero pad to the right so that the key has the same size as the block size. */
        ( void ) memset( ( void * ) ( pHmacContext->key + pHmacContext->keyLen ),
                         0,
                         pCryptoInterface->hashBlockLen - pHmacContext->keyLen );

        for( i = 0U; i < pCryptoInterface->hashBlockLen; i++ )
        {
            /* XOR the key with the ipad. */
            pHmacContext->key[ i ] ^= ( char ) 0x36;
        }

        returnStatus = pCryptoInterface->hashInit( pCryptoInterface->pHashContext );
    }

    if( returnStatus == 0 )
    {
        /* Hash the inner-padded block-sized key. */
        returnStatus = pCryptoInterface->hashUpdate( pCryptoInterface->pHashContext,
                                                     pHmacContext->key,
                                                     pCryptoInterface->hashBlockLen );
    }

    if( ( returnStatus == 0 ) && ( dataLen > 0U ) )
    {
        /* Hash the data. */
        returnStatus = pCryptoInterface->hashUpdate( pCryptoInterface->pHashContext,
                                                     pData,
                                                     dataLen );
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

int32_t hmacFinal( HmacContext_t * pHmacContext,
                   char * pMac,
                   size_t macLen )
{
    int32_t returnStatus = -1;
    char innerHashDigest[ SIGV4_HASH_MAX_DIGEST_LENGTH ];
    size_t i = 0U;
    const SigV4CryptoInterface_t * pCryptoInterface = NULL;

    assert( pHmacContext != NULL );
    assert( pHmacContext->key != NULL );
    assert( pHmacContext->pCryptoInterface != NULL );
    /* Note that we must have a block-sized derived key before calling this function. */
    assert( pHmacContext->pCryptoInterface->hashInit != NULL );
    assert( pHmacContext->pCryptoInterface->hashUpdate != NULL );
    assert( pHmacContext->pCryptoInterface->hashFinal != NULL );

    pCryptoInterface = pHmacContext->pCryptoInterface;

    /* Write the inner hash. */
    returnStatus = pCryptoInterface->hashFinal( pCryptoInterface->pHashContext,
                                                innerHashDigest,
                                                pCryptoInterface->hashDigestLen );

    if( returnStatus == 0 )
    {
        /* Create the outer-padded key by retrieving the original key from
         * the inner-padded key then XOR with opad. XOR is associative,
         * so one way to do this is by performing XOR on each byte of the
         * inner-padded key with (0x36 ^ 0x5c) = (ipad ^ opad) = 0x6a.  */
        for( i = 0U; i < pCryptoInterface->hashBlockLen; i++ )
        {
            pHmacContext->key[ i ] ^= ( char ) ( 0x6a );
        }

        returnStatus = pCryptoInterface->hashInit( pCryptoInterface->pHashContext );
    }

    if( returnStatus == 0 )
    {
        /* Update hash using the outer-padded key. */
        returnStatus = pCryptoInterface->hashUpdate( pCryptoInterface->pHashContext,
                                                     pHmacContext->key,
                                                     pCryptoInterface->hashBlockLen );
    }

    if( returnStatus == 0 )
    {
        /* Update hash using the inner digest. */
        returnStatus = pCryptoInterface->hashUpdate( pCryptoInterface->pHashContext,
                                                     innerHashDigest,
                                                     pCryptoInterface->hashDigestLen );
    }

    if( returnStatus == 0 )
    {
        /* Write the final HMAC value. */
        returnStatus = pCryptoInterface->hashFinal( pCryptoInterface->pHashContext,
                                                    pMac,
                                                    macLen );
    }

    /* Reset the HMAC context. */
    pHmacContext->keyLen = 0U;

    return returnStatus;
}

static SigV4Status_t writeLineToCanonicalRequest( const char * pLine,
                                                  size_t lineLen,
                                                  CanonicalContext_t * pCanonicalContext )
{
    SigV4Status_t returnStatus = SigV4Success;

    if( pCanonicalContext->bufRemaining < lineLen + LINEFEED_CHAR_LEN )
    {
        LogError( ( "Insufficient space in processing buffer for canonical request. "
                    "Increase `SIGV4_PROCESSING_BUFFER_LENGTH` to fix, bytesExceeded=%zu.",
                    lineLen - pCanonicalContext->bufRemaining ) );
        returnStatus = SigV4InsufficientMemory;
    }
    else
    {
        ( void ) memcpy( pCanonicalContext->pBufCur,
                         pLine,
                         lineLen );
        pCanonicalContext->pBufCur += lineLen;

        *pCanonicalContext->pBufCur = LINEFEED_CHAR;
        pCanonicalContext->pBufCur += LINEFEED_CHAR_LEN;

        pCanonicalContext->bufRemaining -= lineLen + \
                                           LINEFEED_CHAR_LEN;
    }

    return returnStatus;
}

int32_t completeHmac( HmacContext_t * pHmacContext,
                      const char * pKey,
                      size_t keyLen,
                      const char * pData,
                      size_t dataLen,
                      char * pOutput,
                      size_t outputLen,
                      const SigV4CryptoInterface_t * pCryptoInterface )
{
    int32_t returnStatus = 0;

    if( outputLen < pCryptoInterface->hashDigestLen )
    {
        LogError( ( "Not enough buffer to write the hash digest, bytesExceeded=%zu",
                    pCryptoInterface->hashDigestLen - outputLen ) );
        returnStatus = -1;
    }

    if( returnStatus == 0 )
    {
        returnStatus = hmacKey( pHmacContext, pKey, keyLen );
    }

    if( returnStatus == 0 )
    {
        returnStatus = hmacData( pHmacContext, pData, dataLen );
    }

    if( returnStatus == 0 )
    {
        returnStatus = hmacFinal( pHmacContext, pOutput, outputLen );
    }

    return returnStatus;
}

static size_t writeStringToSignPrefix( char * pBufStart,
                                       const char * pAlgorithm,
                                       size_t algorithmLen,
                                       const char * pDateIso8601,
                                       SigV4String_t * pCredentialScope )
{
    SigV4String_t credentialScope;

    /* Need to write all substrings that come before the hash in the string to sign. */

    /* Write HMAC and hashing algorithm used for SigV4 authentication. */
    ( void ) memcpy( pBufStart, pAlgorithm, algorithmLen );
    pBufStart += algorithmLen;

    *pBufStart = LINEFEED_CHAR;
    pBufStart += LINEFEED_CHAR_LEN;

    /* Concatenate entire ISO 8601 date string. */
    ( void ) memcpy( pBufStart, pDateIso8601, SIGV4_ISO_STRING_LEN );
    pBufStart += SIGV4_ISO_STRING_LEN;

    *pBufStart = LINEFEED_CHAR;

    return algorithmLen + LINEFEED_CHAR_LEN + SIGV4_ISO_STRING_LEN + LINEFEED_CHAR_LEN;
}

static SigV4Status_t writeStringToSign( const SigV4Parameters_t * pParams,
                                        CanonicalContext_t * pCanonicalContext )
{
    SigV4Status_t returnStatus = SigV4Success;
    size_t encodedLen = pCanonicalContext->bufRemaining, algorithmLen = 0U;
    char * pBufStart = ( char * ) pCanonicalContext->pBufProcessing;
    char * pAlgorithm = NULL;

    if( ( pParams->pAlgorithm == NULL ) || ( pParams->algorithmLen == 0 ) )
    {
        /* The default algorithm is AWS4-HMAC-SHA256. */
        pAlgorithm = SIGV4_AWS4_HMAC_SHA256;
        algorithmLen = SIGV4_AWS4_HMAC_SHA256_LENGTH;
    }
    else
    {
        pAlgorithm = pParams->pAlgorithm;
        algorithmLen = pParams->algorithmLen;
    }

    returnStatus = completeHashAndHexEncode( pBufStart,
                                             ( size_t ) ( pCanonicalContext->pBufCur - pBufStart ),
                                             pCanonicalContext->pBufCur + 1,
                                             &encodedLen,
                                             pParams->pCryptoInterface );

    if( returnStatus == SigV4Success )
    {
        /* Note that the credential scope size calculation already
         * accounts for the linefeed. */
        size_t sizeNeededBeforeHash = algorithmLen + LINEFEED_CHAR_LEN +         \
                                      SIGV4_ISO_STRING_LEN + LINEFEED_CHAR_LEN + \
                                      sizeNeededForCredentialScope( pParams );

        /* Check if there is enough space for the string to sign. */
        if( sizeNeededBeforeHash + ( pParams->pCryptoInterface->hashDigestLen * 2 ) >
            SIGV4_PROCESSING_BUFFER_LENGTH )
        {
            LogError( ( "Insufficient space in processing buffer for string to sign. "
                        "Increase `SIGV4_PROCESSING_BUFFER_LENGTH` to fix, bytesExceeded=%zu.",
                        sizeNeededBeforeHash + ( pParams->pCryptoInterface->hashDigestLen * 2 ) - \
                        SIGV4_PROCESSING_BUFFER_LENGTH ) );
            returnStatus = SigV4InsufficientMemory;
        }
        else
        {
            /* Copy the hash of the canonical request to where it will be in the string to sign. */
            ( void ) memmove( pBufStart + sizeNeededBeforeHash, pCanonicalContext->pBufCur + 1, encodedLen );
            pCanonicalContext->pBufCur = pBufStart + sizeNeededBeforeHash + encodedLen;
            pCanonicalContext->bufRemaining = SIGV4_PROCESSING_BUFFER_LENGTH - encodedLen - sizeNeededBeforeHash;
        }
    }

    if( returnStatus == SigV4Success )
    {
        size_t bytesWritten = 0U;
        SigV4String_t credentialScope;
        bytesWritten = writeStringToSignPrefix( pBufStart,
                                                pAlgorithm,
                                                algorithmLen,
                                                pParams->pDateIso8601,
                                                &credentialScope );
        pBufStart += bytesWritten;
        credentialScope.pData = pBufStart;
        credentialScope.dataLen = sizeNeededForCredentialScope( pParams );
        /* Concatenate credential scope. */
        ( void ) generateCredentialScope( pParams, &credentialScope );
    }

    return returnStatus;
}

static SigV4Status_t generateSigningKey( SigV4Parameters_t * pSigV4Params,
                                         HmacContext_t * pHmacContext,
                                         SigV4String_t * pSigningKey,
                                         size_t * pBytesRemaining )
{
    SigV4Status_t returnStatus = SigV4Success;
    int32_t hmacStatus = 0;
    char * pSigningKeyStart = NULL;

    assert( pSigV4Params != NULL );
    assert( pHmacContext != NULL );
    assert( pSigningKey != NULL );
    assert( pBytesRemaining != NULL );

    hmacStatus = hmacKey( pHmacContext,
                          SIGV4_HMAC_SIGNING_KEY_PREFIX,
                          SIGV4_HMAC_SIGNING_KEY_PREFIX_LEN );

    /* To calculate the final signing key, this function needs at least enough
     * buffer to hold the length of two digests since one digest is used to
     * calculate the other. */
    if( *pBytesRemaining < pSigV4Params->pCryptoInterface->hashDigestLen * 2 )
    {
        returnStatus == SigV4InsufficientMemory;
    }

    if( hmacStatus == 0 )
    {
        hmacStatus = completeHmac( pHmacContext,
                                   pSigV4Params->pCredentials->pSecretAccessKey,
                                   pSigV4Params->pCredentials->secretAccessKeyLen,
                                   pSigV4Params->pDateIso8601,
                                   ISO_DATE_SCOPE_LEN,
                                   pSigningKey->pData,
                                   pSigningKey->dataLen,
                                   pSigV4Params->pCryptoInterface );
        *pBytesRemaining -= pSigV4Params->pCryptoInterface->hashDigestLen;
    }

    if( hmacStatus == 0 )
    {
        pSigningKeyStart = pSigningKey->pData + pSigV4Params->pCryptoInterface->hashDigestLen + 1U;
        hmacStatus = completeHmac( pHmacContext,
                                   pSigningKey->pData,
                                   pSigV4Params->pCryptoInterface->hashDigestLen,
                                   pSigV4Params->pRegion,
                                   pSigV4Params->regionLen,
                                   pSigningKeyStart,
                                   *pBytesRemaining,
                                   pSigV4Params->pCryptoInterface );
        *pBytesRemaining -= pSigV4Params->pCryptoInterface->hashDigestLen;
    }

    if( hmacStatus == 0 )
    {
        hmacStatus = completeHmac( pHmacContext,
                                   pSigningKeyStart,
                                   pSigV4Params->pCryptoInterface->hashDigestLen,
                                   pSigV4Params->pService,
                                   pSigV4Params->serviceLen,
                                   pSigningKey->pData,
                                   pSigV4Params->pCryptoInterface->hashDigestLen,
                                   pSigV4Params->pCryptoInterface );
    }

    if( hmacStatus == 0 )
    {
        hmacStatus = completeHmac( pHmacContext,
                                   pSigningKey->pData,
                                   pSigV4Params->pCryptoInterface->hashDigestLen,
                                   CREDENTIAL_SCOPE_TERMINATOR,
                                   CREDENTIAL_SCOPE_TERMINATOR_LEN,
                                   pSigningKeyStart,
                                   pSigV4Params->pCryptoInterface->hashDigestLen,
                                   pSigV4Params->pCryptoInterface );
    }

    if( hmacStatus == 0 )
    {
        pSigningKey->pData = pSigningKeyStart;
        pSigningKey->dataLen = pSigV4Params->pCryptoInterface->hashDigestLen;
    }
    else
    {
        returnStatus = SigV4HashError;
    }

    return returnStatus;
}

SigV4Status_t SigV4_AwsIotDateToIso8601( const char * pDate,
                                         size_t dateLen,
                                         char * pDateISO8601,
                                         size_t dateISO8601Len )
{
    SigV4Status_t returnStatus = SigV4InvalidParameter;
    SigV4DateTime_t date = { 0 };
    char * pWriteLoc = pDateISO8601;
    const char * pFormatStr = NULL;
    size_t formatLen = 0U;

    /* Check for NULL parameters. */
    if( pDate == NULL )
    {
        LogError( ( "Parameter check failed: pDate is NULL." ) );
    }
    else if( pDateISO8601 == NULL )
    {
        LogError( ( "Parameter check failed: pDateISO8601 is NULL." ) );
    }
    /* Check that the date provided is of the expected length. */
    else if( ( dateLen != SIGV4_EXPECTED_LEN_RFC_3339 ) &&
             ( dateLen != SIGV4_EXPECTED_LEN_RFC_5322 ) )
    {
        LogError( ( "Parameter check failed: dateLen must be either %u or %u, "
                    "for RFC 3339 and RFC 5322 formats, respectively.",
                    SIGV4_EXPECTED_LEN_RFC_3339,
                    SIGV4_EXPECTED_LEN_RFC_5322 ) );
    }

    /* Check that the output buffer provided is large enough for the formatted
     * string. */
    else if( dateISO8601Len < SIGV4_ISO_STRING_LEN )
    {
        LogError( ( "Parameter check failed: dateISO8601Len must be at least %u.",
                    SIGV4_ISO_STRING_LEN ) );
    }
    else
    {
        /* Assign format string according to input type received. */
        pFormatStr = ( dateLen == SIGV4_EXPECTED_LEN_RFC_3339 ) ?
                     ( FORMAT_RFC_3339 ) : ( FORMAT_RFC_5322 );

        formatLen = ( dateLen == SIGV4_EXPECTED_LEN_RFC_3339 ) ?
                    ( FORMAT_RFC_3339_LEN ) : ( FORMAT_RFC_5322_LEN );

        returnStatus = parseDate( pDate, dateLen, pFormatStr, formatLen, &date );
    }

    if( returnStatus == SigV4Success )
    {
        returnStatus = validateDateTime( &date );
    }

    if( returnStatus == SigV4Success )
    {
        /* Combine date elements into complete ASCII representation, and fill
         * buffer with result. */
        intToAscii( date.tm_year, &pWriteLoc, ISO_YEAR_LEN );
        intToAscii( date.tm_mon, &pWriteLoc, ISO_NON_YEAR_LEN );
        intToAscii( date.tm_mday, &pWriteLoc, ISO_NON_YEAR_LEN );
        *pWriteLoc = 'T';
        pWriteLoc++;
        intToAscii( date.tm_hour, &pWriteLoc, ISO_NON_YEAR_LEN );
        intToAscii( date.tm_min, &pWriteLoc, ISO_NON_YEAR_LEN );
        intToAscii( date.tm_sec, &pWriteLoc, ISO_NON_YEAR_LEN );
        *pWriteLoc = 'Z';

        LogDebug( ( "Successfully formatted ISO 8601 date: \"%.*s\"",
                    ( int ) dateISO8601Len,
                    pDateISO8601 ) );
    }

    return returnStatus;
}

SigV4Status_t SigV4_GenerateHTTPAuthorization( const SigV4Parameters_t * pParams,
                                               char * pAuthBuf,
                                               size_t * authBufLen,
                                               char ** pSignature,
                                               size_t * signatureLen )
{
    SigV4Status_t returnStatus = SigV4Success;
    CanonicalContext_t canonicalContext;
    char * pPath = NULL;
    size_t pathLen = 0U, encodedLen = 0U;
    HmacContext_t hmacContext = { 0 };
    SigV4String_t signingKey;

    /*returnStatus = verifySigV4Parameters( pParams ); */

    if( returnStatus == SigV4Success )
    {
        canonicalContext.pBufCur = canonicalContext.pBufProcessing;
        canonicalContext.bufRemaining = SIGV4_PROCESSING_BUFFER_LENGTH;

        /* Write the HTTP Request Method to the canonical request. */
        returnStatus = writeLineToCanonicalRequest( pParams->pHttpParameters->pHttpMethod,
                                                    pParams->pHttpParameters->httpMethodLen,
                                                    &canonicalContext );
    }

    /* Set defaults for path and algorithm. */
    if( ( pParams->pHttpParameters->pPath == NULL ) ||
        ( pParams->pHttpParameters->pathLen == 0U ) )
    {
        /* If the absolute path is empty, use a forward slash (/). */
        pPath = HTTP_EMPTY_PATH;
        pathLen = HTTP_EMPTY_PATH_LEN;
    }
    else
    {
        pPath = pParams->pHttpParameters->pPath;
        pathLen = pParams->pHttpParameters->pathLen;
    }

    if( returnStatus == SigV4Success )
    {
        /* Write the URI to the canonical request. */
        if( pParams->pHttpParameters->flags & SIGV4_HTTP_PATH_IS_CANONICAL_FLAG )
        {
            /* URI is already canonicalized, so just write it to the buffer as is. */
            returnStatus = writeLineToCanonicalRequest( pPath,
                                                        pathLen,
                                                        &canonicalContext );
        }
        else if( ( pParams->serviceLen >= S3_SERVICE_NAME_LEN ) &&
                 ( strncmp( pParams->pService, S3_SERVICE_NAME, S3_SERVICE_NAME_LEN ) == 0 ) )
        {
            /* S3 is the only service in which the URI must only be encoded once. */
            returnStatus = generateCanonicalURI( pPath, pathLen, false, &canonicalContext );
        }
        else
        {
            returnStatus = generateCanonicalURI( pPath, pathLen, true, &canonicalContext );
        }
    }

    if( returnStatus == SigV4Success )
    {
        /* Write the query to the canonical request. */
        if( pParams->pHttpParameters->flags & SIGV4_HTTP_QUERY_IS_CANONICAL_FLAG )
        {
            /* HTTP query is already canonicalized, so just write it to the buffer as is. */
            returnStatus = writeLineToCanonicalRequest( pParams->pHttpParameters->pQuery,
                                                        pParams->pHttpParameters->queryLen,
                                                        &canonicalContext );
        }
        else
        {
            returnStatus = generateCanonicalQuery( pParams->pHttpParameters->pQuery, pParams->pHttpParameters->queryLen, &canonicalContext );
        }
    }

    if( returnStatus == SigV4Success )
    {
        /* Write the headers to the canonical request. */
        if( pParams->pHttpParameters->flags & SIGV4_HTTP_HEADERS_ARE_CANONICAL_FLAG )
        {
            /* Headers are already canonicalized, so just write it to the buffer as is. */
            returnStatus = writeLineToCanonicalRequest( pParams->pHttpParameters->pHeaders,
                                                        pParams->pHttpParameters->headersLen,
                                                        &canonicalContext );
        }
        else
        {
            /* Canonicalize original HTTP headers before writing to buffer.
             * returnStatus = generateCanonicalHeaders( pParams->pHttpParameters->pHeaders, pParams->pHttpParameters->headersLen, &canonicalContext );
             */
        }
    }

    /* Hash and hex-encode the canonical request to the buffer. */
    if( returnStatus == SigV4Success )
    {
        encodedLen = canonicalContext.bufRemaining;
        returnStatus = completeHashAndHexEncode( pParams->pHttpParameters->pPayload,
                                                 pParams->pHttpParameters->payloadLen,
                                                 canonicalContext.pBufCur,
                                                 &encodedLen,
                                                 pParams->pCryptoInterface );

        if( returnStatus == SigV4Success )
        {
            canonicalContext.pBufCur += encodedLen;
            canonicalContext.bufRemaining -= encodedLen;
        }
    }

    /* Write string to sign. */
    if( returnStatus == SigV4Success )
    {
        returnStatus = writeStringToSign( pParams, &canonicalContext );
    }

    /* Write the signing key. The is done by computing the following function:
     * HMAC(HMAC(HMAC(HMAC("AWS4" + kSecret,pDate),pRegion),pService),"aws4_request") */
    if( returnStatus == SigV4Success )
    {
        hmacContext.pCryptoInterface = pParams->pCryptoInterface;
        signingKey.pData = canonicalContext.pBufCur;
        signingKey.dataLen = canonicalContext.bufRemaining;
        returnStatus = generateSigningKey( pParams,
                                           &hmacContext,
                                           &signingKey,
                                           &canonicalContext.bufRemaining );
    }

    SigV4String_t originalHmac;
    SigV4String_t hexEncodedHmac;
    originalHmac.pData = signingKey.pData;
    originalHmac.dataLen = pParams->pCryptoInterface->hashDigestLen;
    hexEncodedHmac.pData = ( char * ) canonicalContext.pBufProcessing;
    hexEncodedHmac.dataLen = 64;

    if( returnStatus == SigV4Success )
    {
        /* Hex-encode the request payload. */
        returnStatus = lowercaseHexEncode( &originalHmac,
                                           &hexEncodedHmac );
    }

    if( returnStatus == SigV4Success )
    {
        printf( "Return status is %d\n", returnStatus );
        printf( "Canonical query is %.*s\n", 64, hexEncodedHmac.pData );
    }

    return returnStatus;
}
