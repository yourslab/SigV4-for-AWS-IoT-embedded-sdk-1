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
 * @file sigv4_quicksort.c
 * @brief Implements Quicksort
 */

#include "sigv4_quicksort.h"

#include <string.h>
#include <assert.h>

/**
 * @brief A helper function to swap the value of two pointers
 * given their sizes.
 *
 * @param[in] pFirstItem The item to swap with @p pSecondItem.
 * @param[in] pSecondItem The item to swap with @p pFirstItem.
 * @param[in] itemSize The amount of memory per entry in the array.
 */
static void swap( void * pFirstItem,
                  void * pSecondItem,
                  size_t itemSize );

/**
 * @brief A helper function to perform quicksort on a subarray.
 *
 * @param[in] pArray The array to be sorted.
 * @param[in] low The low index of the array.
 * @param[in] high The high index of the array.
 * @param[in] itemSize The amount of memory per entry in the array.
 * @param[out] comparator The comparison function to determine if one item is less than another.
 */
static void quickSortHelper( void * pArray,
                             size_t low,
                             size_t high,
                             size_t itemSize,
                             ComparisonFunc_t comparator );

/**
 * @brief A helper function to partition a subarray using the last element
 * of the array as the pivot. All items smaller than the pivot end up
 * at its left while all items greater than end up at its right.
 *
 * @param[in] pArray The array to be sorted.
 * @param[in] low The low index of the array.
 * @param[in] high The high index of the array.
 * @param[in] itemSize The amount of memory per entry in the array.
 * @param[out] comparator The comparison function to determine if one item is less than another.
 *
 * @return The index of the pivot
 */
static size_t partition( void * pArray,
                         size_t low,
                         size_t high,
                         size_t itemSize,
                         ComparisonFunc_t comparator );

/*-----------------------------------------------------------*/

static void swap( void * pFirstItem,
                  void * pSecondItem,
                  size_t itemSize )
{
    uint8_t * pFirstByte = pFirstItem;
    uint8_t * pSecondByte = pSecondItem;

    if( ( pFirstItem != NULL ) && ( pSecondItem != NULL ) )
    {
        /* Swap one byte at a time. */
        while( itemSize-- )
        {
            uint8_t tmp = *pFirstByte;
            *pFirstByte++ = *pSecondByte;
            *pSecondByte++ = tmp;
        }
    }
}

static void quickSortHelper( void * pArray,
                             size_t low,
                             size_t high,
                             size_t itemSize,
                             ComparisonFunc_t comparator )
{
    size_t stack[ high - low + 1 ];
    /* Low and high are first two items on the stack. */
    size_t top = 0;

    stack[ top++ ] = low;
    stack[ top++ ] = high;

    while( top > 0 )
    {
        size_t partitionIndex;
        high = stack[ --top ];
        low = stack[ --top ];

        partitionIndex = partition( pArray, low, high, itemSize, comparator );

        if( ( partitionIndex != 0U ) && ( partitionIndex - 1U > low ) )
        {
            stack[ top++ ] = low;
            stack[ top++ ] = partitionIndex - 1U;
        }

        if( partitionIndex + 1U < high )
        {
            stack[ top++ ] = partitionIndex + 1U;
            stack[ top++ ] = high;
        }
    }
}

static size_t partition( void * pArray,
                         size_t low,
                         size_t high,
                         size_t itemSize,
                         ComparisonFunc_t comparator )
{
    void * pivot;
    size_t i = low - 1U, j = low;

    assert( pArray != NULL );

    pivot = pArray + ( high * itemSize );

    for( ; j <= high - 1; j++ )
    {
        /* Use comparator function to check if
         * current element is smaller than the pivot */
        if( comparator( pArray + ( j * itemSize ), pivot ) < 0 )
        {
            swap( pArray + ( ++i * itemSize ), pArray + ( j * itemSize ), itemSize );
        }
    }

    swap( pArray + ( ( i + 1 ) * itemSize ), pivot, itemSize );
    return i + 1;
}

void quickSort( void * pArray,
                size_t numItems,
                size_t itemSize,
                ComparisonFunc_t comparator )
{
    if( ( numItems != 0 ) && ( pArray != NULL ) )
    {
        quickSortHelper( pArray, 0, numItems - 1U, itemSize, comparator );
    }
}
