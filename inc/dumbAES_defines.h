#ifndef DUMBAES_DEFINES_H
#define DUMBAES_DEFINES_H

/******************************************************************************/
// Constants
/******************************************************************************/

#define AES_128_NR                    (10)
#define AES_192_NR                    (12)
#define AES_256_NR                    (14)
#define AES_128_NK                    (4)
#define AES_192_NK                    (6)
#define AES_256_NK                    (8)

#define DUMBAES_KEYSIZE_128           (16)
#define DUMBAES_KEYSIZE_192           (24)
#define DUMBAES_KEYSIZE_256           (32)

#define DUMBAES_BLOCKSIZE             (16)
#define DUMBAES_NB                    (4)
#define DUMBAES_MAX_NR                (AES_256_NR)
#define DUMBAES_MAX_KEYSIZE           (DUMBAES_KEYSIZE_256)

#endif // DUMBAES_DEFINES_H