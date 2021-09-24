/*
 *  Own key generation application
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/platform.h"

#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/rsa.h"
#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#define DEV_RANDOM_THRESHOLD 32

#if defined(MBEDTLS_ECP_C)
#define DFL_EC_CURVE mbedtls_ecp_curve_list()->grp_id
#else
#define DFL_EC_CURVE 0
#endif

#define FORMAT_PEM 0
#define FORMAT_DER 1

#define DFL_TYPE MBEDTLS_PK_RSA
#define DFL_RSA_KEYSIZE 1024  // MAX 1024, check mbedtls_rsa_gen_key function
#define DFL_FILENAME "keyfile.key"
#define DFL_FORMAT FORMAT_PEM
#define DFL_USE_DEV_RANDOM 0

#define USAGE \
    "\n usage: gen_key param=<>...\n"                                       \
    "\n acceptable parameters:\n"                                           \
    "    type=rsa|ec           default: rsa\n"                              \
    "    rsa_keysize=%%d        default: 1024\n"                            \
    "    ec_curve=%%s           see below\n"                                \
    "    filename=%%s           default: keyfile.key\n"                     \
    "    format=pem|der        default: pem\n"                              \
    "    secret_id=%%s         default: 1982\n"                             \
    "    secret_md5=%%s        default: 00112233445566778899AABBCCDDEEFF\n" \
    "\n"

/*
 * global options
 */
typedef struct config {
  int type;           /* the type of key to generate          */
  int rsa_keysize;    /* length of key in bits                */
  int ec_curve;       /* curve identifier for EC keys         */
  const char *filename;       /* filename of the key file             */
  int format;         /* the output format to use             */
  int use_dev_random; /* use /dev/random as entropy source    */
} options;


static uint8_t  secret_md5[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
                                  0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
static uint32_t secret_id = 0x1982;

static int own_entropy_func(void *data, unsigned char *output, size_t len) {
  int      ret;
  uint32_t counter = 0;
  if (data) {
    for (int i = 0; i < (int)len; i++) {
      counter += (secret_id >> ((i) % 24)) & 0xFF;
      counter %= 16;
      output[i] = secret_md5[counter] & (((secret_id >> i) % 2) ? 0x0F : 0xF0);
    }

    ret = 0;
  } else {
    ret = -1;
  }

  return (ret);
}

static int write_private_key(int format, mbedtls_pk_context *key, unsigned char *output_buf, int buf_size) {
  int    ret;
  size_t len = 0;

  memset(output_buf, 0, buf_size);
  if (format == FORMAT_PEM) {
    if ((ret = mbedtls_pk_write_key_pem(key, output_buf, buf_size)) != 0) return (ret);

    len = strlen((char *)output_buf);
  } else {
    return (-1);
  }

  if (len <= 0) {
    return (-1);
  }
  return (0);
}

int keygen(options *opt, unsigned char *output_key, int output_size) {
  int                      ret       = 1;
  int                      exit_code = MBEDTLS_EXIT_FAILURE;
  mbedtls_pk_context       key;
  char                     buf[1024];
  mbedtls_mpi              N, P, Q, D, E, DP, DQ, QP;
  mbedtls_entropy_context  entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  const char *             pers = "gen_key";

  /*
   * Set to sane values
   */

  mbedtls_mpi_init(&N);
  mbedtls_mpi_init(&P);
  mbedtls_mpi_init(&Q);
  mbedtls_mpi_init(&D);
  mbedtls_mpi_init(&E);
  mbedtls_mpi_init(&DP);
  mbedtls_mpi_init(&DQ);
  mbedtls_mpi_init(&QP);

  mbedtls_pk_init(&key);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  memset(buf, 0, sizeof(buf));

  mbedtls_printf("\n  . Seeding the random number generator...");
  fflush(stdout);

  mbedtls_entropy_init(&entropy);

  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, own_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) !=
      0) {
    mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n", (unsigned int)-ret);
    goto exit;
  }

  /*
   * 1.1. Generate the key
   */
  mbedtls_printf("\n  . Generating the private key ...");
  fflush(stdout);

  if ((ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type((mbedtls_pk_type_t)opt->type))) != 0) {
    mbedtls_printf(" failed\n  !  mbedtls_pk_setup returned -0x%04x", (unsigned int)-ret);
    goto exit;
  }

#if defined(MBEDTLS_RSA_C) && defined(MBEDTLS_GENPRIME)
  if (opt->type == MBEDTLS_PK_RSA) {
    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random, &ctr_drbg, opt->rsa_keysize, 65537);
    if (ret != 0) {
      mbedtls_printf(" failed\n  !  mbedtls_rsa_gen_key returned -0x%04x", (unsigned int)-ret);
      goto exit;
    }
    printf("mbedtls_rsa_gen_key ok!");
  } else
#endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECP_C)
      if (opt->type == MBEDTLS_PK_ECKEY) {
    ret = mbedtls_ecp_gen_key(
        (mbedtls_ecp_group_id)opt->ec_curve, mbedtls_pk_ec(key), mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
      mbedtls_printf(" failed\n  !  mbedtls_ecp_gen_key returned -0x%04x", (unsigned int)-ret);
      goto exit;
    }
  } else
#endif /* MBEDTLS_ECP_C */
  {
    mbedtls_printf(" failed\n  !  key type not supported\n");
    goto exit;
  }

  /*
   * 1.2 Print the key
   */
  mbedtls_printf(" ok\n  . Key information:\n");

#if defined(MBEDTLS_RSA_C)
  if (mbedtls_pk_get_type(&key) == MBEDTLS_PK_RSA) {
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(key);

    if ((ret = mbedtls_rsa_export(rsa, &N, &P, &Q, &D, &E)) != 0 ||
        (ret = mbedtls_rsa_export_crt(rsa, &DP, &DQ, &QP)) != 0) {
      mbedtls_printf(" failed\n  ! could not export RSA parameters\n\n");
      goto exit;
    }
  } else
#endif
#if defined(MBEDTLS_ECP_C)
      if (mbedtls_pk_get_type(&key) == MBEDTLS_PK_ECKEY) {
    mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(key);
    mbedtls_printf("curve: %s\n", mbedtls_ecp_curve_info_from_grp_id(ecp->grp.id)->name);
    mbedtls_mpi_write_file("X_Q:   ", &ecp->Q.X, 16, NULL);
    mbedtls_mpi_write_file("Y_Q:   ", &ecp->Q.Y, 16, NULL);
    mbedtls_mpi_write_file("D:     ", &ecp->d, 16, NULL);
  } else
#endif
    mbedtls_printf("  ! key type not supported\n");

  /*
   * 1.3 Export key
   */
  mbedtls_printf("  . Writing key to file...");

  if ((ret = write_private_key(opt->format, &key, output_key, output_size)) != 0) {
    mbedtls_printf(" failed\n");
    goto exit;
  }

  mbedtls_printf(" ok\n");

  exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

  if (exit_code != MBEDTLS_EXIT_SUCCESS) {
#ifdef MBEDTLS_ERROR_C
    mbedtls_strerror(ret, buf, sizeof(buf));
    mbedtls_printf(" - %s\n", buf);
#else
    mbedtls_printf("\n");
#endif
  }

  mbedtls_mpi_free(&N);
  mbedtls_mpi_free(&P);
  mbedtls_mpi_free(&Q);
  mbedtls_mpi_free(&D);
  mbedtls_mpi_free(&E);
  mbedtls_mpi_free(&DP);
  mbedtls_mpi_free(&DQ);
  mbedtls_mpi_free(&QP);

  mbedtls_pk_free(&key);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);

  return exit_code;
}

int main( int argc, char *argv[] )
{
    int exit_code = MBEDTLS_EXIT_FAILURE;
    int i;
    char *p, *q;
    char aux[2];
#if defined(MBEDTLS_ECP_C)
    const mbedtls_ecp_curve_info *curve_info;
#endif
    options opt;

    FILE *f;

    unsigned char output_key[16000];

    if( argc == 0 )
    {
    usage:
        mbedtls_printf( USAGE );
#if defined(MBEDTLS_ECP_C)
        mbedtls_printf( " available ec_curve values:\n" );
        curve_info = mbedtls_ecp_curve_list();
        mbedtls_printf( "    %s (default)\n", curve_info->name );
        while( ( ++curve_info )->name != NULL )
            mbedtls_printf( "    %s\n", curve_info->name );
#endif /* MBEDTLS_ECP_C */
        goto exit;
    }

    opt.type                = DFL_TYPE;
    opt.rsa_keysize         = DFL_RSA_KEYSIZE;
    opt.ec_curve            = DFL_EC_CURVE;
    opt.filename            = DFL_FILENAME;
    opt.format              = DFL_FORMAT;
    opt.use_dev_random      = DFL_USE_DEV_RANDOM;

    for( i = 1; i < argc; i++ )
    {
        p = argv[i];
        if( ( q = strchr( p, '=' ) ) == NULL )
            goto usage;
        *q++ = '\0';
        if( strcmp( p, "type" ) == 0 )
        {
            if( strcmp( q, "rsa" ) == 0 )
                opt.type = MBEDTLS_PK_RSA;
            else if( strcmp( q, "ec" ) == 0 )
                opt.type = MBEDTLS_PK_ECKEY;
            else
                goto usage;
        }
        else if( strcmp( p, "format" ) == 0 )
        {
            if( strcmp( q, "pem" ) == 0 )
                opt.format = FORMAT_PEM;
            else if( strcmp( q, "der" ) == 0 )
                opt.format = FORMAT_DER;
            else
                goto usage;
        }
        else if( strcmp( p, "rsa_keysize" ) == 0 )
        {
            opt.rsa_keysize = atoi( q );
            if( opt.rsa_keysize < 1024 ||
                opt.rsa_keysize > MBEDTLS_MPI_MAX_BITS )
                goto usage;
        }
#if defined(MBEDTLS_ECP_C)
        else if( strcmp( p, "ec_curve" ) == 0 )
        {
            if( ( curve_info = mbedtls_ecp_curve_info_from_name( q ) ) == NULL )
                goto usage;
            opt.ec_curve = curve_info->grp_id;
        }
#endif
        else if( strcmp( p, "filename" ) == 0 )
            opt.filename = q;
        else if( strcmp( p, "use_dev_random" ) == 0 )
        {
            opt.use_dev_random = atoi( q );
            if( opt.use_dev_random < 0 || opt.use_dev_random > 1 )
                goto usage;
        }
        else if( strcmp( p, "secret_id" ) == 0)
        {
          secret_id = strtoul((const char*)q, NULL, 16);
        }
        else if( strcmp( p, "secret_md5" ) == 0)
        {
          if (strlen(q) != 32)
          {
            mbedtls_printf( "Invalid secret md5 %s\n", q );
            goto usage;
          }
          else {
            for (int j = 0; j < 16; j++) {
              aux[0] = q[j*2];
              aux[1] = q[j*2+1];
              secret_md5[j] = (uint8_t)strtoul((const char*)&aux, NULL, 16);
            }
          }
        }        
        else
            goto usage;
    }

    exit_code = keygen(&opt, output_key, 16000);

    mbedtls_printf("output key = \n%s", output_key);

    if( ( f = fopen( opt.filename, "wb" ) ) == NULL )
        return( -1 );

    mbedtls_printf("SIZE = %d\n", (int)strlen((char*)output_key));
    if( fwrite( output_key, 1, strlen((char*)output_key), f ) != strlen((char*)output_key) )
    {
        fclose( f );
        return( -1 );
    }

    fclose( f );

exit:
    // return 0;
    mbedtls_exit( exit_code );
}