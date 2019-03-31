#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define MAX_BUFFER_SIZE 1024
#define MIN_KEY_LEN 256

/** Function Definitions **/
int validate_cert(char* file_path, char* cert_URL);
char* get_ext(X509 *cert, int nid);

/** Structures for storing input information from the input csv **/
// Change these to regular non-typedef structs
typedef struct {
  char *file_path;
  char *cert_URL;
} file_data_t;

typedef struct {
  file_data_t **array;
  size_t size;
} all_t;

/** The main function, it loads in the values in the CSV filename specified by
the value of the provided command-line argument. It then runs through each
'test' one-by-one, validating certificates and writing to an output file
'output.csv' **/
int main(int argc, char **argv) {
    int i=0;

    // Initial memory allocation for certificate input data
    all_t *cert_data=NULL;
    cert_data = (all_t*)malloc(sizeof(all_t));
    cert_data->array = (file_data_t**)malloc(sizeof(file_data_t*));
    cert_data->array[i] = (file_data_t*)malloc((i+1)*sizeof(file_data_t));
    cert_data->array[i]->file_path = (char*)malloc(sizeof(char));
    cert_data->array[i]->cert_URL = (char*)malloc(sizeof(char));
    cert_data->size = 0;

    // We weren't given a file name in the command line
    if (argc < 2) {
      fprintf(stderr,"ERROR, incorrect arguments provided\n");
      exit(EXIT_FAILURE);
    }

    // Open up the file specified by the command-line input
    FILE *fp = fopen(argv[1], "r");
    char r_buffer[MAX_BUFFER_SIZE];
    if (fp != NULL) {
      const char s[2] = ",";
      const char r[2] = "\n";
      // Read the CSV line by line
      while (fgets(r_buffer, sizeof(r_buffer), fp)) {
        // Get the first value (the file path for the certificate
        // and put it in the storing structures
        char* token = strtok(r_buffer, s);
        strcpy(cert_data->array[i]->file_path,token);
        // And the second value (the certificate URL)
        token = strtok(NULL, r);
        strcpy(cert_data->array[i]->cert_URL,token);
        i++;
        // Update memory allocations for our storing structures
        cert_data->size = cert_data->size+1;
        cert_data->array = realloc(cert_data->array, (i+1)*sizeof(file_data_t*));
        cert_data->array[i] = (file_data_t*)malloc((i+1)*sizeof(file_data_t));
        cert_data->array[i]->file_path = (char*)malloc(sizeof(char));
        cert_data->array[i]->cert_URL = (char*)malloc(sizeof(char));
      }
    }

    // Close the input file and initialise an output file 'output.csv'
    fclose(fp);
    FILE *fo = fopen("output.csv", "w");
    // Run through each 'test', and write to 'output.csv' based on the result
    // of each of these tests
    for (i=0; i<cert_data->size; i++) {
      char* file_path = cert_data->array[i]->file_path;
      char* cert_URL = cert_data->array[i]->cert_URL;
      fprintf(fo, "%s,%s,", file_path, cert_URL);
      // Here we validate the certificate
      fprintf(fo, "%d\n", validate_cert(file_path, cert_URL));
    }

    // Close the output file, free memory and return
    fclose(fo);
    for (i=0; i<=cert_data->size; i++) {
      free(cert_data->array[i]->file_path);
      free(cert_data->array[i]->cert_URL);
      free(cert_data->array[i]);
    }
    free(cert_data->array);
    free(cert_data);
    return 0;
}

/** The function for validating certificates, given two arguments
'file_path', the path to the certificate file and 'cert_URL', the URL
the certificate was sourced from, validates these certificates against the
following:
- notBefore
- notAfter
- commonName
- min. RSA key length
- keyUsage (BasicConstraints and TLS Web Server Authentication)
- subjectAlternativeNames UNTESTED
Return 1 if the certificate is valid, return 0 otherwise **/
int validate_cert(char* file_path, char* cert_URL) {
  BIO *certificate_bio = NULL;
  X509 *cert = NULL;

  // Initialise openSSL
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  // Create BIO object to read certificate
  certificate_bio = BIO_new(BIO_s_file());

  // Read certificate into BIO
  if (!(BIO_read_filename(certificate_bio, file_path))) {
      fprintf(stderr, "Error in reading cert BIO filename");
      exit(EXIT_FAILURE);
  }
  if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL))) {
      fprintf(stderr, "Error in loading certificate");
      exit(EXIT_FAILURE);
  }
  // Cert now contains the x509 certificate

  // Check notBefore and notAfter dates, use ASN1_TIME_diff to compare them
  // to the current time
  const ASN1_TIME *not_before = X509_get_notBefore(cert);
  const ASN1_TIME *not_after = X509_get_notAfter(cert);
  int day;
  int sec;
  // Checking notBefore
  ASN1_TIME_diff(&day, &sec, NULL, not_before);
  if (day>0 || sec>0) {
    return 0;
  }
  // Checking notAfter
  ASN1_TIME_diff(&day, &sec, NULL, not_after);
  if (day<0 || sec<0) {
    return 0;
  }

  // Check if the URL the certificate was sourced from matches the commonName
  // In the case it doesn't, we check wildcard cases as well as subjectAltNames
  char cert_cn[MAX_BUFFER_SIZE] = "Cert CN NOT FOUND";
  X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, cert_cn, MAX_BUFFER_SIZE);
  // We don't have a match with commonName, so have to do some more checks
  if (strcmp(cert_cn, cert_URL)) {
    // We have a wildcard commonName, check if the URL fits this wildcard
    if (strstr(cert_cn, "*") != NULL) {
      char* cert_cut = cert_cn + 1;
      // The URL doesn't fit the commonName wildcard
      if (strstr(cert_URL, cert_cut) == NULL || strstr(strtok(cert_URL, cert_cut), ".") != NULL) {
        // Now we have to check through the subjectAltNames to see if
        // any of them match the certificate URL
        // Generating the desired 'wildcard' entry, note this regrettably does not
        // handle partial wildcards
        char *full_wild = malloc(strlen(cert_URL)+1);
        strcpy(full_wild, "*");
        strcat(full_wild, strstr(cert_URL, "."));
        char* san = get_ext(cert, NID_subject_alt_name);
        // Now see if we can find the wildcard or the full URL in the SAN
        if (san != NULL) {
          if (strstr(san, cert_URL) == NULL) {
            if (strstr(san, full_wild) == NULL) {
              return 0;
            }
          }
        }
        // No subjectAltNames so there's nothing left to check, invalid
        else {
          return 0;
        }
      }
    }
    // Not a wildcard, can skip straight to subjectAltNames, same process
    else {
      char *full_wild = malloc(strlen(cert_URL)+1);
      strcpy(full_wild, "*");
      strcat(full_wild, strstr(cert_URL, "."));
      char* san = get_ext(cert, NID_subject_alt_name);
      if (san != NULL) {
        if (strstr(san, cert_URL) == NULL) {
          if (strstr(san, full_wild) == NULL) {
            return 0;
          }
        }
      }
      else {
        return 0;
      }
    }
  }

  // Checking that the RSA key length is greater than 2048 bits
  EVP_PKEY *pubkey = X509_get_pubkey(cert);
  // EVP_PKEY_size returns bytes so have to check against 2048/8 = 256
  if (EVP_PKEY_size(pubkey)<MIN_KEY_LEN) {
    return 0;
  }

  // Checking that "CA:FALSE" exists in basicConstraints by seeing if "CA:TRUE"
  // is in basicConstraints (CA is a mandatory field)
  char* bc = get_ext(cert, NID_basic_constraints);
  if (strstr(bc, "CA:TRUE")) {
    return 0;
  }

  // Checking that "TLS Web Server Authentication" exists in extKeyUsage
  char* ext_ku = get_ext(cert, NID_ext_key_usage);
  if (strstr(ext_ku, "serverAuth") == NULL && strstr(ext_ku, "TLS Web Server Authentication") == NULL) {
    return 0;
  }

  // All checks made, the certificate is valid, so free memory and return valid
  X509_free(cert);
  BIO_free_all(certificate_bio);
  return 1;
}

/** Given a certificate 'cert' and the NID of the extension desired 'nid',
returns a string of the desired extension **/
char* get_ext(X509 *cert, int nid) {
  // Find out where the extension is, make sure it exists as well before
  // going further
  int loc = X509_get_ext_by_NID(cert, nid, -1);
  if (loc >= 0) {
    // Use this location to extract the extension
    X509_EXTENSION *ext = X509_get_ext(cert, loc);

    // Buffer and a pointer to the buffer
    BUF_MEM *bptr = NULL;
    char *buf = NULL;

    // Create a BIO, which we write the contents of the extension to
    BIO *bio = BIO_new(BIO_s_mem());
    if (!X509V3_EXT_print(bio, ext, 0, 0)) {
        fprintf(stderr, "Error in reading extensions");
    }
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);
    // bptr->data is not NULL terminated - add null character
    buf = (char *)malloc((bptr->length + 1) * sizeof(char));
    memcpy(buf, bptr->data, bptr->length);
    buf[bptr->length] = '\0';

    // Free the memory of the BIO object and return the string buffer
    BIO_free_all(bio);
    return buf;
  }
  // No extension found, so return NULL
  else {
    return NULL;
  }
}
