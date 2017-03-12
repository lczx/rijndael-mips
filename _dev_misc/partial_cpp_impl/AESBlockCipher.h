#ifndef _AES_BLOCK_CIPHER_H_
#define _AES_BLOCK_CIPHER_H_

#include <cstdint>    // Use universal variable types
#include <iostream>   // Print nice derp excuses
#include <iomanip>    // Hexdump format

/**
 * Rijndael "rèin-daal" FIPS / NIST Advanced Encryption Standard
 *   http://csrc.nist.gov/archive/aes/rijndael/Rijndael-ammended.pdf
 *   http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 *
 * CURRENTLY ONLY BLOCK DIRECT ENCRYPTION IS IMPLEMENTED, AES-192, AES-256
 * CIPHER SUITES ARE INCLUDED BUT NOT TESTED.
 * THIS MAY BE A BASIC BUILDING BLOCK FOR MORE COMPLEX SCHEMES LIKE
 * ELECTRONIC CODEBOOK (AES-128-ECB, AES-192-ECB, AES-256-ECB) AND
 * CIPHER-BLOCK CHAINING (AES-128-CBC, AES-192-CBC, AES-256-CBC) WITH INIT VECTOR.
 * 
 * Here follows simple introductions and biography about the various components.
 *
 *
 // AFFINE-TRANSFORMATION S-BOX //////////////////////////////
 * http://en.wikipedia.org/wiki/Rijndael_S-box
 *   fast algorithm for the direct one
 * http://crypto.stackexchange.com/questions/10996/
 *   fast algorithm for the inverse
 *
 *
 * The following transformation defines the S-box:
 *   / 1 0 0 0 1 1 1 1 \   / x0 \   / 1 \
 *   | 1 1 0 0 0 1 1 1 |   | x1 |   | 1 |
 *   | 1 1 1 0 0 0 1 1 |   | x2 |   | 0 |
 *   | 1 1 1 1 0 0 0 1 | . | x3 | + | 0 |
 *   | 1 1 1 1 1 0 0 0 |   | x4 |   | 0 |
 *   | 0 1 1 1 1 1 0 0 |   | x5 |   | 1 |
 *   | 0 0 1 1 1 1 1 0 |   | x6 |   | 1 |
 *   \ 0 0 0 1 1 1 1 1 /   \ x7 /   \ 0 /
 * where
 * - [x0:x7] are the bits of the multiplicative inverse
 *   of the table index
 * - the addition is defined by the XOR operation
 * - the affine transformation is defined as
 *     A^4 x + A^3 x + A^2 x + A x + x + 0x63
 *     (A^4 + A^3 + A^2 + A + eye(8)) x + 0x63
 *   where A is the matrix
 *   >> A = [ 0 0 0 0 0 0 0 1;
 *            1 0 0 0 0 0 0 0;
 *            0 1 0 0 0 0 0 0;
 *            0 0 1 0 0 0 0 0;
 *            0 0 0 1 0 0 0 0;
 *            0 0 0 0 1 0 0 0;
 *            0 0 0 0 0 1 0 0;
 *            0 0 0 0 0 0 1 0 ]
 *   always using XOR as add
 *
 *
 // 4K LOOKUP TABLES /////////////////////////////////////////
 * Each lookup table is the application of the S-Box and the
 * rotated transform, which converts each byte of the S-Box
 * to a DWORD, the MixColumns transform is defined as (sect. 4.2.3):
 *     c(x) + d(x) = '01' (+ is XOR)
 *   direct  --> c(x) = '03' x^3 + '01' x^2 + '01' x + '02'
 *   inverse --> d(x) = '0B' x^3 + '0D' x^2 + '09' x + '0E'
 *
 * Each resulting 1K table is the rotbyte of the previous.
 * Everything can be made with a single table and rotating.
 * With 4K of cache lookup tables we don't have do do 'rotbyte'
 * operations during encoding / decoding.
 *
 * In case of embedded systems with low available memory, only 1K
 * or only the S-Box can be used, with a loss of performance.
 *
 *
 // EUCLIDEAN CALCULATION OF INVERSE //////////////////////////////
 * http://crypto.stackexchange.com/questions/12956/
 *   Answer
// http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
 *   Description of the algorithm / Examples
 *   Simple Algebraic field extensions
 *
 *
 // RIJNDAEL'S BASIC FINITE FIELD MATH //////////////////////////////
 * http://en.wikipedia.org/wiki/Finite_field_arithmetic
 *
 *
 // >>> KEYS USED IN THE DOCS FOR TESTING <<< ///////////////////////

 TESTING KEYS (size = 4 * Nk) FOR KEY EXPANSION
	const uint8_t key128[] = {
		0x2B, 0x7E, 0x15, 0x16,
		0x28, 0xAE, 0xD2, 0xA6,
		0xAB, 0xF7, 0x15, 0x88,
		0x09, 0xCF, 0x4F, 0x3C };
	const uint8_t key192[] = {
		0x8E, 0x73, 0xB0, 0xF7,
		0xDA, 0x0E, 0x64, 0x52,
		0xC8, 0x10, 0xF3, 0x2B,
		0x80, 0x90, 0x79, 0xE5,
		0x62, 0xF8, 0xEA, 0xD2,
		0x52, 0x2C, 0x6B, 0x7B };
	const uint8_t key256[] = {
		0x60, 0x3D, 0xEB, 0x10,
		0x15, 0xCA, 0x71, 0xBE,
		0x2B, 0x73, 0xAE, 0xF0,
		0x85, 0x7D, 0x77, 0x81,
		0x1F, 0x35, 0x2C, 0x07,
		0x3B, 0x61, 0x08, 0xD7,
		0x2D, 0x98, 0x10, 0xA3,
		0x09, 0x14, 0xDF, 0xF4 };

 *
 *
 */



class AESBlockCipher {

public:

	/**
	 * Constructor with passed-in key and key size (in bytes), it will be copied locally.
	 * You can otherwise pass the key later using 'setKey()'.
	 */
	AESBlockCipher();
	AESBlockCipher(uint8_t *inkey, size_t ksz);

	/**
	 * Language called class destructor, cleanup of non-static (non-cache) heap.
	 */
	~AESBlockCipher();
	
	/**
	 * Set the key used for data processing. Returns EXIT_SUCCESS if key size is adequate.
	 * It invalidates previous generated key expansions.
	 */
	int setKey(uint8_t *inkey, size_t ksz);

	/**
	 * Get the key previously stored for processing, returns EXIT_FAILURE if the key was not defined.
	 * Else it returns the amount of bytes copied.
	 */
	int getKey(uint8_t *dst, size_t dsz);

	/**
	 * Main encryption/decryption methods, AES-128, AES-192, AES-256 choosen basing on key size.
	 * Since we are working with the base block cipher, the only allowed input size is of 16 bytes.
	 * Returns output size if everything went OK.
	 */
	int encrypt(uint8_t *in, size_t isz, uint8_t *out, size_t osz);
	int decrypt(uint8_t *in, size_t isz, uint8_t *out, size_t osz);

	/**
	 * Advanced methods for performance critical implementations, allows to initialize static fast caches
	 * (S-Box, lookup tables, Rcon) before first call to encrypt/decrypt methods.
	 */
	void preinitializeEncryptionTables();
	void preinitializeDecryptionTables();
	void preinitializeAllTables();

	/**
	 * Debug hexdump methods for checking data generation, caches and options. Prints on the stdout.
	 */
	void dumpSboxes();
	void dumpDirectLookups();
	void dumpInverseLookups();
	void dumpRcon();
	void dumpDirectKeyExpansion();
	void dumpInverseKeyExpansion();
	void dumpSetup();


private:

	// The given key. Used to generate key material for processing rounds.
	uint8_t *key;

	// Operation parameters generated from given key size and used for
	// key material generation and data processing.
	struct {
		uint16_t bits; // 128 .. 256
		uint16_t Nk; // Key lenght
		uint16_t Nb; // Block size
		uint16_t Nr; // # rounds
	} opParams;

	// Generated round key material is stored here in order to
	// speed-up consecutive encryptions with the same key.
	// On encryption/decryption or preload, if the current key doesn't
	// equal the first entry of this, the list is invalidated and recalculated.
	uint32_t *rkeyd, *rkeyi;

	// Struct of equal 4k sized lookup tables. They are rotword()ed versions of each other.
	struct rjLookupTables {
		uint32_t t0[256];
		uint32_t t1[256];
		uint32_t t2[256];
		uint32_t t3[256];
	};

	// Static cache structure
	static struct Cache {
		uint8_t *sboxD;
		rjLookupTables *lkD;
		uint8_t *sboxI;
		rjLookupTables *lkI;
		uint32_t *rcon;
	} cache;

	// Maximum rcon table expansion level (0x36000000), we will never go beyond that.
	// The expansion function will do nothing if this value is less than 2.
	static const uint16_t
		RconMaxSize = 10;

	// Constants for 4k lookup tables generation from S-Box.
	static const uint32_t
		EncrVector = 0x02010103,
		DecrVector = 0x0e090d0b;


	/**
	 * Key expansion algorithm, the decryption algorithm requires the key expansion
	 * for encryption to be available, so if invoked, it fills out both 'rkeyd' and 'rkeyi'.
	 */
	void genKeyMaterialEncrypt();
	void genKeyMaterialAll();


	// For a better rcon table, consider avoiding _gpwr and, instead
	// using a multiply, store, multiply, store approach until reaching
	// a constant defined max-size (0x36..) as an index.


	/**
	 * Invoked by preinitialize* to calculate S-Boxes, lookup tables and rcon,
	 * allocates memory on the heap and sets cache pointer.
	 * Does nothing if the cache already exists.
	 */
	void _staticInitializeSboxD();
	void _staticInitializeSboxI();
	void _staticInitializeLkupD();
	void _staticInitializeLkupI();
	void _staticInitializeRcon();

	/**
	 * Internal lookup table initialization, call '_staticInitializeLkupX()' instead.
	 */
	rjLookupTables *_fillLookup(uint8_t *sbox, uint32_t vector);
	
	/**
	 * These math. utilities are used for the S-Box calculation
	 */
	int _numbits(uint32_t i);
	uint8_t _ginv(uint8_t x);

	/**
	 * These are basic GF(2^8) operations, used for S-Box and Rcon calculus.
	 */
	uint8_t _gadd(uint8_t a, uint8_t b);
	uint8_t _gsub(uint8_t a, uint8_t b);
	uint8_t _gmul(uint8_t a, uint8_t b);
};


// Dump utility function
template <typename T>
void hexdump(T *ptr, short siz, char *prefix = "");

#endif // _AES_BLOCK_CIPHER_H_
