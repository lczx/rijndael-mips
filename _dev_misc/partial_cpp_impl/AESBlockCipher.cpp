// TODO: Fix insanity

#include "AESBlockCipher.h"

// !!! decrypt(...) AND genKeyMaterialAll(...) NOT IMPLEMENTED !!!

// Initial state of class caches
AESBlockCipher::Cache AESBlockCipher::cache =
	{nullptr, nullptr, nullptr, nullptr, nullptr};



// ----- PUBLIC -----



AESBlockCipher::AESBlockCipher()
{
	key = nullptr;
	rkeyi = nullptr;
	rkeyd = nullptr;
}

AESBlockCipher::AESBlockCipher(uint8_t *inkey, size_t ksz)
{
	// OMG C++11 IS BROKEN
	key = nullptr;
	rkeyi = nullptr;
	rkeyd = nullptr;

	// Silent fail, no catch ret.
	setKey(inkey, ksz);
}

AESBlockCipher::~AESBlockCipher()
{
	if (key != nullptr) free(key);
	if (rkeyi != nullptr) free(rkeyi);
	if (rkeyd != nullptr) free(rkeyd);
	// Other SHOULD be static
}



int AESBlockCipher::setKey(uint8_t *inkey, size_t ksz)
{
	if (inkey == 0) return EXIT_FAILURE; // Passed nullptr

	uint16_t bits = (uint16_t)ksz * 8;

	switch (bits) {
	case 128:
		opParams.Nk = 4; opParams.Nb = 4; opParams.Nr = 10;
		break;
	case 192:
		opParams.Nk = 6; opParams.Nb = 4; opParams.Nr = 12;
		break;
	case 256:
		opParams.Nk = 8; opParams.Nb = 4; opParams.Nr = 14;
		break;
	default:
		return EXIT_FAILURE; // Wrong size.
	}

	opParams.bits = bits;

	this->key = (uint8_t *)malloc(ksz);

	if (this->key == nullptr) return EXIT_FAILURE; // Cannot allocate

	memcpy(key, inkey, ksz);

	return EXIT_SUCCESS;
}

int AESBlockCipher::getKey(uint8_t *dst, size_t dsz)
{
	uint8_t amount = opParams.bits / 8;

	if (dst == 0 || this->key == 0)
		return EXIT_FAILURE; // No key or  invalid params

	if (dsz < amount) return EXIT_FAILURE; // Key too large

	memcpy(dst, this->key, amount);

	return opParams.bits / 8;
}



int AESBlockCipher::encrypt(uint8_t *in, size_t isz, uint8_t *out, size_t osz)
{
	// Offsets (but are they really considered by contemporary implementations?)
	//        C1  C2  C3
	// Nb=4    1   2   3
	// Nb=6    1   2   3
	// Nb=8    1   3   4

	if (isz != 4 * opParams.Nb || osz < 4 * opParams.Nb)
		return EXIT_FAILURE; // Wrong allocated memory size.

	// Check if we have a key... and generate everything we need,
	// including lookups and round key schedule.
	if (key == 0) return EXIT_FAILURE;
	genKeyMaterialEncrypt();

	uint32_t
		*buf = (uint32_t *)malloc(4 * opParams.Nb), // TEMP BUFFER IN
		*ret = (uint32_t *)malloc(4 * opParams.Nb); // TEMP BUFFER OUT
	uint32_t *tmp = nullptr; // 16 Bytes TEMP PTR

	/* BAD JOKING LITTLE ENDIAN PERF BOOST (ALSO ON KEYGEN) CAN BE MADE TO WORK, BUT I'M ALREADY CRAZY
	uint32_t *blockd = (uint32_t *)block;
	for (int i = 0; i < md.Nk; i++)
		buf[i] = blockd[i] ^ kd[i];*/

	// Reformat endianness, 1st round
	for (int i = 0; i < opParams.Nb; i++) {
		buf[i] = in[4*i] << 24 | in[4*i+1] << 16 |
			in[4*i+2] << 8 | in[4*i+3];
		buf[i] ^= rkeyd[i];
	}

	rjLookupTables *t = this->cache.lkD;

	// Mid rounds
	uint32_t x1, x2, x3, x4;
	for(int i = opParams.Nb; i < opParams.Nb * opParams.Nr; i++) {
		x1 = t->t0[ buf[(i + 0) % 4] >> 24        ];
		x2 = t->t1[ buf[(i + 1) % 4] >> 16 & 0xff ];
		x3 = t->t2[ buf[(i + 2) % 4] >>  8 & 0xff ];
		x4 = t->t3[ buf[(i + 3) % 4]       & 0xff ];
		ret[i % 4] = x1 ^ x2 ^ x3 ^ x4 ^ rkeyd[i];

		if (i % 4 == 3) { // Swap buffers:
			tmp = ret;    //  'buf' is always LATEST calculated value
			ret = buf;    //  'ret' can be OVERWRITTEN
			buf = tmp;    //  'tmp' value is INDETERMINED (= buf)
		}
	}

	// End round, no MixColumns
	for (int i = opParams.Nb * opParams.Nr; i < opParams.Nb * (opParams.Nr + 1); i++) {
		// The sbox (and lkp above) index is the input byte, sbox performs everything except
		// MixColumns, lkp mixes columns, each lkp table is the same, but rotated.
		// Here x1, x2, x3 XOR equals OR (but not Kd I think, watch out for precedence).
		// USING LOOKUPS, TAKING ADVANTAGE OF ....01.. IN 'EncrVector'
		x1 = t->t2[ buf[(i + 0) % 4] >> 24        ] & 0xff000000; // sbox[ buf[(i + 0) % 4] >> 24        ] << 24;
		x2 = t->t3[ buf[(i + 1) % 4] >> 16 & 0xff ] & 0x00ff0000; // sbox[ buf[(i + 1) % 4] >> 16 & 0xff ] << 16;
		x3 = t->t0[ buf[(i + 2) % 4] >>  8 & 0xff ] & 0x0000ff00; // sbox[ buf[(i + 2) % 4] >>  8 & 0xff ] << 8;
		x4 = t->t1[ buf[(i + 3) % 4]       & 0xff ] & 0x000000ff; // sbox[ buf[(i + 3) % 4]       & 0xff ];
		ret[i % 4] = x1 ^ x2 ^ x3 ^ x4 ^ rkeyd[i];
	}

	free(buf);

	uint8_t *ret8 = (uint8_t *)ret;
	uint32_t *out32 = (uint32_t *)out;
	// Reformat endianness
	for (int i = 0; i < opParams.Nb; i++) {
		out32[i] = ret8[4*i] << 24 | ret8[4*i+1] << 16 |
			ret8[4*i+2] << 8 | ret8[4*i+3];
	}

	return 4 * opParams.Nb;
}

int AESBlockCipher::decrypt(uint8_t *in, size_t isz, uint8_t *out, size_t osz)
{
	// Aah!
	// Blabla blablablabla, bla.

	// Iiii!
	//   Oooh!
	// Uuh!
	//   Aah!

	return 999;
}




void AESBlockCipher::preinitializeEncryptionTables()
{
	_staticInitializeSboxD();
	_staticInitializeLkupD();
	_staticInitializeRcon();
}

void AESBlockCipher::preinitializeDecryptionTables()
{
	_staticInitializeSboxI();
	_staticInitializeLkupI();
	_staticInitializeRcon();
}

void AESBlockCipher::preinitializeAllTables()
{
	preinitializeEncryptionTables();
	preinitializeDecryptionTables();
}



void AESBlockCipher::dumpSboxes()
{
	if (this->cache.sboxD == 0)
		std::cout << "Direct S-Box has not yet been computed." << std::endl;
	else {
		std::cout << std::endl << "Rijndael direct S-Box:" << std::endl;
		hexdump(this->cache.sboxD, 256, "  ");
	}

	if (this->cache.sboxI == 0)
		std::cout << "Inverse S-Box has not yet been computed." << std::endl;
	else {
		std::cout << std::endl << "Rijndael inverse S-Box:" << std::endl;
		hexdump(this->cache.sboxI, 256, "  ");
	}
}

void AESBlockCipher::dumpDirectLookups()
{
	if (this->cache.lkD == 0) {
		std::cout << "Direct lookup tables weren't computed yet." << std::endl;
		return;
	}

	std::cout << std::endl << "Rijndael 4k direct lookup tables:" << std::endl;
	for (int i = 0; i < 4; i++) {
		hexdump((uint32_t *)this->cache.lkD + i * 1024 / sizeof(uint32_t), 1024, "  ");
		std::cout << std::endl;
	}
}

void AESBlockCipher::dumpInverseLookups()
{
	if (this->cache.lkI == 0) {
		std::cout << "Inverse lookup tables weren't computed yet." << std::endl;
		return;
	}

	std::cout << std::endl << "Rijndael 4k inverse lookup tables:" << std::endl;
	for (int i = 0; i < 4; i++) {
		hexdump((uint32_t *)this->cache.lkI + i * 1024 / sizeof(uint32_t), 1024, "  ");
		std::cout << std::endl;
	}
}

void AESBlockCipher::dumpRcon()
{
	if (this->cache.rcon == 0)
		std::cout << "RCON values not yet calculated." << std::endl;
	else {
		std::cout << "First " << this->RconMaxSize << " RCON values:" << std::endl;
		hexdump(this->cache.rcon, this->RconMaxSize * sizeof(uint32_t), "  ");
	}
}

void AESBlockCipher::dumpDirectKeyExpansion()
{
	if (this->key == 0) {
		std::cout << "No encryption / decryption key defined." << std::endl;
		return;
	}

	if (this->rkeyd == 0)
		std::cout << "No current local ^1 key expansion defined." << std::endl;
	else {
		std::cout << "Current local ^1 key expansion cache:" << std::endl;
		// Size varies on key size, if key = 0, rkeyd = 0.
		// This will never be executed if key = 0, so no problems with opParams.
		hexdump(this->rkeyd, 4 * opParams.Nb * (opParams.Nr + 1), "  ");
	}
}

void AESBlockCipher::dumpInverseKeyExpansion()
{
	if (this->key == 0) {
		std::cout << "No encryption / decryption key defined." << std::endl;
		return;
	}

	if (this->rkeyi == 0)
		std::cout << "No current local ^-1 key expansion defined." << std::endl;
	else {
		std::cout << "Current local ^-1 key expansion cache:" << std::endl;
		// Never executed with undefined key, opParams here always defined.
		hexdump(this->rkeyi, 4 * opParams.Nb * (opParams.Nr + 1), "  ");
	}
}

void AESBlockCipher::dumpSetup()
{
	if (this->key == 0)
		std::cout << "No key specified." << std::endl;
	else {
		hexdump(this->key, opParams.bits / 8, "Key dump:     ");
		std::cout <<
			"  Mode:       AES-" << opParams.bits << "-ECB" << std::endl <<
			"  Key length: " << opParams.Nk << " dwords" << std::endl <<
			"  Block size: " << opParams.Nb << " dwords" << std::endl <<
			"  # rounds:   " << opParams.Nr << std::endl;
	}
}



// ----- PRIVATE -----


void AESBlockCipher::genKeyMaterialEncrypt()
{
	// Check on key size already done in 'setKey()'.
	// This generates caches if not already done.
	preinitializeEncryptionTables();

	rjLookupTables *t = this->cache.lkD;

	rkeyd = (uint32_t *)malloc(sizeof(uint32_t) * opParams.Nb * (opParams.Nr + 1));

	uint32_t temp;

	/* BAD JOKING LITTLE ENDIAN PERF BOOST
	uint32_t *keyd = (uint32_t *)key;
	for (int i = 0; i < md.Nk; i++)
		kd[i] = keyd[i];*/

	// If it was big endian... we only needed to recast pointer.
	for (int i = 0; i < opParams.Nk; i++)
		rkeyd[i] = key[4*i] << 24 | key[4*i+1] << 16 |
			key[4*i+2] << 8 | key[4*i+3];

	/* Default, non-lookup implementation
	for (int i = Nk; i < Nb * (Nr + 1); i++) {
		temp = w[i-1];
		if (i % Nk == 0) temp = subword(rotword(temp), sbox) ^ rcon(i / Nk);
		else if (Nk > 6 && i % Nk == 4) temp = subword(temp, sbox);
		w[i] = w[i - Nk] ^ temp;
	}
	*/

	for (int i = opParams.Nk; i < opParams.Nb * (opParams.Nr + 1); i++) {
		temp = rkeyd[i - 1];

		if (i % opParams.Nk == 0)
			temp =
				(t->t2[(temp >> 16) & 0xff] & 0xff000000) ^
				(t->t3[(temp >>  8) & 0xff] & 0x00ff0000) ^
				(t->t0[(temp      ) & 0xff] & 0x0000ff00) ^
				(t->t1[(temp >> 24)       ] & 0x000000ff) ^
				this->cache.rcon[i / opParams.Nk - 1]; // Fix array start
		else if (opParams.Nk > 6 && i % opParams.Nk == 4)
			temp =
				(t->t2[(temp >> 24)       ] & 0xff000000) ^
				(t->t3[(temp >> 16) & 0xff] & 0x00ff0000) ^
				(t->t0[(temp >>  8) & 0xff] & 0x0000ff00) ^
				(t->t1[(temp      ) & 0xff] & 0x000000ff);
		
		rkeyd[i] = rkeyd[i - opParams.Nk] ^ temp;
	}
}

void AESBlockCipher::genKeyMaterialAll()
{
	// This calls genKeyMaterialEncrypt and preinitializeDecryptionTables,
	// copies direct key expansion and invertes it, blabla, using OpenSSL's algorithm.
}



void AESBlockCipher::_staticInitializeSboxD()
{
	if (this->cache.sboxD != 0) return;

	uint8_t s, x, *dataptr = (uint8_t *)malloc(256);

	for (int i = 0; i < 256; i++) {
		// Multiplicative inverse
		s = _ginv(i);
		x = s;

		// Apply matrix
		for (uint8_t j = 0; j < 4; j++) {
			// Left-rotate s by 1.
			s = (s & 0x80) ? (s << 1) + 1 : (s << 1);
			x ^= s;
		}
		
		dataptr[i] = x ^ 0x63;
	}

	this->cache.sboxD = dataptr;
}

void AESBlockCipher::_staticInitializeSboxI()
{
	if (this->cache.sboxI != 0) return;

	uint8_t *dataptr = (uint8_t *)malloc(256);

	for (int i = 0; i < 256; i++) {
		// last row of inverse transform, inverted bits,
		// so we don't have to MSB->LSB input.
		uint8_t invt = 0x52;
		// For the direct matrix this should be instead:
		//uint8_t invt = 0xf8;

		uint8_t out = 0x00;

		// From bottom to top.
		for (int j = 0; j < 8; j++) {
			// Left-rotate by 1.
			invt = (invt & 0x80) ? (invt << 1) + 1 : (invt << 1);
			// Bit XOR alternative, if numbits odd out is true.
			out |= (_numbits(i & invt) % 2) << j;
		}
		dataptr[i] = _ginv(out ^ 0x05);
	}

	this->cache.sboxI = dataptr;
}

void AESBlockCipher::_staticInitializeLkupD()
{
	if (this->cache.lkD != 0) return;

	if (this->cache.sboxD == 0) _staticInitializeSboxD();
	this->cache.lkD = _fillLookup(this->cache.sboxD, EncrVector);
}

void AESBlockCipher::_staticInitializeLkupI()
{
	if (this->cache.lkI != 0) return;

	if (this->cache.sboxI == 0) _staticInitializeSboxI();
	this->cache.lkI = _fillLookup(this->cache.sboxI, DecrVector);
}

void AESBlockCipher::_staticInitializeRcon()
{
	if (this->cache.rcon != 0 || this->RconMaxSize < 2) return;
	this->cache.rcon = (uint32_t *)malloc(this->RconMaxSize * sizeof(uint32_t));

	this->cache.rcon[0] = 0x01000000;

	for (uint8_t i = 1, v = 0x02; i < RconMaxSize; i++, v = _gmul(v, 2))
		this->cache.rcon[i] = v << 24;
}



AESBlockCipher::rjLookupTables *AESBlockCipher::_fillLookup(uint8_t *sbox, uint32_t vector)
{
	uint8_t *t = (uint8_t *)malloc(sizeof(rjLookupTables));
	uint8_t *r = (uint8_t *)&vector;

	for (int i = 0; i < 4; i++) // Table index
		for (int j = 0; j < 256; j++) // S-BOX index
			for (int k = 0; k < 4; k++) // Transform index
				t[1024*i+4*j+k] = _gmul(sbox[j], r[(k + i) % 4]);

	return (rjLookupTables *)t;
}


	
int AESBlockCipher::_numbits(uint32_t i)
{
    i = i - ((i >> 1) & 0x55555555);
    i = (i & 0x33333333) + ((i >> 2) & 0x33333333);
    return (((i + (i >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
}

uint8_t AESBlockCipher::_ginv(uint8_t x)
{
    uint16_t
		u1 = 0,     // t
		u3 = 0x11b, // r (p)     // m(x)
		v1 = 1,     // newt
		v3 = x;     // newr (a)

    while (v3 != 0) {
        uint16_t t1, t3, // extended bits of v1, v3
			x, y; // grade calculus
		
		// A way to obtain max grade of fn?
		//   y = 01000000 ---> 01111111
        x = u3; x |= x>>1; x |= x>>2; x |= x>>4;
        y = v3; y |= y>>1; y |= y>>2; y |= y>>4;
        if (x >= y) {
			// q seems grade of x - grade y
            uint16_t z = x & ~y;
            uint8_t q = _numbits(z);

            t1 = u1 ^ (v1<<q);
            t3 = u3 ^ (v3<<q);
        } else {
            t1 = u1;
            t3 = u3;
        }
        u1 = v1; u3 = v3; // t = newt, n = newr

        v1 = t1; v3 = t3; // new* assume last cycle values
    }

    if (u1 >= 0x100) u1 ^= 0x11b;

    return (uint8_t)u1;
}



uint8_t AESBlockCipher::_gadd(uint8_t a, uint8_t b) {
	// Add two numbers in a GF(2^8) finite field
	return a ^ b;
}
 
uint8_t AESBlockCipher::_gsub(uint8_t a, uint8_t b) {
	// Subtract two numbers in a GF(2^8) finite field
	return a ^ b;
}
 
uint8_t AESBlockCipher::_gmul(uint8_t a, uint8_t b) {
	// Multiply two numbers in the GF(2^8) finite field defined 
	// by the polynomial x^8 + x^4 + x^3 + x + 1 = 0

	uint8_t p = 0;
	uint8_t counter;
	uint8_t carry;
	for (counter = 0; counter < 8; counter++) {
		if (b & 1) 
			p ^= a;
		carry = a & 0x80;  /* detect if x^8 term is about to be generated */
		a <<= 1;
		if (carry) 
			a ^= 0x001B; /* replace x^8 with x^4 + x^3 + x + 1 */
		b >>= 1;
	}
	return p;
}



template <typename T>
void hexdump(T *ptr, short siz, char *prefix)
{
	if (ptr == nullptr) {
		std::cout << "Are you kidding me?" << std::endl;
		return;
	}

	std::ios state(NULL);
	state.copyfmt(std::cout);

	std::cout << std::hex << prefix;
	for (int i = 0; i < siz/sizeof(T); i++) {
		if (i && !(i*sizeof(T) % 16)) std::cout << std::endl << prefix;
		std::cout << std::setw(2*sizeof(T)) << std::setfill('0') << (int)ptr[i] << " ";
	}
	std::cout << std::endl;

	std::cout.copyfmt(state);
}



/* UTILITY FUNCTIONS, NOT USED BY THE LOOKUP VERSION

// Get sbox value for each byte in 4B word
uint32_t subword(uint32_t d, uint8_t *sbox)
{
	uint8_t *dp = (uint8_t*)&d;
	for (int i = 0; i < 4; i++)
		dp[i] = sbox[dp[i]];
	return d;
}

// Rotate bytes to the left
// {s1, s2, s3, s4} => {s2, s3, s4, s1}
uint32_t rotword(uint32_t d) {
	return d << 8 | d >> 24;
}

// Self-made (=unreliable) power function for rcon()
uint8_t AESBlockCipher::_gpwr(uint8_t b, uint8_t e) {
	if (!e) return 0x01;
	uint8_t mul = b;
	for (int i = 1; i < e; i++) b = _gmul(b, mul);
	return b;
}

*/
