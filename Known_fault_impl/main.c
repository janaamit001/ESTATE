#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <stdlib.h>

#include "crypto_aead.h"
#include "api.h"

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

#define MAX_FILE_NAME				256
#define MAX_MESSAGE_LENGTH			32
#define MAX_ASSOCIATED_DATA_LENGTH	32
#define number 2
#define sboxSize 256


extern unsigned char ftag[ 16 ], st_sb[16];
unsigned char tag1[16];

unsigned char s[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};



void init_buffer(unsigned char *buffer, unsigned long long numbytes);

void fprint_bstr(FILE *fp, const char *label, const unsigned char *data, unsigned long long length);

int generate_test_vectors();

int main()
{
	int ret = generate_test_vectors();

	if (ret != KAT_SUCCESS) {
		fprintf(stderr, "test vector generation failed with code %d\n", ret);
	}

	return ret;
}


void print( unsigned char *m ) {

	/*printf("Ciphertext::\n");
	for( short i = 0; i < 64; ++i )
		printf("%2x ", m[ i ]);
		
	printf("\n\n");*/
	
	printf("Tag::\n");
	for( short i = 0; i < 16; ++i )
		printf("%02x ", m[ i ]);
		
	printf("\n\n");

	return;
}																																												

/*int generate_test_vectors()
{
	FILE                *fp;
	char                fileName[MAX_FILE_NAME];
	unsigned char       key[CRYPTO_KEYBYTES];
	unsigned char		nonce[CRYPTO_NPUBBYTES];
	unsigned char       msg[MAX_MESSAGE_LENGTH];
	unsigned char       msg2[MAX_MESSAGE_LENGTH];
	unsigned char		ad[MAX_ASSOCIATED_DATA_LENGTH];
	unsigned char		ct[MAX_MESSAGE_LENGTH + CRYPTO_ABYTES];
	unsigned long long  clen, mlen2;
	int                 count = 1;
	int                 func_ret, ret_val = KAT_SUCCESS;

	init_buffer(key, sizeof(key));
	init_buffer(nonce, sizeof(nonce));
	init_buffer(msg, sizeof(msg));
	init_buffer(ad, sizeof(ad));

	sprintf(fileName, "LWC_AEAD_KAT_%d_%d.txt", (CRYPTO_KEYBYTES * 8), (CRYPTO_NPUBBYTES * 8));

	if ((fp = fopen(fileName, "w")) == NULL) {
		fprintf(stderr, "Couldn't open <%s> for write\n", fileName);
		return KAT_FILE_OPEN_ERROR;
	}

	for (unsigned long long mlen = 0; (mlen <= MAX_MESSAGE_LENGTH) && (ret_val == KAT_SUCCESS); mlen++) {

		for (unsigned long long adlen = 0; adlen <= MAX_ASSOCIATED_DATA_LENGTH; adlen++) {

			fprintf(fp, "Count = %d\n", count++);

			fprint_bstr(fp, "Key = ", key, CRYPTO_KEYBYTES);

			fprint_bstr(fp, "Nonce = ", nonce, CRYPTO_NPUBBYTES);

			fprint_bstr(fp, "PT = ", msg, mlen);

			fprint_bstr(fp, "AD = ", ad, adlen);

			if ((func_ret = crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen, NULL, nonce, key)) != 0) {
				fprintf(fp, "crypto_aead_encrypt returned <%d>\n", func_ret);
				ret_val = KAT_CRYPTO_FAILURE;
				break;
			}

			fprint_bstr(fp, "CT = ", ct, clen);

			fprintf(fp, "\n");

			if ((func_ret = crypto_aead_decrypt(msg2, &mlen2, NULL, ct, clen, ad, adlen, nonce, key)) != 0) {
				fprintf(fp, "crypto_aead_decrypt returned <%d>\n", func_ret);
				ret_val = KAT_CRYPTO_FAILURE;
				break;
			}

			if (mlen != mlen2) {
				fprintf(fp, "crypto_aead_decrypt returned bad 'mlen': Got <%llu>, expected <%llu>\n", mlen2, mlen);
				ret_val = KAT_CRYPTO_FAILURE;
				break;
			}

			if (memcmp(msg, msg2, mlen)) {
				fprintf(fp, "crypto_aead_decrypt did not recover the plaintext\n");
				ret_val = KAT_CRYPTO_FAILURE;
				break;
			}
		}
	}

	fclose(fp);

	return ret_val;
}*/


void shift_rows1(unsigned char *state_bytes)
{
    unsigned char state_;
    
    // first row
    state_ = state_bytes[1];
    state_bytes[1] = state_bytes[5];
    state_bytes[5] = state_bytes[9];
    state_bytes[9] = state_bytes[13];
    state_bytes[13] = state_;
    
    // second row
    state_ = state_bytes[2];
    state_bytes[2] = state_bytes[10];
    state_bytes[10] = state_;
    state_ = state_bytes[6];
    state_bytes[6] = state_bytes[14];
    state_bytes[14] = state_;
    
    // third row
    state_ = state_bytes[15];
    state_bytes[15] = state_bytes[11];
    state_bytes[11] = state_bytes[7];
    state_bytes[7] = state_bytes[3];
    state_bytes[3] = state_;
}


void xor_of_diff_tag( unsigned char state[ ], unsigned char ct1[] ) {

	unsigned char byte[ 16 ];
	short i, j, counter = 0;
	
	/*for( i = 0; i < 4; ++i ) {
	
		for( j = 0; j < 4; ++j ) {
		
			//byte[ counter ] = (( state[ i ][ j ] << 4 ) & 0xf0 ) ^ ( state[ i ][ j + 1 ] & 0x0f );
			byte[i*4+j]  = state[i][j*2  ] << 4;
			byte[i*4+j] |= state[i][j*2+1];
		}
	}*/
	
	//memset(byte, 0, 32);
	/*for (i = 0; i < 64; i++)
	{
		byte[i / 2] |= (state[i / D][i % D] & 0xf) << (4 * (i & 1));
		//ct1[i / 2] |= ((state[i / D][i % D] & 0xf) << (4 * (i & 1)) );
	}
	
	counter = 0;*/
	printf("xoring differences in the tag::\n");
	for( i = 0; i < 16; ++i ) {
	
		ct1[ i ] = ct1[ i ] ^ state[ i ];
		//++counter;
	}

	return;
}


void print_state( unsigned char st[  ] ) {

	//for( short i = 0; i < 16; ++i ) {
	
		//for( short j = 0; j < 8; ++j ) 
			printf("%02x %02x %02x %02x ", st[0], st[4 ], st[ 8], st[ 12] );
			printf("\n");
			
			printf("%02x %02x %02x %02x ", st[1 ], st[5 ], st[ 9], st[13 ] );
			printf("\n");
			
			printf("%02x %02x %02x %02x ", st[ 2], st[ 6], st[ 10], st[ 14] );
			printf("\n");
			
			printf("%02x %02x %02x %02x ", st[ 3], st[7 ], st[ 11], st[15 ] );
			printf("\n");

	return;
}


unsigned char **diffDistribution(unsigned char s[sboxSize]) {

	int i; 
	int x, y, delta, delta1;
	
	unsigned char** count = malloc(sboxSize*sizeof(int *));
	
	for(i = 0; i < sboxSize; ++i) {
		
		count[i] = malloc(sboxSize*sizeof(int));
		memset(count[i],0,sboxSize*sizeof(int));
	}
		
	for(y = 0; y < sboxSize; ++y) {
		
		for(x = 0; x < sboxSize; ++x) {
			
			delta = y^x;
			delta1 = s[x]^s[y];
			count[delta][delta1]++;
		}		
	}
	
	return count;
}



void invShiftRow(unsigned char *state_bytes)
{
    unsigned char state_;
    
    // first row
    state_ = state_bytes[13];
    state_bytes[13] = state_bytes[9];
    state_bytes[9] = state_bytes[5];
    state_bytes[5] = state_bytes[1];
    state_bytes[1] = state_;
    
    // second row
    state_ = state_bytes[14];
    state_bytes[14] = state_bytes[6];
    state_bytes[6] = state_;
    state_ = state_bytes[10];
    state_bytes[10] = state_bytes[2];
    state_bytes[2] = state_;
    
    // third row
    state_ = state_bytes[3];
    state_bytes[3] = state_bytes[7];
    state_bytes[7] = state_bytes[11];
    state_bytes[11] = state_bytes[15];
    state_bytes[15] = state_;
}


void fprint_bstr1(FILE *fp, const char *label, const unsigned char *data, unsigned long long length)
{    
    fprintf(fp, "%s", label);
        
	for (unsigned long long i = 0; i < length; i++)
		fprintf(fp, "%02x", data[i]);
	    
    //fprintf(fp, "\n");
}


void Recover_state_columnwise( unsigned char known_diff, unsigned char pos, unsigned char count, unsigned char **ptr ) {

	unsigned char nfst[ 16 ], fst[ 16 ], temp[ 16 ], col[ 8 ][ 8 ];
	FILE *f0, *f1, *f2, *f3, *f4, *f5, *f6, *f7;
	unsigned char diff[ 8 ], diff1[ 8 ], delta, filename[ 24 ];
	unsigned char i, j;
	time_t t;

	srand( (unsigned) time( &t ) );

	for (i = 0; i < 16; i++)
	{
		nfst[ i ] = tag1[i];
		fst[ i ] = ftag[i];
		//fst[i / 8][i % 8] = (ftag[i / 2] >> (4 * ((i & 1)))) & 0xf;
		
		//state[i / D][i % D] = (state_inout[i / 2] >> (4 * (i & 1))) & 0xf;
	}
	
	for( i = 0; i < 16; ++i ) {
	
		//for( j = 0; j < 8; ++j ) 
		temp[ i ] = nfst[ i ] ^ fst[ i ];
	}
	
	
	
	
	//print_state(nfst);
	//print_state(fst);
	
	//print_state(temp);
	printf("Full state difference before sr::\n");
	printf("%02x %02x %02x %02x ", temp[0], temp[4 ], temp[ 8], temp[ 12] );
	printf("\n");
	
	printf("%02x %02x %02x %02x ", temp[1 ], temp[5 ], temp[ 9], temp[13 ] );
	printf("\n");
	
	printf("%02x %02x %02x %02x ", temp[ 2], temp[ 6], temp[ 10], temp[ 14] );
	printf("\n");
	
	printf("%02x %02x %02x %02x ", temp[ 3], temp[7 ], temp[ 11], temp[15 ] );
	printf("\n");
	
	/*for( short i = 0; i < 8; ++i ) {
	
		for( short j = 0; j < 8; ++j ) 
			printf("%x ", temp[ i ][ j ] );
		
		printf("\n");
	}*/
	
	printf("\n");
	
	//invMixColumn( temp );
	//print_state( temp );
	invShiftRow( temp );
	//print_state( temp );
	
	printf("Full state difference after inverse sr::\n");
	printf("%02x %02x %02x %02x ", temp[0], temp[4 ], temp[ 8], temp[ 12] );
	printf("\n");
	
	printf("%02x %02x %02x %02x ", temp[1 ], temp[5 ], temp[ 9], temp[13 ] );
	printf("\n");
	
	printf("%02x %02x %02x %02x ", temp[ 2], temp[ 6], temp[ 10], temp[ 14] );
	printf("\n");
	
	printf("%02x %02x %02x %02x ", temp[ 3], temp[7 ], temp[ 11], temp[15 ] );
	printf("\n");
	
	/*for( short i = 0; i < 8; ++i ) {
	
		for( short j = 0; j < 8; ++j ) 
			printf("%x ", temp[ i ][ j ] );
		
		printf("\n");
	}*/
	
	printf("\n");
	
	printf("Right hand diff:\n");
	diff[ 0 ] = temp[ pos ];
	
	
	
	//state_inout[i / 2] |= (state[i / D][i % D] & 0xf) << (4 * (i & 1));
	
	
	
	printf("= %x\n", diff[0]);
		
	sprintf(filename, "key_column%d,%d,%d,0.txt", pos%4,(pos/4), count);
	if ((f0 = fopen(filename, "w+")) == NULL) {
		fprintf(stderr, "Couldn't open <%s> for write\n", filename);
		exit(1);
	}
	for( i = 0; i < 256; ++i ) {
	
		
		//printf("0-> %x %x %x\n", i, s[ i ] ^ s[ i ^ diff1[ 0 ] ], diff[ 0 ]);
		if( ( s[ i ] ^ s[ i ^ known_diff ] ) == diff[ 0 ] ) {
			
			printf("f0:: i = %x, diff = %x\n", i, diff[ 0 ]);
			fprint_bstr1(f0, "", &i, 1);
		}
		
		if( i == 255 )
			break;
	}
	
	fclose( f0 );
		
	return;
}



unsigned short findMax( unsigned short arr[] ) {

	unsigned short max = 0;

	for( unsigned char i = 0; i < 256; ++i ) {
	
		if( max < arr[ i ] )
			max = arr[ i ];
			
		if(i == 255)
			break;
	}

	return( max );
}




void state_nibble( unsigned char pos, unsigned char value ) {

	FILE *fp1; 
	unsigned char val[2], val1;
	unsigned short max, arr[ 256 ] = {0};
	unsigned short num = 0, count1 = 0;
	unsigned char filename[ 24 ];

	//int number = 8;
	//printf("State[%d]\n");
	
	printf("count = %d, ", value);
	for( unsigned char count = 0; count < value; ++count ) {
	
		sprintf(filename, "key_column%d,%d,%d,0.txt", pos%4,(pos/4),count);
		if ((fp1 = fopen(filename, "r+")) == NULL) {
			fprintf(stderr, "Couldn't open <%s> for read\n", filename);
			exit(1);
		}
		fseek(fp1, 0, SEEK_SET);
		while(fread(&val, 1, 2, fp1) == 2) {
		

			//printf ("val[0] = %c, val[1] = %c\n", val[0], val[1]);
			if( ( val[0] == 'a' ) || ( val[0] == 'b' ) || ( val[0] == 'c' ) || ( val[0] == 'd' ) || ( val[0] == 'e' ) || ( val[0] == 'f' ) )
				val[0] = val[0] - 97 + 10;
			else 
				val[0] = val[0] - 48;
				
			if( ( val[1] == 'a' ) || ( val[1] == 'b' ) || ( val[1] == 'c' ) || ( val[1] == 'd' ) || ( val[1] == 'e' ) || ( val[1] == 'f' ) )
				val[1] = val[1] - 97 + 10;
			else 
				val[1] = val[1] - 48;
			
			val1 = 16*val[0]+val[1];	
			//printf ("......val1 = %x\n", val1);
			
			arr[ val1 ] += 1;
		}
		//printf("\n");
		fclose( fp1 );
	}
	printf("Recovered nibble value at (%d,%d)-th position of the state::\n", pos%4, pos/4);
	printf("{ ");

	max = findMax( arr );
	printf("max = %d:: ", max);
	for( unsigned char i = 0; i < 256; ++i ) {

		if( arr[ i ] == max ) {
		
			printf("%x ", i );
			//printf("1st column = %04x\n", i);
			//++count1;
		}
		if(i == 255)
			break;
	}
	printf("}\n\n");
	
	return;
}





int generate_test_vectors()
{
	FILE                *fp;
	char                fileName[MAX_FILE_NAME];
	unsigned char       key[CRYPTO_KEYBYTES] = {0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0xf1};
	unsigned char		nonce[CRYPTO_NPUBBYTES] = {0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0xf1};
	unsigned char       msg[MAX_MESSAGE_LENGTH] = {0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0xf1};
	unsigned char       msg2[MAX_MESSAGE_LENGTH];
	unsigned char		ad[MAX_ASSOCIATED_DATA_LENGTH] = {0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0x10, 0x20, 0x30, 0xf1};
	unsigned char		ct[MAX_MESSAGE_LENGTH + CRYPTO_ABYTES], ct1[MAX_MESSAGE_LENGTH + CRYPTO_ABYTES];
	//unsigned long long  clen, mlen2;
	//int                 count = 1;
	int                 func_ret, ret_val = KAT_SUCCESS;
	
	unsigned long long mlen, mlen2, clen, adlen;
	unsigned char diff, diff1;
	unsigned char state[ 16 ];
	unsigned char i1;
	unsigned char count = 0, pos = 0;
	unsigned char **ddt = diffDistribution(s);
	unsigned char i, j;
	//uint8_t i1;
	
	
	time_t t;
	srand( (unsigned) time( &t ) );

	//init_buffer(key, sizeof(key));
	init_buffer(nonce, sizeof(nonce));
	init_buffer(msg, sizeof(msg));
	init_buffer(ad, sizeof(ad));
	
	mlen = mlen2 = 0;
	adlen = 16;
	clen = 16;
	
	//printDDT( &ddt[ 0 ] );
	
	printf("...............Encryption.....................\n");
	if ( crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen, NULL, nonce, key) == 0)
		print(ct);
		
	/*for( i = mlen; i < mlen+32; ++i )
		tag[i-mlen] = ct[i];*/
		
	memcpy(tag1, ct, clen);
		
	if ( crypto_aead_decrypt(msg2, &mlen2, NULL, ct, clen, ad, adlen, nonce, key) == 0) {
	
		print(ct);
		printf("Decryption is successful!!\n\n\n");
	}
	else
		printf("Not successful!!\n\n\n");
	/*copy_ciphertext( ct1, ct );
	print(ct1);	
	if ( crypto_aead_decrypt(msg2, &mlen2, NULL, ct1, clen, ad, adlen, nonce, key) == 0) {
	
		print(ct);
		printf("Decryption1 is successful!!\n\n\n");
	}
	else
		printf("Not successful!!\n\n\n");*/
		
		
		
	count = 0;
	for( pos = 0; pos < 16; ++pos ) {
	
		//pos = 0;
		diff = rand() & 0xff;
		if( diff == 0 )
			diff = rand() & 0xff;
		//diff = 0;
	
		printf("....................................................faulty forgery by injecting fault at the nibble position (%d,%d)...............................\n\n", pos%4, pos/4);	
		for( i1 = 1; i1 < 256; ++i1 ) {
		
			printf("...................................................................................\n\n");
			for( i = 0; i < 16; ++i ) {

				//for( j = 0; j < 4; ++j )
					state[ i ] = 0;
			}
			
			//if(pos%2 == 0)
			state[ pos ] ^= i1;
			
			
			printf("state difference before sr and mc:\n");
			print_state( state );
			shift_rows1(state);
			//MixColumn1( state );
			printf("state difference after sr and mc:\n");
			print_state( state );
			//copy_ciphertext( ct1, ct );
			memcpy(ct1, ct, clen);
			printf("non faulty tag::");print(tag1);
			xor_of_diff_tag( state, ct1 );
			printf("faulty tag difference::");print(ct1);
			//print("in falty ecryption::\n");
			
			printf("At %d-th query::\n", i1);
			//printf("fault in the dec query\n");	
			if ( faulty_aead_decrypt(msg2, &mlen2, NULL, ct1, clen, ad, adlen, nonce, key, diff, pos ) == 0 ) {
				
				printf("\n------------------------------------Tag Compare is successful!! at the position position = (%d, %d) with input diff = %x, output diff = %x\n\n", (pos%4), (pos/4),diff,i1);

				//printf("enter into the fun::Recover_state_columnwise\n");
				Recover_state_columnwise( diff, pos, count, &ddt[ 0 ] );
				//return 0;
				++count;
				
				diff1 = rand() & 0xff;
				while(diff1 == diff )
					diff1 = rand() & 0xff;
				diff = diff1;
				
				
				printf("tag difference::\n\n");
				/*for(int k = 0; k < 16; ++k ) {
				
					if(k%4 == 0)
						printf("\n");*/
				printf("0x%02x, 0x%02x, 0x%02x, 0x%02x, \n", tag1[0]^ftag[0], tag1[4]^ftag[4], tag1[8]^ftag[8], tag1[12]^ftag[12]);
				printf("0x%02x, 0x%02x, 0x%02x, 0x%02x, \n", tag1[1]^ftag[1], tag1[5]^ftag[5], tag1[9]^ftag[9], tag1[13]^ftag[13]);
				printf("0x%02x, 0x%02x, 0x%02x, 0x%02x, \n", tag1[2]^ftag[2], tag1[6]^ftag[6], tag1[10]^ftag[10], tag1[14]^ftag[14]);
				printf("0x%02x, 0x%02x, 0x%02x, 0x%02x, \n", tag1[3]^ftag[3], tag1[7]^ftag[7], tag1[11]^ftag[11], tag1[15]^ftag[15]);
				//}
				
				printf("\n\nnon faulty tag::");print(tag1);
				printf("faulty tag::");print(ftag);	
				
				
			}
				
			printf("\n\n");
			if(count == number)
				break;							
		}
		count = 0;
	}
	
	
	/*printf("faulty tag::\n");
	print(ct1);
	printf("Actual TAG DIFFERENCES:\n");
	for( i = 0; i < 16; ++i ) 
		printf("%x, ", ftag[i]^tag1[i]);*/
		
	printf("\nActual state values before s-box\n");
	printf("%02x %02x %02x %02x ", st_sb[0], st_sb[4 ], st_sb[ 8], st_sb[ 12] );
	printf("\n");
	
	printf("%02x %02x %02x %02x ", st_sb[1 ], st_sb[5 ], st_sb[ 9], st_sb[13 ] );
	printf("\n");
	
	printf("%02x %02x %02x %02x ", st_sb[ 2], st_sb[ 6], st_sb[ 10], st_sb[ 14] );
	printf("\n");
	
	printf("%02x %02x %02x %02x ", st_sb[ 3], st_sb[7 ], st_sb[ 11], st_sb[15 ] );
	printf("\n");
	
	/*for( short i = 0; i < 8; ++i ) {
	
		for( short j = 0; j < 8; ++j ) {
		
			//dstate[i][j] = st[ i ][ j ]^st1[ i ][ j ];
			printf("%x ", st[ i ][ j ]);
		}
		
		printf("\n");
	}
	
	printf("\n");*/
	
		
	for( pos = 0; pos < 16; ++pos )
		state_nibble( pos, number );		
	
	
	return 0;
}





void fprint_bstr(FILE *fp, const char *label, const unsigned char *data, unsigned long long length)
{    
    fprintf(fp, "%s", label);
        
	for (unsigned long long i = 0; i < length; i++)
		fprintf(fp, "%02X", data[i]);
	    
    fprintf(fp, "\n");
}

void init_buffer(unsigned char *buffer, unsigned long long numbytes)
{
	for (unsigned long long i = 0; i < numbytes; i++)
		buffer[i] = (unsigned char)i;
}
