#include <iostream>
#include <iomanip>

using namespace std;
/*-------- globals: The subkey arrays -----------------------------------*/
typedef unsigned char u8;
typedef unsigned int u32;

u8 Box[256] = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

/*---------------------------------------------------------------------
 * Sbox()
 * The Rijndael S-box is a square matrix (square array of numbers)
 * used in the Rijndael cipher.
 *---------------------------------------------------------------------*/
void SBox(u8 data[4][4]) {
    for (int i = 0; i < sizeof(data[0]); ++i) {
        for (int j = 0; j < (sizeof(data)/ sizeof(data[0])); ++j) {
            data[i][j] = Box[data[i][j]];
        }
    }
}
/*---------------------------------------------------------------------
 * Shift_Row()
 * The ShiftRows step operates on the rows of the state; it cyclically
 * shifts the bytes in each row by a certain offset.
 *---------------------------------------------------------------------*/
void Shift_Row(u8 data[4][4]) {
    data[1][0] = data[1][1];
    data[1][1] = data[1][2];
    data[1][2] = data[1][3];
    data[1][3] = data[1][0];
    data[2][0] = data[1][2];
    data[2][1] = data[1][3];
    data[2][2] = data[1][0];
    data[2][3] = data[1][1];
    data[3][0] = data[1][3];
    data[3][1] = data[1][0];
    data[3][2] = data[1][1];
    data[3][3] = data[1][2];
}
/*---------------------------------------------------------------------
 * Mix_column()
 * The MixColumns operation performed by the Rijndael cipher, along with
 * the ShiftRows step, is the primary source of diffusion in Rijndael.
 *---------------------------------------------------------------------*/
void Mix_column(u8 data[4][4], int column) {
    unsigned char a[4];
    unsigned char b[4];
    unsigned char c;
    unsigned char h;
    /* The array 'a' is simply a copy of the input array 'data'
     * The array 'b' is each element of the array 'a' multiplied by 2
     * in Rijndael's Galois field
     * a[n] ^ b[n] is element n multiplied by 3 in Rijndael's Galois field */
    a[0] = data[0][column];
    a[1] = data[1][column];
    a[2] = data[2][column];
    a[3] = data[3][column];
    for (c = 0; c < 4; c++) {
        /* h is 0xff if the high bit of data[c] is set, 0 otherwise */
        /* arithmetic right shift, thus shifting in either zeros or ones */
        h = (unsigned char)((signed char)data[c][column] >> 7);
        /* implicitly removes high bit because b[c] is an 8-bit char,
         * so we xor by 0x1b and not 0x11b in the next line */
        b[c] = data[c][column] << 1;
        /* Rijndael's Galois field */
        b[c] ^= 0x1B & h;
    }
    /* 2 * a0 + a3 + a2 + 3 * a1 */
    data[0][column] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
    /* 2 * a1 + a0 + a3 + 3 * a2 */
    data[1][column] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
    /* 2 * a2 + a1 + a0 + 3 * a3 */
    data[2][column] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
    /* 2 * a3 + a2 + a1 + 3 * a0 */
    data[3][column] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
}
/*---------------------------------------------------------------------
 * AES()
 * Rijndael encryption algorithm. Transforms the 128-bit input.
 *---------------------------------------------------------------------*/
void AES(u8 data[4][4], int round){
    for (int r = 0; r < round - 1; ++r) {
        SBox(data);
        Shift_Row(data);
        for (int c = 0; c < 4; ++c) {
            Mix_column(data, c);
        }
    }
    SBox(data);
    Shift_Row(data);
}

void u8print(u8 data[4][4]){
    u32 temp[8] = {};
    for (int i = 0; i < 4; ++i) {
        temp[0] = data[0][0];
        temp[0] = 0X100 * temp[0] + data[0][1];
        temp[1] = data[0][2];
        temp[1] = 0X100 * temp[1] + data[0][3];
        temp[2] = data[1][0];
        temp[2] = 0X100 * temp[2] + data[1][1];
        temp[3] = data[1][2];
        temp[3] = 0X100 * temp[3] + data[1][3];
        temp[4] = data[2][0];
        temp[4] = 0X100 * temp[4] + data[2][1];
        temp[5] = data[2][2];
        temp[5] = 0X100 * temp[5] + data[2][3];
        temp[6] = data[3][0];
        temp[6] = 0X100 * temp[6] + data[3][1];
        temp[7] = data[3][2];
        temp[7] = 0X100 * temp[7] + data[3][3];
    }
    for (int i = 0; i < sizeof(temp)/sizeof(temp[0]); ++i) {
        for (int j = 0; j < 4 - sizeof(temp[i]); ++j)
            cout << '0';
        cout << hex << temp[i];
    }
    cout << endl;
}

int main() {

    u8 Dist_table[256][256] = {};
    for (u8 fpt = 0; fpt < 255; ++fpt) {
        for (u8 spt = 0; spt < 255 - fpt; ++spt) {
            Dist_table[fpt ^ spt][Box[fpt] ^ Box[spt]]++;
        }
    }
    u8 temp[4][4];
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            temp[i][j] = Dist_table[i][j];
        }
    }

    u8 ptext[4][4] = {
            {0x99, 0x00, 0xAA, 0xBB}, {0xCC, 0xDD, 0xEE, 0xFF},
            {0x11, 0x22, 0x33, 0x44}, {0x55, 0x66, 0x77, 0x88}
    };
//    u8 ptext2[4][4] = {
//            {0x39, 0x03, 0x2A, 0xB4}, {0x2C, 0xD4, 0x5E, 0x7F},
//            {0x21, 0x52, 0xF3, 0xD4}, {0x5A, 0xB6, 0xC7, 0x98}
//    };
//    AES(ptext, 1);
//    AES(ptext2, 2);
//    u8print(ptext);
//    u8print(ptext2);
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            cout << (int) temp[i][j] << '\t';
        }
        cout << '\n';
    }
    u8print(ptext);
    return 0;
}