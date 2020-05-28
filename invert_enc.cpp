#include "helib/helib.h"
#include "helib/EncryptedArray.h"
#include <NTL/lzz_pXFactoring.h>
#include <fstream>
#include <sstream>
#include <sys/time.h>
#include <string>
#include <iostream>
#include <stdio.h>

using namespace std;
using namespace helib;

int main(int argc, char *argv[]) {

  long m=0;

  // MODIFY CODE HERE - set the value for the plaintext modulus p as required
  

  long r=1;
  long L=250;
  long c=3;
  long w=64;
  long d=0;
  long security = 128;

  // Generate key
  NTL::ZZX G;
  m = FindM(security,L,c,p,d,0,0);
  helib::Context context(m,p,r);
  buildModChain(context, L, c);
  helib::SecKey secretKey(context);
  const helib::PubKey& publicKey = secretKey;
  G = context.alMod.getFactorsOverZZ()[0];
  secretKey.GenSecKey(w);
  addSome1DMatrices(secretKey);

  // Initialize encrypted array
  EncryptedArray ea(context,G);
  long nslots = ea.size();

  cout <<"Generated key & Initialized encrypted array" << endl;

  // get terminal argument - filename
  std::string filename = argv[1];

  int i;
  FILE* f = fopen(filename.c_str(), "rb+");
  FILE* out = fopen("inverted.bmp","w");

  // check if file is empty
  if(f == NULL)
    throw "Argument Exception: invalid input file";

  // Get the image information
  unsigned char info[54];

  // read the 54-byte header
  fread(info, sizeof(unsigned char), 54, f);

  // write the 54-byte header to the output file
  fwrite(info, sizeof(unsigned char), 54, out);

  // extract image height and width from header
  int width = *(int*)&info[18];
  int height = *(int*)&info[22];

  // Initialize variables that will be used to iterate
  int row_padded = (width*3 + 3) & (~3);
  unsigned char* data = new unsigned char[row_padded];
  unsigned char tmp;

  Ctxt ct_data(publicKey);

  int pt_constant;

  // MODIFY CODE HERE - set the correct integer value for pt_constant to allow color inversion



  vector<long> const_value;
  for(int i = 0 ; i < nslots; i++) {
    const_value.push_back(pt_constant);
  }

  Ctxt ct_const(publicKey);

  // MODIFY CODE HERE - encrypt const_value vector into ct_const using publicKey



  cout <<"Inverting image row-by-row" << endl;
  // Read the pixels and perform the inversion
  for(int i = 0; i < height; i++) {
    // read the image row-by-row
    fread(data, sizeof(unsigned char), row_padded, f);
    vector<long> pt_data;
    // read the (r,g,b) triplets and invert
    for(int j = 0; j < width*3; j++) {
      //cout << "R: "<< (int)data[j] << " G: " << (int)data[j+1]<< " B: " << (int)data[j+2]<< endl;
      pt_data.push_back(int(data[j]));
    }

    // pad to nslots with zeros
    for(int j = width*3; j < nslots; j++) {
      pt_data.push_back(0);
    }

    // encrypt the row vectors

    // MODIFY CODE HERE - encrypt pt_data into ct_data using publicKey



    Ctxt ct_inverse(publicKey);

    // Color inversion

    // MODIFY CODE HERE - compute ct_inverse homomorphically so the colors are inverted


    // decrypt the vectors
    ea.decrypt(ct_inverse, secretKey, pt_data);

    unsigned char* pt_data_unencrypted = new unsigned char[row_padded];

    for (int i = 0; i < width *3; i++) {
      pt_data_unencrypted[i] = (unsigned char)pt_data[i];
    }

    // write the inverted data row to the output file
    fwrite(pt_data_unencrypted, sizeof(unsigned char), row_padded, out);
  }

  // close files
  fclose(f);
  fclose(out);
  cout << "Done!" << endl;
  return 0;
}
