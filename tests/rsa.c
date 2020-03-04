//based on https://github.com/fotisolgr/RSA

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <gmp.h> // Use of GMP library

void gen_key (mpz_t p, mpz_t q, mpz_t n, mpz_t e, mpz_t d, mpz_t dp, mpz_t dq, mpz_t qp) {
    mpz_t temp1;	//4096 bits number
    mpz_t temp2;    	//4096 bits number
    mpz_t temp3;	//1
    mpz_t temp4;	//-1
    mpz_t pp;		//p -1
    mpz_t qq;		//q-1
    mpz_t fn;       	//(p-1)*(q-1)
    mpz_t rop;	    	//rop=gcd(n,e)

    mpz_init(temp1);
    mpz_init(temp2);
    mpz_init(temp3);
    mpz_init(temp4);
    mpz_init(pp);
    mpz_init(qq);
    mpz_init(fn);
    mpz_init(rop);

    mpz_ui_pow_ui(temp1,2,1024); //RSA-1024 bits  temp1=2^1024
    mpz_ui_pow_ui(temp2,2,1025); //RSA-1024 bits  temp2=2^1025

    mpz_init_set_str(temp3, "1", 10);  // temp3 = 1
    mpz_init_set_str(temp4, "-1", 10); // temp4 = -1

    mpz_nextprime (p, temp1);		    //Find 1st prime number greater than p
    //gmp_printf("prime p is:   %Zd\n\n", p); //prime p
    mpz_nextprime (q, temp2);               //Find 1st prime number greater than q
    //gmp_printf("prime q is:   %Zd\n\n", q); //prime q

    mpz_init_set_str(e, "65537", 10);

    mpz_mul(n, p, q);
    //gmp_printf("n is:   %Zd\n\n", n);       //n=p*q 8192 bits


    mpz_sub(pp, p, temp3);            //pp=p-1
    mpz_sub(qq, q, temp3);            //qq=q-1
    mpz_mul(fn, pp, qq);              //f(n)=(p-1)*(q-1)

    //gmp_printf("f(n) is:   %Zd\n\n", fn); //f(n)

    mpz_gcd(rop, n, e);                   //GCD between n & e
    //gmp_printf("gcd is:   %Zd\n\n", rop); //gcd

    mpz_powm(d, e, temp4 , fn);           //d= (65537^-1) modn
    //gmp_printf("d is :   %Zd\n\n", d);

    mpz_mod(dp, d, pp);
    mpz_mod(dq, d, qq);
    mpz_invert(qp, q, p);

    return ;
}

uint64_t gettime () {
  struct timespec now;
  if (clock_gettime (CLOCK_MONOTONIC, &now)) return 0;
  return ((uint64_t)(now.tv_sec) * (uint64_t)1000000000 + (uint64_t)(now.tv_nsec));
}

void decrypt_normal (mpz_t pt, mpz_t ct, mpz_t d, mpz_t n) {
    mpz_t pt2;
    mpz_init(pt2);
    mpz_powm(pt2, ct, d, n);     //pt = (ct^d) mod n
    if (mpz_cmp(pt, pt2)) exit(23);
    //gmp_printf("normal: %Zd\n", pt);  //plain text
}

void decrypt_normal_powmsec (mpz_t pt, mpz_t ct, mpz_t d, mpz_t n) {
    mpz_t pt2;
    mpz_init(pt2);
    mpz_powm_sec(pt2, ct, d, n);     //pt = (ct^d) mod n
    if (mpz_cmp(pt, pt2)) exit(23);
    //gmp_printf("normal powm_sec: %Zd\n", pt);  //plain text
}

void decrypt_crt (mpz_t pt, mpz_t ct, mpz_t p, mpz_t q, mpz_t dp, mpz_t dq, mpz_t qp) {
  mpz_t m1;
  mpz_t m2;
  mpz_t temp1;
  mpz_t temp2;
  mpz_t h;
  mpz_init(m1);
  mpz_init(m2);
  mpz_init(temp1);
  mpz_init(temp2);
  mpz_init(h);
  mpz_powm(m1, ct, dp, p);
  mpz_powm(m2, ct, dq, q);
  mpz_sub(temp1, m1, m2);
  mpz_mul(temp2, qp, temp1);
  mpz_tdiv_qr(temp1, h, temp2, p);
  mpz_mul(temp1, h, q);
  mpz_add(temp2, temp1, m2);
  if (mpz_cmp(pt, temp2)) exit(23);
  //gmp_printf("crt: %Zd\n", temp2);  //plain text
}

void decrypt_crt_powmsec (mpz_t pt, mpz_t ct, mpz_t p, mpz_t q, mpz_t dp, mpz_t dq, mpz_t qp) {
  mpz_t m1;
  mpz_t m2;
  mpz_t temp1;
  mpz_t temp2;
  mpz_t h;
  mpz_init(m1);
  mpz_init(m2);
  mpz_init(temp1);
  mpz_init(temp2);
  mpz_init(h);
  mpz_powm_sec(m1, ct, dp, p);
  mpz_powm_sec(m2, ct, dq, q);
  mpz_sub(temp1, m1, m2);
  mpz_mul(temp2, qp, temp1);
  mpz_tdiv_qr(temp1, h, temp2, p);
  mpz_mul(temp1, h, q);
  mpz_add(temp2, temp1, m2);
  if (mpz_cmp(pt, temp2)) exit(23);
  //gmp_printf("crt powm_sec: %Zd\n", temp2);  //plain text
}

int main(void)
{
    mpz_t p;		//prime p
    mpz_t q;		//prime q
    mpz_t e;        	//65537 for greater security
    mpz_t n;		//n= p*q
    mpz_t d;        	//65537^(-1) mod fn
    mpz_t pt;       	//plaintext variable
    mpz_t ct;       	//chiphertext variable
    mpz_t dp;           //d mod (p-1)
    mpz_t dq;           //d mod (q-1)
    mpz_t qp;           //invert q over p (q ^ -1 mod p)
    uint64_t a, b, dur = 0L;
    uint64_t min, max, total = 0L;

    //Initialize integers

    mpz_init(pt);
    mpz_init(ct);
    mpz_init(p);
    mpz_init(q);
    mpz_init(n);
    mpz_init(e);
    mpz_init(d);
    mpz_init(dp);
    mpz_init(dq);
    mpz_init(qp);

    gen_key(p, q, n, e, d, dp, dq, qp);

    const char *plaintext = "RSA is one of the first practical public-key cryptosystems,";

    mpz_import(pt, strlen(plaintext), 1, 1, 0, 0, plaintext); //Convert ASCII characters into integers
    //gmp_printf("pt size is:   %Zd\n\n", pt);

    if (mpz_cmp(pt, n) > 0)         //Compare plain text with n. If pt>n, RSA encryption is impossible.
    exit(1);
    mpz_powm(ct, pt, e, n);	//ct = (pt^65537) mod n
    //gmp_printf("Encrypted message:   %Zd\n\n", ct);  //cipher text

    //now we're ready for some comparisons
    min = LONG_MAX;
    max = 0L;
    total = 0L;
    for (int i = 0 ; i < 1000 ; i++) {
      a = gettime();
      decrypt_normal(pt, ct, d, n);
      b = gettime();
      dur = b - a;
      if (dur < min) min = dur;
      if (dur > max) max = dur;
      total += dur;
    }
    printf("avg %lu min %lu max %lu (normal)\n", (total / 1000), min, max);

    min = LONG_MAX;
    max = 0L;
    total = 0L;
    for (int i = 0 ; i < 1000 ; i++) {
      a = gettime();
      decrypt_normal_powmsec(pt, ct, d, n);
      b = gettime();
      dur = b - a;
      if (dur < min) min = dur;
      if (dur > max) max = dur;
      total += dur;
    }
    printf("avg %lu min %lu max %lu (normal powm_sec)\n", (total / 1000), min, max);

    min = LONG_MAX;
    max = 0L;
    total = 0L;
    for (int i = 0 ; i < 1000 ; i++) {
      a = gettime();
      decrypt_crt(pt, ct, p, q, dp, dq, qp);
      b = gettime();
      dur = b - a;
      if (dur < min) min = dur;
      if (dur > max) max = dur;
      total += dur;
    }
    printf("avg %lu min %lu max %lu (crt)\n", (total / 1000), min, max);

    min = LONG_MAX;
    max = 0L;
    total = 0L;
    for (int i = 0 ; i < 1000 ; i++) {
      a = gettime();
      decrypt_crt_powmsec(pt, ct, p, q, dp, dq, qp);
      b = gettime();
      dur = b - a;
      if (dur < min) min = dur;
      if (dur > max) max = dur;
      total += dur;
    }
    printf("avg %lu min %lu max %lu (crt powm_sec)\n", (total / 1000), min, max);
    return 0;
}
