#include "../openssl/bn.h"
#include <stdio.h>
#include <stdlib.h>

void ExpMod(BIGNUM* res,BIGNUM *a,BIGNUM* e,BIGNUM* m);
void printBN(char *msg, BIGNUM *a);
int getBufSize(int num);
void printBuf(unsigned char *buf, int size);
BIGNUM* MRtest(BIGNUM* prime,int num);
BIGNUM* GenProbPrime2(int pBits);
int p_list[] = {2,3,5,7,11,13,17,19,23,29};
int loop_num =0;
typedef struct _b10dh_param_st {
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *g;
}BOB10_DH_PARAM;

typedef struct _b10dh_keypair_st {
    BIGNUM *prk;
    BIGNUM *puk;
}BOB10_DH_KEYPAIR;

BOB10_DH_PARAM *BOB10_DH_PARAM_new();
BOB10_DH_KEYPAIR *BOB10_DH_KEYPAIR_new();
int BOB10_DH_PARAM_free(BOB10_DH_PARAM *b10dhp);
int BOB10_DH_KEYPAIR_free(BOB10_DH_KEYPAIR *b10dhk);
int BOB10_DH_ParamGenPQ(BOB10_DH_PARAM *dhp, int pBits, int qBits);
int BOB10_DH_ParamGenG(BOB10_DH_PARAM *dhp);
int BOB10_DH_KeypairGen(BOB10_DH_KEYPAIR *dhk,BOB10_DH_PARAM *dhp);
int BOB10_DH_Derive(BIGNUM *sharedSecret, BIGNUM *peerKey, BOB10_DH_KEYPAIR *dhk, BOB10_DH_PARAM *dhp);

int main (int argc, char *argv[]) 
{
	BIGNUM *sharedSecret = BN_new();
    
	BOB10_DH_PARAM *dhp = BOB10_DH_PARAM_new();
	BOB10_DH_KEYPAIR *aliceK = BOB10_DH_KEYPAIR_new();
	BOB10_DH_KEYPAIR *bobK = BOB10_DH_KEYPAIR_new();
    
	BOB10_DH_ParamGenPQ(dhp, 2048, 256);
    
	printf("p=0x");BN_print_fp(stdout,dhp->p);printf("\n");
	printf("q=0x");BN_print_fp(stdout,dhp->q);printf("\n");
	BOB10_DH_ParamGenG(dhp);
	printf("g=0x");BN_print_fp(stdout,dhp->g);printf("\n");
    
	BOB10_DH_KeypairGen(aliceK,dhp);
	printf("alicePuk=0x");BN_print_fp(stdout,aliceK->puk);printf("\n");
	printf("alicePrk=0x");BN_print_fp(stdout,aliceK->prk);printf("\n");
    
	BOB10_DH_KeypairGen(bobK,dhp);
	printf("bobPuk=0x");BN_print_fp(stdout,bobK->puk);printf("\n");
	printf("bobPrk=0x");BN_print_fp(stdout,bobK->prk);printf("\n");

    
	BOB10_DH_Derive(sharedSecret, bobK->puk, aliceK, dhp);
	printf("SS1=0x");BN_print_fp(stdout,sharedSecret);printf("\n");
	BOB10_DH_Derive(sharedSecret, aliceK->puk, bobK, dhp);
	printf("SS2=0x");BN_print_fp(stdout,sharedSecret);printf("\n");
    
	BOB10_DH_PARAM_free(dhp);
	BOB10_DH_KEYPAIR_free(aliceK);
	BOB10_DH_KEYPAIR_free(bobK);
	BN_free(sharedSecret);
    return 0;
}
BIGNUM* GenProbPrime2(int pBits){
    BIGNUM* prime = BN_new();
    BIGNUM* prime_o = BN_new(); // prime - 1
    BIGNUM* d = BN_new(); // d (몫)
    BIGNUM* a = BN_new(); // d (몫)
    int s = 0;
    char t_list[2];// a 
    char t_r[2];//  
    int pass_ck = 0;
    //
    BIGNUM* tmulr = BN_new();
    //
    BIGNUM* res = BN_new();
    BIGNUM* one = BN_new();
    BIGNUM* two = BN_new();
    BIGNUM* sqtwo = BN_new();
    BIGNUM* total = BN_new();
    BIGNUM* rem = BN_new();
    BIGNUM* temp = BN_new();
    BIGNUM* temp2 = BN_new();
    //
    BN_CTX *ctx = BN_CTX_new();
    while(1){
        pass_ck = 0;
        s = 0;
        BN_dec2bn(&one,"1");
        BN_dec2bn(&sqtwo,"1");
        BN_dec2bn(&two,"2");
        //get Random
        BN_rand(prime,pBits,BN_RAND_TOP_ONE,BN_RAND_BOTTOM_ODD);// prime
        BN_sub(prime_o,prime,one);//prime_o = prime - one
        BN_copy(temp,prime_o);
        while(1){// find s , d
            BN_div(d,rem,temp,two,ctx);
            s++;
            if(BN_is_one(rem)){// rem == 1
                s--;
                BN_copy(d,temp);
                break;
            }else{
               BN_copy(temp,d);
            }
        }
        for(int i=0;i<sizeof(p_list)/sizeof(int);i++){
            if(pass_ck == 2){
                break;
            }
            pass_ck=2;
            sprintf(t_list,"%d",p_list[i]);
            BN_dec2bn(&a,t_list);// a=p_list[i]
            // start Test
            for(int k=0; k < s; k++)//0~s-1
            {
                //cal (2^r)*d
                if(k==0){//first test
                    ExpMod(res,a,d,prime);
                    if(BN_is_one(res) || !BN_cmp(res,prime_o)){
                        pass_ck = 1;
                        break;
                    }
                }else{
                    BN_mul(sqtwo,sqtwo,two,ctx);
                    BN_mul(total,sqtwo,d,ctx);
                    ExpMod(res,a,total,prime);
                    if(!BN_cmp(res,prime_o)){
                        pass_ck = 1;
                        break;
                    }else{
                        pass_ck = 2;
                    }
                }
            }
            if(pass_ck == 1 && i == 6){
                return prime;
            }
        }
    }
}
BIGNUM* MRtest(BIGNUM* prime,int num){
    BIGNUM* prime_o = BN_new(); // prime - 1
    BIGNUM* d = BN_new(); // d (몫)
    BIGNUM* a = BN_new(); // d (몫)
    int s = 0;
    char t_list[2];// a 
    char t_r[2];//  
    int pass_ck = 0;
    //
    BIGNUM* tmulr = BN_new();
    //
    BIGNUM* res = BN_new();
    BIGNUM* one = BN_new();
    BIGNUM* two = BN_new();
    BIGNUM* sqtwo = BN_new();
    BIGNUM* total = BN_new();
    BIGNUM* rem = BN_new();
    BIGNUM* temp = BN_new();
    BIGNUM* temp2 = BN_new();
    //
    BN_CTX *ctx = BN_CTX_new();
    pass_ck = 0;
    s = 0;
    BN_dec2bn(&one,"1");
    BN_dec2bn(&sqtwo,"1");
    BN_dec2bn(&two,"2");
    //get Random
    BN_sub(prime_o,prime,one);//prime -1
    BN_copy(temp,prime_o);
    while(1){// find s , d
        BN_div(d,rem,temp,two,ctx);
        s++;
        if(BN_is_one(rem)){// rem == 1
            s--;
            BN_copy(d,temp);
            break;
        }else{
            BN_copy(temp,d);
        }
    }
    for(int i=0;i < num;i++){
        if(pass_ck == 2){
            break;
        }
        pass_ck=2;
        sprintf(t_list,"%d",p_list[i]);//2,3,5,7,11,13,17,19,23,29
        BN_dec2bn(&a,t_list);// a=p_list[i]
        // start Test
        BN_dec2bn(&sqtwo,"1");
        for(int k=0; k < s; k++)//0~s-1
        {
            
            if(k==0){//first test
                ExpMod(res,a,d,prime);
                if(BN_is_one(res) || !BN_cmp(res,prime_o)){
                    pass_ck = 1;
                    break;
                }
            }else{
                BN_mul(sqtwo,sqtwo,two,ctx);
                BN_mul(total,sqtwo,d,ctx);
                ExpMod(res,a,total,prime);
                if(!BN_cmp(res,prime_o)){
                    pass_ck = 1;
                    break;
                }else{
                    pass_ck = 2;
                }
            }
        }
        if(pass_ck == 1 && i == num-1){
            free(prime_o);
            free(d);
            free(a);
            free(tmulr);
            free(res);
            free(one);
            free(two);
            free(sqtwo);
            free(total);
            free(rem);
            free(temp);
            free(temp2);
            free(ctx);
            return prime;
        }else if(pass_ck == 2){
            free(prime_o);
            free(d);
            free(a);
            free(tmulr);
            free(res);
            free(two);
            free(sqtwo);
            free(total);
            free(rem);
            free(temp);
            free(temp2);
            free(ctx);
            return one;
        }
    }
}
void ExpMod(BIGNUM* res, BIGNUM *a, BIGNUM *e,BIGNUM *m){
    
// res =  a^e (mod m)
	int anum = BN_num_bits(a);
	int bnum = BN_num_bits(e);
	int cnum = BN_num_bits(m);
	int bnum_buf = getBufSize(bnum);	
	BN_CTX *ctx = BN_CTX_new();

	BIGNUM *temp_a = BN_new();
	BN_dec2bn(&temp_a,"1");
	unsigned char *buf = (unsigned char*)malloc(sizeof(unsigned char)*bnum_buf);
	BN_bn2bin(e,buf);	

	int first_bit = bnum - bnum_buf*8 ;
	for(int i=0; i < bnum_buf; i++)
	{
		if((buf[i] & 128)>>7 == 1){
			first_bit++;
			if(first_bit > 0){
				BN_sqr(temp_a,temp_a,ctx);// (An-1)^2
				BN_mul(temp_a,temp_a, a, ctx);	//(An-1)^2 * A
				BN_mod(temp_a,temp_a,m,ctx);
			}
		}else{
			first_bit++;
			if(first_bit > 0){
				BN_sqr(temp_a,temp_a,ctx);//  ^2
				BN_mod(temp_a,temp_a,m,ctx);
			}

		}
		if((buf[i] & 64)>>6 == 1){
			first_bit++;
			if(first_bit > 0){
				BN_sqr(temp_a,temp_a,ctx);// (An-1)^2
				BN_mul(temp_a,temp_a, a, ctx);	//(An-1)^2 * A
				BN_mod(temp_a,temp_a,m,ctx);
			}

		}else{
			first_bit++;
			if(first_bit > 0){
				BN_sqr(temp_a,temp_a,ctx);//  ^2
				BN_mod(temp_a,temp_a,m,ctx);
			}

		}
		if((buf[i] & 32)>>5 == 1){
			first_bit++;
			if(first_bit > 0){
				BN_sqr(temp_a,temp_a,ctx);// (An-1)^2
				BN_mul(temp_a,temp_a, a, ctx);	//(An-1)^2 * A
				BN_mod(temp_a,temp_a,m,ctx);
			}

		}else{
			first_bit++;
			if(first_bit > 0){
				BN_sqr(temp_a,temp_a,ctx);//  ^2
				BN_mod(temp_a,temp_a,m,ctx);
			}

		}
		if((buf[i] & 16)>>4 == 1){
			first_bit++;
			if(first_bit > 0){
				BN_sqr(temp_a,temp_a,ctx);// (An-1)^2
				BN_mul(temp_a,temp_a, a, ctx);	//(An-1)^2 * A
				BN_mod(temp_a,temp_a,m,ctx);
			}

		}else{
			first_bit++;
			if(first_bit > 0){
				BN_sqr(temp_a,temp_a,ctx);//  ^2
				BN_mod(temp_a,temp_a,m,ctx);
			}

		}
		if((buf[i] & 8)>>3 == 1){
			first_bit++;
			if(first_bit > 0){
				BN_sqr(temp_a,temp_a,ctx);// (An-1)^2
				BN_mul(temp_a,temp_a, a, ctx);	//(An-1)^2 * A
				BN_mod(temp_a,temp_a,m,ctx);
			}

		}else{
			first_bit++;
			if(first_bit > 0){
				BN_sqr(temp_a,temp_a,ctx);//  ^2
				BN_mod(temp_a,temp_a,m,ctx);
			}

		}
		if((buf[i] & 4)>>2 == 1){
			first_bit++;
			if(first_bit > 0){
				BN_sqr(temp_a,temp_a,ctx);// (An-1)^2
				BN_mul(temp_a,temp_a, a, ctx);	//(An-1)^2 * A
				BN_mod(temp_a,temp_a,m,ctx);
			}

		}else{
			first_bit++;
			if(first_bit > 0){
				BN_sqr(temp_a,temp_a,ctx);//  ^2
				BN_mod(temp_a,temp_a,m,ctx);
			}

		}
		if((buf[i] & 2)>>1 == 1){
			first_bit++;
			if(first_bit > 0){
				BN_sqr(temp_a,temp_a,ctx);// (An-1)^2
				BN_mul(temp_a,temp_a, a, ctx);	//(An-1)^2 * A
				BN_mod(temp_a,temp_a,m,ctx);
			}

		}else{
			first_bit++;
			if(first_bit > 0){
				BN_sqr(temp_a,temp_a,ctx);//  ^2
				BN_mod(temp_a,temp_a,m,ctx);
			}

		}
		if((buf[i] & 1)>>0 == 1){
			first_bit++;
			if(first_bit > 0){
				BN_sqr(temp_a,temp_a,ctx);// (An-1)^2
				BN_mul(temp_a,temp_a, a, ctx);	//(An-1)^2 * A
				BN_mod(temp_a,temp_a,m,ctx);
			}

		}else{
			first_bit++;
			if(first_bit > 0){
				BN_sqr(temp_a,temp_a,ctx);//  ^2
				BN_mod(temp_a,temp_a,m,ctx);
			}

		}
	}
	BN_copy(res,temp_a);
}
void printBN(char *msg, BIGNUM *a)
{
    char *number_str = BN_bn2dec(a);
    printf("%s %s\n",msg,number_str);
    OPENSSL_free(number_str);
}
int getBufSize(int num)
{
	int div;
	int mod;
	div = num /8;
	mod = num % 8;

	if(mod !=0)
	{
		div +=1;
	}

	return div;
}


BOB10_DH_PARAM *BOB10_DH_PARAM_new(){
    BOB10_DH_PARAM* temp = malloc(sizeof(struct _b10dh_param_st));
    temp->p = BN_new(); 
    temp->q = BN_new(); 
    temp->g = BN_new(); 
    return temp;
}
BOB10_DH_KEYPAIR *BOB10_DH_KEYPAIR_new(){
   BOB10_DH_KEYPAIR* temp = malloc(sizeof(struct _b10dh_keypair_st));
   temp->prk = BN_new(); 
   temp->puk = BN_new(); 
   return temp;
}
int BOB10_DH_PARAM_free(BOB10_DH_PARAM *b10dhp){
    free(b10dhp->p);
    free(b10dhp->q);
    free(b10dhp->g);
    free(b10dhp);
    return 0;
}
int BOB10_DH_KEYPAIR_free(BOB10_DH_KEYPAIR *b10dhk){
    free(b10dhk->prk);
    free(b10dhk->puk);
    free(b10dhk);
    return 0;
}
int BOB10_DH_ParamGenPQ(BOB10_DH_PARAM *dhp, int pBits, int qBits){
    BIGNUM *one = BN_new();
    BIGNUM *two = BN_new();
    BIGNUM *q_one = BN_new();
    BIGNUM *even = BN_new();
    BIGNUM *temp = BN_new();
    BIGNUM *temp2 = BN_new();
    BIGNUM *prime_o = BN_new();
    BIGNUM *podiv = BN_new();
    BIGNUM *rem = BN_new();
    BIGNUM *res = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    
    BN_dec2bn(&one,"1");
    BN_dec2bn(&two,"2");
    BN_copy(q_one,one);
    while(1){//make q
        BN_rand(dhp->q,qBits,BN_RAND_TOP_ONE,BN_RAND_BOTTOM_ODD);//ODD
        dhp->q = MRtest(dhp->q,3);
        if(!BN_is_one(dhp->q)){
            break;
        }
    }
    while(1){//make non odd number_str
        loop_num++;
        BN_rand(even,pBits - qBits,BN_RAND_TOP_ONE,BN_RAND_BOTTOM_ODD);//ODD
        BN_sub(even,even,one);// even = odd - 1
        BN_mul(temp,even,dhp->q,ctx);// temp = q * j 
        BN_add(temp,temp,one);// temp = q * j + 1
        if(BN_num_bits(temp) != pBits)
            continue;
        temp = MRtest(temp,10);//temp Prime test
        if(!BN_is_one(temp)){
            BN_copy(dhp->p,temp);
            break;
        }
    }
    free(one);
    free(two);
    free(q_one);
    free(even);
    free(temp);
    free(temp2);
    free(prime_o);
    free(podiv);
    free(rem);
    free(res);
    free(ctx);
}
int BOB10_DH_ParamGenG(BOB10_DH_PARAM *dhp){
    BIGNUM *one = BN_new();
    BIGNUM *two = BN_new();
    BIGNUM *even = BN_new();//
    BIGNUM *prime_o = BN_new();
    BIGNUM *temp = BN_new();
    BIGNUM *rem = BN_new();
    BIGNUM *podiv = BN_new();
    BIGNUM *res = BN_new();//
    BN_CTX *ctx = BN_CTX_new();//
    
    BN_dec2bn(&one,"1");
    BN_dec2bn(&two,"2");

    BN_sub(prime_o,dhp->p,one);//p-1
    BN_div(podiv,res,prime_o,two,ctx);//even = (p-1)/2
    BN_div(even,res,prime_o,dhp->q,ctx);//even = (p-1)/q
    int b1 = BN_num_bits(dhp->q);
    int b2 = BN_num_bits(dhp->p);
    while(1){// find g
        BN_rand(dhp->g,b2-b1,BN_RAND_TOP_ANY,BN_RAND_BOTTOM_ANY);//ODD
        int check;
        if(check = BN_cmp(dhp->g,dhp->p) != -1){
            continue;
        }
        ExpMod(res,dhp->g,podiv,dhp->p); 
        if(!BN_cmp(res,prime_o)){//g^(p-1)/2 == p-1
            break;
        }
    }
    //mkae 1/4 bit g 
    //BN_div(temp,temp2,prime_o,dhp->q);
    ExpMod(dhp->g,dhp->g,even,dhp->p);

    free(one);
    free(two);
    free(even);
    free(prime_o);
    free(temp);
    free(rem);
    free(podiv);
    free(res);
    free(ctx);

}
int BOB10_DH_KeypairGen(BOB10_DH_KEYPAIR *dhk,BOB10_DH_PARAM *dhp){
     
    BN_rand(dhk->prk,BN_num_bits(dhp->q)-1,BN_RAND_TOP_ANY,BN_RAND_BOTTOM_ANY);
    ExpMod(dhk->puk,dhp->g,dhk->prk,dhp->p); 

}
int BOB10_DH_Derive(BIGNUM *sharedSecret, BIGNUM *peerKey, BOB10_DH_KEYPAIR *dhk, BOB10_DH_PARAM *dhp){
   ExpMod(sharedSecret,peerKey,dhk->prk,dhp->p); 
}
