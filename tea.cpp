#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

char pwd[16];
uint32_t key[4]; 
uint32_t Header[2];
uint32_t block[2];
void inputPW (char* mode);
void makeKey();
void encrypt (uint32_t v[2], const uint32_t k[4]);
void decrypt (uint32_t v[2], const uint32_t k[4]);
void encryption(char* mode, char* fname);
void decryption(char* mode, char* fname);

int main(int argv, char* args[]){
	inputPW(args[1]);
	makeKey();
	if(!strcmp(args[1],"-e"))
		encryption(args[2],args[3]);
	else if(!strcmp(args[1],"-d"))
		decryption(args[2],args[3]);
	else{
		printf("mode error");
		exit(1);
	}
	
	return 0;
}

void inputPW (char* mode){
	char checkpwd[16]; 
	
	if (!strcmp(mode, "-e")){	
		printf("Please enter your password(At least 10 letters): ");
		scanf("%s",pwd);
		printf("Please enter your password again: ");
		scanf("%s",checkpwd);
		if (strcmp(pwd,checkpwd) || (int)strlen(pwd)<10) { printf("passward error\n"); exit(1); }
	}
	
	else if (!strcmp(mode, "-d")){
		printf("Please enter your password: ");
		scanf("%s",pwd);
	}
	
	else { printf("mode error\n"); exit(1); }
	
	for(int i = (int)strlen(pwd); i<16; i++)
        pwd[i] = '0';
}

void makeKey(){
	for (int i=0; i<4; i++){
		int j=i*4;
		key[i]= (pwd[j]<<24) | (pwd[j+1]<<16) | (pwd[j+2]<<8) | (pwd[j+3]);
	}
}

void encrypt (uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
    uint32_t delta=0x9E3779B9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<32; i++) {                         /* basic cycle start */
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

void decrypt (uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  /* set up; sum is (delta << 5) & 0xFFFFFFFF */
    uint32_t delta=0x9E3779B9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<32; i++) {                         /* basic cycle start */
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

void encryption(char* mode, char* fname){
	FILE *fp,*fp1;
	char name[200];
	strcpy(name,fname);
	strcat(name,".tea");
	int flag = 0;
	if ((fp=fopen(fname,"rb"))==NULL) 
		{ printf("File Open Error\n"); exit(1); }
	fp1=fopen(name,"wb");
	
	if (!strcmp(mode, "ecb")){
		Header[0]= ('T'<<24) | ('E'<<16) | ('A'<<8) | ('\0');
		Header[1]= ('E'<<24) | ('C'<<16) | ('B'<<8) | ('\0');
        encrypt(Header,key);
        fwrite(Header,sizeof(Header),1,fp1);
        	
		while(1){
			memset(block, 0, sizeof(block));
			flag=fread(block,1,8,fp);
			if (flag<1) break;
			encrypt(block,key);
			fwrite(block,flag,1,fp1);
		}
	}
	
	else if (!strcmp(mode, "cbc")){
		uint32_t IV[2]; 
		srand(time(NULL));
		
	    Header[0]= ('T'<<24) | ('E'<<16) | ('A'<<8) | ('\0');
		Header[1]= ('C'<<24) | ('B'<<16) | ('C'<<8) | ('\0');
        encrypt(Header,key);
        
        IV[0]=(rand()%256)<<24+(rand()%256)<<16+(rand()%256)<<8+(rand()%256); 
		IV[1]=(rand()%256)<<24+(rand()%256)<<16+(rand()%256)<<8+(rand()%256); //ÃÊ±âÈ­º¤ ÅÍ  
		
        fwrite(IV,sizeof(IV),1,fp1);
		fwrite(Header,sizeof(Header),1,fp1);
		
        
        while(1){
			memset(block, 0, sizeof(block));
			flag=fread(block,1,8,fp);
			if (flag<1) break;
			block[0]=block[0]^IV[0];
			block[1]=block[1]^IV[1];
			encrypt(block,key);
			fwrite(block,flag,1,fp1);
			memmove(IV,block,sizeof(IV));
		}
    }
    else {  printf("Mode error");  exit(1); }
    fclose(fp);
    fclose(fp1);
}

void decryption(char* mode, char* fname){
    FILE *fp,*fp1;
    char name[200];
    strncpy(name,fname,(strlen(fname)-4));
    printf("%s",name);
	uint32_t check[2];
	uint32_t prev[2];
	
	
	if ((fp=fopen(fname,"rb"))==NULL) 
		{ printf("File Open Error\n"); exit(1); }
	fp1=fopen(name,"wb");
	
	if (!strcmp(mode, "ecb")){
		if(!(fread(Header,sizeof(Header),1,fp))) {
			printf("File Read Error\n");
			exit(1);
		}
		
		check[0]= ('T'<<24) | ('E'<<16) | ('A'<<8) | ('\0');
		check[1]= ('E'<<24) | ('C'<<16) | ('B'<<8) | ('\0');
		decrypt(Header,key);
		
		if(!((Header[0]==check[0]) && (Header[1]==check[1]))) {
			printf("The password is not correct");
			exit(1);
		}
		
		while(1){
			memset(block, 0, sizeof(block));
			if(!(fread(block,sizeof(block),1,fp))) 
				break;
			decrypt(block,key);
			fwrite(block,sizeof(block),1,fp1);
		}
	}
	
	else if (!strcmp(mode, "cbc")){
		uint32_t IV[2]; 
	
		if(!(fread(IV,sizeof(IV),1,fp))) {
			printf("File Read Error\n");
			exit(1);
		}
		fread(Header,sizeof(Header),1,fp);
		
	    check[0]= ('T'<<24) | ('E'<<16) | ('A'<<8) | ('\0');
		check[1]= ('C'<<24) | ('B'<<16) | ('C'<<8) | ('\0');
        decrypt(Header,key);
        
        if(!((Header[0]==check[0]) && (Header[1]==check[1]))) {
			printf("The password is not correct");
			exit(1);
		}
		
		
		while(1){
			memset(block, 0, sizeof(block));
			if(!(fread(block,sizeof(block),1,fp))) 
				break;
			memmove(prev,block,sizeof(IV));
			decrypt(block,key);
			block[0]=block[0]^IV[0];
			block[1]=block[1]^IV[1];
			fwrite(block,sizeof(block),1,fp1);
			memmove(IV,prev,sizeof(IV));
		}
    }
    else {  printf("Mode error");  exit(1); }
    fclose(fp);
    fclose(fp1);
}
	
	
    	


