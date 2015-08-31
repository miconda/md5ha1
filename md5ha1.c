/* 
 * MD5 HA1 Ops
 * 
 * Copyright (c) 2015 Daniel-Constantin Mierla
 * http://www.asipto.com
 * 
 * (MIT License)
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * - The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 * - The Software is provided "as is", without warranty of any kind, express or
 *   implied, including but not limited to the warranties of merchantability,
 *   fitness for a particular purpose and noninfringement. In no event shall the
 *   authors or copyright holders be liable for any claim, damages or other
 *   liability, whether in an action of contract, tort or otherwise, arising from,
 *   out of or in connection with the Software or the use or other dealings in the
 *   Software.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

/* md5 lib functions */
extern void md5_hash(const uint8_t *message, uint32_t len, uint32_t hash[4]);

/**/
typedef struct ha1_decode_env {
	char *pwfile;
	char *ptfile;
	char *charset;
	int lenmin;
	int lenmax;
	char *ptextra[16];
	int ptextra_len;

} ha1_decode_env_t;

/* global vars */
static int etime = 0;
static int verbose = 0;

static char *cs_a_num = "0123456789";
static char *cs_l_hex = "0123456789abcdf";
static char *cs_u_hex = "0123456789ABCDF";
static char *cs_a_hex = "0123456789abcdfABCDF";
static char *cs_l_alpha = "abcdefghijklmnopqrstuvwxyz";
static char *cs_u_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static char *cs_a_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
static char *cs_l_alphanum = "0123456789abcdefghijklmnopqrstuvwxyz";
static char *cs_u_alphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static char *cs_a_alphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
static char *cs_a_full = " \"\\!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~";

/* print help message */
void help(int argc, char **argv)
{
	printf("%s (v0.1.0) usage:\n", argv[0]);
	printf("    %s -e <username> <realm> <password> : generate (encode) md5 ha1\n", argv[0]);
	printf("    %s -d <username> <realm> <ha1> : discover (decode) password in md5 ha1\n", argv[0]);
	printf("    %s -h : help message\n\n", argv[0]);
}

void etime_print(char *txt, struct timeval *tval_s, struct timeval *tval_e)
{
	struct timeval tval_r;
	long int h;
	int m;
	int s;

	timersub(tval_e, tval_s, &tval_r);
	h = ((long int)tval_r.tv_sec)/3600;
	m = ((int)((long int)tval_r.tv_sec)%3600)/60;
	s = (int)((long int)tval_r.tv_sec)%60;
	printf("%s: %ld.%06ld (%ld:%02d:%02d.%06ld)\n",
			txt, (long int)tval_r.tv_sec, (long int)tval_r.tv_usec,
			h, m, s, (long int)tval_r.tv_usec);

}

char *cs_lookup(char *name)
{
	static char cs_a_file[512];
	FILE* fp;
	int i;

	if(strcmp(name, "num")==0) {
		return cs_a_num;
	} else if(strcmp(name, "hex")==0) {
		return cs_a_hex;
	} else if(strcmp(name, "hex-low")==0) {
		return cs_l_hex;
	} else if(strcmp(name, "hex-upper")==0) {
		return cs_u_hex;
	} else if(strcmp(name, "alpha")==0) {
		return cs_a_alpha;
	} else if(strcmp(name, "alpha-low")==0) {
		return cs_l_alpha;
	} else if(strcmp(name, "alpha-upper")==0) {
		return cs_u_alpha;
	} else if(strcmp(name, "alphanum")==0) {
		return cs_a_alphanum;
	} else if(strcmp(name, "alphanum-low")==0) {
		return cs_l_alphanum;
	} else if(strcmp(name, "alphanum-upper")==0) {
		return cs_u_alphanum;
	} else if(strcmp(name, "full")==0) {
		return cs_a_full;
	} else {
		if ((fp = fopen(name, "r")) == NULL) {
			printf("failed to open charset file [%s]\n", name);
			return NULL;
		}
		if(fgets(cs_a_file, 512, fp) != NULL) {
			i = strlen(cs_a_file);
			if(i>1 && cs_a_file[i-1]=='\n') {
				cs_a_file[i-1] = '\0';
				i--;
			}
			fclose(fp);
			printf("using file [%s] with charset [%s]\n", name, cs_a_file);
			return cs_a_file;
		} else {
			printf("failed to read charset file [%s]\n", name);
			fclose(fp);
			return NULL;
		}
	}
}

/* hex conversions */
static char hextable[] = { '0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9' ,'a', 'b', 'c', 'd', 'e', 'f' };

/* expect at least _b[16] and _h[33] */
void hex_encode(char _b[16], char *_h)
{
	unsigned short i;
	unsigned char j;

	for (i = 0; i < 16; i++) {
		j = (_b[i] >> 4) & 0xf;
		if (j <= 9) {
			_h[i * 2] = (j + '0');
		} else {
			_h[i * 2] = (j + 'a' - 10);
		}

		j = _b[i] & 0xf;

		if (j <= 9) {
			_h[i * 2 + 1] = (j + '0');
		} else {
			_h[i * 2 + 1] = (j + 'a' - 10);
		}
	};

	_h[32] = '\0';
}

int ha1_encode(char *username, char *realm, char *password)
{
	char ibuf[1024];
	char obuf[40];
	uint32_t ha1bin[4];

	if(strlen(username) + strlen(realm) + strlen(password) + 3 >= 1024) {
		printf("input values are too big\n");
		return -2;
	}

	strcpy(ibuf, username);
	strcat(ibuf, ":");
	strcat(ibuf, realm);
	strcat(ibuf, ":");
	strcat(ibuf, password);

	printf("computing md5 for: %s\n", ibuf);

	md5_hash((const uint8_t *)ibuf, strlen(ibuf), ha1bin);
	hex_encode((char*)ha1bin, obuf);

	printf("encoded ha1 [%s] bin: %u %u %u %u\n", obuf,
			ha1bin[0], ha1bin[1], ha1bin[2], ha1bin[3]);
	printf("\n%s\n", obuf);
	return 0;
}

int hex_decode(char *_h, char _b[16])
{
	int i;
	int k;
	int n;

	for(k=0; k<16; k++) {
		_b[k] = 0;
		for(n=0; n<2; n++) {
			_b[k] <<= 4;
			i = 2*k+n;
			if (_h[i] >='0' && _h[i]<='9')       _b[k]+=_h[i] -'0';
			else if (_h[i] >='a' && _h[i] <='f') _b[k]+=_h[i] -'a'+10;
			else if (_h[i] >='A' && _h[i] <='F') _b[k]+=_h[i] -'A'+10;
			else return -1;
		}
	}
	return 0;
}

int ha1_decode_run(ha1_decode_env_t *penv, char *username, char *realm, char *ha1)
{
	uint32_t ha1bin[4];
	uint32_t ha1out[4];
	int ret;
	char *cset;
	int cset_len;
	char ibuf[1024];
	int ibuf_pidx;
	int ibuf_len;
	int a, b, i;
	int cipos[64];
	FILE* fp;
	char lbuf[128];
	char tbuf[256];
	char *p;
	char *q;
	struct timeval tval_s, tval_e;

	if(penv->lenmax > 64) {
		printf("error - password max len is too big [%d] (max 64)\n", penv->lenmax);
		return -1;
	}

	ret = hex_decode(ha1, (char*)ha1bin);
	if(ret<0) {
		printf("error hex decoding ha1 [%s]\n", ha1);
		return ret;
	}
	printf("decoded ha1 [%s] bin: %u %u %u %u\n", ha1,
			ha1bin[0], ha1bin[1], ha1bin[2], ha1bin[3]);
	if(penv->charset) {
		cset = cs_lookup(penv->charset);
	} else {
		cset = cs_a_alphanum;
	}
	if(cset==NULL) {
		printf("characters set not found [%s]\n",
				(penv->charset)?penv->charset:"");
		return -2;
	}
	cset_len = strlen(cset);

	if(strlen(username) + strlen(realm) + 3 >= 1024) {
		printf("input values are too big\n");
		return -2;
	}

	strcpy(ibuf, username);
	strcat(ibuf, ":");
	strcat(ibuf, realm);
	strcat(ibuf, ":");
	ibuf_pidx = strlen(ibuf);

	memset(cipos, 0, 64*sizeof(int));

	if(etime) gettimeofday(&tval_s, NULL);

	/* try password words file */
	if(penv->pwfile) {
		if(strlen(username) + strlen(realm) + 128 + 3 >= 1024) {
			printf("input values are too big\n");
			return -2;
		}
		if ((fp = fopen(penv->pwfile, "r")) == NULL)
		{
			printf("failed to open password words file\n");
			return -2;
		}
		while (fgets(lbuf, 128, fp) != NULL) {
			i = strlen(lbuf);
			// drop the newline from fgets()
			if(i>0 && lbuf[i - 1]=='\n') {
				lbuf[i - 1] = '\0';
				i--;
			}
			printf("trying pw value: [%s]\n", lbuf);
			strcpy(ibuf+ibuf_pidx, lbuf);
			ibuf_len = ibuf_pidx + i;
			// printf("trying: [%s]\n", ibuf);
			md5_hash((const uint8_t *)ibuf, ibuf_len, ha1out);
			if(memcmp(ha1bin, ha1out, 4*sizeof(uint32_t))==0) {
				printf("pw matched: [%s]\n", ibuf);
				if(etime) {
					gettimeofday(&tval_e, NULL);
					etime_print("found - execution time", &tval_s, &tval_e);
				}
				fclose(fp);
				return 1;
			}
		}
		fclose(fp);
	}

	/* try password templatess file */
	if(penv->ptfile) {
		if(strlen(username) + strlen(realm) + 256 + 3 >= 1024) {
			printf("input values are too big\n");
			return -2;
		}
		if ((fp = fopen(penv->ptfile, "r")) == NULL)
		{
			printf("failed to open password templates file\n");
			return -2;
		}
		while (fgets(lbuf, 128, fp) != NULL) {
			i = strlen(lbuf);
			// drop the newline from fgets()
			if(i>0 && lbuf[i - 1]=='\n') {
				lbuf[i - 1] = '\0';
				i--;
			}
			q = lbuf;
			tbuf[0] = '\0';
			if((p=strchr(lbuf, '%'))==NULL) {
				printf("trying pt s-value: [%s]\n", lbuf);
				strcpy(ibuf+ibuf_pidx, lbuf);
				ibuf_len = ibuf_pidx + i;
			} else {
				do {
					if(p+1<lbuf+i) {
						if(*(p+1)=='u') {
							strncat(tbuf, q, p-q);
							strcat(tbuf, username);
							q = p+2;
						} else if(*(p+1)=='r') {
							strncat(tbuf, q, p-q);
							strcat(tbuf, realm);
							q = p+2;
						} else if(*(p+1)=='%') {
							strncat(tbuf, q, p-q);
							strcat(tbuf, "%");
							q = p+2;
						} else {
							for(a=0; a<penv->ptextra_len; a++) {
								if(*(p+1)==penv->ptextra[a][0])
									break;
							}
							if(a==penv->ptextra_len) {
								strncat(tbuf, q, p-q+1);
								q = p+1;
							} else {
								strncat(tbuf, q, p-q);
								strcat(tbuf, penv->ptextra[a]+2);
								q = p+2;
							}
						}
					} else {
						strncat(tbuf, q, p-q+1);
						q = p+1;
					}
					if(p<lbuf+i)
						p=strchr(q, '%');
					else
						p = NULL;
				} while(p);
				if(q!=lbuf+i)
					strcat(tbuf, q);
				printf("trying pt d-value: [%s]\n", tbuf);
				strcpy(ibuf+ibuf_pidx, tbuf);
				i = strlen(tbuf);
				ibuf_len = ibuf_pidx + i;
			}
			// printf("trying: [%s]\n", ibuf);
			md5_hash((const uint8_t *)ibuf, ibuf_len, ha1out);
			if(memcmp(ha1bin, ha1out, 4*sizeof(uint32_t))==0) {
				printf("pt matched: [%s]\n", ibuf);
				if(etime) {
					gettimeofday(&tval_e, NULL);
					etime_print("found - execution time", &tval_s, &tval_e);
				}
				fclose(fp);
				return 1;
			}
		}
		fclose(fp);
	}

	/* try generating passwords */
	if(penv->lenmax>=0) {
		if(strlen(username) + strlen(realm) + penv->lenmax + 3 >= 1024) {
			printf("input values are too big\n");
			return -2;
		}
		for(a=penv->lenmin; a<=penv->lenmax; a++) {
			for(b=0; b<=a; b++) {
				cipos[b]=0;
				ibuf[ibuf_pidx+b] = cset[cipos[b]];
			}
			ibuf_len = ibuf_pidx+a+1;
			ibuf[ibuf_len] = '\0';
			do {
				// printf("trying: [%s]\n", ibuf);
				md5_hash((const uint8_t *)ibuf, ibuf_len, ha1out);
				if(memcmp(ha1bin, ha1out, 4*sizeof(uint32_t))==0) {
					printf("gw matched: [%s]\n", ibuf);
					if(etime) {
						gettimeofday(&tval_e, NULL);
						etime_print("found - execution time", &tval_s, &tval_e);
					}
					return 1;
				}
				i = a;
				while (i >= 0) {
					cipos[i]++;
					ibuf[ibuf_pidx+i] = cset[cipos[i]];

					if(cipos[i]>=cset_len) {
						if(i>0) {
							cipos[i] = 0;
							ibuf[ibuf_pidx+i] = cset[cipos[i]];
						}
						i--;
					} else {
						break;
					}
				}
			} while(cipos[0]<cset_len);
		}
	}

	if(etime) {
		gettimeofday(&tval_e, NULL);
		etime_print("not found - execution time", &tval_s, &tval_e);
	}
	return 0;
}

/* main function */
int main(int argc, char **argv)
{
	int i;
	int k;
	ha1_decode_env_t denv;
	char *params[3];

	if (argc<2) {
		printf("not enough parameters\n\n");
		help(argc, argv);
		return -1;
	}
	if (argc==2) {
		if(strcmp(argv[1], "-h")==0) {
			help(argc, argv);
			return 0;
		} else {
			printf("invalid parameter: %s\n", argv[1]);
			return -1;
		}
	}

	memset(&denv, 0, sizeof(ha1_decode_env_t));
	k = 0;

	if(strcmp(argv[1], "-e")==0) {
		if (argc!=5) {
			printf("invalid number of parameter to generate ha1\n");
			return -1;
		}
		return ha1_encode(argv[2], argv[3], argv[4]);
	} else if(strcmp(argv[1], "-d")==0) {
		if (argc<5) {
			printf("invalid number of parameter to decode ha1\n");
			return -1;
		}
		for(i=2; i<argc; i++) {
			if(strcmp(argv[i], "-t")==0) {
				etime = 1;
			} else if(strcmp(argv[i], "-q")==0) {
				verbose = 0;
			} else if(strcmp(argv[i], "-qq")==0) {
				verbose = 1;
			} else if(strcmp(argv[i], "-qqq")==0) {
				verbose = 2;
			} else if(strcmp(argv[i], "-c")==0) {
				i++;
				if(argc==i) {
					printf("missing char set id for parameter [%d]: %s\n", i-1, argv[i-1]);
					return -1;
				}
				printf("using charset [%s]\n", argv[i]);
				denv.charset = argv[i];
			} else if(strcmp(argv[i], "-p")==0) {
				i++;
				if(argc==i) {
					printf("missing passwords file for parameter [%d]: %s\n", i-1, argv[i-1]);
					return -1;
				}
				denv.pwfile = argv[i];
			} else if(strcmp(argv[i], "-P")==0) {
				i++;
				if(argc==i) {
					printf("missing patterns file for parameter [%d]: %s\n", i-1, argv[i-1]);
					return -1;
				}
				denv.ptfile = argv[i];
			} else if(strcmp(argv[i], "-R")==0) {
				i++;
				if(argc==i) {
					printf("missing value for replacement in password templates [%d]: %s\n", i-1, argv[i-1]);
					return -1;
				}
				if(strlen(argv[i])<3 || argv[i][1]!='=') {
					printf("invalid value for replacement in password templates [%d]: %s\n", i-1, argv[i-1]);
					return -1;
				}
				if(denv.ptextra_len>15) {
					printf("too many values for replacement in password templates [%d]: %s\n", i-1, argv[i-1]);
					return -1;
				}
				denv.ptextra[denv.ptextra_len] = argv[i];
				denv.ptextra_len++;
			} else if(strcmp(argv[i], "-m")==0) {
				i++;
				if(argc==i) {
					printf("missing value for parameter [%d]: %s\n", i-1, argv[i-1]);
					return -1;
				}
				denv.lenmin = atoi(argv[i]);
			} else if(strcmp(argv[i], "-M")==0) {
				i++;
				if(argc==i) {
					printf("missing value for parameter [%d]: %s\n", i-1, argv[i-1]);
					return -1;
				}
				denv.lenmax = atoi(argv[i]);
			} else {
				if(k>3) {
					printf("unexpected parameter[%d]: %s\n", i, argv[i]);
					return -1;
				} else {
					params[k] = argv[i];
					k++;
				}
			}
		}
		if(k!=3) {
			printf("missing <username> <realm> <ha1> (provided [%d])\n", k);
			return -1;
		}
		if(strlen(params[2])!=32) {
			printf("invalid lenght for ha1 [%s] (%lu) - has to be 32\n",
					params[2], strlen(params[2]));
			return -1;
		}
		if(denv.lenmin<0 || denv.lenmax<0 || denv.lenmin>denv.lenmax) {
			printf("invalid minimum or maximum lenght\n");
			return -1;
		}
		if(denv.lenmin>0) denv.lenmin--;
		denv.lenmax--;

		return ha1_decode_run(&denv, params[0], params[1], params[2]);
	} else {
		printf("invalid command parameter: %s\n", argv[1]);
		return -1;
	}

	return 0;
}

