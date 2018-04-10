
/* by KI4LKF */

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

#define VERSION "v3.1"

static  int sockDst = -1;
static struct sockaddr_in toDst;
static void dst_close();
static bool dst_open(char *ip, int port);
static void calcPFCS(unsigned char rawbytes[58]);

static FILE *fp = NULL;
static time_t tNow = 0;
static short streamid_raw = 0;

static unsigned short crc_tabccitt[256] = {
	0x0000,0x1189,0x2312,0x329b,0x4624,0x57ad,0x6536,0x74bf,
	0x8c48,0x9dc1,0xaf5a,0xbed3,0xca6c,0xdbe5,0xe97e,0xf8f7,
	0x1081,0x0108,0x3393,0x221a,0x56a5,0x472c,0x75b7,0x643e,
	0x9cc9,0x8d40,0xbfdb,0xae52,0xdaed,0xcb64,0xf9ff,0xe876,
	0x2102,0x308b,0x0210,0x1399,0x6726,0x76af,0x4434,0x55bd,
	0xad4a,0xbcc3,0x8e58,0x9fd1,0xeb6e,0xfae7,0xc87c,0xd9f5,
	0x3183,0x200a,0x1291,0x0318,0x77a7,0x662e,0x54b5,0x453c,
	0xbdcb,0xac42,0x9ed9,0x8f50,0xfbef,0xea66,0xd8fd,0xc974,
	0x4204,0x538d,0x6116,0x709f,0x0420,0x15a9,0x2732,0x36bb,
	0xce4c,0xdfc5,0xed5e,0xfcd7,0x8868,0x99e1,0xab7a,0xbaf3,
	0x5285,0x430c,0x7197,0x601e,0x14a1,0x0528,0x37b3,0x263a,
	0xdecd,0xcf44,0xfddf,0xec56,0x98e9,0x8960,0xbbfb,0xaa72,
	0x6306,0x728f,0x4014,0x519d,0x2522,0x34ab,0x0630,0x17b9,
	0xef4e,0xfec7,0xcc5c,0xddd5,0xa96a,0xb8e3,0x8a78,0x9bf1,
	0x7387,0x620e,0x5095,0x411c,0x35a3,0x242a,0x16b1,0x0738,
	0xffcf,0xee46,0xdcdd,0xcd54,0xb9eb,0xa862,0x9af9,0x8b70,
	0x8408,0x9581,0xa71a,0xb693,0xc22c,0xd3a5,0xe13e,0xf0b7,
	0x0840,0x19c9,0x2b52,0x3adb,0x4e64,0x5fed,0x6d76,0x7cff,
	0x9489,0x8500,0xb79b,0xa612,0xd2ad,0xc324,0xf1bf,0xe036,
	0x18c1,0x0948,0x3bd3,0x2a5a,0x5ee5,0x4f6c,0x7df7,0x6c7e,
	0xa50a,0xb483,0x8618,0x9791,0xe32e,0xf2a7,0xc03c,0xd1b5,
	0x2942,0x38cb,0x0a50,0x1bd9,0x6f66,0x7eef,0x4c74,0x5dfd,
	0xb58b,0xa402,0x9699,0x8710,0xf3af,0xe226,0xd0bd,0xc134,
	0x39c3,0x284a,0x1ad1,0x0b58,0x7fe7,0x6e6e,0x5cf5,0x4d7c,
	0xc60c,0xd785,0xe51e,0xf497,0x8028,0x91a1,0xa33a,0xb2b3,
	0x4a44,0x5bcd,0x6956,0x78df,0x0c60,0x1de9,0x2f72,0x3efb,
	0xd68d,0xc704,0xf59f,0xe416,0x90a9,0x8120,0xb3bb,0xa232,
	0x5ac5,0x4b4c,0x79d7,0x685e,0x1ce1,0x0d68,0x3ff3,0x2e7a,
	0xe70e,0xf687,0xc41c,0xd595,0xa12a,0xb0a3,0x8238,0x93b1,
	0x6b46,0x7acf,0x4854,0x59dd,0x2d62,0x3ceb,0x0e70,0x1ff9,
	0xf78f,0xe606,0xd49d,0xc514,0xb1ab,0xa022,0x92b9,0x8330,
	0x7bc7,0x6a4e,0x58d5,0x495c,0x3de3,0x2c6a,0x1ef1,0x0f78
};



static void calcPFCS(unsigned char rawbytes[58])
{
	unsigned short crc_dstar_ffff = 0xffff;
	unsigned short tmp, short_c;
	short int i;

	for (i = 17; i < 56 ; i++) {
		short_c = 0x00ff & (unsigned short)rawbytes[i];
		tmp = (crc_dstar_ffff & 0x00ff) ^ short_c;
		crc_dstar_ffff = (crc_dstar_ffff >> 8) ^ crc_tabccitt[tmp];
	}
	crc_dstar_ffff =  ~crc_dstar_ffff;
	tmp = crc_dstar_ffff;

	rawbytes[56] = (unsigned char)(crc_dstar_ffff & 0xff);
	rawbytes[57] = (unsigned char)((tmp >> 8) & 0xff);
	return;

}

static bool dst_open(char *ip, int port)
{
	int reuse = 1;

	sockDst = socket(PF_INET,SOCK_DGRAM,0);
	if (sockDst == -1) {
		printf("Failed to create DSTAR socket\n");
		return false;
	}
	if (setsockopt(sockDst,SOL_SOCKET,SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) == -1) {
		close(sockDst);
		sockDst = -1;
		printf("setsockopt DSTAR REUSE failed\n");
		return false;
	}
	memset(&toDst,0,sizeof(struct sockaddr_in));
	toDst.sin_family = AF_INET;
	toDst.sin_port = htons(port);
	toDst.sin_addr.s_addr = inet_addr(ip);

	fcntl(sockDst,F_SETFL,O_NONBLOCK);
	return true;
}

static void dst_close()
{
	if (sockDst != -1) {
		close(sockDst);
		sockDst = -1;
	}
	return;
}

int main(int argc, char **argv)
{
	unsigned short rlen = 0;
	static unsigned short G2_COUNTER = 0;
	size_t nread = 0;
	unsigned char dstar_buf[56];
	unsigned char rptr_buf[58];
	unsigned long delay;
	unsigned short i;
	char RADIO_ID[21];
	short int TEXT_idx = 0;

	if (argc != 10) {
		printf("Usage: g2link_test_audio <IPaddress> <port> <dvtoolFile> <repeaterCallsign> <module> <delay_between> <delay_before> <MYCALL> <YRCALL>\n");
		printf("Example: g2link_test_audio 127.0.0.1 20010 somefile.dvtool KJ4NHF B 19 2 KI4LKF CQCQCQ\n");
		printf("Where...\n");
		printf("        127.0.0.1 is the IP address of the local G2\n");
		printf("        20010 is the port of the INTERNAL G2\n");
		printf("        somefile.dvtool is a dvtool file\n");
		printf("        KJ4NHF is your G2 callsign, dont use KJ4NHF\n");
		printf("        B is one of your modules\n");
		printf("        19 millisecond delay between each packet\n");
		printf("        2 second delay before we begin this test\n");
		printf("        mycall is KI4LKF, your personal callsign, do not use KI4LKF\n");
		printf("        yrcall is CQCQCQ\n");
		return 0;
	}

	if (strlen(argv[4]) > 6) {
		printf("repeaterCallsign can not be more than 6 characters, %s is invalid\n", argv[4]);
		return 0;
	}
	for (i = 0; i < strlen(argv[4]); i++)
		argv[4][i] = toupper(argv[4][i]);

	if ((argv[5][0] != 'A') && (argv[5][0] != 'B') && (argv[5][0] != 'C')) {
		printf("module must be one of A B C\n");
		return 0;
	}

	if (strlen(argv[8]) > 8) {
		printf("No more than 8 characters in MYCALL\n");
		return 0;
	}
	for (i = 0; i < strlen(argv[8]); i++)
		argv[8][i] = toupper(argv[8][i]);

	if (strlen(argv[9]) > 8) {
		printf("No more than 8 characters in YRCALL\n");
		return 0;
	}
	for (i = 0; i < strlen(argv[9]); i++)
		argv[9][i] = toupper(argv[9][i]);


	fp = fopen(argv[3], "rb");
	if (!fp) {
		printf("Failed to open file %s for reading\n", argv[3]);
		return 0;
	}

	/* stupid DVTOOL + 4 byte num_of_records */
	nread = fread(dstar_buf, 10, 1, fp);
	if (nread != 1) {
		printf("Cant read first 10 bytes\n");
		fclose(fp);
		return 0;
	}
	if (memcmp(dstar_buf, "DVTOOL", 6) != 0) {
		printf("DVTOOL not found\n");
		fclose(fp);
		return 0;
	}

	memset(RADIO_ID, ' ', 20);
	RADIO_ID[20] = '\0';

	memcpy(RADIO_ID, "TEST", 4);

	delay = atol(argv[6]) * 1000L;
	sleep(atoi(argv[7]));

	time(&tNow);
	srand(tNow + getpid());

	if (dst_open(argv[1], atoi(argv[2]))) {
		while (true) {
			/* 2 byte length */
			nread = fread(&rlen, 2, 1, fp);
			if (nread != 1) {
				printf("End-Of-File\n");
				break;
			}
			if (rlen == 56)
				streamid_raw = (short)(::rand() & 0xFFFF);
			else if (rlen == 27)
				;
			else {
				printf("Not 56-byte and not 27-byte\n");
				break;
			}

			/* read the packet */
			nread = fread(dstar_buf, rlen, 1, fp);
			if (nread == 1) {
				if (memcmp(dstar_buf, "DSVT", 4) != 0) {
					printf("DVST not found\n");
					break;
				}

				if (dstar_buf[8] != 0x20) {
					printf("Not Voice type\n");
					break;
				}

				if (dstar_buf[4] == 0x10)
					;
				else if (dstar_buf[4] == 0x20)
					;
				else {
					printf("Not a valid record type\n");
					break;
				}

				if (rlen == 56) {
					memcpy(rptr_buf, "DSTR", 4);
					rptr_buf[5] = (unsigned char)(G2_COUNTER & 0xff);
					rptr_buf[4] = (unsigned char)((G2_COUNTER >> 8) & 0xff);
					rptr_buf[6] = 0x73;
					rptr_buf[7] = 0x12;
					rptr_buf[8] = 0x00;
					rptr_buf[9] = 0x30;
					rptr_buf[10] = 0x20;
					memcpy(rptr_buf + 11, dstar_buf + 9, 47);

					rptr_buf[14] = (unsigned char)(streamid_raw & 0xFF);
					rptr_buf[15] = (unsigned char)((streamid_raw >> 8) & 0xFF);

					memcpy(rptr_buf + 20, argv[4], strlen(argv[4]));
					if (strlen(argv[4]) < 6)
						memset(rptr_buf + 20 + strlen(argv[4]), ' ', 6 - strlen(argv[4]));
					rptr_buf[26] = ' ';
					rptr_buf[27] = 'G';

					memcpy(rptr_buf + 28, argv[4], strlen(argv[4]));
					if (strlen(argv[4]) < 6)
						memset(rptr_buf + 28 + strlen(argv[4]), ' ', 6 - strlen(argv[4]));
					rptr_buf[34] = ' ';
					rptr_buf[35] = argv[5][0];

					/* yrcall */
					memcpy(rptr_buf + 36, argv[9], strlen(argv[9]));
					if (strlen(argv[9]) < 8)
						memset(rptr_buf + 36 + strlen(argv[9]), ' ', 8 - strlen(argv[9]));

					/* mycall */
					memcpy(rptr_buf + 44, argv[8], strlen(argv[8]));
					if (strlen(argv[8]) < 8)
						memset(rptr_buf + 44 + strlen(argv[8]), ' ', 8 - strlen(argv[8]));

					memcpy(rptr_buf + 52, "TEST", 4);

					calcPFCS(rptr_buf);
				} else {
					rptr_buf[5] = (unsigned char)(G2_COUNTER & 0xff);
					rptr_buf[4] = (unsigned char)((G2_COUNTER >> 8) & 0xff);
					rptr_buf[9] = 0x13;

					if ((dstar_buf[24] != 0x55) ||
					        (dstar_buf[25] != 0x2d) ||
					        (dstar_buf[26] != 0x16)) {
						if (TEXT_idx == 0) {
							dstar_buf[24] = '@' ^ 0x70;
							dstar_buf[25] = RADIO_ID[TEXT_idx++] ^ 0x4f;
							dstar_buf[26] = RADIO_ID[TEXT_idx++] ^ 0x93;
						} else if (TEXT_idx == 2) {
							dstar_buf[24] = RADIO_ID[TEXT_idx++] ^ 0x70;
							dstar_buf[25] = RADIO_ID[TEXT_idx++] ^ 0x4f;
							dstar_buf[26] = RADIO_ID[TEXT_idx++] ^ 0x93;
						} else if (TEXT_idx == 5) {
							dstar_buf[24] = 'A' ^ 0x70;
							dstar_buf[25] = RADIO_ID[TEXT_idx++] ^ 0x4f;
							dstar_buf[26] = RADIO_ID[TEXT_idx++] ^ 0x93;
						} else if (TEXT_idx == 7) {
							dstar_buf[24] = RADIO_ID[TEXT_idx++] ^ 0x70;
							dstar_buf[25] = RADIO_ID[TEXT_idx++] ^ 0x4f;
							dstar_buf[26] = RADIO_ID[TEXT_idx++] ^ 0x93;
						} else if (TEXT_idx == 10) {
							dstar_buf[24] = 'B' ^ 0x70;
							dstar_buf[25] = RADIO_ID[TEXT_idx++] ^ 0x4f;
							dstar_buf[26] = RADIO_ID[TEXT_idx++] ^ 0x93;
						} else if (TEXT_idx == 12) {
							dstar_buf[24] = RADIO_ID[TEXT_idx++] ^ 0x70;
							dstar_buf[25] = RADIO_ID[TEXT_idx++] ^ 0x4f;
							dstar_buf[26] = RADIO_ID[TEXT_idx++] ^ 0x93;
						} else if (TEXT_idx == 15) {
							dstar_buf[24] = 'C' ^ 0x70;
							dstar_buf[25] = RADIO_ID[TEXT_idx++] ^ 0x4f;
							dstar_buf[26] = RADIO_ID[TEXT_idx++] ^ 0x93;
						} else if (TEXT_idx == 17) {
							dstar_buf[24] = RADIO_ID[TEXT_idx++] ^ 0x70;
							dstar_buf[25] = RADIO_ID[TEXT_idx++] ^ 0x4f;
							dstar_buf[26] = RADIO_ID[TEXT_idx++] ^ 0x93;
						} else {
							dstar_buf[24] = 0x70;
							dstar_buf[25] = 0x4f;
							dstar_buf[26] = 0x93;
						}
					}
					memcpy(rptr_buf + 11, dstar_buf + 9, 18);
					rptr_buf[14] = (unsigned char)(streamid_raw & 0xFF);
					rptr_buf[15] = (unsigned char)((streamid_raw >> 8) & 0xFF);
				}

				sendto(sockDst,(char *)rptr_buf,rlen + 2,0,
				       (struct sockaddr *)&toDst,sizeof(toDst));
				G2_COUNTER ++;

			}
			usleep(delay);
		}
		dst_close();
	}
	fclose(fp);

	printf("g2link_test_audio exiting...\n");
	return 0;
}
