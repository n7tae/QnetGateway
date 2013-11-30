
/*
 *   Copyright (C) 2010 by Scott Lawson KI4LKF
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

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

#define VERSION "v3.2"

static  int sockDst = -1;
static struct sockaddr_in toDst;
static void dst_close();
static bool dst_open(char *ip, int port);
static void calcPFCS(unsigned char rawbytes[58]);

static time_t tNow = 0;
static short streamid_raw = 0;

/***
static char silence[12] =
{
   0x4e,0x8d,0x32,0x88,0x26,0x1a,0x3f,0x61,0xe8,
   0x70,0x4f,0x93
};
***/

static char silence[12] =
{
   0xfa,0x87,0x1e,0x32,0x30,0x2f,0xea,0x45,0x66,
   0x70,0x4f,0x93
};


static unsigned short crc_tabccitt[256] =
{
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

   for (i = 17; i < 56 ; i++)
   {
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
   if (sockDst == -1)
   {
      printf("Failed to create DSTAR socket\n");
      return false;
   }
   if (setsockopt(sockDst,SOL_SOCKET,SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) == -1)
   {
      close(sockDst); sockDst = -1;
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
   if (sockDst != -1)
   {
      close(sockDst);
      sockDst = -1;
   }
   return;
}

int main(int argc, char **argv)
{
   unsigned char dstar_buf[58];
   static unsigned short G2_COUNTER = 0;
   unsigned long delay;
   char RADIO_ID[21];
   short int i;

   if (argc != 10)
   {
      printf("Usage: g2link_test <IPaddress> <port> <textMessage> <repeaterCallsign> <module> <delay_between> <delay_before> <MYCALL> <YRCALL>\n");
      printf("Example: g2link_test 127.0.0.1 19000 \"HELLO\" KJ4NHF B 20 2 KI4LKF XRF005AL\n");
      printf("Where...\n\n");
      printf("        127.0.0.1 is the G2 INTERNAL IP of the G2 gateway\n");
      printf("        19000 is the the G2 INTERNAL port of the G2 gateway\n");
      printf("        HELLO is the text message that we will send, no more than 20 characters\n");
      printf("              Note: the text message will be converted to UPPERCASE\n");
      printf("        KJ4NHF is your dstar repeater callsign\n");
      printf("        B is the local repeater module\n");
      printf("        20 millisecond delay before each packet is sent\n"); 
      printf("        2 second delay before the program starts processing your input \n");
      printf("        KI4LKF is the value of mycall\n");
      printf("        XRF005AL is the value of yrcall, in this case this is a Link command\n\n");
      return 0;
   }

   if (strlen(argv[4]) > 6)
   {
      printf("repeaterCallsign can not be more than 6 characters, %s is invalid\n", argv[4]);
      return 0;
   }
   for (i = 0; i < 6; i++)
      argv[4][i] = toupper(argv[4][i]);


   if (strlen(argv[8]) > 8)
   {
      printf("MYCALL can not be nore than 8 characters, %s is invalid\n", argv[8]);
      return 0;
   }
   for (i = 0; i < 8; i++)
      argv[8][i] = toupper(argv[8][i]);


   if (strlen(argv[9]) > 8)
   {
      printf("YRCALL can not be nore than 8 characters, %s is invalid\n", argv[9]);
      return 0;
   }
   for (i = 0; i < 8; i++)
      argv[9][i] = toupper(argv[9][i]); 

   if ((argv[5][0] != 'A') && (argv[5][0] != 'B') && (argv[5][0] != 'C'))
   {
      printf("module must be one of A B C\n");
      return 0;
   }

   delay = atol(argv[6]) * 1000L;
   sleep(atoi(argv[7]));

   memset(RADIO_ID, ' ', 20);
   RADIO_ID[20] = '\0';
   memcpy(RADIO_ID, argv[3], (strlen(argv[3]) > 20)?20:strlen(argv[3]));

   /***
   for (i = 0; i < 20; i++)
      RADIO_ID[i] = toupper(RADIO_ID[i]);
   ***/

   time(&tNow);
   srand(tNow + getpid());

   if (dst_open(argv[1], atoi(argv[2])))
   {
      streamid_raw = (short)(::rand() & 0xFFFF);
      memcpy(dstar_buf,"DSTR", 4);
      dstar_buf[5] = (unsigned char)(G2_COUNTER & 0xff); 
      dstar_buf[4] = (unsigned char)((G2_COUNTER >> 8) & 0xff);
      dstar_buf[6] = 0x73;
      dstar_buf[7] = 0x12;
      dstar_buf[8] = 0x00;
      dstar_buf[9] = 0x30;
      dstar_buf[10] = 0x20;

      dstar_buf[11] = 0x00;
      dstar_buf[12] = 0x01;
      if (argv[5][0] == 'A')
         dstar_buf[13] = 0x03;
      else
      if (argv[5][0] == 'B')
         dstar_buf[13] = 0x01;
      else
      if (argv[5][0] == 'C')
         dstar_buf[13] = 0x02;
      else
         dstar_buf[13] = 0x00;

      dstar_buf[14] = (unsigned char)(streamid_raw & 0xFF);
      dstar_buf[15] = (unsigned char)((streamid_raw >> 8) & 0xFF);
      dstar_buf[16] = 0x80;
      dstar_buf[17] = 0x00;
      dstar_buf[18] = 0x00;
      dstar_buf[19] = 0x00;

      /* RPT2 */
      memcpy(dstar_buf + 20, argv[4], strlen(argv[4]));
      if (strlen(argv[4]) < 6)
         memset(dstar_buf + 20 + strlen(argv[4]), ' ', 6 - strlen(argv[4]));
      dstar_buf[26] = ' ';
      dstar_buf[27] = 'G';

      /* RPT1 */
      memcpy(dstar_buf + 28, argv[4], strlen(argv[4]));
      if (strlen(argv[4]) < 6)
         memset(dstar_buf + 28 + strlen(argv[4]), ' ', 6 - strlen(argv[4]));
      dstar_buf[34] = ' ';
      dstar_buf[35] = argv[5][0];

      /* YRCALL */
      memcpy(dstar_buf + 36, argv[9], strlen(argv[9]));
      if (strlen(argv[9]) < 8)
         memset(dstar_buf + 36 + strlen(argv[9]), ' ', 8 - strlen(argv[9]));

      /* MYCALL */
      memcpy(dstar_buf + 44, argv[8], strlen(argv[8]));
      if (strlen(argv[8]) < 8)
         memset(dstar_buf + 44 + strlen(argv[8]), ' ', 8 - strlen(argv[8]));

      /* suffix */
      memcpy(dstar_buf + 52, "    ", 4);
      calcPFCS(dstar_buf);
      (void)sendto(sockDst,(char *)dstar_buf,58,0,(struct sockaddr *)&toDst,sizeof(toDst));
      G2_COUNTER ++;
      usleep(delay);

      dstar_buf[9] = 0x13;
      memcpy((char *)dstar_buf + 17, silence, 9);

      /* start sending silence + text */
      
      /* SYNC */
      dstar_buf[5] = (unsigned char)(G2_COUNTER & 0xff);
      dstar_buf[4] = (unsigned char)((G2_COUNTER >> 8) & 0xff);        
      dstar_buf[16] = 0x00;
      dstar_buf[26] = 0x55;
      dstar_buf[27] = 0x2d;
      dstar_buf[28] = 0x16;
      (void)sendto(sockDst,(char *)dstar_buf,29,0,(struct sockaddr *)&toDst,sizeof(toDst));
      G2_COUNTER ++;
      usleep(delay);

      dstar_buf[5] = (unsigned char)(G2_COUNTER & 0xff);
      dstar_buf[4] = (unsigned char)((G2_COUNTER >> 8) & 0xff);
      dstar_buf[16] = 0x01;
      dstar_buf[26] = '@' ^ 0x70;
      dstar_buf[27] = RADIO_ID[0] ^ 0x4f;
      dstar_buf[28] = RADIO_ID[1] ^ 0x93;
      (void)sendto(sockDst,(char *)dstar_buf,29,0,(struct sockaddr *)&toDst,sizeof(toDst));
      G2_COUNTER ++;
      usleep(delay);

      dstar_buf[5] = (unsigned char)(G2_COUNTER & 0xff);
      dstar_buf[4] = (unsigned char)((G2_COUNTER >> 8) & 0xff);
      dstar_buf[16] = 0x02;
      dstar_buf[26] = RADIO_ID[2] ^ 0x70;
      dstar_buf[27] = RADIO_ID[3] ^ 0x4f;
      dstar_buf[28] = RADIO_ID[4] ^ 0x93;
      (void)sendto(sockDst,(char *)dstar_buf,29,0,(struct sockaddr *)&toDst,sizeof(toDst));
      G2_COUNTER ++;
      usleep(delay);

      dstar_buf[5] = (unsigned char)(G2_COUNTER & 0xff);
      dstar_buf[4] = (unsigned char)((G2_COUNTER >> 8) & 0xff);
      dstar_buf[16] = 0x03;
      dstar_buf[26] = 'A' ^ 0x70;
      dstar_buf[27] = RADIO_ID[5] ^ 0x4f;
      dstar_buf[28] = RADIO_ID[6] ^ 0x93;
      (void)sendto(sockDst,(char *)dstar_buf,29,0,(struct sockaddr *)&toDst,sizeof(toDst));
      G2_COUNTER ++;
      usleep(delay);
        
      dstar_buf[5] = (unsigned char)(G2_COUNTER & 0xff);
      dstar_buf[4] = (unsigned char)((G2_COUNTER >> 8) & 0xff);
      dstar_buf[16] = 0x04;
      dstar_buf[26] = RADIO_ID[7] ^ 0x70;
      dstar_buf[27] = RADIO_ID[8] ^ 0x4f;
      dstar_buf[28] = RADIO_ID[9] ^ 0x93;
      (void)sendto(sockDst,(char *)dstar_buf,29,0,(struct sockaddr *)&toDst,sizeof(toDst));
      G2_COUNTER ++;
      usleep(delay);
     
      dstar_buf[5] = (unsigned char)(G2_COUNTER & 0xff);
      dstar_buf[4] = (unsigned char)((G2_COUNTER >> 8) & 0xff);
      dstar_buf[16] = 0x05;
      dstar_buf[26] = 'B' ^ 0x70;
      dstar_buf[27] = RADIO_ID[10] ^ 0x4f;
      dstar_buf[28] = RADIO_ID[11] ^ 0x93;
      (void)sendto(sockDst,(char *)dstar_buf,29,0,(struct sockaddr *)&toDst,sizeof(toDst));
      G2_COUNTER ++;
      usleep(delay);
        
      dstar_buf[5] = (unsigned char)(G2_COUNTER & 0xff);
      dstar_buf[4] = (unsigned char)((G2_COUNTER >> 8) & 0xff);
      dstar_buf[16] = 0x06;
      dstar_buf[26] = RADIO_ID[12] ^ 0x70;
      dstar_buf[27] = RADIO_ID[13] ^ 0x4f;
      dstar_buf[28] = RADIO_ID[14] ^ 0x93;
      (void)sendto(sockDst,(char *)dstar_buf,29,0,(struct sockaddr *)&toDst,sizeof(toDst));
      G2_COUNTER ++;
      usleep(delay);

      dstar_buf[5] = (unsigned char)(G2_COUNTER & 0xff);
      dstar_buf[4] = (unsigned char)((G2_COUNTER >> 8) & 0xff);
      dstar_buf[16] = 0x07;
      dstar_buf[26] = 'C' ^ 0x70;
      dstar_buf[27] = RADIO_ID[15] ^ 0x4f;
      dstar_buf[28] = RADIO_ID[16] ^ 0x93;
      (void)sendto(sockDst,(char *)dstar_buf,29,0,(struct sockaddr *)&toDst,sizeof(toDst));
      G2_COUNTER ++;
      usleep(delay);
            
      dstar_buf[5] = (unsigned char)(G2_COUNTER & 0xff);
      dstar_buf[4] = (unsigned char)((G2_COUNTER >> 8) & 0xff);
      dstar_buf[16] = 0x08;
      dstar_buf[26] = RADIO_ID[17] ^ 0x70;
      dstar_buf[27] = RADIO_ID[18] ^ 0x4f;
      dstar_buf[28] = RADIO_ID[19] ^ 0x93;
      (void)sendto(sockDst,(char *)dstar_buf,29,0,(struct sockaddr *)&toDst,sizeof(toDst));
      G2_COUNTER ++;
      usleep(delay);

      dstar_buf[5] = (unsigned char)(G2_COUNTER & 0xff);
      dstar_buf[4] = (unsigned char)((G2_COUNTER >> 8) & 0xff);
      dstar_buf[16] = 0x09 | 0x40;

      memset((char *)dstar_buf + 17, '\0', 9);

      dstar_buf[26] = 0x70;
      dstar_buf[27] = 0x4f;
      dstar_buf[28] = 0x93;
      (void)sendto(sockDst,(char *)dstar_buf,29,0,(struct sockaddr *)&toDst,sizeof(toDst));
      G2_COUNTER ++;
      usleep(delay);

      dst_close();
   }

   printf("g2link_test exiting...\n");
   return 0;
}
