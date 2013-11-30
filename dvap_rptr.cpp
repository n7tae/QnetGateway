/*
 *   Copyright (C) 2010, 2011 by Scott Lawson KI4LKF
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

/***
   KI4LKF
***/

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <sys/file.h>
#include <pthread.h>

#define VERSION "2.32"
#define CALL_SIZE 8
#define RPTR_SIZE 8
#define IP_SIZE 15

/* data from dvap */
struct dvap_hdr
{
   unsigned char hdr0; // 0x2f
   unsigned char hdr1; // 0xa0
   unsigned char streamid[2];
   unsigned char framepos;
   unsigned char seq;
   unsigned char flag1;
   unsigned char flag2;
   unsigned char flag3;
   unsigned char rpt1[8];
   unsigned char rpt2[8];
   unsigned char urcall[8];
   unsigned char mycall[8];
   unsigned char sfx[4];
   unsigned char pfcs[2];
};
struct dvap_voice
{
   unsigned char hdr0; // 0x12
   unsigned char hdr1; // 0xc0
   unsigned char streamid[2];
   unsigned char framepos;
   unsigned char seq;
   unsigned char voice[9];
   unsigned char txt[3];
};

/* data from the local gateway */
struct hdr
{
   unsigned char flags[3];
   unsigned char rpt2[8];
   unsigned char rpt1[8];
   unsigned char urcall[8];
   unsigned char mycall[8];
   unsigned char sfx[4];
   unsigned char pfcs[2];
};

struct icm
{
   unsigned char icm_id;
   unsigned char dst_rptr_id;
   unsigned char snd_rptr_id;
   unsigned char snd_term_id;
   unsigned char streamid[2];
   unsigned char ctrl;
};

struct voice_and_text
{
   unsigned char voice[9];
   unsigned char text[3];
};

struct audio
{
   unsigned char buff[sizeof(struct hdr)];
};

struct pkt
{
   unsigned char pkt_id[4];
   unsigned char nothing1[2];
   unsigned char flags[2];
   unsigned char nothing2[2];
   struct icm myicm;
   union
   {
      struct audio rf_audio;
      struct hdr rf_hdr;
      struct voice_and_text vat;
   };
};

struct dvap_ack_arg_type
{
   char mycall[8];
   float ber;
};
dvap_ack_arg_type dvap_ack_arg;

/* Default configuration data */
static char RPTR[RPTR_SIZE + 1] = {"ABCDEF"};
static char OWNER[RPTR_SIZE + 1] = {"ABCDEF"};
static char RPTR_MOD = 'B';
static char RPTR_VIRTUAL_IP[IP_SIZE + 1] = {"172.16.0.1"};
static int RPTR_PORT = 20000;
static char G2_INTERNAL_IP[IP_SIZE + 1] = {"172.16.0.20"};
static int G2_PORT = 20000;
static char DVP_SERIAL[64]; /* APxxxxxx */
static u_int32_t DVP_FREQ = 145500000; /* between 144000000 and 148000000 */
static int16_t DVP_PWR = 10; /* between  -12 and 10 */
static char DVP_SQL = -100; /* between  -128 and -45 */
static int16_t DVP_OFF = 0; /* between -2000 and 2000 */
static int WAIT_FOR_PACKETS=25;   /* wait 25 ms in reading from local G2 */
static int REMOTE_TIMEOUT=1;  /* 1 second */
static int DELAY_BETWEEN = 20;
static int DELAY_BEFORE = 1;
static bool RPTR_ACK = true;
static char INVALID_YRCALL_KEY[CALL_SIZE + 1] = { "" };

/* helper data */
static int32_t val32bits = 1;
#define isit_bigendian() ( (*(char*)&val32bits) == 0 )
#define do_swap16(val) \
   ((int16_t) ( \
    (((u_int16_t) (val) & (u_int16_t) 0x00ffU) << 8) | \
    (((u_int16_t) (val) & (u_int16_t) 0xff00U) >> 8)))
#define do_swapu16(val) \
   ((u_int16_t) ( \
    (((u_int16_t) (val) & (u_int16_t) 0x00ffU) << 8) | \
    (((u_int16_t) (val) & (u_int16_t) 0xff00U) >> 8)))
#define do_swapu32(val) \
   ((u_int32_t) ( \
    (((u_int32_t) (val) & (u_int32_t) 0x000000ffU) << 24) | \
    (((u_int32_t) (val) & (u_int32_t) 0x0000ff00U) <<  8) | \
    (((u_int32_t) (val) & (u_int32_t) 0x00ff0000U) >>  8) | \
    (((u_int32_t) (val) & (u_int32_t) 0xff000000U) >> 24)))
static unsigned char SND_TERM_ID = 0x00;
static char RPTR_and_G[9];
static char RPTR_and_MOD[9];
static int inactiveMax = 25;
static const int TRACE_BFSZ = 256;
static int insock = -1;
static struct sockaddr_in outaddr;
static int serfd = -1;
static bool busy20000 = false;
static bool keep_running = true;
static unsigned char DVP_RQST_NAME[] = {0x04, 0x20, 0x01, 0x00};
static unsigned char DVP_REPL_NAME[] = {0x10, 0x00, 0x01, 0x00, 'D', 'V', 'A', 'P', ' ', 'D', 'o', 'n', 'g', 'l', 'e', 0x00};
static unsigned char DVP_RQST_SER[] = {0x04, 0x20, 0x02, 0x00};
static unsigned char DVP_REPL_SER[] = {0x0C, 0x00, 0x02, 0x00};
static unsigned char DVP_RQST_FW[] = {0x05, 0x20, 0x04, 0x00, 0x01};
static unsigned char DVP_REPL_FW[] = {0x07, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00};
static unsigned char DVP_RQST_MODU[] = {0x05, 0x00, 0x28, 0x00, 0x01};
static unsigned char DVP_REPL_MODU[] = {0x05, 0x00, 0x28, 0x00, 0x01};
static unsigned char DVP_RQST_MODE[] = {0x05, 0x00, 0x2A, 0x00, 0x00};
static unsigned char DVP_REPL_MODE[] = {0x05, 0x00, 0x2A, 0x00, 0x00};
static unsigned char DVP_RQST_SQL[] = {0x05, 0x00, 0x80, 0x00, 0x00};
static unsigned char DVP_REPL_SQL[] = {0x05, 0x00, 0x80, 0x00, 0x00};
static unsigned char DVP_RQST_PWR[] = {0x06, 0x00, 0x38, 0x01, 0x00, 0x00};
static unsigned char DVP_REPL_PWR[] = {0x06, 0x00, 0x38, 0x01, 0x00, 0x00};
static unsigned char DVP_RQST_OFF[] = {0x06, 0x00, 0x00, 0x04, 0x00, 0x00};
static unsigned char DVP_REPL_OFF[] = {0x06, 0x00, 0x00, 0x04, 0x00, 0x00};
static unsigned char DVP_RQST_FREQ[] = {0x08, 0x00, 0x20, 0x02, 0x00, 0x00, 0x00, 0x00};
static unsigned char DVP_REPL_FREQ[] = {0x08, 0x00, 0x20, 0x02, 0x00, 0x00, 0x00, 0x00};
static unsigned char DVP_RQST_START[] = {0x05, 0x00, 0x18, 0x00, 0x01};
static unsigned char DVP_REPL_START[] = {0x05, 0x00, 0x18, 0x00, 0x01};
static unsigned char DVP_RQST_STOP[] = {0x05, 0x00, 0x18, 0x00, 0x00};
static unsigned char DVP_REPL_STOP[] = {0x05, 0x00, 0x18, 0x00, 0x00};
static unsigned char DVP_HDR[] =
{
  0x2F, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static unsigned char DVP_REPL_HDR[] =
{
  0x2F, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static unsigned char DVP_REPL_PTT[] = {0x05, 0x20, 0x18, 0x01, 0x00};
static unsigned char DVP_DAT[] = 
{
  0x12, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static unsigned char DVP_STS[] = {0x07, 0x20, 0x90, 0x00, 0x00, 0x00, 0x00};
static unsigned char DVP_ACK[] = {0x03, 0x60, 0x00};
static unsigned int MAX_REPL_CNT = 20;
enum REPLY_TYPE 
{
   RT_TIMEOUT,
   RT_ERR,
   RT_UNKNOWN,
   RT_NAME,
   RT_SER,
   RT_FW,
   RT_START,
   RT_STOP,
   RT_MODU,
   RT_MODE,
   RT_SQL,
   RT_PWR,
   RT_OFF,
   RT_FREQ,
   RT_STS,
   RT_PTT,
   RT_ACK,
   RT_HDR,
   RT_HDR_ACK,
   RT_DAT
};

static unsigned int space = 0;
static unsigned int aseed = 0;

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

/* helper routines */
static void traceit(const char *fmt,...);
static int read_config(const char *cfgFile);
static void sig_catch(int signum);
static int open_sock();
static bool open_ser(char *dvp);
static bool open_dvp();
static int read_from_dvp(unsigned char* buf, unsigned int len);
static int write_to_dvp(unsigned char* buf, unsigned int len);
static bool get_name();
static bool get_fw();
static bool get_ser(char *dvp);
static bool set_modu();
static bool set_mode();
static bool set_sql();
static bool set_pwr();
static bool set_off();
static bool set_freq();
static bool start_dvap();
static void readFrom20000();
static REPLY_TYPE get_reply(unsigned char *buf,  unsigned int *len);
static void syncit();
static void calcPFCS(unsigned char *packet, unsigned char *pfcs);
static void *readFromRF(void *arg);
static void *rptr_ack(void *arg);

/*** BER stuff ***/
static int ber_data[3];
static int ber_errs;
static int num_dv_frames;
static int num_bit_errors;
extern void dstar_dv_init();
extern int dstar_dv_decode(const unsigned char *d, int data[3]);

static void calcPFCS(unsigned char *packet, unsigned char *pfcs)
{
   unsigned short crc_dstar_ffff = 0xffff;
   unsigned short tmp, short_c;
   short int i;

   for (i = 0; i < 39 ; i++)
   {
      short_c = 0x00ff & (unsigned short)packet[i];
      tmp = (crc_dstar_ffff & 0x00ff) ^ short_c;
      crc_dstar_ffff = (crc_dstar_ffff >> 8) ^ crc_tabccitt[tmp];
   }
   crc_dstar_ffff =  ~crc_dstar_ffff;
   tmp = crc_dstar_ffff;

   pfcs[0] = (unsigned char)(crc_dstar_ffff & 0xff);
   pfcs[1] = (unsigned char)((tmp >> 8) & 0xff);

   return;
}

static void sig_catch(int signum)
{
   if ((signum == SIGTERM) || 
       (signum == SIGINT)  ||
       (signum == SIGHUP))
      keep_running = false;
   exit(0);
}

/* log the event */
static void traceit(const char *fmt,...)
{
   time_t ltime;
   struct tm mytm;
   char trace_buf[TRACE_BFSZ];

   time(&ltime);
   localtime_r(&ltime,&mytm);

   snprintf(trace_buf,TRACE_BFSZ - 1,"%02d%02d%02d at %02d:%02d:%02d:",
            mytm.tm_mon+1,mytm.tm_mday,mytm.tm_year % 100,
            mytm.tm_hour,mytm.tm_min,mytm.tm_sec);

   va_list args;
   va_start(args,fmt);
   vsnprintf(trace_buf + strlen(trace_buf), TRACE_BFSZ - strlen(trace_buf) - 1, fmt, args);
   va_end(args);

   fprintf(stdout, "%s", trace_buf);
   return;
}

/* process configuration file */
static int read_config(const char *cfgFile)
{
   short int valid_params = 18;
   short int params = 0;

   FILE *cnf = NULL;
   char inbuf[1024];
   char *p = NULL;
   char *ptr;
   unsigned short i;

   cnf = fopen(cfgFile, "r");
   if (!cnf)
   {
      traceit("Failed to open file %s\n", cfgFile);
      return 1;
   }

   traceit("Reading file %s\n", cfgFile);
   while (fgets(inbuf, 1020, cnf) != NULL)
   {
      if (strchr(inbuf, '#'))
         continue;

      p = strchr(inbuf, '\r');
      if (p)
         *p = '\0';
      p = strchr(inbuf, '\n');
      if (p)
         *p = '\0';

      p = strchr(inbuf, '=');
      if (!p)
         continue;
      *p = '\0';

      if (strcmp(inbuf,"RPTR") == 0)
      {
          memset(RPTR,' ', sizeof(RPTR));
          RPTR[RPTR_SIZE] = '\0';

          ptr = strchr(p + 1, ' ');
          if (ptr)
             *ptr = '\0';

          if ((strlen(p + 1) < 1) || (strlen(p + 1) > (RPTR_SIZE - 2)))
             traceit("RPTR value [%s] invalid\n", p + 1);
          else
          {
             memcpy(RPTR, p + 1, strlen(p + 1));
             traceit("RPTR=[%s]\n",RPTR);
             params ++;
          }
      }
      else
      if (strcmp(inbuf,"OWNER") == 0)
      {
          memset(OWNER,' ', sizeof(OWNER));
          OWNER[RPTR_SIZE] = '\0';

          ptr = strchr(p + 1, ' ');
          if (ptr)
             *ptr = '\0';

          if ((strlen(p + 1) < 1) || (strlen(p + 1) > (RPTR_SIZE - 2)))
             traceit("OWNER value [%s] invalid\n", p + 1);
          else
          {
             memcpy(OWNER, p + 1, strlen(p + 1));
             traceit("OWNER=[%s]\n",OWNER);
             params ++;
          }
      }
      else
      if (strcmp(inbuf,"INVALID_YRCALL_KEY") == 0)
      {
         memset(INVALID_YRCALL_KEY, 0, sizeof(INVALID_YRCALL_KEY));

         if ( (strlen(p + 1) < 1) || (strlen(p + 1) > CALL_SIZE) )
            traceit("INVALID_YRCALL_KEY value [%s] invalid\n", p + 1);
         else
         {
            memcpy(INVALID_YRCALL_KEY, p + 1, strlen(p + 1));

            for (i = 0; i < strlen(INVALID_YRCALL_KEY); i++)
               INVALID_YRCALL_KEY[i] = toupper(INVALID_YRCALL_KEY[i]);

            traceit("INVALID_YRCALL_KEY=[%s]\n",INVALID_YRCALL_KEY);
            params ++;
         }
      }
      else
      if (strcmp(inbuf,"RPTR_MOD") == 0)
      {
         RPTR_MOD = *(p + 1);
         traceit("RPTR_MOD=[%c]\n", *(p + 1));
         params ++;
      }
      else
      if (strcmp(inbuf,"RPTR_VIRTUAL_IP") == 0)
      {
         ptr = strchr(p + 1, ' ');
         if (ptr)
            *ptr = '\0';

         if (strlen(p + 1) < 1)
            traceit("RPTR_VIRTUAL_IP value [%s] invalid\n", p + 1);
         else
         {
            strncpy(RPTR_VIRTUAL_IP, p + 1, IP_SIZE);
            RPTR_VIRTUAL_IP[IP_SIZE] = '\0';
            traceit("RPTR_VIRTUAL_IP=[%s]\n", RPTR_VIRTUAL_IP);
            params ++;
         }
      }
      else
      if (strcmp(inbuf,"RPTR_PORT") == 0)
      {
         RPTR_PORT = atoi(p + 1);
         traceit("RPTR_PORT=[%d]\n",RPTR_PORT);
         params ++;
      }
      else
      if (strcmp(inbuf,"G2_INTERNAL_IP") == 0)
      {
         ptr = strchr(p + 1, ' ');
         if (ptr)
            *ptr = '\0';

         if (strlen(p + 1) < 1)
            traceit("G2_INTERNAL_IP value [%s] invalid\n", p + 1);
         else
         {
            strncpy(G2_INTERNAL_IP, p + 1, IP_SIZE);
            G2_INTERNAL_IP[IP_SIZE] = '\0';
            traceit("G2_INTERNAL_IP=[%s]\n", G2_INTERNAL_IP);
            params ++;
         }
      }
      else
      if (strcmp(inbuf,"G2_PORT") == 0)
      {
         G2_PORT = atoi(p + 1);
         traceit("G2_PORT=[%d]\n",G2_PORT);
         params ++;
      }
      else
      if (strcmp(inbuf,"DVP_SERIAL") == 0)
      {
          ptr = strchr(p + 1, ' ');
          if (ptr)
             *ptr = '\0';

          if ((strlen(p + 1) > 63) || (strlen(p + 1) < 1))
             traceit("DVP_SERIAL value [%s] invalid\n", p + 1);
          else
          {
             strcpy(DVP_SERIAL, p + 1);
             traceit("DVP_SERIAL=[%s]\n", DVP_SERIAL);
             params ++;
          }
      }
      else
      if (strcmp(inbuf,"DVP_FREQ") == 0)
      {
         DVP_FREQ = atoi(p + 1);
         traceit("DVP_FREQ=[%u]\n", DVP_FREQ);
         params ++;
      }
      else
      if (strcmp(inbuf,"DVP_PWR") == 0)
      {
         DVP_PWR = atoi(p + 1);
         traceit("DVP_PWR=[%d]\n", DVP_PWR);
         params ++;
      }
      else
      if (strcmp(inbuf,"DVP_SQL") == 0)
      {
         DVP_SQL = atoi(p + 1);
         traceit("DVP_SQL=[%d]\n", DVP_SQL);
         params ++;
      }
      else
      if (strcmp(inbuf,"DVP_OFF") == 0)
      {
         DVP_OFF = atoi(p + 1);
         traceit("DVP_OFF=[%u]\n", DVP_OFF);
         params ++;
      }
      else
      if (strcmp(inbuf,"WAIT_FOR_PACKETS") == 0)
      {
         WAIT_FOR_PACKETS = atoi(p + 1);
         if (WAIT_FOR_PACKETS <= 5)
            WAIT_FOR_PACKETS = 25;
         traceit("WAIT_FOR_PACKETS=[%d]\n",WAIT_FOR_PACKETS);
         params ++;
      }
      else
      if (strcmp(inbuf,"REMOTE_TIMEOUT") == 0)
      {
         REMOTE_TIMEOUT = atoi(p + 1);
         if (REMOTE_TIMEOUT < 1)
            REMOTE_TIMEOUT = 1;
         traceit("REMOTE_TIMEOUT=[%d]\n",REMOTE_TIMEOUT);
         params ++;
      }
      else
      if (strcmp(inbuf,"DELAY_BETWEEN") == 0)
      {
         DELAY_BETWEEN = atoi(p + 1);
         if (DELAY_BETWEEN <= 0)
            DELAY_BETWEEN = 20;
         traceit("DELAY_BETWEEN=[%d]\n",DELAY_BETWEEN);
         params ++;
      }
      else
      if (strcmp(inbuf,"DELAY_BEFORE") == 0)
      {
         DELAY_BEFORE = atoi(p + 1);
         if (DELAY_BEFORE <= 0)
            DELAY_BEFORE = 1;
         traceit("DELAY_BEFORE=[%d]\n",DELAY_BEFORE);
         params ++;
      }
      else
      if (strcmp(inbuf,"RPTR_ACK") == 0)
      {
         if (*(p + 1) == 'Y')
            RPTR_ACK = true;
         else
            RPTR_ACK = false;
         traceit("RPTR_ACK=[%c]\n", *(p + 1));
         params ++;
      }
   }
   fclose(cnf);

   if (params != valid_params)
   {
      traceit("Configuration file %s invalid\n",cfgFile);
      return 1;
   }

   /*********   HERE HERE check for valid values *************/
   /* check valid values */
   /*********   HERE HERE check for valid values *************/

   inactiveMax = (REMOTE_TIMEOUT * 1000) / WAIT_FOR_PACKETS;
   traceit("Max loops = %d\n", inactiveMax);

   /* convert to Microseconds */
   WAIT_FOR_PACKETS = WAIT_FOR_PACKETS * 1000;

   return 0;
}

static int open_sock()
{
   struct  sockaddr_in inaddr;
   int rc = -1;

   insock = socket(PF_INET, SOCK_DGRAM, 0);
   if (insock == -1)
   {
      traceit("Failed to create insock, error=%d, message=%s\n",errno,strerror(errno));
      return -1;
   }

   memset(&inaddr, 0, sizeof(inaddr));
   inaddr.sin_family = AF_INET;
   inaddr.sin_port = htons(RPTR_PORT);
   inaddr.sin_addr.s_addr = inet_addr(RPTR_VIRTUAL_IP);
   rc = bind(insock, (struct sockaddr *)&inaddr, sizeof(inaddr));
   if (rc == -1)
   {
      traceit("Failed to bind server socket, error=%d, message=%s\n", errno,strerror(errno));
      close(insock); insock = -1;
      return -1;
   }
   fcntl(insock,F_SETFL,O_NONBLOCK);

   memset(&outaddr, 0, sizeof(outaddr));
   outaddr.sin_family = AF_INET;
   outaddr.sin_port = htons(G2_PORT);
   outaddr.sin_addr.s_addr = inet_addr(G2_INTERNAL_IP);

   return 0;
}

static bool open_ser(char *dvp)
{
   static termios t;
    
   serfd = open(dvp, O_RDWR | O_NOCTTY | O_NDELAY, 0);
   if (serfd < 0)
   {
      traceit("Failed to open device [%s], error=%d, message=%s\n", dvp, errno, strerror(errno));
      return false;
   }

   if (isatty(serfd) == 0)
   {
      traceit("Device %s is not a tty device\n", dvp);
      close(serfd); serfd = -1;
      return false;
   }

   if (tcgetattr(serfd, &t) < 0)
   {
      traceit("tcgetattr failed for %s, error=%d\n", dvp, errno);
      close(serfd); serfd = -1;
      return false;
   }

   t.c_lflag    &= ~(ECHO | ECHOE | ICANON | IEXTEN | ISIG);
   t.c_iflag    &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON | IXOFF | IXANY);
   t.c_cflag    &= ~(CSIZE | CSTOPB | PARENB | CRTSCTS);
   t.c_cflag    |= CS8;
   t.c_oflag    &= ~(OPOST);
   t.c_cc[VMIN]  = 0;
   t.c_cc[VTIME] = 10;

   cfsetospeed(&t, B230400);
   cfsetispeed(&t, B230400);

   if (tcsetattr(serfd, TCSANOW, &t) < 0)
   {
      traceit("tcsetattr failed for %s, error=%d\n", dvp, errno);
      close(serfd); serfd = -1;
      return false;
   }

   return true;
}

static bool open_dvp()
{
   short int i;
   bool ok = false;
   char dvp_device[128];

   do 
   {
      for (i = 0; i < 32; i++)
      {
         sprintf(dvp_device, "/dev/ttyUSB%d", i);

         if (access(dvp_device, R_OK | W_OK) != 0)
            continue;

         ok = open_ser(dvp_device);
         if (!ok)
            continue;

         if (flock(serfd, LOCK_EX | LOCK_NB) != 0)
         {
            close(serfd); serfd = -1;
            ok = false;
            traceit("Device %s is already locked/used by other dvap_rptr\n", dvp_device);
            continue;
         }
         traceit("Device %s now locked for exclusive use\n", dvp_device);

         ok = get_ser(dvp_device);
         if (!ok)
         {
            close(serfd); serfd = -1;
            continue;
         }
         break;
      }
      if (!ok)
         break;

      ok = get_name();
      if (!ok)
         break;

      ok = get_fw();
      if (!ok)
         break;


      ok = set_modu();
      if (!ok)
         break;

      ok = set_mode();
      if (!ok)
         break;

      ok = set_sql(); 
      if (!ok)
         break;

      ok = set_pwr();
      if (!ok)
         break;

      ok = set_off();
      if (!ok)
         break;

      ok = set_freq();
      if (!ok)
         break;

      ok = start_dvap();
      if (!ok)
        break;

   } while (false);

   if (!ok)
   {
      if (serfd != -1)
      {
         (void)write_to_dvp(DVP_RQST_STOP, 5);
         close(serfd);
         serfd = -1;
      }
      return false;
   }
   return true; 
}

static int read_from_dvp(unsigned char *buf, unsigned int len)
{
   unsigned int off = 0;
   fd_set fds;
   int n;
   struct timeval tv;
   ssize_t temp_len;

   if (len == 0)
      return 0;

   while (off < len)
   {
      FD_ZERO(&fds);
      FD_SET(serfd, &fds); 

      if (off == 0)
      {
         tv.tv_sec  = 0;
         tv.tv_usec = 0;
         n = select(serfd + 1, &fds, NULL, NULL, &tv);
         if (n == 0)
            return 0; // nothing to read from the dvap
      }
      else
         n = select(serfd + 1, &fds, NULL, NULL, NULL); 

      if (n < 0)
      {
         traceit("select error=%d on dvap\n", errno);
         return -1;
      }

      if (n > 0)
      {
         temp_len = read(serfd, buf + off, len - off);
         if (temp_len > 0)
            off += temp_len;
      }
   }
 
   return len;
}

static int write_to_dvp(unsigned char *buf, unsigned int len)
{
   unsigned int ptr = 0;
   ssize_t n;

   if (len == 0)
      return 0;

   while (ptr < len)
   {
      n = write(serfd, buf + ptr, len - ptr);
      if (n < 0)
      {
         traceit("Error %d writing to dvap\n", errno);
         return -1;
      }

      if (n > 0)
         ptr += n;
   }

   return len;
}

static REPLY_TYPE get_reply(unsigned char *buf,  unsigned int *len)
{
   unsigned int off = 2;
   int rc = -1;

   rc = read_from_dvp(buf, 2);
   if (rc == 0)
      return RT_TIMEOUT; 
   if (rc != 2)
      return RT_ERR;

   *len = buf[0] + (buf[1] & 0x1f) * 256;
   if (*len > 50)
   {
      syncit();
      return RT_TIMEOUT;
   }

   while (off < *len)
   {
      rc = read_from_dvp(buf + off, *len - off);
      if (rc < 0)
         return RT_TIMEOUT;
      if (rc > 0)
        off += rc;
   }

   if (memcmp(buf, DVP_STS, 4) == 0)
      return RT_STS;
   else
   if (memcmp(buf, DVP_DAT, 2) == 0)
      return RT_DAT;
   else
   if (memcmp(buf, DVP_HDR, 2) == 0)
      return RT_HDR;
   else
   if (memcmp(buf, DVP_REPL_HDR, 2) == 0)
      return RT_HDR_ACK;
   else
   if (memcmp(buf, DVP_REPL_PTT, 4) == 0)
      return RT_PTT;
   else
   if (memcmp(buf, DVP_REPL_START, 5) == 0)
      return RT_START;
   else
   if (memcmp(buf, DVP_REPL_STOP, 5) == 0)
      return RT_STOP;
   else
   if (memcmp(buf, DVP_REPL_OFF, 4) == 0)
      return RT_OFF;
   else
   if (memcmp(buf, DVP_REPL_NAME, 4) == 0)
      return RT_NAME;
   else
   if (memcmp(buf + 1, DVP_REPL_SER + 1, 3) == 0)
      return RT_SER;
   else
   if (memcmp(buf, DVP_REPL_FW, 5) == 0)
      return RT_FW;
   else
   if (memcmp(buf, DVP_REPL_FREQ, 4) == 0)
      return RT_FREQ;
   else
   if (memcmp(buf, DVP_REPL_MODU, 5) == 0)
      return RT_MODU;
   else
   if (memcmp(buf, DVP_REPL_MODE, 5) == 0)
      return RT_MODE;
   else
   if (memcmp(buf, DVP_REPL_PWR, 4) == 0)
      return RT_PWR;
   else
   if (memcmp(buf, DVP_REPL_SQL, 4) == 0)
     return RT_SQL;
   else
   {
      syncit();
      return RT_TIMEOUT;
   }

   /* It should never get here */
   return RT_TIMEOUT;
}

static void syncit()
{
   unsigned char data[7];
   unsigned char c;
   int n;
   struct timeval tv;
   fd_set fds;
   short cnt = 0;

   traceit("Starting syncing dvap\n");
   memset(data,  0x00, 7);
 
   while (memcmp(data, DVP_STS, 4) != 0)
   {
      FD_ZERO(&fds);
      FD_SET(serfd, &fds);
      tv.tv_sec  = 0;
      tv.tv_usec = 1000;
      n = select(serfd + 1, &fds, NULL, NULL, &tv);
      if (n <= 0)
      {
         cnt ++;
         if (cnt > 100)
         {
            traceit("dvap is not responding,...stopping\n");
            keep_running = false;
            return;
         } 
      }
      else
      {
         n = read_from_dvp(&c, 1);
         if (n > 0)
         {
            data[0] = data[1];
            data[1] = data[2];
            data[2] = data[3];
            data[3] = data[4];
            data[4] = data[5];
            data[5] = data[6];
            data[6] = c;
           
            cnt = 0;
         }
      }
   }
   traceit("Stopping syncing dvap\n");
   return;
}

static bool get_name()
{
   unsigned cnt = 0;
   unsigned int len = 0;
   REPLY_TYPE reply;
   bool testit = false;
   int rc = -1;
   unsigned char dvp_buf[200];

   rc = write_to_dvp(DVP_RQST_NAME, 4);
   if (rc != 4)
   {
      traceit("Failed to send request to get dvap name\n");
      return false;
   }

   do {
      usleep(5000);

      reply = get_reply(dvp_buf, &len);
      cnt ++;
      if (cnt >= MAX_REPL_CNT)
      {
         traceit("Reached max number of requests to receive dvap name\n");
         return false;
      }
   } while (reply != RT_NAME);

   testit = (memcmp(dvp_buf, DVP_REPL_NAME, len) == 0);

   if (!testit)
   {
      traceit("Failed to receive dvap name\n");
      return false;
   }

   traceit("Device name: %.*s\n", 11, dvp_buf + 4);
   return true;
}

static bool get_fw()
{
   unsigned cnt = 0;
   unsigned int len = 0;
   REPLY_TYPE reply;
   unsigned int ver;
   int rc = -1;
   unsigned char dvp_buf[200];

   rc = write_to_dvp(DVP_RQST_FW, 5);
   if (rc != 5)
   {
      traceit("Failed to send request to get dvap fw\n");
      return false;
   }

   do {
      usleep(5000);

      reply = get_reply(dvp_buf, &len);
      cnt ++;
      if (cnt >= MAX_REPL_CNT)
      {
         traceit("Reached max number of requests to receive dvap fw\n");
         return false;
      }
   } while (reply != RT_FW);

   ver = dvp_buf[6] * 256 + dvp_buf[5];
   traceit("dvap fw ver: %u.%u\n", ver / 100, ver % 100);

   return true; 
}

static bool get_ser(char *dvp)
{
   unsigned cnt = 0;
   unsigned int len = 0;
   REPLY_TYPE reply;
   int rc = -1;
   unsigned char dvp_buf[200];

   rc = write_to_dvp(DVP_RQST_SER, 4);
   if (rc != 4)
   {
      traceit("Failed to send request to get dvap serial#\n");
      return false;
   }

   do {
      usleep(5000);

      reply = get_reply(dvp_buf, &len);
      cnt ++;
      if (cnt >= MAX_REPL_CNT)
      {
         traceit("Reached max number of requests to receive dvap serial#\n");
         return false;
      }
   } while (reply != RT_SER);

   if (strcmp((char *)(dvp_buf + 4), DVP_SERIAL) == 0)
   {
      traceit("Using %s:  %s, because serial number matches your dvap_rptr.cfg\n",
              dvp, DVP_SERIAL);
      return true;
   }
   else
   {
      traceit("Device %s has serial %s, but does not match your config value %s\n", dvp, dvp_buf + 4, DVP_SERIAL);
      return false;
   }
}

static bool set_modu()
{
   unsigned cnt = 0;
   unsigned int len = 0;
   REPLY_TYPE reply;
   int rc = -1;
   unsigned char dvp_buf[200];

   rc = write_to_dvp(DVP_RQST_MODU, 5);
   if (rc != 5)
   {
      traceit("Failed to send request to set dvap modulation\n");
      return false;
   }

   do {
      usleep(5000);

      reply = get_reply(dvp_buf, &len);
 
      cnt ++;
      if (cnt >= MAX_REPL_CNT)
      {
         traceit("Reached max number of requests to set dvap modulation\n");
         return false;
      }
   } while (reply != RT_MODU);

   return true;
}

static bool set_mode()
{
   unsigned cnt = 0;
   unsigned int len = 0;
   REPLY_TYPE reply;
   int rc = -1;
   unsigned char dvp_buf[200];

   rc = write_to_dvp(DVP_RQST_MODE, 5);
   if (rc != 5)
   {
      traceit("Failed to send request to set dvap mode\n");
      return false;
   }

   do {
      usleep(5000);

      reply = get_reply(dvp_buf, &len);

      cnt ++;
      if (cnt >= MAX_REPL_CNT)
      {
         traceit("Reached max number of requests to set dvap mode\n");
         return false;
      }
   } while (reply != RT_MODE);

   return true;
}

static bool set_sql()
{
   unsigned cnt = 0;
   unsigned int len = 0;
   REPLY_TYPE reply;
   int rc = -1;
   unsigned char buf[10];
   unsigned char dvp_buf[200];

   memcpy(buf, DVP_RQST_SQL, 5);
   memcpy(buf + 4, &DVP_SQL, 1); 

   rc = write_to_dvp(buf, 5);
   if (rc != 5)
   {
      traceit("Failed to send request to set dvap sql\n");
      return false;
   }

   do {
      usleep(5000);

      reply = get_reply(dvp_buf, &len);

      cnt ++;
      if (cnt >= MAX_REPL_CNT)
      {
         traceit("Reached max number of requests to set dvap sql\n");
         return false;
      }
   } while (reply != RT_SQL);

   return true;
}

static bool set_pwr()
{
   unsigned cnt = 0;
   unsigned int len = 0;
   REPLY_TYPE reply;
   int rc = -1;
   unsigned char buf[10];
   int16_t temp_pwr;
   unsigned char dvp_buf[200];

   memcpy(buf, DVP_RQST_PWR, 6);
   temp_pwr = (isit_bigendian())?do_swap16(DVP_PWR):DVP_PWR;
   memcpy(buf + 4, &temp_pwr, sizeof(int16_t));

   rc = write_to_dvp(buf, 6);
   if (rc != 6)
   {
      traceit("Failed to send request to set dvap pwr\n");
      return false;
   }

   do {
      usleep(5000);

      reply = get_reply(dvp_buf, &len);

      cnt ++;
      if (cnt >= MAX_REPL_CNT)
      {
         traceit("Reached max number of requests to set dvap pwr\n");
         return false;
      }
   } while (reply != RT_PWR);

   return true;
}

static bool set_off()
{
   unsigned cnt = 0;
   unsigned int len = 0;
   REPLY_TYPE reply;
   int rc = -1;
   unsigned char buf[10];
   int16_t temp_off;
   unsigned char dvp_buf[200];

   memcpy(buf, DVP_RQST_OFF, 6);
   temp_off = (isit_bigendian())?do_swap16(DVP_OFF):DVP_OFF;
   memcpy(buf + 4, &temp_off, sizeof(int16_t));

   rc = write_to_dvp(buf, 6);
   if (rc != 6)
   {
      traceit("Failed to send request to set dvap offset\n");
      return false;
   }

   do {
      usleep(5000);

      reply = get_reply(dvp_buf, &len);

      cnt ++;
      if (cnt >= MAX_REPL_CNT)
      {
         traceit("Reached max number of requests to set dvap offset\n");
         return false;
      }
   } while (reply != RT_OFF);

   return true;
}

static bool set_freq()
{
   unsigned cnt = 0;
   unsigned int len = 0;
   REPLY_TYPE reply;
   int rc = -1;
   unsigned char buf[10];
   u_int32_t temp_freq;
   unsigned char dvp_buf[200];

   memcpy(buf, DVP_RQST_FREQ, 8);
   temp_freq = (isit_bigendian())?do_swapu32(DVP_FREQ):DVP_FREQ;
   memcpy(buf + 4, &temp_freq, sizeof(u_int32_t));

   rc = write_to_dvp(buf, 8);
   if (rc != 8)
   {
      traceit("Failed to send request to set dvap frequency\n");
      return false;
   }

   do {
      usleep(5000);

      reply = get_reply(dvp_buf, &len);

      cnt ++;
      if (cnt >= MAX_REPL_CNT)
      {
         traceit("Reached max number of requests to set dvap frequency\n");
         return false;
      }
   } while (reply != RT_FREQ);

   return true;
}

static bool start_dvap()
{
   unsigned cnt = 0;
   unsigned int len = 0;
   REPLY_TYPE reply;
   int rc = -1;
   unsigned char dvp_buf[200];

   rc = write_to_dvp(DVP_RQST_START, 5);
   if (rc != 5)
   {
      traceit("Failed to send request to start the dvap dongle\n");
      return false;
   }

   do {
      usleep(5000);
      
      reply = get_reply(dvp_buf, &len);

      cnt ++;
      if (cnt >= MAX_REPL_CNT)
      {
         traceit("Reached max number of requests to start the dvap dongle\n");
         return false;
      }
   } while (reply != RT_START);

   return true;
}

static void readFrom20000()
{
   unsigned char dvp_buf[200];
   struct  sockaddr_in from;
   socklen_t fromlen;
   int len;
   fd_set  readfd;
   struct  timeval tv;
   int inactive = 0;
   short seq_no = 0;
   unsigned streamid[2] = {0x00, 0x00};
   u_int16_t sid;
   unsigned char sync_codes[3] = {0x55, 0x2d, 0x16};
   struct pkt net_buf;
   u_int16_t stream_id_to_dvap = 0;
   u_int8_t frame_pos_to_dvap = 0;
   u_int8_t seq_to_dvap = 0;
   char silence[12] =
   {
      0x4e,0x8d,0x32,0x88,0x26,0x1a,0x3f,0x61,0xe8,
      0x70,0x4f,0x93
   };

   bool written_to_q = false;
   unsigned char ctrl_in = 0x80;

   while (keep_running)
   {
      written_to_q = false;

      tv.tv_sec = 0;
      tv.tv_usec = WAIT_FOR_PACKETS;
      fromlen = sizeof(struct sockaddr);
      FD_ZERO (&readfd);
      FD_SET (insock, &readfd);
      select(insock + 1, &readfd, NULL, NULL, &tv);

      if (FD_ISSET(insock, &readfd))
      {
         len = recvfrom (insock, (char *)&net_buf, 58, 0, (struct sockaddr *)&from, &fromlen);
         if (len == 58)
         {
            if (busy20000)
            {
               FD_CLR (insock, &readfd);
               continue;
            }

            /* check the module and gateway */
            if (net_buf.rf_hdr.rpt2[7] != RPTR_MOD)
            {
               FD_CLR (insock, &readfd);
               break;
            }
            memcpy(net_buf.rf_hdr.rpt1, OWNER, 7);
            net_buf.rf_hdr.rpt1[7] = 'G';

            if (memcmp(RPTR, OWNER, RPTR_SIZE) != 0)
            {
               // restriction mode
               memcpy(net_buf.rf_hdr.rpt1, RPTR, 7);
               memcpy(net_buf.rf_hdr.rpt2, RPTR, 7);

               if (memcmp(net_buf.rf_hdr.mycall, OWNER, 7) == 0)
               {
                  /* this is an ACK back */
                  memcpy(net_buf.rf_hdr.mycall, RPTR, 7);
               }
            }

            if ((net_buf.rf_hdr.flags[0] != 0x00) &&
                (net_buf.rf_hdr.flags[0] != 0x01) &&
                (net_buf.rf_hdr.flags[0] != 0x08) &&
                (net_buf.rf_hdr.flags[0] != 0x20) &&
                (net_buf.rf_hdr.flags[0] != 0x28) &&
                (net_buf.rf_hdr.flags[0] != 0x40))
            {
               FD_CLR (insock, &readfd);
               break;
            }

            if ((memcmp(net_buf.pkt_id, "DSTR", 4) != 0) ||
                (net_buf.flags[0] != 0x73) ||
                (net_buf.flags[1] != 0x12) ||
                (net_buf.myicm.icm_id != 0x20)) /* voice type */
            {
               FD_CLR (insock, &readfd);
               break;
            }

            busy20000 = true;

            ctrl_in = 0x80;
            written_to_q = true;

            traceit("Start G2: streamid=%d,%d, flags=%02x:%02x:%02x, my=%.8s, sfx=%.4s, ur=%.8s, rpt1=%.8s, rpt2=%.8s\n",
                       net_buf.myicm.streamid[0], net_buf.myicm.streamid[1],
                       net_buf.rf_hdr.flags[0], net_buf.rf_hdr.flags[1], net_buf.rf_hdr.flags[2],
                       net_buf.rf_hdr.mycall, net_buf.rf_hdr.sfx, net_buf.rf_hdr.urcall,
                       net_buf.rf_hdr.rpt2, net_buf.rf_hdr.rpt1);

            /* save the streamid that is winning */
            streamid[0] = net_buf.myicm.streamid[0];
            streamid[1] = net_buf.myicm.streamid[1];

            if (net_buf.rf_hdr.flags[0] != 0x01)
            {

               if (net_buf.rf_hdr.flags[0] == 0x00)
                  net_buf.rf_hdr.flags[0] = 0x40;
               else
               if (net_buf.rf_hdr.flags[0] == 0x08)
                  net_buf.rf_hdr.flags[0] = 0x48;
               else
               if (net_buf.rf_hdr.flags[0] == 0x20)
                  net_buf.rf_hdr.flags[0] = 0x60;
               else
               if (net_buf.rf_hdr.flags[0] == 0x28)
                  net_buf.rf_hdr.flags[0] = 0x68;
               else
                  net_buf.rf_hdr.flags[0] = 0x40;
            }
            net_buf.rf_hdr.flags[1] = 0x00;
            net_buf.rf_hdr.flags[2] = 0x00;

            // write the header packet to the dvap here
            while ((space < 1) && keep_running)
               usleep(5);
            stream_id_to_dvap = (rand_r(&aseed) % 65535U) + 1U;
            memcpy(dvp_buf, DVP_HDR, 47);
            sid = (isit_bigendian())?do_swapu16(stream_id_to_dvap):stream_id_to_dvap;
            memcpy(dvp_buf + 2, &sid, sizeof(u_int16_t));
            dvp_buf[4] = 0x80;
            dvp_buf[5] = 0;
            memset(dvp_buf + 6, ' ', 41);
            dvp_buf[6] = net_buf.rf_hdr.flags[0];
            dvp_buf[7] = net_buf.rf_hdr.flags[1];
            dvp_buf[8] = net_buf.rf_hdr.flags[2];
            memcpy(dvp_buf + 9, net_buf.rf_hdr.rpt1, 8);
            memcpy(dvp_buf + 17, net_buf.rf_hdr.rpt2, 8);
            memcpy(dvp_buf + 25, net_buf.rf_hdr.urcall, 8);
            memcpy(dvp_buf + 33, net_buf.rf_hdr.mycall, 8);
            memcpy(dvp_buf + 41, net_buf.rf_hdr.sfx, 4);
            calcPFCS(dvp_buf + 6, dvp_buf + 45);
            frame_pos_to_dvap = 0;
            seq_to_dvap = 0;
            (void)write_to_dvp(dvp_buf, 47);
             
            inactive = 0;
            seq_no = 0;
         }
         else
         if (len == 29)
         {
            if (busy20000)
            {
               if ((net_buf.myicm.streamid[0] == streamid[0]) &&
                   (net_buf.myicm.streamid[1] == streamid[1]))
               {
                  if (net_buf.myicm.ctrl == ctrl_in)
                  {
                     /* do not update written_to_q, ctrl_in */
                     ; // traceit("dup\n");
                  }
                  else
                  {
                     ctrl_in = net_buf.myicm.ctrl;
                     written_to_q = true;

                     if (seq_no == 0)
                     {
                        net_buf.rf_audio.buff[9]  = 0x55;
                        net_buf.rf_audio.buff[10] = 0x2d;
                        net_buf.rf_audio.buff[11] = 0x16;
                     }
                     else
                     {
                        if ((net_buf.rf_audio.buff[9] == 0x55) &&
                            (net_buf.rf_audio.buff[10] == 0x2d) &&
                            (net_buf.rf_audio.buff[11] == 0x16))
                        {
                           net_buf.rf_audio.buff[9]  = 0x70;
                           net_buf.rf_audio.buff[10] = 0x4f;
                           net_buf.rf_audio.buff[11] = 0x93;
                        }
                     }

                     // write the audio packet to the dvap here
                     while ((space < 1) && keep_running)
                        usleep(5);
                     memcpy(dvp_buf, DVP_DAT, 18);
                     if (memcmp(net_buf.rf_audio.buff + 9, sync_codes, 3) == 0)
                        frame_pos_to_dvap = 0;
                     sid = (isit_bigendian())?do_swapu16(stream_id_to_dvap):stream_id_to_dvap;
                     memcpy(dvp_buf + 2, &sid, sizeof(u_int16_t));
                     dvp_buf[4] = frame_pos_to_dvap;
                     dvp_buf[5] = seq_to_dvap;
                     if ((net_buf.myicm.ctrl & 0x40) != 0)
                        dvp_buf[4] |= 0x40U;
                     memcpy(dvp_buf + 6, net_buf.rf_audio.buff, 12);
                     (void)write_to_dvp(dvp_buf, 18);
                     frame_pos_to_dvap ++;
                     seq_to_dvap ++;
                  
                     inactive = 0;

                     seq_no ++;
                     if (seq_no == 21)
                        seq_no = 0;

                     if ((net_buf.myicm.ctrl & 0x40) != 0)
                     {
                        traceit("End G2: streamid=%d,%d\n", net_buf.myicm.streamid[0], net_buf.myicm.streamid[1]);

                        streamid[0] = 0x00;
                        streamid[1] = 0x00;

                        inactive = 0;
                        FD_CLR (insock, &readfd);
                        // maybe put a sleep here to prevent fast voice-overs 

                        busy20000 = false;
                        break;
                     }
                  }
               }
            }
            else
            {
               FD_CLR (insock, &readfd);
               break;
            }
         }
         else
         {
            if (!busy20000)
            {
               FD_CLR (insock, &readfd);
               break;
            }
         }
         FD_CLR (insock, &readfd);
      }

      /*
         If we received a dup or select() timed out or streamids dont match,
         then written_to_q is false
      */
      if (!written_to_q) /* nothing was written to the adapter */
      {
         if (busy20000)
         {
            if (++inactive == inactiveMax)
            {
               traceit("G2 Timeout...\n");

               streamid[0] = 0x00;
               streamid[1] = 0x00;

               inactive = 0;
               // maybe put a sleep here to prevent fast voice-overs

               busy20000 = false;
               break;
            }
            else
            {
               if (space == 127)
               {
                  if (seq_no == 0)
                  {
                     silence[9]  = 0x55;
                     silence[10] = 0x2d;
                     silence[11] = 0x16;
                  }
                  else
                  {
                     silence[9]  = 0x70;
                     silence[10] = 0x4f;
                     silence[11] = 0x93;
                  }

                  memcpy(dvp_buf, DVP_DAT, 18);
                  if (memcmp(silence + 9, sync_codes, 3) == 0)
                     frame_pos_to_dvap = 0;
                  sid = (isit_bigendian())?do_swapu16(stream_id_to_dvap):stream_id_to_dvap;
                  memcpy(dvp_buf + 2, &sid, sizeof(u_int16_t));
                  dvp_buf[4] = frame_pos_to_dvap;
                  dvp_buf[5] = seq_to_dvap;
                  memcpy(dvp_buf + 6, silence, 12);
                  (void)write_to_dvp(dvp_buf, 18);
                  frame_pos_to_dvap ++;
                  seq_to_dvap ++;

                  seq_no ++;
                  if (seq_no == 21)
                     seq_no = 0;
               }
            }
         }
         else
            break;
      }
   }
   return;
}

int main(int argc, const char **argv)
{
   struct sigaction act;
   int rc = -1;
   time_t tnow = 0;
   time_t ackpoint = 0;
   pthread_t readFromRF_t;
   pthread_attr_t attr;
   short cnt = 0;

   setvbuf(stdout, NULL, _IOLBF, 0);
   traceit("dvap_rptr VERSION %s\n", VERSION);

   if (argc != 2)
   {
      traceit("Usage:  dvap_rptr dvap_rptr.cfg\n");
      return 1;
   }

   rc = read_config(argv[1]);
   if (rc != 0)
   {
      traceit("Failed to process config file %s\n", argv[1]);
      return 1;
   }

   if (strlen(RPTR) != 8)
   {
      traceit("Bad RPTR value, length must be exactly 8 bytes\n");
      return 1;
   }
   if ((RPTR_MOD != 'A') && (RPTR_MOD != 'B') && (RPTR_MOD != 'C'))
   {
     traceit("Bad RPTR_MOD value, must be one of A or B or C\n");
     return 1;
   }

   if (RPTR_MOD == 'A')
      SND_TERM_ID = 0x03;
   else
   if (RPTR_MOD == 'B')
      SND_TERM_ID = 0x01;
   else
   if (RPTR_MOD == 'C')
      SND_TERM_ID = 0x02;

   strcpy(RPTR_and_G, RPTR);
   RPTR_and_G[7] = 'G';

   strcpy(RPTR_and_MOD, RPTR);
   RPTR_and_MOD[7] = RPTR_MOD;

   time(&tnow);
   aseed = tnow + getpid();

   act.sa_handler = sig_catch;
   sigemptyset(&act.sa_mask);
   if (sigaction(SIGTERM, &act, 0) != 0)
   {
      traceit("sigaction-TERM failed, error=%d\n", errno);
      return 1;
   }
   if (sigaction(SIGHUP, &act, 0) != 0)
   {
      traceit("sigaction-HUP failed, error=%d\n", errno);
      return 1;
   }
   if (sigaction(SIGINT, &act, 0) != 0)
   {
      traceit("sigaction-INT failed, error=%d\n", errno);
      return 1;
   }

   /* open dvp */
   if (!open_dvp())
      return 1;

   rc = open_sock();
   if (rc != 0)
   {
      (void)write_to_dvp(DVP_RQST_STOP, 5);
      close(serfd);
      return 1;
   }

   dstar_dv_init();

   pthread_attr_init(&attr);
   pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
   rc = pthread_create(&readFromRF_t, &attr, readFromRF, (void *)0);
   if (rc != 0)
   {
      keep_running = false;
      traceit("failed to start thread readFromRF thread\n");
   }
   else
      traceit("Started thread readFromRF\n");
   pthread_attr_destroy(&attr);

   while (keep_running)
   {
      time(&tnow);
      if ((tnow - ackpoint) > 2)
      {
         rc = write_to_dvp(DVP_ACK, 3);
         if (rc < 0)
         {
            cnt ++;
            if (cnt > 5)
            {
                traceit("Could not send KEEPALIVE signal to dvap 5 times...exiting\n");
                keep_running = false;
            }
         }
         else
            cnt = 0;
         ackpoint = tnow;
      }
      readFrom20000();
   }

   close(insock);
   traceit("dvap_rptr exiting\n");
   return 0;
}

static void *rptr_ack(void *arg)
{
   char mycall[8];
   memcpy(mycall, ((struct dvap_ack_arg_type *)arg)->mycall, 8);
   float ber = ((struct dvap_ack_arg_type *)arg)->ber;

   char RADIO_ID[21];
   
   sprintf(RADIO_ID, "%20.2f", ber);
   memcpy(RADIO_ID, "BER%", 4);

   struct sigaction act;
   unsigned char dvp_buf[200];
   u_int16_t stream_id_to_dvap = 0;
   u_int16_t sid;
   time_t tnow = 0;
   char silence[12] =
   {
      0x4e,0x8d,0x32,0x88,0x26,0x1a,0x3f,0x61,0xe8,
      0x70,0x4f,0x93
   };
   unsigned int aseed_ack = 0;
   struct timespec nanos;

   act.sa_handler = sig_catch;
   sigemptyset(&act.sa_mask);
   if (sigaction(SIGTERM, &act, 0) != 0)
   {
      traceit("sigaction-TERM failed, error=%d\n", errno);
      traceit("thread rptr_ack exiting\n");
      pthread_exit(NULL);
   }
   if (sigaction(SIGHUP, &act, 0) != 0)
   {
      traceit("sigaction-HUP failed, error=%d\n", errno);
      traceit("thread rptr_ack exiting\n");
      pthread_exit(NULL);
   }
   if (sigaction(SIGINT, &act, 0) != 0)
   {
      traceit("sigaction-INT failed, error=%d\n", errno);
      traceit("thread rptr_ack exiting\n");
      pthread_exit(NULL);
   }

   sleep(DELAY_BEFORE);
   // traceit("ack-start\n");

   time(&tnow);
   aseed_ack = tnow + getpid();

   stream_id_to_dvap = (rand_r(&aseed_ack) % 65535U) + 1U;
   sid = (isit_bigendian())?do_swapu16(stream_id_to_dvap):stream_id_to_dvap;

   // HEADER
   while ((space < 1) && keep_running)
      usleep(5);
   memcpy(dvp_buf, DVP_HDR, 47);
   memcpy(dvp_buf + 2, &sid, sizeof(u_int16_t));
   dvp_buf[4] = 0x80;
   dvp_buf[5] = 0;
   memset(dvp_buf + 6, ' ', 41);
   dvp_buf[6] = 0x01;
   dvp_buf[7] = 0x00;
   dvp_buf[8] = 0x00;
   memcpy(dvp_buf + 9, RPTR_and_MOD, 8);
   memcpy(dvp_buf + 17, RPTR_and_G, 8);
   memcpy(dvp_buf + 25, mycall, 8);
   memcpy(dvp_buf + 33, RPTR_and_MOD, 8);
   memcpy(dvp_buf + 41, (unsigned char *)"    ", 4);
   calcPFCS(dvp_buf + 6, dvp_buf + 45);
   (void)write_to_dvp(dvp_buf, 47);
   nanos.tv_sec = 0;
   nanos.tv_nsec = DELAY_BETWEEN * 1000000;
   nanosleep(&nanos,0);

   // SYNC
   while ((space < 1) && keep_running)
      usleep(5);
   silence[9] = 0x55; silence[10] = 0x2d; silence[11] = 0x16;
   memcpy(dvp_buf, DVP_DAT, 18);
   memcpy(dvp_buf + 2, &sid, sizeof(u_int16_t));
   dvp_buf[4] = 0x00;
   dvp_buf[5] = 0x00;
   memcpy(dvp_buf + 6, silence, 12);
   (void)write_to_dvp(dvp_buf, 18);
   nanos.tv_sec = 0;
   nanos.tv_nsec = DELAY_BETWEEN * 1000000;
   nanosleep(&nanos,0);

   // NOTHING
   while ((space < 1) && keep_running)
      usleep(5);
   silence[9] = '@' ^ 0x70;
   silence[10] = RADIO_ID[0] ^ 0x4f;
   silence[11] = RADIO_ID[1] ^ 0x93;
   memcpy(dvp_buf, DVP_DAT, 18);
   memcpy(dvp_buf + 2, &sid, sizeof(u_int16_t));
   dvp_buf[4] = 0x01;
   dvp_buf[5] = 0x01;
   memcpy(dvp_buf + 6, silence, 12);
   (void)write_to_dvp(dvp_buf, 18);
   nanos.tv_sec = 0;
   nanos.tv_nsec = DELAY_BETWEEN * 1000000;
   nanosleep(&nanos,0);

   while ((space < 1) && keep_running)
      usleep(5);
   silence[9] = RADIO_ID[2] ^ 0x70;
   silence[10] = RADIO_ID[3] ^ 0x4f;
   silence[11] = RADIO_ID[4] ^ 0x93;
   memcpy(dvp_buf, DVP_DAT, 18);
   memcpy(dvp_buf + 2, &sid, sizeof(u_int16_t));
   dvp_buf[4] = 0x02;
   dvp_buf[5] = 0x02;
   memcpy(dvp_buf + 6, silence, 12);
   (void)write_to_dvp(dvp_buf, 18);
   nanos.tv_sec = 0;
   nanos.tv_nsec = DELAY_BETWEEN * 1000000;
   nanosleep(&nanos,0);

   while ((space < 1) && keep_running)
      usleep(5);
   silence[9] = 'A' ^ 0x70;
   silence[10] = RADIO_ID[5] ^ 0x4f;
   silence[11] = RADIO_ID[6] ^ 0x93;
   memcpy(dvp_buf, DVP_DAT, 18);
   memcpy(dvp_buf + 2, &sid, sizeof(u_int16_t));
   dvp_buf[4] = 0x03;
   dvp_buf[5] = 0x03;
   memcpy(dvp_buf + 6, silence, 12);
   (void)write_to_dvp(dvp_buf, 18);
   nanos.tv_sec = 0;
   nanos.tv_nsec = DELAY_BETWEEN * 1000000;
   nanosleep(&nanos,0);

   while ((space < 1) && keep_running)
      usleep(5);
   silence[9] = RADIO_ID[7] ^ 0x70;
   silence[10] = RADIO_ID[8] ^ 0x4f;
   silence[11] = RADIO_ID[9] ^ 0x93;
   memcpy(dvp_buf, DVP_DAT, 18);
   memcpy(dvp_buf + 2, &sid, sizeof(u_int16_t));
   dvp_buf[4] = 0x04;
   dvp_buf[5] = 0x04;
   memcpy(dvp_buf + 6, silence, 12);
   (void)write_to_dvp(dvp_buf, 18);
   nanos.tv_sec = 0;
   nanos.tv_nsec = DELAY_BETWEEN * 1000000;
   nanosleep(&nanos,0);

   while ((space < 1) && keep_running)
      usleep(5);
   silence[9] = 'B' ^ 0x70;
   silence[10] = RADIO_ID[10] ^ 0x4f;
   silence[11] = RADIO_ID[11] ^ 0x93;
   memcpy(dvp_buf, DVP_DAT, 18);
   memcpy(dvp_buf + 2, &sid, sizeof(u_int16_t));
   dvp_buf[4] = 0x05;
   dvp_buf[5] = 0x05;
   memcpy(dvp_buf + 6, silence, 12);
   (void)write_to_dvp(dvp_buf, 18);
   nanos.tv_sec = 0;
   nanos.tv_nsec = DELAY_BETWEEN * 1000000;
   nanosleep(&nanos,0);

   while ((space < 1) && keep_running)
      usleep(5);
   silence[9] = RADIO_ID[12] ^ 0x70;
   silence[10] = RADIO_ID[13] ^ 0x4f;
   silence[11] = RADIO_ID[14] ^ 0x93;
   memcpy(dvp_buf, DVP_DAT, 18);
   memcpy(dvp_buf + 2, &sid, sizeof(u_int16_t));
   dvp_buf[4] = 0x06;
   dvp_buf[5] = 0x06;
   memcpy(dvp_buf + 6, silence, 12);
   (void)write_to_dvp(dvp_buf, 18);
   nanos.tv_sec = 0;
   nanos.tv_nsec = DELAY_BETWEEN * 1000000;
   nanosleep(&nanos,0);

   while ((space < 1) && keep_running)
      usleep(5);
   silence[9] = 'C' ^ 0x70;
   silence[10] = RADIO_ID[15] ^ 0x4f;
   silence[11] = RADIO_ID[16] ^ 0x93;
   memcpy(dvp_buf, DVP_DAT, 18);
   memcpy(dvp_buf + 2, &sid, sizeof(u_int16_t));
   dvp_buf[4] = 0x07;
   dvp_buf[5] = 0x07;
   memcpy(dvp_buf + 6, silence, 12);
   (void)write_to_dvp(dvp_buf, 18);
   nanos.tv_sec = 0;
   nanos.tv_nsec = DELAY_BETWEEN * 1000000;
   nanosleep(&nanos,0);

   while ((space < 1) && keep_running)
      usleep(5);
   silence[9] = RADIO_ID[17] ^ 0x70;
   silence[10] = RADIO_ID[18] ^ 0x4f;
   silence[11] = RADIO_ID[19] ^ 0x93;
   memcpy(dvp_buf, DVP_DAT, 18);
   memcpy(dvp_buf + 2, &sid, sizeof(u_int16_t));
   dvp_buf[4] = 0x08;
   dvp_buf[5] = 0x08;
   memcpy(dvp_buf + 6, silence, 12);
   (void)write_to_dvp(dvp_buf, 18);
   nanos.tv_sec = 0;
   nanos.tv_nsec = DELAY_BETWEEN * 1000000;
   nanosleep(&nanos,0);

   // END
   while ((space < 1) && keep_running)
      usleep(5);
   silence[0] = 0x55; silence[1] = 0xc8; silence[2] = 0x7a;
   silence[9] = 0x55; silence[10] = 0x55; silence[11] = 0x55;
   memcpy(dvp_buf, DVP_DAT, 18);
   memcpy(dvp_buf + 2, &sid, sizeof(u_int16_t));
   dvp_buf[4] = (0x09 | 0x40);
   dvp_buf[5] = 0x09;
   memcpy(dvp_buf + 6, silence, 12);
   (void)write_to_dvp(dvp_buf, 18);

   // traceit("ack-end\n");
   pthread_exit(NULL);
}

static void *readFromRF(void *arg)
{
   REPLY_TYPE reply;
   unsigned int len = 0;
   unsigned char dvp_buf[200];
   struct pkt net_buf;
   time_t tnow = 0;
   time_t S_ctrl_msg_time = 0;
   unsigned char S_packet[26];
   unsigned short C_COUNTER = 0;
   time_t last_RF_time = 0;
   struct sigaction act;
   bool dvap_busy = false;
   bool ptt = false;
   bool the_end = true;
   dvap_hdr *from_dvap_hdr = (dvap_hdr *)dvp_buf;
   // dvap_voice *from_dvap_voice = (dvap_voice *)dvp_buf;
   bool ok = true;
   int i = 0;
   u_int16_t streamid_raw = 0;
   short int sequence = 0x00;
   char mycall[8];
   pthread_t rptr_ack_t;
   pthread_attr_t attr;
   int rc = -1;
   short int status_cntr = 3000; 
   char temp_yrcall[CALL_SIZE + 1];
   char *temp_ptr = NULL;

   num_dv_frames = 0;
   num_bit_errors = 0;

   arg = arg;
   act.sa_handler = sig_catch;
   sigemptyset(&act.sa_mask);
   if (sigaction(SIGTERM, &act, 0) != 0)
   {
      traceit("sigaction-TERM failed, error=%d\n", errno);
      keep_running = false;
      traceit("thread readFromRF exiting\n");
      pthread_exit(NULL);
   }
   if (sigaction(SIGHUP, &act, 0) != 0)
   {
      traceit("sigaction-HUP failed, error=%d\n", errno);
      keep_running = false;
      traceit("thread readFromRF exiting\n");
      pthread_exit(NULL);
   }
   if (sigaction(SIGINT, &act, 0) != 0)
   {
      traceit("sigaction-INT failed, error=%d\n", errno);
      keep_running = false;
      traceit("thread readFromRF exiting\n");
      pthread_exit(NULL);
   }

   /* prepare the S server status packet */
   memcpy(S_packet, "DSTR", 4);
   S_packet[4] = 0x00;
   S_packet[5] = 0x00;
   S_packet[6] = 0x73;
   S_packet[7] = 0x21;
   S_packet[8] = 0x00;
   S_packet[9] = 0x10;

   while (keep_running)
   {
      time(&tnow);

      /* send the S packet if needed */
      if ((tnow - S_ctrl_msg_time) > 60)
      {
         S_packet[5] = (unsigned char)(C_COUNTER & 0xff);
         S_packet[4] = ((C_COUNTER >> 8) & 0xff);
         memcpy(S_packet + 10, OWNER, 8); S_packet[17] = 'S';
         memcpy(S_packet + 18, OWNER, 8); S_packet[25] = 'S';
         sendto(insock, (char *)S_packet, sizeof(S_packet), 0, (struct sockaddr *)&outaddr, sizeof(outaddr));
         C_COUNTER ++;
         S_ctrl_msg_time = tnow;
      }

      // local RF user went away ?
      if (dvap_busy)
      {
         time(&tnow);
         if ((tnow - last_RF_time) > 1)
            dvap_busy = false;
      }

      // read from the dvap and process
      reply = get_reply(dvp_buf, &len);
      if (reply == RT_ERR)
      {
         traceit("Detected ERROR event from DVAP dongle, stopping...n");
         break;
      }
      else
      if (reply == RT_STOP)
      {
         traceit("Detected STOP event from DVAP dongle, stopping...\n");
         break;
      }
      else if (reply == RT_START)
         traceit("Detected START event from DVAP dongle\n"); 
      else
      if (reply == RT_PTT)
      {
         ptt = (dvp_buf[4] == 0x01);
         // traceit("Detected PTT=%s\n", ptt?"on":"off");
      }
      else
      if (reply == RT_STS)
      {
         space = dvp_buf[6];
         if (status_cntr < 3000)
            status_cntr += 20;
      }
      else
      if (reply == RT_HDR)
      {
         num_dv_frames = 0;
         num_bit_errors = 0;

         traceit("From DVAP: flags=%02x:%02x:%02x, my=%.8s, sfx=%.4s, ur=%.8s, rpt1=%.8s, rpt2=%.8s\n",
              from_dvap_hdr->flag1, from_dvap_hdr->flag2, from_dvap_hdr->flag3,
              from_dvap_hdr->mycall, from_dvap_hdr->sfx, from_dvap_hdr->urcall,
              from_dvap_hdr->rpt2, from_dvap_hdr->rpt1);

         ok = true;

         /* Accept valid flags only */
        if (ok)
        {
           /* net flags */
           if ((from_dvap_hdr->flag1 != 0x00) &&
               (from_dvap_hdr->flag1 != 0x08) &&
               (from_dvap_hdr->flag1 != 0x20) &&
               (from_dvap_hdr->flag1 != 0x28) &&

           /* rptr flags */
               (from_dvap_hdr->flag1 != 0x40) &&
               (from_dvap_hdr->flag1 != 0x48) &&
               (from_dvap_hdr->flag1 != 0x60) &&
               (from_dvap_hdr->flag1 != 0x68))
           ok = false;
        }

        /* Reject those stupid STN stations */
        if (ok)
        {
           memcpy(temp_yrcall, from_dvap_hdr->urcall, CALL_SIZE);
           temp_yrcall[CALL_SIZE] = '\0';
           temp_ptr = strstr(temp_yrcall, INVALID_YRCALL_KEY);
           if (temp_ptr == temp_yrcall) // found it at first position
           {
              traceit("YRCALL value [%s] starts with the INVALID_YRCALL_KEY [%s], resetting to CQCQCQ\n", 
                      temp_yrcall, INVALID_YRCALL_KEY);
              memcpy(from_dvap_hdr->urcall, "CQCQCQ  ", 8);
           }
        }

         /*** copy the dvap header ***/
         memcpy(net_buf.rf_audio.buff, dvp_buf + 6, 41);

         /* RPT1 must always be the repeater + module */
         memcpy(net_buf.rf_hdr.rpt1, RPTR_and_MOD, 8);
         /* copy RPT2 */
         memcpy(net_buf.rf_hdr.rpt2, from_dvap_hdr->rpt1, 8);

         /* RPT2 must also be valid */
         if ((net_buf.rf_hdr.rpt2[7] == 'A') ||
             (net_buf.rf_hdr.rpt2[7] == 'B') ||
             (net_buf.rf_hdr.rpt2[7] == 'C') ||
             (net_buf.rf_hdr.rpt2[7] == 'G'))
            memcpy(net_buf.rf_hdr.rpt2, RPTR, 7);
         else
            memset(net_buf.rf_hdr.rpt2, ' ', 8);

         if ((memcmp(net_buf.rf_hdr.urcall, "CQCQCQ", 6) != 0) && (net_buf.rf_hdr.rpt2[0] != ' '))
            memcpy(net_buf.rf_hdr.rpt2,  RPTR_and_G, 8);

         /* 8th in rpt1, rpt2 must be diff */
         if (net_buf.rf_hdr.rpt2[7] == net_buf.rf_hdr.rpt1[7])
            memset(net_buf.rf_hdr.rpt2, ' ', 8);

         /*
            Are we restricting the RF user ?
            If RPTR is OWNER, then any RF user can talk.
            If RPTR is not OWNER,
            that means that mycall, rpt1, rpt2 must be equal to RPTR
              otherwise we drop the rf data
         */
         if (memcmp(RPTR, OWNER, RPTR_SIZE) != 0)
         {
            if (memcmp(net_buf.rf_hdr.mycall, RPTR, RPTR_SIZE) != 0)
            {
               traceit("mycall=[%.8s], not equal to %s\n", net_buf.rf_hdr.mycall, RPTR);
               ok = false;
            }
         }
         else
         if (memcmp(net_buf.rf_hdr.mycall, "        ", 8) == 0)
         {
            traceit("Invalid value for mycall=[%.8s]\n", net_buf.rf_hdr.mycall);
            ok = false;
         }

         if (ok)
         {
            for (i = 0; i < 8; i++)
            {
               if (!isupper(net_buf.rf_hdr.mycall[i]) &&
                   !isdigit(net_buf.rf_hdr.mycall[i]) &&
                   (net_buf.rf_hdr.mycall[i] != ' '))
               {
                  memset(net_buf.rf_hdr.mycall, ' ', 8);
                  ok = false;
                  traceit("Invalid value for MYCALL\n");
                  break;
               }
            }

            for (i = 0; i < 4; i++)
            {
               if (!isupper(net_buf.rf_hdr.sfx[i]) &&
                   !isdigit(net_buf.rf_hdr.sfx[i]) &&
                   (net_buf.rf_hdr.sfx[i] != ' '))
               {
                  memset(net_buf.rf_hdr.sfx, ' ', 4);
                  break;
               }
            }

            for (i = 0; i < 8; i++)
            {
               if (!isupper(net_buf.rf_hdr.urcall[i]) &&
                   !isdigit(net_buf.rf_hdr.urcall[i]) &&
                   (net_buf.rf_hdr.urcall[i] != ' ') &&
                   (net_buf.rf_hdr.urcall[i] != '/'))
               {
                  memcpy(net_buf.rf_hdr.urcall, "CQCQCQ  ", 8);
                  break;
               }
            }

            /*** what if YRCALL is all spaces, we can NOT allow that ***/
            if (memcmp(net_buf.rf_hdr.urcall, "        ", 8) == 0)
               memcpy(net_buf.rf_hdr.urcall, "CQCQCQ  ", 8);

            /* change the rptr flags to net flags */
            if (from_dvap_hdr->flag1 == 0x40)
               net_buf.rf_hdr.flags[0] = 0x00;
            else
            if (from_dvap_hdr->flag1 == 0x48)
               net_buf.rf_hdr.flags[0] = 0x08;
            else
            if (from_dvap_hdr->flag1 == 0x60)
               net_buf.rf_hdr.flags[0] = 0x20;
            else
            if (from_dvap_hdr->flag1 == 0x68)
               net_buf.rf_hdr.flags[0] = 0x28;
            else
               net_buf.rf_hdr.flags[0] = 0x00;
            net_buf.rf_hdr.flags[1] = 0x00;
            net_buf.rf_hdr.flags[2] = 0x00;

            /* for icom g2 */
            S_packet[5] = (unsigned char)(C_COUNTER & 0xff);
            S_packet[4] = ((C_COUNTER >> 8) & 0xff);
            memcpy(S_packet + 10, net_buf.rf_hdr.mycall, 8);
            memcpy(S_packet + 18, OWNER, 8); S_packet[25] = RPTR_MOD;
            sendto(insock, (char *)S_packet, sizeof(S_packet), 0, (struct sockaddr *)&outaddr, sizeof(outaddr));
            C_COUNTER ++;

            /*
               Before we send the data to the local gateway,
               set RPT1, RPT2 to be the local gateway
            */
            memcpy(net_buf.rf_hdr.rpt1, OWNER, 7);
            if (net_buf.rf_hdr.rpt2[7] != ' ')
               memcpy(net_buf.rf_hdr.rpt2, OWNER, 7);

            memcpy(net_buf.pkt_id, "DSTR", 4);
            net_buf.nothing1[0] = ((C_COUNTER >> 8) & 0xff);
            net_buf.nothing1[1] = (unsigned char)(C_COUNTER & 0xff);
            net_buf.flags[0] = 0x73;
            net_buf.flags[1] = 0x12;
            net_buf.nothing2[0] = 0x00;
            net_buf.nothing2[1] = 0x30;
            net_buf.myicm.icm_id = 0x20;
            net_buf.myicm.dst_rptr_id = 0x00;
            net_buf.myicm.snd_rptr_id = 0x01;
            net_buf.myicm.snd_term_id = SND_TERM_ID;
            streamid_raw = (rand_r(&aseed) % 65535U) + 1U;
            net_buf.myicm.streamid[0] = streamid_raw / 256U;
            net_buf.myicm.streamid[1] = streamid_raw % 256U;
            net_buf.myicm.ctrl = 0x80;  sequence = 0x00;
            calcPFCS((unsigned char *)&(net_buf.rf_hdr), net_buf.rf_hdr.pfcs);
            sendto(insock, (char *)&net_buf, 58, 0, (struct sockaddr *)&outaddr, sizeof(outaddr));
            C_COUNTER ++;

            // local RF user keying up, start timer
            dvap_busy = true;
            time(&last_RF_time);

            // save mycall for the ack later
            memcpy(mycall, from_dvap_hdr->mycall, 8);

         }
      }
      else
      if (reply == RT_DAT)
      {
         /* have we already received a header ? */
         if (dvap_busy)
         {
            the_end = ((dvp_buf[4] & 0x40) == 0x40);

            net_buf.nothing1[0] = ((C_COUNTER >> 8) & 0xff);
            net_buf.nothing1[1] = (unsigned char)(C_COUNTER & 0xff);
            net_buf.nothing2[1] = 0x13;
            net_buf.myicm.ctrl = sequence++;
            if (the_end)
               net_buf.myicm.ctrl = sequence | 0x40;
            memcpy(net_buf.rf_audio.buff, dvp_buf + 6, 12);
            sendto(insock, (char *)&net_buf, 29, 0, (struct sockaddr *)&outaddr, sizeof(outaddr));

            ber_errs = dstar_dv_decode((unsigned char *)&net_buf + 17, ber_data);
            if (ber_data[0] != 0xf85)
            {
               num_bit_errors += ber_errs;
               num_dv_frames ++;
            }

            C_COUNTER ++;
            if (sequence > 0x14)
               sequence = 0x00;

            // local RF user still talking, update timer
            time(&last_RF_time); 
            if (the_end)
            {
               // local RF user stopped talking
               dvap_busy = false; 
               traceit("End of dvap audio,  ber=%.02f\n",
                        (num_dv_frames == 0)?0.00:100.00 * ((float)num_bit_errors / (float)(num_dv_frames * 24.00)) );

               if (RPTR_ACK && !busy20000)
               {
                  pthread_attr_init(&attr);
                  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
                  memcpy(dvap_ack_arg.mycall, mycall, 8);
                  dvap_ack_arg.ber = (num_dv_frames == 0)?0.00:100.00 * ((float)num_bit_errors / (float)(num_dv_frames * 24.00));
                  rc = pthread_create(&rptr_ack_t, &attr, rptr_ack, (void *)&dvap_ack_arg);
                  if (rc != 0)
                     traceit("failed to start thread rptr_ack thread\n");
                  pthread_attr_destroy(&attr);
               }
            }
         }
      }
      usleep(1000);
      status_cntr --;
      if (status_cntr < 0)
         break;
   }

   /* stop dvap */
   (void)write_to_dvp(DVP_RQST_STOP, 5);
   close(serfd);

   traceit("readFromRF thread exiting\n");

   keep_running = false;
   pthread_exit(NULL);
}

