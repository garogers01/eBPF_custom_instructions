/* Psuedo Code  */

#include <stdio.h>
#include <string.h>
#include "bpf.h"
#include <netinet/in.h>

#define uint8_t unsigned char
#define uint16_t unsigned short
#define uint32_t unsigned int


#define COMPARE 0x1 
#define PEND 0x2 
#define NEXT_PROTO 0x4 
#define INCLUDE_FIELD 0x8

#define PARSE_NO_PROTO -1

struct lkup_next { 
     uint16_t val; 
     uint16_t tbl_index; 
}; 

struct table_entry { 
    uint16_t sz; 
    uint8_t mask[128];
    uint8_t flags; 
    struct lkup_next   val[24]; 
}; 

struct parse_table { 
    uint8_t num; 
    struct table_entry entries[256]; 
}; 

struct packet_buf {
	uint32_t size;
	uint8_t data[2048];
};

void dump_buf (uint8_t *buf, uint32_t sz);
/* Pulled from OVS */

static bool
load_op(size_t offset, uint64_t *valuep, size_t n, void *aux_)
{   
    struct packet_buf *aux = aux_;
    uint64_t value = 0;
    uint8_t *vp = (uint8_t *) valuep + (8 - n);
    
    printf("bpf ptr %llx\n", (uint64_t)aux);
    printf ("bpf->size %d\n", aux->size);
    printf ("offset %d\n", (int)offset);
    printf ("dump ptr + offset \n");
    dump_buf(aux->data+offset, n);
    printf ("\n\n");
    if (offset + n <= aux->size) {
        memcpy(vp, aux->data+offset, n);
    } else {
        printf("bad load offset 0x%ul, length %ul",
                  (uint32_t)offset, (uint32_t)n);
        return false;
    }
    printf ("vp \n");
    dump_buf(vp, n);
    printf ("valuep \n");
    dump_buf((uint8_t *)valuep, n);
    printf("vp %llx valuep %llx value %llx\n",(uint64_t)*vp,  *valuep, value);
    //value=(uint64_t)vp;
    //*valuep = value;
     
    printf("vp %llx valuep %llx value %llx\n",(uint64_t)vp,  *valuep, value);
    return true;
}

static bool
store_op(size_t offset, uint64_t value_, size_t n, void *aux_)
{
    struct packet_buf *aux = aux_;
    uint64_t value = value_;
    const uint8_t *vp = (const uint8_t *) &value + (8 - n);

    if (offset >= 0x10000 && offset + n <= 0x10000 + aux->size) {
        memcpy((uint8_t *) aux->data + (offset - 0x10000), vp, n);
    } else {
        printf("bad store offset 0x%ul, length %ul",
                  (uint32_t)offset,(uint32_t) n);
        return false;
    }
    return true;
}

static const struct bpf_ops ops = { load_op, store_op };

/* End Pulled from OVS */

unsigned long long rdtscl(void)
{
    unsigned int lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));                        
    return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );  
}

void dump_buf (uint8_t *buf, uint32_t sz)
{
   uint32_t cnt=0;

   while (cnt<sz) {
       printf("%02hhx ", *buf);
       cnt++;
       buf++;
       if ((cnt > 0) & !(cnt%10)) {
          printf("\n");
       }
   }
   printf("\n");

}

/*

     Works on character, but could be extended to work more efficiently.

*/

static void inline apply_mask(uint8_t * buf, uint8_t *mask, uint16_t sz)
{
   uint16_t *tbuf = (uint16_t *) buf;
   uint16_t *tmask = (uint16_t *) mask;

   while (sz)
   {
       *tbuf &= *tmask;
       tbuf ++;
       tmask ++;
       sz --;
   }
}

uint8_t parse(uint8_t * buf, uint8_t * match_buf, struct parse_table *ptable);

struct parse_table tbls[10];
int tbl_id;

void set_table(uint32_t table)
{
     printf("tbl_id %d\n", table);
     tbl_id = table;
}

void parse_ins(uint64_t to_parse, uint64_t to_dest,uint32_t tbl)
{
  printf("Parse %d\n", __LINE__);
  printf("to_parse %llx\n", to_parse);
  printf("to_dest %llx\n", to_dest);

   parse((uint8_t *)to_parse, (uint8_t *)to_dest, &tbls[tbl]);
}

/*

  Returns 0 on success

  No Parse protocol on failure

*/

uint8_t parse(uint8_t * buf, uint8_t * match_buf, struct parse_table *ptable) { 
    uint32_t start=0; 
    uint8_t *pmatch = match_buf; 
    uint8_t * pbuf = buf; 
    uint32_t next_proto=0;
    uint32_t vidx; 
    unsigned long stsc;
    unsigned long etsc;

    stsc=rdtscl();
    while (start < ptable->num) {

       if (ptable->entries[start].flags & INCLUDE_FIELD) {
            memcpy(pmatch, pbuf, ptable->entries[start].sz); 

            apply_mask(pmatch, ptable->entries[start].mask, ptable->entries[start].sz);

            if (ptable->entries[start].flags & COMPARE) { 
                  next_proto=0;
                  vidx=0;
                  while (ptable->entries[start].val[vidx].val !=0) {
                        if ((uint16_t) *pmatch == ptable->entries[start].val[vidx].val) {
                              next_proto=ptable->entries[start].val[vidx].tbl_index;
                              break; /* exit while */
                        }
                        vidx ++;
                   }
                   if (!next_proto) {
                        goto no_next_proto; /* exception packet unknown protocol*/
                   }
              } 
              pmatch += ptable->entries[start].sz; 
              pbuf += ptable->entries[start].sz; 

              if ((ptable->entries[start].flags & PEND) & (ptable->entries[start].flags & NEXT_PROTO)) { 
                    /* Move to next protocol to process as put in table, note could be same one */
                     start = next_proto; /* no next_proto was handled above */
         
              } else if (ptable->entries[start].flags & PEND){
                    if (next_proto > 0) {
                       start = next_proto;
                       next_proto=0;
                    } else {
                         //break; /* Found end of protocols to parse */        
                         goto out;
                    }
              } else {
                       start ++;
              }
           } else {
              pbuf += ptable->entries[start].sz;  /* advance the buffer to next field */
              start ++;
           }
           
      }
out:
      etsc=rdtscl();
      printf("time %lu\n", (etsc-stsc));
      return 0;

no_next_proto:
  
      //printf("No Next Protocol\n");
      etsc=rdtscl();
      printf("time %lu\n", (etsc-stsc));

      return PARSE_NO_PROTO;
}

#include "bpf.h"

int hash_data()
{
}

extern bool bpf_execute(const struct bpf_insn code[], size_t n,
            const struct bpf_ops *ops, void *aux,
            uint64_t regs[10]);

void test_bpf_ether_only()
{

    uint8_t buf[]= {
                    0xde, 0xad, 0xbe, 0xef, 0xf5, 0xf6, /* ether dst mac */
                    0x01, 0x02, 0x3, 0x04, 0x05, 0x07, /* ether src mac */
                    0x08, 0x00,                        /* ether type */

                    0xde, 0xad, 0xbe, 0xef, 0xf5, 0xf6, /* ether dst mac */
                    0x01, 0x02, 0x3, 0x04, 0x05, 0x09, /* ether src mac */
                    0x08, 0x00,                        /* ether type */
                    
                    0xde, 0xad, 0xbe, 0xef, 0xf5, 0xf6, /* ether dst mac */
                    0x01, 0x02, 0x3, 0x04, 0x05, 0x11, /* ether src mac */
                    0x08, 0x00,                        /* ether type */
                    
                   };
    struct parse_table tbl;
    uint8_t result[512] = {};
    int rslt=0;

                //{0xe0,0,0,0,0,0},
#if 0
    /* Program to parse L2 and do L2 Lookup  L2 Bridge*/
    struct bpf_insn ins[]= {
                {0xb7,1,0,0,0},
                {0x79,2,1,0,0,0},
                {0xb7,1,0,0,0,8},
                {0x79,3,1,0,0,0},
                {0xe1,3,2,0,0,1}, /* Parse buffer in R2, put result in R1  using table 1 */
                {0xe2,2,3,0,0,0}, /* Hash result in R2, Key data pointer in R3 */
                {0xb2,2,"0x00000fff",0,0,0} /* 64 bit and on Hash to get index */
                {0xe3,2,3,0,0,1}, /* Hash in R2, Key pointer in R3, use Lookup Table 1 */
                {0xe4,4,50,0,0,0}, /* Send Metadata + pkt to queue  HW QOS block that then forwards to device*/
                {0x95,0,0,0,0,8}
     };
#endif
    /* Program to parse L2 and do L2 Lookup  L2 Bridge*/
    struct bpf_insn ins[]= {
                {0xb7,1,0,0,0},
                {0x79,2,1,0,0,0},
                {0xb7,1,0,0,0,8},
                {0x79,3,1,0,0,0},
                {0xe1,3,2,0,0,1}, /* Parse buffer in R2, put result in R1  using table 1 */
                {0x95,0,0,0,0,8}
     };
    /* Program to parse L3 forwarding */
    struct bpf_insn ins[]= {
    };


    struct packet_buf bpf_mem;

    uint64_t regs[10];

    printf("\n ---- TEST BPF ETHER BEGIN ----\n");

    tbls[0].num=3;

    tbls[0].entries[0].sz=6;

    tbls[0].entries[0].mask[0]=0xf0;
    tbls[0].entries[0].mask[1]=0xf0;
    tbls[0].entries[0].mask[2]=0xf0;
    tbls[0].entries[0].mask[3]=0xf0;
    tbls[0].entries[0].mask[4]=0xf0;
    tbls[0].entries[0].mask[5]=0xf0;
    
    tbls[0].entries[0].flags |= INCLUDE_FIELD;

    tbls[0].entries[1].sz=6;

    tbls[0].entries[1].mask[0]=0xff;
    tbls[0].entries[1].mask[1]=0xff;
    tbls[0].entries[1].mask[2]=0xff;
    tbls[0].entries[1].mask[3]=0xff;
    tbls[0].entries[1].mask[4]=0xff;
    tbls[0].entries[1].mask[5]=0xff;
    
    tbls[0].entries[1].flags |= INCLUDE_FIELD;

    tbls[0].entries[2].sz=2;

    tbls[0].entries[2].mask[0]=0xff;
    tbls[0].entries[2].mask[1]=0xff;
    
    tbls[0].entries[2].flags |= PEND;
    tbls[0].entries[2].flags |= INCLUDE_FIELD;

    dump_buf((unsigned char *) & tbls[0], 256);

    printf("\n\nstart bpf engine\n\n");

    *((uint64_t*)&bpf_mem.data[0])=(uint64_t)&buf;
    *((uint64_t*)&bpf_mem.data[8])=(uint64_t)&result[0];

    printf("bpf_mem \n");

    bpf_mem.size=2048;
    dump_buf(&bpf_mem.data[0], 64); 

    printf("bpf ptr %llx\n", (uint64_t)&bpf_mem);
    printf("void bpf ptr %llx\n", (uint64_t) &bpf_mem);
    bpf_execute(&ins, 7,&ops,(void *)&bpf_mem, &regs[0]); 

    printf("\n\nresult after bpf engine\n");
    dump_buf(result, 64); 
    //int loop;
    //for (loop=1;loop<1000;loop++)
         rslt=parse (buf, result, &tbl);

    printf("Result %d\n", rslt);

    dump_buf(result, 64); 

    printf("\n ---- TEST BPF ETHER END ----\n");
}

void test_ether_only()
{

    uint8_t buf[]= {
                    0xde, 0xad, 0xbe, 0xef, 0xf5, 0xf6, /* ether dst mac */
                    0x01, 0x02, 0x3, 0x04, 0x05, 0x07, /* ether src mac */
                    0x08, 0x00,                        /* ether type */

                    0xde, 0xad, 0xbe, 0xef, 0xf5, 0xf6, /* ether dst mac */
                    0x01, 0x02, 0x3, 0x04, 0x05, 0x09, /* ether src mac */
                    0x08, 0x00,                        /* ether type */
                    
                    0xde, 0xad, 0xbe, 0xef, 0xf5, 0xf6, /* ether dst mac */
                    0x01, 0x02, 0x3, 0x04, 0x05, 0x11, /* ether src mac */
                    0x08, 0x00,                        /* ether type */
                    
                   };
    struct parse_table tbl;
    uint8_t result[512] = {};
    int rslt=0;

    printf("\n ---- TEST ETHER BEGIN ----\n");
    tbl.num=3;

    tbl.entries[0].sz=6;

    tbl.entries[0].mask[0]=0xf0;
    tbl.entries[0].mask[1]=0xf0;
    tbl.entries[0].mask[2]=0xf0;
    tbl.entries[0].mask[3]=0xf0;
    tbl.entries[0].mask[4]=0xf0;
    tbl.entries[0].mask[5]=0xf0;
    
    tbl.entries[0].flags |= INCLUDE_FIELD;

    tbl.entries[1].sz=6;

    tbl.entries[1].mask[0]=0xff;
    tbl.entries[1].mask[1]=0xff;
    tbl.entries[1].mask[2]=0xff;
    tbl.entries[1].mask[3]=0xff;
    tbl.entries[1].mask[4]=0xff;
    tbl.entries[1].mask[5]=0xff;
    
    tbl.entries[1].flags |= INCLUDE_FIELD;

    tbl.entries[2].sz=2;

    tbl.entries[2].mask[0]=0xff;
    tbl.entries[2].mask[1]=0xff;
    
    tbl.entries[2].flags |= PEND;
    tbl.entries[2].flags |= INCLUDE_FIELD;

    dump_buf((unsigned char *) & tbl, 256);

    int loop;
    for (loop=1;loop<1000;loop++)
         rslt=parse (buf, result, &tbl);

    printf("Result %d\n", rslt);

    dump_buf(result, 64); 

    printf("\n ---- TEST ETHER END ----\n");
}

void test_ether_ipv4_only()
{

    uint8_t buf[]= {
                    0xde, 0xad, 0xbe, 0xef, 0xf5, 0xf6, /* ether dst mac */
                    0x01, 0x02, 0x3, 0x04, 0x05, 0x07, /* ether src mac */
                    0x08, 0x00,                        /* ether type */
                    0x04,                              /* ipv4 version */
                    0xff,                              /* IHL */
                    0xde,0xed,                         /* dscp en */
                    0xde,0xed,                         /* length */
                    0xde,0xed,                         /* id */
                    0xde,0xed,                         /* flags & fragment */
                    0xff,                              /* ttl */
                    0xff,                              /* protocol */
                    0xde,0xed,                         /* cs */
                    0xde,0xed,0xbe,0xef,               /* ipv4 src */
                    0xef,0xbe,0xed,0xde,               /* ipv4 dst */

                    0xde, 0xad, 0xbe, 0xef, 0xf5, 0xf6, /* ether dst mac */
                    0x01, 0x02, 0x3, 0x04, 0x05, 0x09, /* ether src mac */
                    0x86, 0xdd,                        /* ether type */
                    
                    0xde, 0xad, 0xbe, 0xef, 0xf5, 0xf6, /* ether dst mac */
                    0x01, 0x02, 0x3, 0x04, 0x05, 0x11, /* ether src mac */
                    0x08, 0x01,                        /* ether type */
                    
                   };

    struct parse_table tbl;
    uint8_t result[512] = {};
    int rslt=0;

    printf("\n ---- TEST ETHER & IPV4 ----\n");
    tbl.num=13;

    tbl.entries[0].sz=6;

    tbl.entries[0].mask[0]=0xf0;
    tbl.entries[0].mask[1]=0xf0;
    tbl.entries[0].mask[2]=0xf0;
    tbl.entries[0].mask[3]=0xf0;
    tbl.entries[0].mask[4]=0xf0;
    tbl.entries[0].mask[5]=0xf0;
    
    tbl.entries[0].flags |= INCLUDE_FIELD;

    tbl.entries[1].sz=6;

    tbl.entries[1].mask[0]=0xff;
    tbl.entries[1].mask[1]=0xff;
    tbl.entries[1].mask[2]=0xff;
    tbl.entries[1].mask[3]=0xff;
    tbl.entries[1].mask[4]=0xff;
    tbl.entries[1].mask[5]=0xff;
    
    tbl.entries[1].flags |= INCLUDE_FIELD;

    tbl.entries[2].sz=2;

    tbl.entries[2].mask[0]=0xff;
    tbl.entries[2].mask[1]=0xff;
    
    tbl.entries[2].flags |= PEND;
    tbl.entries[2].flags |= COMPARE;
    tbl.entries[2].flags |= NEXT_PROTO;
    tbl.entries[2].flags |= INCLUDE_FIELD;

    tbl.entries[2].val[0].val=0x0008;
    tbl.entries[2].val[0].tbl_index=3;

    /* Grabs version & IHL */
    tbl.entries[3].sz=1;        

    tbl.entries[3].mask[0]=0x00;
    
    tbl.entries[3].flags =0;

    /* Grabs dscp & ECN */
    tbl.entries[4].sz=1;        

    tbl.entries[4].mask[0]=0xff;
    
    tbl.entries[4].flags |= INCLUDE_FIELD;

    /* length  */
    tbl.entries[5].sz=2;        

    tbl.entries[5].mask[0]=0x0;
    tbl.entries[5].mask[1]=0x0;
    
    tbl.entries[5].flags =0;

    /* id  */
    tbl.entries[6].sz=2;        

    tbl.entries[6].mask[0]=0x0;
    tbl.entries[6].mask[1]=0x0;
    
    tbl.entries[6].flags =0;

    /* flags & fragment  */
    tbl.entries[7].sz=2;        

    tbl.entries[7].mask[0]=0x0;
    tbl.entries[7].mask[1]=0x0;
    
    tbl.entries[7].flags = 0;

    /* ttl  */
    tbl.entries[8].sz=1;        

    tbl.entries[8].mask[0]=0xff;
    
    tbl.entries[8].flags |= INCLUDE_FIELD;

    /* protocol  */
    tbl.entries[9].sz=1;        

    tbl.entries[9].mask[0]=0xff;
    
    tbl.entries[9].flags |= INCLUDE_FIELD;

    /* cs  */
    tbl.entries[10].sz=2;        

    tbl.entries[10].mask[0]=0x00;
    tbl.entries[10].mask[1]=0x00;
    
    tbl.entries[10].flags = 0;

    /* src ip  */
    tbl.entries[11].sz=4;        

    tbl.entries[11].mask[0]=0xff;
    tbl.entries[11].mask[1]=0xff;
    tbl.entries[11].mask[2]=0xff;
    tbl.entries[11].mask[3]=0xff;
    
    tbl.entries[11].flags |= INCLUDE_FIELD;

    /* dst ip  */
    tbl.entries[12].sz=4;        

    tbl.entries[12].mask[0]=0xff;
    tbl.entries[12].mask[1]=0xff;
    tbl.entries[12].mask[2]=0xff;
    tbl.entries[12].mask[3]=0xff;
    
    tbl.entries[12].flags |= PEND;
    tbl.entries[12].flags |= INCLUDE_FIELD;


    printf("Test 1:\n");
    rslt=parse (buf, result, &tbl);

    printf("Result %d\n", rslt);

    dump_buf(result, 64); 

    printf("Test 2:\n");
    memset(result,0,512);
    rslt=parse (buf+36, result, &tbl);

    printf("Result %d\n", rslt);

    dump_buf(result, 64); 

    printf("\n ---- TEST ETHER & IPV4END ----\n");
}

void test_ether_ipv4_udp_only()
{

    uint8_t buf[]= {
                    0xde, 0xad, 0xbe, 0xef, 0xf5, 0xf6, /* ether dst mac */
                    0x01, 0x02, 0x3, 0x04, 0x05, 0x07, /* ether src mac */
                    0x08, 0x00,                        /* ether type */
                    0x40,                              /* ipv4 version */
                    0xde,                              /* dscp en */
                    0xde,0xed,                         /* length */
                    0xde,0xed,                         /* id */
                    0xde,0xed,                         /* flags & fragment */
                    0xff,                              /* ttl */
                    0x17,                              /* protocol */
                    0xde,0xed,                         /* cs */
                    0xde,0xed,0xbe,0xef,               /* ipv4 src */
                    0xef,0xbe,0xed,0xde,               /* ipv4 dst */
                    0xbe,0xef,                           /* udp src */
                    0xde,0xad,                           /* udp dst */

                    0xde, 0xad, 0xbe, 0xef, 0xf5, 0xf6, /* ether dst mac */
                    0x01, 0x02, 0x3, 0x04, 0x05, 0x07, /* ether src mac */
                    0x08, 0x00,                        /* ether type */
                    0x40,                              /* ipv4 version */
                    0xde,                              /* dscp en */
                    0xde,0xed,                         /* length */
                    0xde,0xed,                         /* id */
                    0xde,0xed,                         /* flags & fragment */
                    0xff,                              /* ttl */
                    0x06,                              /* protocol */
                    0xde,0xed,                         /* cs */
                    0xde,0xed,0xbe,0xef,               /* ipv4 src */
                    0xef,0xbe,0xed,0xde,               /* ipv4 dst */
                    0xbe,0xef,                           /* udp src */
                    0xde,0xad,                           /* udp dst */

                    0xde, 0xad, 0xbe, 0xef, 0xf5, 0xf6, /* ether dst mac */
                    0x01, 0x02, 0x3, 0x04, 0x05, 0x07, /* ether src mac */
                    0x08, 0x00,                        /* ether type */
                    0x04,                              /* ipv4 version */
                    0xff,                              /* IHL */
                    0xde,0xed,                         /* dscp en */
                    0xde,0xed,                         /* length */
                    0xde,0xed,                         /* id */
                    0xde,0xed,                         /* flags & fragment */
                    0xff,                              /* ttl */
                    0x0f,                              /* protocol */
                    0xde,0xed,                         /* cs */
                    0xde,0xed,0xbe,0xef,               /* ipv4 src */
                    0xef,0xbe,0xed,0xde,               /* ipv4 dst */
                    0xbe,0xef,                           /* udp src */
                    0xde,0xad,                           /* udp dst */

                    0xde, 0xad, 0xbe, 0xef, 0xf5, 0xf6, /* ether dst mac */
                    0x01, 0x02, 0x3, 0x04, 0x05, 0x09, /* ether src mac */
                    0x86, 0xdd,                        /* ether type */
                    
                    0xde, 0xad, 0xbe, 0xef, 0xf5, 0xf6, /* ether dst mac */
                    0x01, 0x02, 0x3, 0x04, 0x05, 0x11, /* ether src mac */
                    0x08, 0x01,                        /* ether type */
                    
                   };

    struct parse_table tbl;
    uint8_t result[512] = {};
    int rslt=0;

    memset (result, 0, 512);
    printf("\n ---- TEST ETHER & IPV4 UDP----\n");
    tbl.num=15;

    tbl.entries[0].sz=6;

    tbl.entries[0].mask[0]=0xf0;
    tbl.entries[0].mask[1]=0xf0;
    tbl.entries[0].mask[2]=0xf0;
    tbl.entries[0].mask[3]=0xf0;
    tbl.entries[0].mask[4]=0xf0;
    tbl.entries[0].mask[5]=0xf0;
    
    tbl.entries[0].flags |= INCLUDE_FIELD;

    tbl.entries[1].sz=6;

    tbl.entries[1].mask[0]=0xff;
    tbl.entries[1].mask[1]=0xff;
    tbl.entries[1].mask[2]=0xff;
    tbl.entries[1].mask[3]=0xff;
    tbl.entries[1].mask[4]=0xff;
    tbl.entries[1].mask[5]=0xff;
    
    tbl.entries[1].flags |= INCLUDE_FIELD;

    tbl.entries[2].sz=2;

    tbl.entries[2].mask[0]=0xff;
    tbl.entries[2].mask[1]=0xff;
    
    tbl.entries[2].flags |= PEND;
    tbl.entries[2].flags |= COMPARE;
    tbl.entries[2].flags |= NEXT_PROTO;
    tbl.entries[2].flags |= INCLUDE_FIELD;

    tbl.entries[2].val[0].val=0x0008;
    tbl.entries[2].val[0].tbl_index=3;

    /* Grabs version & IHL */
    tbl.entries[3].sz=1;        

    tbl.entries[3].mask[0]=0x00;
    
    tbl.entries[3].flags =0;

    /* Grabs dscp & ECN */
    tbl.entries[4].sz=1;        

    tbl.entries[4].mask[0]=0xff;
    
    tbl.entries[4].flags = INCLUDE_FIELD;

    /* length  */
    tbl.entries[5].sz=2;        

    tbl.entries[5].mask[0]=0x0;
    tbl.entries[5].mask[1]=0x0;
    
    tbl.entries[5].flags =0;

    /* id  */
    tbl.entries[6].sz=2;        

    tbl.entries[6].mask[0]=0x0;
    tbl.entries[6].mask[1]=0x0;
    
    tbl.entries[6].flags =0;

    /* flags & fragment  */
    tbl.entries[7].sz=2;        

    tbl.entries[7].mask[0]=0x0;
    tbl.entries[7].mask[1]=0x0;
    
    tbl.entries[7].flags =0;

    /* ttl  */
    tbl.entries[8].sz=1;        

    tbl.entries[8].mask[0]=0xff;
    
    tbl.entries[8].flags = INCLUDE_FIELD;

    /* protocol  */
    tbl.entries[9].sz=1;        

    tbl.entries[9].mask[0]=0xff;
    
    tbl.entries[9].flags |= COMPARE;
    tbl.entries[9].flags |= INCLUDE_FIELD;

    tbl.entries[9].val[0].val=0x17;
    tbl.entries[9].val[0].tbl_index=13;
    tbl.entries[9].val[1].val=0x06;
    tbl.entries[9].val[1].tbl_index=13;

    /* cs  */
    tbl.entries[10].sz=2;        

    tbl.entries[10].mask[0]=0x00;
    tbl.entries[10].mask[1]=0x00;
    
    tbl.entries[10].flags &=0;

    /* src ip  */
    tbl.entries[11].sz=4;        

    tbl.entries[11].mask[0]=0xff;
    tbl.entries[11].mask[1]=0xff;
    tbl.entries[11].mask[2]=0xff;
    tbl.entries[11].mask[3]=0xff;
    
    tbl.entries[11].flags |= INCLUDE_FIELD;

    /* dst ip  */
    tbl.entries[12].sz=4;        

    tbl.entries[12].mask[0]=0xff;
    tbl.entries[12].mask[1]=0xff;
    tbl.entries[12].mask[2]=0xff;
    tbl.entries[12].mask[3]=0xff;
    
    tbl.entries[12].flags |= PEND ;
    tbl.entries[12].flags |= NEXT_PROTO ;
    tbl.entries[12].flags |= INCLUDE_FIELD ;

    /* tcp src port  */
    tbl.entries[13].sz=2;        

    tbl.entries[13].mask[0]=0xff;
    tbl.entries[13].mask[1]=0xff;
    
    tbl.entries[13].flags = INCLUDE_FIELD;

    /* tcp src port  */
    tbl.entries[14].sz=2;        

    tbl.entries[14].mask[0]=0xff;
    tbl.entries[14].mask[1]=0xff;
    
    tbl.entries[14].flags |= PEND;
    tbl.entries[14].flags |= INCLUDE_FIELD;
 


    printf("Test 1:\n");
    rslt=parse (buf, result, &tbl);

    printf("Result %d\n", rslt);

    dump_buf(result, 64); 

    printf("Test 2:\n");

    memset(result,0,512);
    rslt=parse (buf+38, result, &tbl);

    printf("Result %d\n", rslt);

    dump_buf(result, 64); 

    printf("Test 3:\n");

    memset(result,0,512);
    rslt=parse (buf+76, result, &tbl);

    printf("Result %d\n", rslt);

    dump_buf(result, 64); 

    printf("\n ---- TEST ETHER & IPV4END ----\n");
}


int main (int argc, char *argv[])
{
   unsigned long stsc;
   unsigned long etsc;
   int loop;

   stsc = rdtscl();
       test_bpf_ether_only();
   //for (loop=0; loop<1; loop ++) 
    //   test_ether_only();
   //etsc = rdtscl();
   //printf("Time in clocks %lu\n", (etsc-stsc));
   //stsc = rdtscl();
   //for (loop=0; loop<1; loop ++) 
       //test_ether_ipv4_only();
   //etsc = rdtscl();
   //printf("Time in clocks %lu\n", (etsc-stsc));
   //stsc = rdtscl();
   //for (loop=0; loop<1; loop ++) 
       //test_ether_ipv4_only();
   //etsc = rdtscl();
//   printf("Time in clocks %lu\n", (etsc-stsc));
   //test_ether_ipv4_udp_only();
}
