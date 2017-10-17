#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/times.h>
#include <errno.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <time.h>
#include <bits/socket.h>
#include <bits/ioctls.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include "libavl.h"

#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/

/* default Ethernet snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 10000
/* ethernet headers are 14 bytes */
#define ETH_HDRLEN 14

/* a convenience for V6 addresses */
union v6add {
  u_int16_t sds[8];
  u_int32_t quad[4];
  u_int64_t lds[2];
  };  

typedef union v6add v6addr_t ; 
typedef struct _pktinfo6 pktinfo6;
typedef struct in6_addr in6_addr_t;

struct _pktinfo6 {
  struct in6_addr ipi6_addr;
  int ipi6_ifindex;
  };
  
char *interface = "eth0" ;
//char *pcap_int = "eno1" ;
char *host = "2401:2000:6660::122";
char *http_server = "2001:388:1000:120:d267:e5ff:feef:a842" ;

int port ;
uint8_t src_mac[6] = {0x14,0x18,0x77,0x43,0xb9,0xb8};
uint8_t dst_mac[6] = {0x24,0xe9,0xb3,0x52,0x75,0x00};;
int dst_mac_set = 1 ;
int src_mac_set = 1 ;
int interface_set = 1 ;
//int pcap_int_set = 0 ;

uint8_t *data, *ether_frame ;
struct ifreq ifr ;
int sd ;
int frame_length ;

char *src_ip;
char *dst_ip ;
struct in6_addr ip6_addr ;
struct in6_addr local6_addr;

struct sockaddr_ll device ;

/* structures for the NAT binding table */
/* this is the external address and port used by the incoming connection and the time of latest use */
struct binding {
  struct in6_addr ip6_src ;
  uint16_t sport ;
  struct ports *p ;
  uint32_t seq ;
  time_t used ;  
  } ;

/* we will use a AVL tree to index the binding table */
avl_ptr addr_table_80 = 0 ;
avl_ptr addr_table_443 = 0 ;

/* first free port numbers for ports 80 and 443 */
int first_call = 1 ;
uint16_t freeport_80 = 0 ;
uint16_t p80list[64512] ;
uint16_t freeport_443 = 0 ;
uint16_t p443list[64512] ;


  

/* array of free port numbers for port 80 and port 443*/
struct ports {
  uint16_t portno ;
  struct binding *entry ;
  struct ports *nxt ;
  struct ports *prv ;
  } *head_80 = 0, *tail_80 = 0,  *port_80_ptr[65535],
    *head_443 = 0, *tail_443 = 0,  *port_443_ptr[65535];

pcap_t *handle ;                       /* packet capture handle */
//pcap_t *handle_out ;                   /* packet send handle */


time_t t ;
int debug = 0 ;
  
/*------------------------------------------------------------------------------*/

/**************************
 * v6cmp 
 * compare 2 IPv6 addresses - return less (-1) eql (0) or gtr (1)
 **************************/
 
int
v6cmp(struct in6_addr *a1,  struct in6_addr *a2) {
  v6addr_t *t1, *t2 ;
  t1 = (v6addr_t *)(a1) ;
  t2 = (v6addr_t *)(a2) ;
  if (t1->lds[0] < t2->lds[0]) return(-1) ;
  if (t1->lds[0] > t2->lds[0]) return(1) ;
  if (t1->lds[1] < t2->lds[1]) return(-1) ;
  if (t1->lds[1] > t2->lds[1]) return(1) ;
  return(0) ;
  }

/**************************
 * bind_cmp 
 * compare 2 binding entries return less (-1) eql (0) or gtr (1) 
 **************************/

int 
bind_cmp(avl_ptr a1, avl_ptr a2) {
  int i;
  if ((i = v6cmp(&(((struct binding *)a1->payload)->ip6_src),&(((struct binding *)a2->payload)->ip6_src)))) return(i) ;
  if (((struct binding *)a1->payload)->sport < ((struct binding *)a2->payload)->sport) return(-1) ;
  if (((struct binding *)a1->payload)->sport > ((struct binding *)a2->payload)->sport) return(1) ;
  return(0) ;
  }

/**************************
 * find_bind 
 * find the binding table entry matching the address and port in the binding parameter
 **************************/

struct binding *
find_binding(struct binding *b,uint16_t selector) {
  struct avldata local ;
  struct binding bdg ;
  avl_ptr tmp ;
  
  local.payload = &bdg ;
  bcopy(b,&bdg,sizeof bdg) ;
  if (selector == 80) {
    if ((tmp = avlaccess(addr_table_80,&local,bind_cmp)))
      return((struct binding *)tmp->payload) ;
    }
  else {
    if ((tmp = avlaccess(addr_table_443,&local,bind_cmp)))
      return((struct binding *)tmp->payload) ;
    }
  return(NULL) ;
  }
  
void 
shuffle(uint16_t *array, int n)
{
  if (n > 1) {
    int i;
    for (i = 0; i < n - 1; i++) {
      int j = i + rand() / (RAND_MAX / (n - i) + 1);
      int t = array[j];
      array[j] = array[i];
      array[i] = t;
      }
    }
}

void
init_arrays() {
  if (first_call) {
    int i ;
    for (i = 0 ; i < 64512; ++i) {
      p80list[i] = i + 1024 ; 
      p443list[i] = i + 1024 ;
      }
    shuffle(p80list,64512) ;
    shuffle(p443list,64512) ;
    first_call = 0 ;
    }
    
}

/**************************
 * next_port_80 
 * find the next free port, or if none free then remove the oldest from the table
 **************************/

uint16_t
next_port_80(struct in6_addr *ip6_addr, uint16_t port) {
  struct ports *tmp ;
  struct binding bdg ;
  struct binding *brtn ;
  struct avldata local ;
  avl_ptr ttmp ;
  uint16_t pport ;

  if (first_call) init_arrays() ;

  if (freeport_80 < 64512) {
    pport = p80list[freeport_80] ;
    ++freeport_80 ;
    /* add this to the head of the queue */
    tmp = malloc(sizeof *tmp) ;
    tmp->portno = pport ;
    tmp->nxt = head_80 ;
    tmp->prv = 0 ;
    tmp->entry = 0 ;
    if (head_80) head_80->prv = tmp ;
    head_80 = tmp ;
    if (!tail_80) tail_80 = tmp ;
    port_80_ptr[pport] = tmp ;
    }
  else {
    /* recycle the tail of the queue to the head of the queue */
    tmp = tail_80 ;
    tail_80 = tail_80->prv ;
    if (tail_80)
      tail_80->nxt = 0 ;
  
    /* now clear out the associated binding entry from the table */
    if (tmp->entry) {
      local.payload = tmp->entry ;
      avlremove(&addr_table_80,&local,bind_cmp) ;
      free(tmp->entry) ;
      }
    tmp->prv = 0 ;
    tmp->nxt = head_80 ;
    if (head_80) head_80->prv = tmp ;
    head_80 = tmp ;
    if (!tail_80)
      tail_80 = tmp ;
    head_80 = tmp ;
    }
  /* now put in the new entry in the port 80 binding table */
  local.payload = &bdg ;
  bcopy(ip6_addr,&bdg.ip6_src,16) ;
  bdg.sport = port ;
  avlinserted = 0 ;
  avlinsert(&addr_table_80,&local,bind_cmp) ;
  ttmp = avl_inserted ;
  if (avlinserted) {
    brtn = (struct binding *)malloc(sizeof *brtn) ;
    bcopy(&bdg,brtn,sizeof bdg);
    brtn->seq = 0 ;
    ttmp->payload = brtn ;
    }
  else {
    brtn = ttmp->payload ;
    brtn->seq = 0 ;
    }
  tmp->entry = brtn ; 
  brtn->used = time(0) ;
  brtn->p = tmp ;
  return(tmp->portno) ;
}
  
/**************************
 * next_port_443 
 * find the next free port, or if none free then remove the oldest from the table
 **************************/

uint16_t
next_port_443(struct in6_addr *ip6_addr, uint16_t port) {
  struct ports *tmp ;
  struct binding bdg ;
  struct binding *brtn ;
  struct avldata local ;
  avl_ptr ttmp ;
  uint16_t pport ;

  if (first_call) init_arrays() ;
  
  if (freeport_443 < 64512) {
    pport = p443list[freeport_443] ;
    ++freeport_443 ;
    /* add this to the head of the queue */
    tmp = malloc(sizeof *tmp) ;
    tmp->portno = pport ;
    tmp->nxt = head_443 ;
    tmp->prv = 0 ;
    tmp->entry = 0 ;
    if (head_443) head_443->prv = tmp ;
    head_443 = tmp ;
    if (!tail_443) 
      tail_443 = tmp ;
    port_443_ptr[pport] = tmp ;
    }
  else {
    /* recycle the tail of the queue to the head of the queue */
    tmp = tail_443 ;
    tail_443 = tail_443->prv ;
    if (tail_443) 
      tail_443->nxt = 0 ;
  
    /* now clear out the associated binding entry from the table */
    if (tmp->entry) {
      local.payload = tmp->entry ;
      avlremove(&addr_table_443,&local,bind_cmp) ;
      free(tmp->entry) ;
      }
    tmp->prv = 0 ;
    tmp->nxt = head_443 ;
    if (head_443)
      head_443->prv = tmp ;
    head_443 = tmp ;
    if (!tail_443)
      tail_443 = tmp ;
    head_443 = tmp ;
    }
  /* now put in the new entry in the port 443 binding table */
  local.payload = &bdg ;
  bcopy(ip6_addr,&bdg.ip6_src,16) ;
  bdg.sport = port ;
  avlinserted = 0 ;
  avlinsert(&addr_table_443,&local,bind_cmp) ;
  ttmp = avl_inserted ;
  if (avlinserted) {
    brtn = (struct binding *)malloc(sizeof *brtn) ;
    bcopy(&bdg,brtn,sizeof bdg);
    brtn->seq = 0 ;
    ttmp->payload = brtn ;
    }
  else {
    brtn = ttmp->payload ;
    brtn->seq = 0 ;
    }
  tmp->entry = brtn ; 
  brtn->used = time(0) ;
  brtn->p = tmp ;
  return(tmp->portno) ;
}
  
  
/**************************
 * find_ancillary
 * search through the V6 extension headers
 **************************/

static void *
find_ancillary (struct msghdr *msg, int cmsg_type)
{
  struct cmsghdr *cmsg = NULL;

  for (cmsg = CMSG_FIRSTHDR (msg); cmsg != NULL; cmsg = CMSG_NXTHDR (msg, cmsg)) {
    if ((cmsg->cmsg_level == IPPROTO_IPV6) && (cmsg->cmsg_type == cmsg_type)) {
      return (CMSG_DATA (cmsg));
    }
  }

  return (NULL);
}


// Allocate memory for an array of chars.
char *
allocate_strmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of unsigned chars.
uint8_t *
allocate_ustrmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}



/******************************************************************* 
 * 
 * ra_mac
 *
 * get the MAC address of the local router (needed for the IPv6
 * raw IP packet interface) 
 */ 

 

uint8_t *
ra_mac()
{
  int i, status, sd, on, ifindex, hoplimit;
  struct nd_router_advert *ra;
  uint8_t *inpack;
  int len;
  struct msghdr msghdr;
  struct iovec iov[2];
  uint8_t *opt, *pkt;
  char *destination;
  struct in6_addr dst;
  int rcv_ifindex;
  struct ifreq ifr;

  // Allocate memory for various arrays.
  inpack = allocate_ustrmem (IP_MAXPACKET);
  destination = allocate_strmem (INET6_ADDRSTRLEN);

  // Prepare msghdr for recvmsg().
  memset (&msghdr, 0, sizeof (msghdr));
  msghdr.msg_name = NULL;
  msghdr.msg_namelen = 0;
  memset (&iov, 0, sizeof (iov));
  iov[0].iov_base = (uint8_t *) inpack;
  iov[0].iov_len = IP_MAXPACKET;
  msghdr.msg_iov = iov;
  msghdr.msg_iovlen = 1;

  msghdr.msg_control = allocate_ustrmem (IP_MAXPACKET);
  msghdr.msg_controllen = IP_MAXPACKET * sizeof (uint8_t);

  // Request a socket descriptor sd.
  if ((sd = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0) {
    perror ("Failed to get socket descriptor ");
    exit (EXIT_FAILURE);
    }

  // Set flag so we receive hop limit from recvmsg.
  on = 1;
  if ((status = setsockopt (sd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof (on))) < 0) {
    perror ("setsockopt to IPV6_RECVHOPLIMIT failed ");
    exit (EXIT_FAILURE);
    }

  // Set flag so we receive destination address from recvmsg.
  on = 1;
  if ((status = setsockopt (sd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof (on))) < 0) {
    perror ("setsockopt to IPV6_RECVPKTINFO failed ");
    exit (EXIT_FAILURE);
    }

  //printf("Interface: %s\n",interface);

  // Obtain MAC address of this node.
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
    perror ("ioctl() failed to get source MAC address ");
    exit (EXIT_FAILURE);
  }

  // Retrieve interface index of this node.
  if ((ifindex = if_nametoindex (interface)) == 0) {
    perror ("if_nametoindex() failed to obtain interface index ");
    exit (EXIT_FAILURE);
    }
  // printf ("\nOn this node, index for interface %s is %i\n", interface, ifindex);

  // Bind socket to interface of this node.
  if (setsockopt (sd, SOL_SOCKET, SO_BINDTODEVICE, (void *) &ifr, sizeof (ifr)) < 0) {
    perror ("SO_BINDTODEVICE failed");
    exit (EXIT_FAILURE);
  }

  // Listen for incoming message from socket sd.
  // Keep at it until we get a router advertisement.
  ra = (struct nd_router_advert *) inpack;
  while (ra->nd_ra_hdr.icmp6_type != ND_ROUTER_ADVERT) {
    if ((len = recvmsg (sd, &msghdr, 0)) < 0) {
      perror ("recvmsg failed ");
      exit (EXIT_FAILURE);
    }
  }

  // Ancillary data
  // printf ("\nIPv6 header data:\n");
  opt = find_ancillary (&msghdr, IPV6_HOPLIMIT);
  if (opt == NULL) {
    fprintf (stderr, "Unknown hop limit\n");
    exit (EXIT_FAILURE);
  }
  hoplimit = *(int *) opt;
  // printf ("Hop limit: %i\n", hoplimit);

  opt = find_ancillary (&msghdr, IPV6_PKTINFO);
  if (opt == NULL) {
    fprintf (stderr, "Unkown destination address\n");
    exit (EXIT_FAILURE);
    }
  memset (&dst, 0, sizeof (dst));
  dst = ((pktinfo6 *) opt)->ipi6_addr;
  if (inet_ntop (AF_INET6, &dst, destination, INET6_ADDRSTRLEN) == NULL) {
    status = errno;
    fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
    }
  //printf ("Destination address: %s\n", destination);

  rcv_ifindex = ((pktinfo6 *) opt)->ipi6_ifindex;
  //printf ("Destination interface index: %i\n", rcv_ifindex);

  // ICMPv6 header and options data
  // printf ("\nICMPv6 header data:\n");
  // printf ("Type (134 = router advertisement): %u\n", ra->nd_ra_hdr.icmp6_type);
  // printf ("Code: %u\n", ra->nd_ra_hdr.icmp6_code);
  // printf ("Checksum: %x\n", ntohs (ra->nd_ra_hdr.icmp6_cksum));
  // printf ("Hop limit recommended by this router (0 is no recommendation): %u\n", ra->nd_ra_curhoplimit);
  // printf ("Managed address configuration flag: %u\n", ra->nd_ra_flags_reserved >> 7);
  // printf ("Other stateful configuration flag: %u\n", (ra->nd_ra_flags_reserved >> 6) & 1);
  // printf ("Mobile home agent flag: %u\n", (ra->nd_ra_flags_reserved >> 5) & 1);
  // printf ("Router lifetime as default router (s): %u\n", ntohs (ra->nd_ra_router_lifetime));
  // printf ("Reachable time (ms): %u\n", ntohl (ra->nd_ra_reachable));
  // printf ("Retransmission time (ms): %u\n", ntohl (ra->nd_ra_retransmit)); 

  // printf ("\nOptions:\n");  // Contents here are consistent with ra6.c, but others are possible

  pkt = (uint8_t *) inpack;

  // printf ("Type: %u\n", pkt[sizeof (struct nd_router_advert)]);
  // printf ("Length: %u (units of 8 octets)\n", pkt[sizeof (struct nd_router_advert) + 1]);
  // printf ("MAC address: ");

  for (i=2; i<=7; i++) {
    dst_mac[i-2] = pkt[sizeof (struct nd_router_advert) + i];
    }
  //  printf ("%02x:", pkt[sizeof (struct nd_router_advert) + i]);
  //  }
  //printf ("%02x\n", pkt[sizeof (struct nd_router_advert) + 7]);

  close (sd);

  return (&dst_mac[0]);
}



void
open_raw_socket()
{
  // the mac address of the next hop router can be set by -m <mac_addr>
  // if it is not set then we need to listen for RA messages and pull
  // the mac address of one of them
  //
  if (!dst_mac_set) 
    ra_mac();

  // Allocate memory for various arrays. 
  data = allocate_ustrmem (IP_MAXPACKET); 
  src_ip = allocate_strmem (INET6_ADDRSTRLEN); 
  dst_ip = allocate_strmem (INET6_ADDRSTRLEN); 
  
  // Submit request for a socket descriptor to look up interface. 
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) { 
    perror ("socket() failed to get socket descriptor for using ioctl() "); 
    exit (EXIT_FAILURE); 
    } 
 
  // Use ioctl() to look up interface name and get its MAC address. 
  memset (&ifr, 0, sizeof (ifr)); 
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface); 
  if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) { 
    perror ("ioctl() failed to get source MAC address "); 
    exit (EXIT_FAILURE); 
    } 
  close (sd); 
 
  // Copy source MAC address into src_mac 
  memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t)); 
 
  // Debug code
  // Report source MAC address to stdout. 
  //printf ("MAC address for interface %s is ", interface); 
  //for (i=0; i<5; i++) { 
  //  printf ("%02x:", src_mac[i]); 
  //} 
  //printf ("%02x\n", src_mac[5]); 
 
  // Find interface index from interface name and store index in 
  // struct sockaddr_ll device, which will be used as an argument of sendto(). 
  memset (&device, 0, sizeof (device)); 
  if ((device.sll_ifindex = if_nametoindex (interface)) == 0) { 
    perror ("if_nametoindex() failed to obtain interface index "); 
    exit (EXIT_FAILURE); 
    } 

  // Debug code
  //printf ("Index for interface %s is %i\n", interface, device.sll_ifindex); 
 

  // Fill out sockaddr_ll. 
  device.sll_family = AF_PACKET; 
  memcpy (device.sll_addr, src_mac, 6 * sizeof (uint8_t)); 
  device.sll_halen = 6; 
 
  // Submit request for a raw socket descriptor. 
  if ((sd = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) { 
    perror ("socket() failed "); 
    exit (EXIT_FAILURE); 
    }
  return;
  } 


/******************************************************  
 *  DNS AAAA resolver
 *
 */

int 
resolve_v6_name(char *name, char *address, struct in6_addr *a6) { 
  struct addrinfo hints, *res, *res0; 
  int error; 
  struct sockaddr_in6 *si6 ; 
 
  memset(&hints, 0, sizeof(hints)); 
  hints.ai_family = AF_INET6; 
  if (getaddrinfo(name,0, &hints, &res0)) { 
    return(0) ; 
  } 
  res = res0 ; 
  si6 = (struct sockaddr_in6*) res->ai_addr ; 
  if (address)
    inet_ntop(hints.ai_family,&(si6->sin6_addr),address,INET6_ADDRSTRLEN) ; 
  if (a6) 
    bcopy(&si6->sin6_addr,a6,sizeof a6) ;
  freeaddrinfo(res0); 
  return(1) ; 
} 
 
 
/***************************************************
 *  set up the parameters for the TCP IPv6 connection to the back
 *  end DNS server 
 **************************************************/

void
resolve_dns(char *server_name) {
  int status ;
  char address[112];
  
  if (strchr(server_name,':')) {
    if (!inet_pton(AF_INET6,server_name,&ip6_addr)) {
      status = errno;
      fprintf (stderr, "inet_pton() failed (%s).\nError message: %s",server_name, strerror (status));
      exit (EXIT_FAILURE);
      }
    }
  else if (!resolve_v6_name(server_name,0,&ip6_addr)) {
    fprintf (stderr, "dns-server-frag -d <dns-server> - unable to resolve dns server name %s\n",server_name) ;
    exit (EXIT_FAILURE);
    }
  inet_ntop(AF_INET6,&(ip6_addr),address,112) ; 
  if (debug) printf("Web server is at %s\n",address);
}


/***************************************************
 * tcp checksum
 * calculate the UDP checksum
 **************************************************/

uint16_t 
tcp_checksum (const void *buff, size_t len, size_t length, in6_addr_t *src_addr, in6_addr_t *dest_addr) 	
{
  const uint16_t *buf=buff;
  uint16_t *ip_src=(void *)src_addr, *ip_dst=(void *)dest_addr;
  uint32_t sum;
  int i  ;
 
  // Calculate the sum
  sum = 0;
  while (len > 1) {
    sum += *buf++;
    if (sum & 0x80000000)
      sum = (sum & 0xFFFF) + (sum >> 16);
    len -= 2;
    }
  if ( len & 1 )
    // Add the padding if the packet length is odd
    sum += *((uint8_t *)buf);
 
  // Add the pseudo-header
  for (i = 0 ; i <= 7 ; ++i) 
    sum += *(ip_src++);
 
  for (i = 0 ; i <= 7 ; ++i) 
    sum += *(ip_dst++);
 
  sum += htons(IPPROTO_TCP);
  sum += htons(length);
 
  // Add the carries
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);
 
  // Return the one's complement of sum
  return((uint16_t)(~sum));
}


void 
send_packet_to_http(const u_char *packet, struct binding *bdp) {
  char out_packet_buffer[8192] ;  
  struct ip6_hdr *iphdr ;
  struct ip6_hdr *o_iphdr ;
  struct tcphdr *tcp ;
  struct tcphdr *orig_tcp ;
  int len ;
  int i ;
  int bytes ;
        
  // IPv6 header 
  iphdr = (struct ip6_hdr *) &out_packet_buffer[0] ;  
  o_iphdr = (struct ip6_hdr *) (packet + ETH_HDRLEN) ;
  
  // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits) 
  iphdr->ip6_flow = o_iphdr->ip6_flow ;
  //  iphdr->ip6_flow = htonl ((6 << 28) | (0 << 20) | 0); 

  // payload length
  iphdr->ip6_plen = o_iphdr->ip6_plen ;
  len = ntohs(o_iphdr->ip6_plen) ;
  len -= 4 ;
 
  // Next header (8 bits): 6 for TCP
  iphdr->ip6_nxt = IPPROTO_TCP  ;

  // Hop limit (8 bits): default to maximum value 
  iphdr->ip6_hops = 255; 
  
  // src address
  bcopy(&local6_addr,&(iphdr->ip6_src), 16) ;  

  // dst address
  bcopy(&ip6_addr,&(iphdr->ip6_dst), 16);
  
  orig_tcp = (struct tcphdr *) (packet + ETH_HDRLEN + 40) ;

  tcp = (struct tcphdr *) &(out_packet_buffer[40]);
  tcp->th_dport =  orig_tcp->th_dport ;
  tcp->th_sport = htons(bdp->p->portno) ;

  // Copy original packet payload into outgoing packet buffer
  memcpy(&out_packet_buffer[44],&packet[ETH_HDRLEN + 44],len) ;
  len += 4 ;
  tcp->th_sum = 0 ;
  tcp->th_sum = tcp_checksum(tcp,len,len,&local6_addr,&ip6_addr) ;
  
  // Destination and Source MAC addresses 
  memcpy(ether_frame, dst_mac, 6 * sizeof (uint8_t)); 
  memcpy(ether_frame + 6, src_mac, 6 * sizeof (uint8_t)); 
 
  // Next is ethernet type code (ETH_P_IPV6 for IPv6). 
  // http://www.iana.org/assignments/ethernet-numbers 
  ether_frame[12] = ETH_P_IPV6 / 256;   
  ether_frame[13] = ETH_P_IPV6 % 256; 

  // Overwrite IPv6 header in original packet with data from above setup 
  // to reflect new source and destination
  memcpy(ether_frame + ETH_HDRLEN, &out_packet_buffer[0], len + 40); 

  // Send ethernet frame to socket. 
  frame_length = ETH_HDRLEN + 40 + len ;

  // Send ethernet frame to socket. 
  if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) { 
    perror ("sendto() failed"); 
    exit (EXIT_FAILURE); 
    } 
      
}

void 
send_packet_to_inet(const u_char *packet, struct binding *tp) {
  char out_packet_buffer[8192] ;  
  char *pptr ;
  struct ip6_hdr *iphdr ;
  struct ip6_hdr *e_iphdr ;
  struct ip6_hdr *o_iphdr ;
  struct tcphdr *tcp ;
  struct tcphdr *e_tcp ;
  struct tcphdr *orig_tcp ;
  struct ip6_frag *fhdr ;
  int tcp_hdr_len ;
  int tcp_seg_len ;
  uint32_t tcp_sequence ;
  int bytes ;
  int payload;
  int num_pkts = 0;
  int units;
  int datalen ;
  int frag_offset ;
  int v6_payload ;
  int len ;
  int this_frag ;
  unsigned int offset ;
  int remainder ;

        
  // out_packet_buffer is used to build the outgoing packet, except for the
  // ethernet headers
	
  // IPv6 header 
  iphdr = (struct ip6_hdr *) &out_packet_buffer[0] ;  
  o_iphdr = (struct ip6_hdr *) (packet + ETH_HDRLEN) ;
  
  // IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits) 
  iphdr->ip6_flow = o_iphdr->ip6_flow ;
 

  // payload length
  iphdr->ip6_plen = o_iphdr->ip6_plen ;
  len = ntohs(o_iphdr->ip6_plen) ;
  len -= 4 ;
 
  // Next header (8 bits): 6 for TCP
  iphdr->ip6_nxt = IPPROTO_TCP  ;

  // Hop limit (8 bits): default to maximum value 
  iphdr->ip6_hops = 255; 
  
  // src address
  bcopy(&local6_addr,&(iphdr->ip6_src), 16) ;  

  // dst address
  bcopy(&tp->ip6_src,&(iphdr->ip6_dst), 16);
  
  orig_tcp = (struct tcphdr *) (packet + ETH_HDRLEN + 40) ;
  tcp = (struct tcphdr *) &(out_packet_buffer[40]);
  tcp->th_dport =  htons(tp->sport) ;
  tcp->th_sport = orig_tcp->th_sport;
  /* copy payload bytes from the original packet to the payload buffer */
  memcpy(&out_packet_buffer[44],&packet[ETH_HDRLEN + 44],len) ;

  len += 4 ;
  tcp->th_sum = 0 ;
  tcp->th_sum = tcp_checksum(tcp,len,len,&(iphdr->ip6_src),&(iphdr->ip6_dst)) ;
  
  // Destination and Source MAC addresses 
  memcpy(ether_frame, dst_mac, 6 * sizeof (uint8_t)); 
  memcpy(ether_frame + 6, src_mac, 6 * sizeof (uint8_t)); 
 
  // Next is ethernet type code (ETH_P_IPV6 for IPv6). 
  // http://www.iana.org/assignments/ethernet-numbers 
  ether_frame[12] = ETH_P_IPV6 / 256;   
  ether_frame[13] = ETH_P_IPV6 % 256; 

  // Copy the IPv6 header into the ether_frame
  memcpy(ether_frame + ETH_HDRLEN, &out_packet_buffer[0], 40); 

  payload = ntohs(iphdr->ip6_plen) - (tcp->th_off * 4) ;
  pptr = &out_packet_buffer[40 + (tcp->th_off * 4)];
  tcp_hdr_len = tcp->th_off * 4 ;
  tcp_sequence = ntohl(tcp->th_seq) ;
	
  if (debug) printf("TCP header length, incl. options: %d\n", tcp_hdr_len);
  if (debug) printf("****PAYLOAD = %d bytes\n",payload) ;
	
  if (payload <= 16) {
    /* copy across the TCP header */      
    memcpy(ether_frame + ETH_HDRLEN + 40, &out_packet_buffer[40], tcp_hdr_len);
    /* copy across the payload */
    memcpy(ether_frame + ETH_HDRLEN + 40 + tcp_hdr_len, pptr, payload);
    /* IPv6 payload length */
    e_iphdr = (struct ip6_hdr *) (ether_frame + ETH_HDRLEN) ;  
    e_iphdr->ip6_plen = htons(tcp_hdr_len + payload);
    /* put in the adjusted sequence number and the new checksum */
    e_tcp = (struct tcphdr *) (ether_frame + ETH_HDRLEN + 40) ;
    e_tcp->th_seq = htonl(tcp_sequence) ;
    e_tcp->th_sum = 0 ;
    e_tcp->th_sum = tcp_checksum(e_tcp,tcp_hdr_len + payload,tcp_hdr_len + payload,&(e_iphdr->ip6_src),&(e_iphdr->ip6_dst)) ;
    /* ethernet frame length */
    frame_length = ETH_HDRLEN + 40 + tcp_hdr_len + payload ;

    // if (debug) {
    //   char saddress[112],daddress[112] ;
    //   inet_ntop(AF_INET6,&(e_iphdr->ip6_src),saddress,111) ;
    //   inet_ntop(AF_INET6,&(e_iphdr->ip6_dst),daddress,111) ;
    //   printf("send (unfragmented) %d bytes from %s:%d to %s:%d\n",len+40,saddress,ntohs(tcp->th_sport),daddress,ntohs(tcp->th_dport)) ;
    //   }

    if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) { 
      perror ("sendto() failed"); 
      exit (EXIT_FAILURE); 
      }
	  if (debug) printf("Short payload. Sendto %d bytes\n", bytes);
    return;
    }

  while (payload > 0) {
    if (payload < 1200) {
      tcp_seg_len = payload ;
      this_frag = ((payload / 8) - 1) * 8 ;
      }
    if (payload >= 1200) {
      tcp_seg_len = 1200 ;
      this_frag = 1200 - 256 ;
      }

    if (debug) printf("This frag:%d\n",this_frag);
		
    e_iphdr = (struct ip6_hdr *) (ether_frame + ETH_HDRLEN) ;  
    e_iphdr->ip6_plen = htons(8 + tcp_hdr_len + this_frag);
    e_iphdr->ip6_nxt = 44 ; // Fragmentation header
		
    /* now set up the frag header */
    fhdr = (struct ip6_frag *) &ether_frame[ETH_HDRLEN+40] ;
    fhdr->ip6f_nxt = IPPROTO_TCP ;
    fhdr->ip6f_reserved = 0 ;
    fhdr->ip6f_offlg = htons(1); // Offset is zero and Set more-fragments flag
    fhdr->ip6f_ident = rand() % 4294967296 ; 

    /* copy across the TCP header */      
    memcpy(ether_frame + ETH_HDRLEN + 40 + 8, &out_packet_buffer[40], tcp_hdr_len);

    /* copy across the entire payload (in order to generate the correct tcp checksum) */
    memcpy(ether_frame + ETH_HDRLEN + 40 + 8 + tcp_hdr_len, pptr, tcp_seg_len);

    /* put in the adjusted sequence number and the new checksum */
    e_tcp = (struct tcphdr *) (ether_frame + ETH_HDRLEN + 40 + 8) ;
    e_tcp->th_seq = htonl(tcp_sequence) ;
    e_tcp->th_sum = 0 ;
    e_tcp->th_sum = tcp_checksum(e_tcp,tcp_hdr_len + tcp_seg_len, tcp_hdr_len + tcp_seg_len,&(e_iphdr->ip6_src),&(e_iphdr->ip6_dst)) ;

    frame_length = ETH_HDRLEN + 40 + 8 + tcp_hdr_len + this_frag ;
    if (debug) {
      char saddress[112],daddress[112] ;
      inet_ntop(AF_INET6,&(e_iphdr->ip6_src),saddress,111) ; 
      inet_ntop(AF_INET6,&(e_iphdr->ip6_dst),daddress,111) ; 
      printf("send (FRAG 1 of 2) %d bytes from %s:%d to %s:%d\n",this_frag,saddress,ntohs(e_tcp->th_sport),daddress,ntohs(e_tcp->th_dport)) ;
      }

    if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) { 
      perror ("sendto() failed"); 
      exit (EXIT_FAILURE); 
      } 
    if (debug) printf("First frag. Sendto %d bytes\n", bytes);

    pptr += this_frag;
    offset = (this_frag + tcp_hdr_len) >> 3;
    remainder = tcp_seg_len - this_frag ;

    if (debug) printf("Frag 2 offset: %d, remainder: %d\n", offset, remainder);
    /* now adjust the frag header for the trailing frag */
    fhdr->ip6f_offlg = htons(offset << 3); // Offset
    this_frag = remainder ;
    e_iphdr->ip6_plen = htons(8 + this_frag);
    /* copy across the remainder of the payload immediately folloing the frag header */
    memcpy(ether_frame + ETH_HDRLEN + 40 + 8, pptr, this_frag);

		// int i;
		//     for (i = 0; i < remainder; i ++) {
		//         printf(" %02x", *(pptr +i));
		//     }
		//     putchar('\n');
		

    frame_length = ETH_HDRLEN + 40 + 8 + this_frag ;
    if (debug) {
      char saddress[112],daddress[112] ;
      inet_ntop(AF_INET6,&(e_iphdr->ip6_src),saddress,111) ; 
      inet_ntop(AF_INET6,&(e_iphdr->ip6_dst),daddress,111) ; 
      printf("send (FRAG 2 of 2) %d bytes from %s:%d to %s:%d\n",this_frag,saddress,ntohs(e_tcp->th_sport),daddress,ntohs(e_tcp->th_dport)) ;
      }

    if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) { 
      perror ("sendto() failed"); 
      exit (EXIT_FAILURE); 
      }
    if (debug) printf("Second frag. Sendto %d bytes\n", bytes);

    pptr += this_frag ;
    tcp_sequence += tcp_seg_len ;
    payload -= tcp_seg_len ;
    }
}


/*
 * libpcap packet dispatcher
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  struct ip6_hdr *ip;                  /* The IP header */
  struct tcphdr *tcp;                 /* The TCP header */
  uint16_t sport ;
  uint16_t dport ;
  struct ports *tmp ;
  struct binding *bdp ;
  struct binding bdg ;	
  char saddress[112],daddress[112], xaddress[112];
	
  /* Adjust etherframe payload when using interface "any" in Linux */
  // if (pcap_int_set && !strcmp("any", pcap_int)) {
  //   packet += 2;		
  //   }
	
  /* define IP header from Etherframe */
  ip = (struct ip6_hdr*)(packet + ETH_HDRLEN);
  // Next header (8 bits): 6 for TCP
  // I really should accept extension headers here, but that's left to later...!
  tcp = (struct tcphdr *) (packet + ETH_HDRLEN + 40) ;
  sport = ntohs(tcp->th_sport) ;
  dport = ntohs(tcp->th_dport) ;
  inet_ntop(AF_INET6,&(ip->ip6_src),saddress,111) ; 
  inet_ntop(AF_INET6,&(ip->ip6_dst),daddress,111) ; 
  if (debug) printf("\n\n======\n\n%s.%d -> %s.%d\n",saddress,sport,daddress,dport) ;
  if (ip->ip6_nxt != IPPROTO_TCP) {
    if (debug) printf("Not TCP\n");
    return ;
  }


  /* if the packet is FROM the back end web server then look up the
     <dst port> vector in a local table/
     If found then write in the new values, compute a new checksum and
     send it on as a raw packet */
  
  if (!v6cmp(&(ip6_addr),&(ip->ip6_src))) {
    if (dport < 1024) {
      if (debug) printf("Destination port %d < 1024 - DROPPED\n",dport);
      return ;
      }
    if (sport == 80) {
      if ((tmp = port_80_ptr[dport])) {
        if ((bdp = tmp->entry)) {
          if (head_80 != tmp) {
            if (tmp->nxt) tmp->nxt->prv = tmp->prv ;
            if (tmp->prv) tmp->prv->nxt = tmp->nxt ;
            if (tail_80 == tmp) tail_80 = tmp->prv ; 
            tmp->nxt = head_80 ;
            tmp->prv = 0 ;
            head_80->prv = tmp ;
            head_80 = tmp ;
            }
          tmp->entry->used = time(0) ; 
          if (debug) printf("    send from web to client\n") ;
          send_packet_to_inet(packet,bdp) ;
          }
        }
      else {
        if (debug) printf("COULD NOT FIND NAT binding for port 80 web response: port %d\n", dport) ;
        }
      }
    else if (sport == 443) {
	  if (debug) printf("got packet from web server\n") ; 
		
      if ((tmp = port_443_ptr[dport])) {
        if ((bdp = tmp->entry)) {
          if (head_443 != tmp) {
            if (tmp->nxt) tmp->nxt->prv = tmp->prv ;
            if (tmp->prv) tmp->prv->nxt = tmp->nxt ;
            if (tail_443 == tmp) tail_443 = tmp->prv ; 
            tmp->nxt = head_443 ;
            tmp->prv = 0 ;
            head_443->prv = tmp ;
            head_443 = tmp ;
            }
          tmp->entry->used = time(0) ; 
          if (debug) printf("    send from web to client\n") ;
          send_packet_to_inet(packet,bdp) ;
          }
        }
      else {
        if (debug) printf("COULD NOT FIND NAT binding for port 443 web response: port %d\n", dport) ;
        }
      }
    else {
      if (debug) printf("Unknown port web response: port %d\n",sport) ;
      }
    return ;
    }

    
  /* OTHERWISE assemble the <source-address,dst-address,src-port,dst-port> vector 
     and set up the translation, replacing the source address with the
     local address and the dest address as the dest address of the back end server
     write the table entry if it does not exist and pass the packet to the
     back end http server */

  if ((dport != 80) && (dport != 443)) return ;
  if (debug) printf("got packet from internet\n") ; 
  bcopy(&(ip->ip6_src), &(bdg.ip6_src),16) ; 
  bdg.sport = sport ;
  bdp = find_binding(&bdg,dport) ;  
  if (debug) {
    if (bdp) printf("FOUND binding for %s :%d (%d)\n",saddress,sport,dport);
    else printf("*NOT* FOUND binding for %s :%d (%d)\n",saddress,sport,dport);
    }

  if ((!bdp) && (tcp->th_flags & TH_SYN)) {
    /* at this point we need to create a new binding table entry */
    if (debug) printf("SYN - new binding\n") ;
    if (dport == 80) {
      port = next_port_80(&(ip->ip6_src),ntohs(tcp->th_sport)) ;
      bdp = port_80_ptr[port]->entry ;
      }
    else {
      port = next_port_443(&(ip->ip6_src),ntohs(tcp->th_sport)) ;
      bdp = port_443_ptr[port]->entry ;
      }
    if (debug) printf("CREATED new NAT binding for xtnl packet: %s %d ==> %d\n",saddress, sport,bdp->p->portno) ;
    }
    
  if (!bdp)
    return ;
          
  //  if (tcp->th_flags & TH_SYN) {
  //    if (tcp->th_seq == bdp->seq) { 
  //      if (debug) printf("RETRANSMIT - ignored -  seq = %u, binding table seq = %u\n",tcp->th_seq, bdp->seq) ;
  //      return ; 
  //      }
  //    }

  if (debug) printf("seq = %u, binding table seq = %u\n",tcp->th_seq, bdp->seq) ;
  bdp->seq = tcp->th_seq ;

  tmp = bdp->p ;
  if (dport == 80) {
    if (tmp != head_80) {
      if (tmp == tail_80) {
        tail_80 = tmp->prv ; 
        tail_80->nxt = 0 ;
        }
      else {
        if (tmp->nxt) tmp->nxt->prv = tmp->prv ;
        if (tmp->prv) tmp->prv->nxt = tmp->nxt ;
        }
      tmp->nxt = head_80 ;
      tmp->prv = 0 ;
      head_80->prv = tmp ;
      head_80 = tmp ;
      }
    }
  else {
    if (tmp != head_443) {
      if (tmp == tail_443) {
        tail_443 = tmp->prv ; 
        tail_443->nxt = 0 ;
        }
      else {
        if (tmp->nxt) tmp->nxt->prv = tmp->prv ;
        if (tmp->prv) tmp->prv->nxt = tmp->nxt ;
        }
      tmp->nxt = head_443 ;
      tmp->prv = 0 ;
      head_443->prv = tmp ;
      head_443 = tmp ;
      }
    }
  if (debug) printf("SENT %s :%d as %d to web server %d\n",saddress,sport,bdp->p->portno,dport) ;
  send_packet_to_http(packet,bdp)  ;
  bdp->used = time(0) ; 
  return;
  }



int 
main(int argc, char **argv) 
{
  /* read command parameters */
  /* set up TCP socket back end to actual server */
  /* set up a pcap session listening on the external port */
  /* loop - this has problems with parallelism */
  
  int ch ;
  char filter_exp[1024] ;                /* The filter expression */
  char errbuff[PCAP_ERRBUF_SIZE];        /* error buffer */
  struct bpf_program fp;	 	 /* The compiled filter expression */	   

  int status ;

  while (((ch = getopt(argc,argv, "i:p:d:s:h:l:x:"))) != -1) {
    switch(ch) {
      case 'i':
        // interface name of 'listen' address
        interface = strdup(optarg) ;
				interface_set = 1;
        break ;
				
	//			case 'p':
	//      pcap_int = strdup(optarg) ;
	//			pcap_int_set = 1;
	//			break;

      case 'l':
        // interface IPv6 address of 'listen' address
        host = strdup(optarg) ;

        break ;
        
      case 'd':
        // mac address of V6 gateway on listen address network
				if (sscanf(optarg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dst_mac[0], &dst_mac[1], &dst_mac[2], &dst_mac[3], &dst_mac[4], &dst_mac[5]) != 6) {
          fprintf(stderr,"%s not a MAC address\n",optarg) ;
          exit(1) ;
				}
				dst_mac_set = 1 ;
				break;
	
      case 's':
        // mac address of V6 gateway on listen address network
				if (sscanf(optarg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &src_mac[0], &src_mac[1], &src_mac[2], &src_mac[3], &src_mac[4], &src_mac[5]) != 6) {
          fprintf(stderr,"%s not a MAC address\n",optarg) ;
          exit(1) ;
	  		}
				src_mac_set = 1 ;
				break;

      case 'h':
        http_server = strdup(optarg) ;
        break ;

      case 'x':
        debug = strcmp(optarg,"0") ;
        break;

      default:
        fprintf(stderr, "http-server-frag  parameters\n  -i interface\n -p pcap_interface\n -l listen IPv6 address\n  -h http(s) server\n  -d mac address of the local gateway -x <debug>\n\ne.g. http-proxy -i eth0 -l 2a01:4f8:161:50ad::e:cd5a -h www.potaroo.net -x 0\n") ;
        exit (EXIT_FAILURE);
      }
    }
  //		if (interface_set && ! pcap_int_set) {
  //			pcap_int = strdup(interface);
  //		}

  argc -= optind;
  argv += optind;

  resolve_dns(http_server) ;
  
  srand((unsigned) time(&t));
  ether_frame = allocate_ustrmem (IP_MAXPACKET); 
  open_raw_socket() ;

  /* check we have a good listen address */
  if (!inet_pton(AF_INET6,host,&local6_addr)) {
    status = errno;
    fprintf (stderr, "inet_pton() failed (%s).\nError message: %s",host, strerror (status));
    exit (EXIT_FAILURE);
    }  
    
  /* the PCAP capture filter  - http and https v6 traffic only*/
  sprintf(filter_exp,"dst host %s and (port 80 or port 443) and tcp and ip6",host);

  /* open capture device */  
  if ((handle = pcap_open_live(interface, SNAP_LEN, 1, 1, errbuff)) == NULL)   {		 
    fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuff);
    exit(EXIT_FAILURE) ;
  }	 
	/* open send device */
  //if ((handle_out = pcap_open_live(interface, SNAP_LEN, 1, 1, errbuff)) == NULL)   {		 
  //  fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuff);
  //  exit(EXIT_FAILURE) ;
  //}	 

	if (debug) printf("Outgoing interface is %s\n", interface) ;
	//if (debug) printf("Open PCAP capture on %s\n", pcap_int) ;
	
  
  /* compile the filter expression */
  if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1) {		 
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE) ;
    }	 

  /* install the filter */
  if (pcap_setfilter(handle, &fp) == -1) {		 
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE) ;
    }

  /* set up the packet capture in an infinite loop */
  if (debug) printf("Enter PCAP packet capture loop\n") ;  
  pcap_loop(handle, -1, got_packet, NULL) ;

  /* And close the session (this code is not executed)*/
  pcap_close(handle);
  return(0);
}
