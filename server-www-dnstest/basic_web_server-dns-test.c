/*********************************************
 * vim:sw=8:ts=8:si:et
 * To use the above modeline in vim you must have "set modeline" in your .vimrc
 * Author: Guido Socher
 * Copyright: GPL V2
 *
 * A very basic web server. 
 *
 * http://tuxgraphics.org/electronics/
 * Chip type           : Atmega88/168/328/644 with ENC28J60
 *********************************************/
#include <avr/io.h>
#include <stdlib.h>
#include <string.h>
#include "../ip_arp_udp_tcp.h"
#include "../enc28j60.h"
#include "../timeout.h"
#include "../dnslkup.h"

// please modify the following two lines. mac and ip have to be unique
// in your local area network. You can not have the same numbers in
// two devices:
// how did I get the mac addr? Translate the first 3 numbers into ascii is: TUX
static uint8_t mymac[6] = {0x54,0x55,0x58,0x10,0x00,0x29};
static uint8_t myip[4] = {10,0,0,29}; // aka http://10.0.0.29/
static uint8_t gwip[4]={10,0,0,2}; // your DSL router, GW to get into the internet

// server listen port for www
#define MYWWWPORT 80
// transaction number for resolution of the gw mac
#define TRANS_NUM_GWMAC 1
static uint8_t gwmac[6];
static uint8_t otherside_www_ip[4];
// global packet buffer
#define BUFFER_SIZE 550
static uint8_t buf[BUFFER_SIZE+1];
static int8_t dns_state=0;

uint16_t http200ok(void)
{
        return(fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nPragma: no-cache\r\n\r\n")));
}

// prepare the webpage by writing the data to the tcp send buffer
uint16_t print_webpage(uint8_t *buf)
{
        uint16_t pl;
        pl=http200ok();
        pl=fill_tcp_data_p(buf,pl,PSTR("<h2>DNS lookup test</h2><pre>\n"));
        pl=fill_tcp_data_p(buf,pl,PSTR("domain name to lookup: <input type=text name=dn>\n"));
        pl=fill_tcp_data_p(buf,pl,PSTR("<input type=submit></form>\n"));
        pl=fill_tcp_data_p(buf,pl,PSTR("</pre>\n"));
        return(pl);
}

// the __attribute__((unused)) is a gcc compiler directive to avoid warnings about unsed variables.
void arpresolver_result_callback(uint8_t *ip __attribute__((unused)),uint8_t reference_number,uint8_t *mac){
        uint8_t i=0;
        if (reference_number==TRANS_NUM_GWMAC){
                // copy mac address over:
                while(i<6){gwmac[i]=mac[i];i++;}
        }
}

int main(void){
        uint16_t dat_p;
        
        // set the clock speed to 8MHz
        // set the clock prescaler. First write CLKPCE to enable setting of clock the
        // next four instructions.
        CLKPR=(1<<CLKPCE);
        CLKPR=0; // 8 MHZ
        _delay_loop_1(0); // 60us
        
        //initialize the hardware driver for the enc28j60
        enc28j60Init(mymac);
        enc28j60clkout(2); // change clkout from 6.25MHz to 12.5MHz
        _delay_loop_1(0); // 60us
        enc28j60PhyWrite(PHLCON,0x476);

        // find the mac address of the gateway (e.g your dsl router).
        get_mac_with_arp(gwip,TRANS_NUM_GWMAC,&arpresolver_result_callback);
        while(get_mac_with_arp_wait()){
                // to process the ARP reply we must call the packetloop
                dat_p=enc28j60PacketReceive(BUFFER_SIZE, buf);
                packetloop_arp_icmp_tcp(buf,dat_p);
        }
        
        //init the ethernet/ip layer:
        init_udp_or_www_server(mymac,myip);
        www_server_port(MYWWWPORT);

        while(1){
                // read packet, handle ping and wait for a tcp packet:
                dat_p=packetloop_arp_icmp_tcp(buf,enc28j60PacketReceive(BUFFER_SIZE, buf));

                // dat_p will be unequal to zero if there is a valid  http get
                if(dat_p==0){
                        // no http request
                        /*
                        if (dns_state==0){
                                if (!enc28j60linkup()) continue; // only for dnslkup_request we have to check if the link is up. 
                                gsec=0;
                                dns_state=1;
                                dnslkup_request(buf,WEBSERVER_VHOST,gwmac);
                                LEDON;
                                continue;
                        }
                        if (dns_state==1 && dnslkup_haveanswer()){
                                dns_state=2;
                                dnslkup_get_ip(otherside_www_ip);
                                LEDOFF;
                        }
                        */
                        continue;
                }
                // tcp port 80 begin
                if (strncmp("GET ",(char *)&(buf[dat_p]),4)!=0){
                        // head, post and other methods:
                        dat_p=http200ok();
                        dat_p=fill_tcp_data_p(buf,dat_p,PSTR("<h1>200 OK</h1>"));
                        goto SENDTCP;
                }
                // just one web page in the "root directory" of the web server
                if (strncmp("/ ",(char *)&(buf[dat_p+4]),2)==0){
                        dat_p=print_webpage(buf);
                        goto SENDTCP;
                }else if (strncmp("/i ",(char *)&(buf[dat_p+4]),2)==0){
                        dat_p=print_webpage(buf);
                        goto SENDTCP;
                }else{
                        dat_p=fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 401 Unauthorized\r\nContent-Type: text/html\r\n\r\n<h1>401 Unauthorized</h1>"));
                        goto SENDTCP;
                }
SENDTCP:
                www_server_reply(buf,dat_p); // send web page data
                // tcp port 80 end
        }
        return (0);
}
