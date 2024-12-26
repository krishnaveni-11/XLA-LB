#include "xdp_lb_kern.h"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>

#define IP_ADDRESS(x) (unsigned int)(172 + (17 << 8) + (0 << 16) + (x << 24))

#define BACKEND_A 10
#define BACKEND_B 11
#define BACKEND_C 12
#define BACKEND_D 13
#define BACKEND_E 14
#define BACKEND_F 15
#define BACKEND_H 16
#define BACKEND_I 17
#define BACKEND_J 18
#define BACKEND_K 19
#define BACKEND_L 20
#define BACKEND_M 21
#define BACKEND_N 22

//#define BACKEND_C 2
#define CLIENT 6
#define LB 7
#define BACKEND_G 2

struct bpf_map_def SEC("maps") tcp_packet_count_map = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};

struct map_key {
    __u32 ip;
};

struct map_value {
    double score;
};

struct connection_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
};

// Define per-CPU hash maps
struct bpf_map_def SEC("maps") rxcnt = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(double),
    .max_entries = 1000,
};

struct bpf_map_def SEC("maps") rxcnt1 = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(double),
    .max_entries = 1000,
};


struct bpf_map_def SEC("maps") conn_tracking_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct connection_key),
    .value_size = sizeof(__u32),
    .max_entries =6000,  // Adjust size as needed
};

// Define a per-CPU hash map to count load-balanced requests
struct bpf_map_def SEC("maps") lb_count_map = {
    .type = BPF_MAP_TYPE_PERCPU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};

SEC("xdp_lb")
int xdp_load_balancer(struct xdp_md *ctx)
{
	    void *data = (void *)(long)ctx->data;
	    void *data_end = (void *)(long)ctx->data_end;
             __u64 *value = 0;
              __u32 key = 0;
	    // Check for IPv4 and TCP
	    struct ethhdr *eth = data;
	    if (data + sizeof(struct ethhdr) > data_end)
		return XDP_ABORTED;

	    if (bpf_htons(eth->h_proto) != ETH_P_IP)
		return XDP_PASS;

	    struct iphdr *iph = data + sizeof(struct ethhdr);
	    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
		return XDP_ABORTED;

	    if (iph->protocol != IPPROTO_TCP)
		return XDP_PASS;

	    struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
	    if ((void *)(tcph + 1) > data_end)
		return XDP_PASS;

	    // Create the connection key
	    struct connection_key conn_key = {
		.src_ip = iph->saddr,
		.dst_ip = iph->daddr,
		.src_port = tcph->source,
		.dst_port = tcph->dest,
	    };

         // Check if the connection is already tracked
           __u32 *server_index = bpf_map_lookup_elem(&conn_tracking_map, &conn_key);
    
              if (!server_index && iph->saddr == IP_ADDRESS(CLIENT)) {
                    // Connection is not tracked, select a random server
        
                  // Update the load balancer count for tracking the number of HTTP requests.
              __u32 lb_key = 0;
              __u64 *lb_value = bpf_map_lookup_elem(&lb_count_map, &lb_key);
               if (lb_value) {
			__sync_fetch_and_add(lb_value, 1);
	       } else {
		      __u64 initial_lb_value = 1;
		      bpf_map_update_elem(&lb_count_map, &lb_key, &initial_lb_value, BPF_ANY);
	       }

              /*

	       struct map_key keys[] = {
		    { .ip = 33558956 },    // IP: 2.0.17.172
		    { .ip = 50336172 },    // IP: 3.0.17.172
		    { .ip = 100667820 }    // IP: 6.0.17.172
	       };
	       */
	       	       struct map_key keys[] = {
		    { .ip = 167776684 },    // IP: 10.0.17.172
		    { .ip = 184553900 },    // IP: 11.0.17.172
		    { .ip = 201331116 },    // IP: 12.0.17.172
		    { .ip = 218108332 },    // IP: 13.0.17.172
		    { .ip = 234885548 },    // IP: 14.0.17.172
		    { .ip = 251662764 },    // IP: 15.0.17.172
		    { .ip = 268439980 },    // IP: 16.0.17.172
		    { .ip = 285217196 },    // IP: 17.0.17.172
		    { .ip = 301994412 },    // IP: 18.0.17.172
		    { .ip = 318771628 } ,   // IP: 19.0.17.172		        
		    { .ip = 335548844},   //  20.0.17.172 -> 335548844                       
                    {.ip = 352326060 }, //21.0.17.172 -> 352326060 
                    {.ip = 369103276 } ,// 22.0.17.172 -> 369103276
                    {.ip = 385880492}, //23.0.17.172 -> 385880492
                    {.ip = 402657708  }, //24.0.17.172 -> 402657708
                    {.ip = 419434924}    ,// 25.0.17.172 -> 419434924
                    {.ip = 436212140}  ,//26.0.17.172 -> 436212140
                    {.ip = 452989356 } ,// 27.0.17.172 -> 452989356
		    {.ip = 469766572}	,//28.0.17.172 -> 469766572
		    {.ip = 486543788 },//29.0.17.172 -> 486543788
                     {.ip = 503321004 }, //30.0.17.172 -> 503321004
		     {.ip = 520098220 }, //31.0.17.172 -> 520098220
                      {.ip = 536875436 },//32.0.17.172 -> 536875436
                       {.ip = 553652652 },//33.0.17.172 -> 553652652
                      {.ip =  570429868 }//34.0.17.172 -> 570429868
                     

		        
		    
	       };
               int i, valid_key_count = 0;
               struct map_value *percpu_values;
               __u32 valid_ips[sizeof(keys) / sizeof(keys[0])];
               __u32 selected_index = 0;
               __u32 selected_server_index = BACKEND_A;
               struct map_key selected_key = { .ip = 0 };
               
            // Iterate through the keys to find valid ones and count them.
          
		#pragma clang loop unroll(full)
		for (i = 0; i < (sizeof(keys) / sizeof(keys[0])); i++) {
		    struct map_value *percpu_values = bpf_map_lookup_elem(&rxcnt, &keys[i].ip);
		    if (percpu_values) {
		        // key exists in any CPU's map, store the valid IP and increment the count.
		        
		        valid_ips[valid_key_count] = keys[i].ip;
		        valid_key_count++;
		    }
		}

               if (valid_key_count > 0) {
                    // Generate a random selected server.
                  
		    selected_index = bpf_get_prandom_u32() % valid_key_count;
		    valid_key_count = 0;  // Reset to use it as an index counter
		    for (i = 0; i < (sizeof(keys) / sizeof(keys[0])); i++) {
		    percpu_values = bpf_map_lookup_elem(&rxcnt, &keys[i].ip);
		    if (percpu_values) {
		        if (valid_key_count == selected_index) {
		            selected_key = keys[i];
		            break;
		        }
		        valid_key_count++;
		     }
		   }

		bpf_printk("Randomly selected index: %d\n", selected_index);
		bpf_printk("Randomly selected IP: %u\n", selected_key.ip);
		//selected_key.ip = 167776684;
                selected_server_index = (selected_key.ip >> 24) & 0xFF;
        
                server_index = &selected_server_index;
               // Save the server index in the connection tracking map
                bpf_map_update_elem(&conn_tracking_map, &conn_key, &selected_server_index, BPF_ANY);
                bpf_printk("New connection tracked: server index %u\n", selected_server_index);
                
             }// close of  if (valid_key_count > 0)
      
    } // close of if (!server_index && iph->saddr == IP_ADDRESS(CLIENT)) 
    
    
      // change this condition later time . without explicit conditional operator.
      __u32 selected_server = (server_index) ? *server_index : 10;

      bpf_printk("Load balancing on %u server index:\n", selected_server);

    // Load balancing logic starts here...
    if (iph->saddr == IP_ADDRESS(CLIENT)) {
       iph->daddr = IP_ADDRESS(selected_server);
      //iph->daddr = IP_ADDRESS(10);
        //eth->h_dest[5] = selected_server;
        eth->h_dest[5] = BACKEND_G;
        iph->saddr = IP_ADDRESS(LB);
        eth->h_source[5] = LB;

        iph->check = iph_csum(iph);
        
        value = bpf_map_lookup_elem(&tcp_packet_count_map, &key);
        if (value) {
            __sync_fetch_and_add(value, 1);
            bpf_map_update_elem(&tcp_packet_count_map, &key, value, BPF_ANY);
        }
        
        return XDP_TX;
        
    } else if (tcph->source == bpf_htons(80)) {
        iph->daddr = IP_ADDRESS(CLIENT);
        eth->h_dest[5] = CLIENT;
        iph->saddr = IP_ADDRESS(LB);
        eth->h_source[5] = LB;

        iph->check = iph_csum(iph);
        return XDP_TX;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
