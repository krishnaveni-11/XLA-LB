#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <math.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <arpa/inet.h>
#include <net/if.h>  
#include <bpf/bpf.h>
#include <float.h>
#include<pthread.h>
#define IF_NAME "enp1s0"
#define NUM_SERVERS 25
pthread_mutex_t map_mutex = PTHREAD_MUTEX_INITIALIZER;

// Define the eBPF map key and value structures
struct map_key {
    __u32 ip;
};

struct map_value {
    double score;
};

typedef struct {
    int map_fd;
    int map_fd1;
    int map_fd2;
    int thread_index;
} thread_args_t;



// Callback function for handling the response data from the HTTP request
static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t total_size = size * nmemb;
    strncat((char *)userp, (char *)contents, total_size);
    return total_size;
}


// Function to parse the latency and request count  from the JSON response
double parse_metric(const char *response) {
    struct json_object *parsed_json;
    struct json_object *latency_obj;
    struct json_object *request_count_obj;
    double latency = 0;
    double request_count = 0;
    double score = 0;

    // Parse the JSON response
    parsed_json = json_tokener_parse(response);
    if (json_object_object_get_ex(parsed_json, "ewa_latency", &latency_obj) &&
        json_object_object_get_ex(parsed_json, "ewa_request_count", &request_count_obj)) {
        // Extract latency and request count
        latency = atof(json_object_get_string(latency_obj));
        request_count = atof(json_object_get_string(request_count_obj));
        printf("\nThe extracted latency and request count : %f ::: %f", latency,request_count);

         
       score = request_count * latency;
      // score = request_count ;
     // score =  latency;
    }
    json_object_put(parsed_json);  // Free the parsed JSON object
    
    
    printf("\nThe computed server load: %f\n", score);
    
    return score;
}


// Function to update per-CPU map values

void update_percpu_map(int map_fd, __u32 *key, double value) {
    int ncpus = libbpf_num_possible_cpus();
    struct map_value percpu_values[ncpus];

    // Update the value for each CPU
    for (int i = 0; i < ncpus; i++) {
        percpu_values[i].score = value;
    }

    if (bpf_map_update_elem(map_fd, key, percpu_values, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update per-CPU eBPF map: %s\n", strerror(errno));
    }
}


void update_percpu_map_if_exists(int map_fd, __u32 *key, double value) {
    int ncpus = libbpf_num_possible_cpus();
    struct map_value percpu_values[ncpus];

    // Check if the key exists in the map
    if (bpf_map_lookup_elem(map_fd, key, percpu_values) != 0) {
        // Key does not exist, so return without updating
        fprintf(stderr, "Key %u does not exist in the per-CPU map\n", *key);
        return;
    }

    // Update the value for each CPU
    for (int i = 0; i < ncpus; i++) {
        percpu_values[i].score = value;
    }

    // Update the per-CPU map with new values
    if (bpf_map_update_elem(map_fd, key, percpu_values, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update per-CPU eBPF map: %s\n", strerror(errno));
    }
}

// Function to aggregate per-CPU values

double aggregate_percpu_map_values(int map_fd, __u32 *key) {
    int ncpus = libbpf_num_possible_cpus();
    struct map_value percpu_values[ncpus];
    double total_score = 0;

    if (bpf_map_lookup_elem(map_fd, key, percpu_values) != 0) {
        fprintf(stderr, "Failed to lookup per-CPU eBPF map: %s\n", strerror(errno));
        return -1;
    }

    // Aggregate values from all CPUs
    for (int i = 0; i < ncpus; i++) {
        total_score += percpu_values[i].score;
    }

    // Return the average score across CPUs
    return total_score/ ncpus;
}



void perform_http_request_and_store_server_load(const char *url, int map_fd, int map_fd1, const char *ip_str) {
    CURL *curl;
    CURLcode res;
    char response[1024] = {0};
    struct map_key key;
    double score=0;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        } else {
            score = parse_metric(response);
            inet_pton(AF_INET, ip_str, &key.ip);

            // Update per-CPU maps
            update_percpu_map_if_exists(map_fd, &key.ip, score);// check later whether updation is performing in the correct way.
            update_percpu_map(map_fd1, &key.ip, score);
        }

        curl_easy_cleanup(curl);
    }
}



// replica selection method : 

void manage_servers_based_on_score(int map_fd1, int map_fd) {
    printf("\n Replica selection method called: \n");

    struct map_key key = {0};
    struct map_value percpu_values[libbpf_num_possible_cpus()];
    struct map_value min_value = {0};
    __u32 min_ip = 0;
    double min_score = DBL_MAX;
    double average_score;
    int ncpus = libbpf_num_possible_cpus();
    double sum =0; // for calculating average
    double scores[1000]; 
    int cnt_servers =0;
    
    // Step 1: Find the server with minimum average score in rxcnt1
    while (bpf_map_get_next_key(map_fd1, &key, &key) == 0) {
        if (bpf_map_lookup_elem(map_fd1, &key, percpu_values) == 0) {
            cnt_servers = cnt_servers +1;
            double total_score = 0;

            // Aggregate values from all CPUs
            for (int i = 0; i < ncpus; i++) {
                total_score += percpu_values[i].score;
            }

            // Calculate average score
            scores[cnt_servers] = total_score / ncpus;
           // average_score = total_score / ncpus;
            cnt_servers++;
            if (average_score < min_score) {
                min_score = average_score;
                min_ip = key.ip;
                min_value.score = average_score;
            }
        }
    }
    if (cnt_servers == 0) {
        printf("No servers found in rxcnt1 map.\n");
        return;
    }

    // Step 2: Compute median threshold
    int cmpfunc(const void *a, const void *b) {
        return (*(double*)a > *(double*)b) - (*(double*)a < *(double*)b);
    }
    qsort(scores, cnt_servers, sizeof(double), cmpfunc);

    double median_threshold;
    if (cnt_servers % 2 == 0) {
        median_threshold = (scores[cnt_servers / 2 - 1] + scores[cnt_servers / 2]) / 2.0;
    } else {
        median_threshold = scores[cnt_servers / 2];
    }

    printf("\n +++ The Median threshold %f", median_threshold);

    // Step 2: Add servers from rxcnt1 to rxcnt if their score difference is less than the joining threshold
    key.ip = 0; // Reset key for iteration
    while (bpf_map_get_next_key(map_fd1, &key, &key) == 0) {
    
            // Aggregate values for the server in rxcnt1
        if (bpf_map_lookup_elem(map_fd1, &key, percpu_values) == 0) {
            double total_score = 0;

            // Aggregate values from all CPUs
            for (int i = 0; i < ncpus; i++) {
                total_score += percpu_values[i].score;
            }

            // Calculate average score
            average_score = total_score / ncpus;

            
            
           // if (fabs(average_score - min_value.score) < joining_threshold){              //  printf("\n+++++++Servers +++++++++++");                // Add or update the server in rxcnt map
           if (average_score < median_threshold){ 
                if (bpf_map_update_elem(map_fd, &key.ip, &average_score, BPF_ANY) != 0) {
                    fprintf(stderr, "Failed to add server with IP %u to rxcnt map\n", key.ip);
                } else {
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &key.ip, ip_str, INET_ADDRSTRLEN);
                    printf("\n ****Added/Updated server in rxcnt MAP: %s (score: %f)\n", ip_str, average_score);
                   // printf("\n +++ The Average threshold %f",new_average);
                }
            }
        }
    
    }

    // Step 3: Remove servers from rxcnt if their score difference exceeds the leaving threshold
    key.ip = 0; // Reset key for iteration
    while (bpf_map_get_next_key(map_fd, &key, &key) == 0) {
        
            // Aggregate values for the server in rxcnt1
            if (bpf_map_lookup_elem(map_fd1, &key, percpu_values) == 0) {
                double total_score = 0;

                // Aggregate values from all CPUs
                for (int i = 0; i < ncpus; i++) {
                    total_score += percpu_values[i].score;
                }

                // Calculate average score
                average_score = total_score / ncpus;

              // if (fabs(average_score - min_value.score) > leaving_threshold) {
               if (average_score  > median_threshold) {
                    // Remove the server from rxcnt map
                    if (bpf_map_delete_elem(map_fd, &key.ip) != 0) {
                        fprintf(stderr, "Failed to remove server with IP %u from rxcnt map\n", key.ip);
                    } else {
                        char ip_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &key.ip, ip_str, INET_ADDRSTRLEN);
                        printf("Removed server from rxcnt: %s (score: %f)\n", ip_str, average_score);
                    }
                }
            }
        
    }
}





// Function to randomly select a pair of servers.

void select_random_servers(char *servers[], char *server_ips[], int num_servers, int *index1, int *index2,int *index3,int *index4) {
    srand(time(NULL) + pthread_self());  // Seed with current time + thread ID for randomness

    *index1 = rand() % num_servers;
    do {
        *index2 = rand() % num_servers;
    } while (*index1 == *index2);  // Ensure the second index is different from the first
  
     do {
        *index3 = rand() % num_servers;
    } while (*index3 == *index1 || *index3 == *index2);  // Ensure the third index is different from the first two
   
    
    do {
        *index4 = rand() % num_servers;
    } while (*index4 == *index1 || *index4 == *index2 || *index4 == *index3);  // Ensure the third index is different from the first two
       /*
     do {
        *index5 = rand() % num_servers;
    } while (*index5 == *index1 || *index5 == *index2 || *index5 == *index3 || *index5 == *index4);  // Ensure the third index is different from the first two
   
     do {
        *index6 = rand() % num_servers;
    } while (*index6 == *index1 || *index6 == *index2 || *index6 == *index3 || *index6 == *index4||*index6 == *index5);  // Ensure the third index is different from the first two
    
    */
}


// Function to keep track of requests count.

__u64 print_request_counts(int map_fd) {
    __u32 key = 0;
    __u64 *per_cpu_values;
    int num_cpus = libbpf_num_possible_cpus();
    __u64 total_requests = 0;
    static __u64 prev_total_requests = 0;

    // Allocate memory for per-CPU values
    per_cpu_values = calloc(num_cpus, sizeof(__u64));
    if (!per_cpu_values) {
        fprintf(stderr, "Memory allocation failed\n");
        return 0;
    }

    // Lookup the per-CPU values
    if (bpf_map_lookup_elem(map_fd, &key, per_cpu_values) < 0) {
        fprintf(stderr, "Failed to lookup map element\n");
        free(per_cpu_values);
        return 0;
    }

    // Aggregate the request counts across all CPUs
    for (int cpu = 0; cpu < num_cpus; cpu++) {
        total_requests += per_cpu_values[cpu];
    }

    // Calculate the number of requests in the last second
    __u64 requests_per_second = total_requests - prev_total_requests;
    
    printf("\n ****Total requests %u : request per second %u",total_requests,requests_per_second);
    prev_total_requests = total_requests;

    // Free allocated memory
    free(per_cpu_values);
    
    return  requests_per_second;
}




void initialize_rxcnt_map(int map_fd) {


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
    struct map_value initial_value = { .score = 0.0 };
    
    int num_keys = sizeof(keys) / sizeof(keys[0]);

    for (int i = 0; i < num_keys; i++) {
        int err = bpf_map_update_elem(map_fd, &keys[i].ip, &initial_value, BPF_ANY);
        if (err) {
            fprintf(stderr, "Failed to update rxcnt map for IP %u: %d\n", keys[i].ip, err);
        } else {
            printf("Initialized IP %u in rxcnt map with score \n", keys[i].ip);
        }
    }
}

__u64 print_packets_counts(int map_fd) {
    __u32 key = 0;
    __u64 *per_cpu_values;
    int num_cpus = libbpf_num_possible_cpus();
    __u64 total_requests = 0;
    static __u64 prev_total_requests = 0;

    // Allocate memory for per-CPU values
    per_cpu_values = calloc(num_cpus, sizeof(__u64));
    if (!per_cpu_values) {
        fprintf(stderr, "Memory allocation failed\n");
        return 0;
    }

    // Lookup the per-CPU values
    if (bpf_map_lookup_elem(map_fd, &key, per_cpu_values) < 0) {
        fprintf(stderr, "Failed to lookup map element\n");
        free(per_cpu_values);
        return 0;
    }

    // Aggregate the request counts across all CPUs
    for (int cpu = 0; cpu < num_cpus; cpu++) {
        total_requests += per_cpu_values[cpu];
    }

    // Calculate the number of requests in the last second
    __u64 requests_per_second = total_requests - prev_total_requests;
    
    printf("\n Total packets %u : packets per second %u",total_requests,requests_per_second);
    prev_total_requests = total_requests;

    // Free allocated memory
    free(per_cpu_values);
    
    return  requests_per_second;
}

// Thread function
void* handle_probing(void* args) {
    thread_args_t* targs = (thread_args_t*)args;

    double joining_threshold = 35; // Set the joining threshold
    double leaving_threshold = 45; // Set the leaving threshold

    char *servers[] = {
        "http://172.17.0.10:8081/latency",
        "http://172.17.0.11:8081/latency",
        "http://172.17.0.12:8081/latency",
        "http://172.17.0.13:8081/latency",
        "http://172.17.0.14:8081/latency",
        "http://172.17.0.15:8081/latency",
        "http://172.17.0.16:8081/latency",
        "http://172.17.0.17:8081/latency",
        "http://172.17.0.18:8081/latency",
        "http://172.17.0.19:8081/latency",
         "http://172.17.0.20:8081/latency",
         "http://172.17.0.21:8081/latency",
          "http://172.17.0.22:8081/latency",
         "http://172.17.0.23:8081/latency",
         "http://172.17.0.24:8081/latency",
         "http://172.17.0.25:8081/latency",
         "http://172.17.0.26:8081/latency",
          "http://172.17.0.27:8081/latency",
          "http://172.17.0.28:8081/latency",
          "http://172.17.0.29:8081/latency",
           "http://172.17.0.30:8081/latency",
           "http://172.17.0.31:8081/latency",
           "http://172.17.0.32:8081/latency",
           "http://172.17.0.33:8081/latency",
           "http://172.17.0.34:8081/latency",
       
    };

    char *server_ips[] = {
        "172.17.0.10",
        "172.17.0.11",
        "172.17.0.12",
        "172.17.0.13",
        "172.17.0.14",
        "172.17.0.15",
        "172.17.0.16",
        "172.17.0.17",
        "172.17.0.18",
        "172.17.0.19",
         "172.17.0.20",
         "172.17.0.21",
         "172.17.0.22",
         "172.17.0.23",
         "172.17.0.24",
         "172.17.0.25",
         "172.17.0.26",
         "172.17.0.27",
         "172.17.0.28",
         "172.17.0.29",
         "172.17.0.30",
         "172.17.0.31",
         "172.17.0.32",
         "172.17.0.33",
         "172.17.0.34",
         
       
    };

    int num_servers = NUM_SERVERS;
    
    // Cyclic selection based on thread_index
    
    int index1, index2,index3,index4,index5,index6;

    select_random_servers(servers, server_ips, num_servers, &index1, &index2,&index3,&index4);

    printf("\nThread ID: %lu\n", pthread_self());
    printf("Probes are sent to the following servers:\n");
    printf("Server 1: %s, IP: %s\n", servers[index1], server_ips[index1]);
    printf("Server 2: %s, IP: %s\n", servers[index2], server_ips[index2]);
    printf("Server 3: %s, IP: %s\n", servers[index3], server_ips[index3]);
    printf("Server 4: %s, IP: %s\n", servers[index4], server_ips[index4]);
     printf("Server 5: %s, IP: %s\n", servers[index5], server_ips[index5]);
     //   printf("Server 3: %s, IP: %s\n", servers[index6], server_ips[index6]);

    pthread_mutex_lock(&map_mutex);

    perform_http_request_and_store_server_load(servers[index1], targs->map_fd, targs->map_fd1, server_ips[index1]);
    perform_http_request_and_store_server_load(servers[index2], targs->map_fd, targs->map_fd1, server_ips[index2]);
  perform_http_request_and_store_server_load(servers[index3], targs->map_fd, targs->map_fd1, server_ips[index3]);
    perform_http_request_and_store_server_load(servers[index4], targs->map_fd, targs->map_fd1, server_ips[index4]);
     //   perform_http_request_and_store_server_load(servers[index5], targs->map_fd, targs->map_fd1, server_ips[index5]);
       //    perform_http_request_and_store_server_load(servers[index6], targs->map_fd, targs->map_fd1, server_ips[index6]);




    //find_and_store_min_score_server(targs->map_fd1, targs->map_fd);
    manage_servers_based_on_score(targs->map_fd1, targs->map_fd);

    pthread_mutex_unlock(&map_mutex);

    free(targs);  // Free the allocated memory for targs
    pthread_exit(NULL);
}



// Main Function : 

int main() {
    struct bpf_object *obj;
    int ifindex, err;
    int map_fd,map_fd1,map_fd2,map_fd3,map_fd4;

    // Initialize libcurl, for performing curl probe request.
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Load BPF object file
    obj = bpf_object__open_file("xdp.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object file: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    // Load BPF program
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object file: %s\n", strerror(-err));
        goto cleanup;
    }

    // Get the file descriptor of the XDP program
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_load_balancer");
    if (!prog) {
        fprintf(stderr, "Failed to find XDP program 'xdp_load_balancer' in BPF object\n");

        // Print all program names in the BPF object for debugging
        struct bpf_program *tmp_prog;
        bpf_object__for_each_program(tmp_prog, obj) {
            fprintf(stderr, "Program name: %s\n", bpf_program__name(tmp_prog));
        }
        goto cleanup;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "rxcnt");
    map_fd1 = bpf_object__find_map_fd_by_name(obj, "rxcnt1");
    map_fd2 = bpf_object__find_map_fd_by_name(obj, "lb_count_map");
    map_fd3 = bpf_object__find_map_fd_by_name(obj, "conn_tracking_map");
     map_fd4 = bpf_object__find_map_fd_by_name(obj, "tcp_packet_count_map");
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: finding a map in obj file failed\n");
        goto cleanup;
    }
    if (map_fd1 < 0) {
        fprintf(stderr, "ERROR: finding a map in obj file failed\n");
        goto cleanup;
    }
        if (map_fd2 < 0) {
        fprintf(stderr, "ERROR: finding a map in obj file failed\n");
        goto cleanup;
    }
    if (map_fd3 < 0) {
        fprintf(stderr, "ERROR: finding a map in obj file failed\n");
        goto cleanup;
    }
    if (map_fd4 < 0) {
        fprintf(stderr, "ERROR: finding a map in obj file failed\n");
        goto cleanup;
    }
    printf("Found map FD: %d\n", map_fd);
    printf("Found map FD: %d\n", map_fd1);
    printf("Found map FD: %d\n", map_fd2);
    int prog_fd = bpf_program__fd(prog);

    // Get the index of the network interface
    ifindex = if_nametoindex(IF_NAME);
    if (!ifindex) {
        fprintf(stderr, "Failed to get interface index for %s: %s\n", IF_NAME, strerror(errno));
        goto cleanup;
    }

    // Attach the XDP program to the network interface
    err = bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST);
    if (err) {
        fprintf(stderr, "Failed to attach XDP program to interface %s: %s\n", IF_NAME, strerror(-err));
        goto cleanup;
    }

    printf("XDP program successfully attached to interface %s\n", IF_NAME);
    initialize_rxcnt_map(map_fd);
    // Open a file to log packets per second
    FILE *log_file = fopen("packets_per_second.log", "w");
    if (!log_file) {
        fprintf(stderr, "Failed to open log file: %s\n", strerror(errno));
        goto cleanup;
    }
    
    
    // Main Logic starts here ...................
      
    
     
  
   int cnt =0;
   __u64 requests_per_second =0;
    __u64 packets_per_second =0;
while (1) {
   requests_per_second = print_request_counts(map_fd2); // lb_count_map:tracking HTTP requests 
   packets_per_second = print_packets_counts(map_fd4); // lb_count_map:tracking HTTP requests 
    if ( packets_per_second > 0) {
	   fprintf(log_file, "Packets per second: %llu\n", packets_per_second);
	   fflush(log_file); // Ensure data is written to the file
   }
   if (requests_per_second > 0) {
        pthread_t probing_threads[requests_per_second];

        for (int i = 0; i < requests_per_second; i++) {
            // Allocate memory for thread_args_t and initialize it
            thread_args_t* targs = malloc(sizeof(thread_args_t));
            targs->map_fd = map_fd;
            targs->map_fd1 = map_fd1;
            targs->map_fd2 = map_fd2;

            // Create a thread to execute the probing logic
            if (pthread_create(&probing_threads[i], NULL, handle_probing, targs) == 0) {
                printf("\n In Main Thread %d started\n", i);
            } else {
                printf("Failed to create thread %d\n", i);
                free(targs); // Free memory if thread creation fails
            }
        }
    }

    sleep(1); // Sleep for 1 second before the next loop iteration
}

  
  
  
 cleanup:
    bpf_object__close(obj);
    // Cleanup libcurl
    curl_global_cleanup();
    return err ? EXIT_FAILURE : EXIT_SUCCESS;
    
}// close of int main()
