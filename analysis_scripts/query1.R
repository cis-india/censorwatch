dnsprobe_unique_AS <- dnsprobe$distinct("ip_info.asn.asn")
dnsprobe_unique_region <- dnsprobe$distinct("state")
dnsprobe_AS_number_name_map <- dnsprobe$aggregate('[{"$group":{"_id":"$ip_info.asn.asn", "AS_name": { "$first" : "$ip_info.asn.name" }}}]')

# For each AS number
for (asn in dnsprobe_unique_AS) {
  # For each region
  for (region in dnsprobe_unique_region) {
    # query distinct sites blocked for this asn in this region
    query_with_parameters <- paste('{ "result.test_result.censored": "True", "ip_info.asn.asn" :"', asn, '", "state":"', region, '"}', sep = "")
    results <- dnsprobe$distinct("hostname", query_with_parameters)
    
    # if nothing is blocked, move on
    if (length(results) == 0) {
      next
    }
    
    # map AS number to AS name
    AS_name <- dnsprobe_AS_number_name_map$AS_name[which(dnsprobe_AS_number_name_map$"_id" == asn)]
    
    # print findings
    cat("AS number: ", asn, " AS name: ", AS_name, " blocks ", length(results), " websites in region: ", region, " using DNS\n") 
  }
} 




tlsprobe_unique_AS <- tlsprobe$distinct("ip_info.asn.asn")
tlsprobe_unique_region <- tlsprobe$distinct("state")
tlsprobe_AS_number_name_map <- tlsprobe$aggregate('[{"$group":{"_id":"$ip_info.asn.asn", "AS_name": { "$first" : "$ip_info.asn.name" }}}]')

# For each AS number
for (asn in tlsprobe_unique_AS) {
  # For each region
  for (region in tlsprobe_unique_region) {
    # query distinct sites blocked for this asn in this region
    query_with_parameters <- paste('{ "result.test_result.censored": "True", "ip_info.asn.asn" :"', asn, '", "state":"', region, '"}', sep = "")
    results <- tlsprobe$distinct("sniHostname", query_with_parameters)
    
    # if nothing is blocked, move on
    if (length(results) == 0) {
      next
    }
    
    # map AS number to AS name
    AS_name <- tlsprobe_AS_number_name_map$AS_name[which(tlsprobe_AS_number_name_map$"_id" == asn)]
    
    # print findings
    cat("AS number: ", asn, " AS name: ", AS_name, " blocks ", length(results), " websites in region: ", region, " using SNI\n") 
  }
} 


httpprobe_unique_AS <- httpprobe$distinct("ip_info.asn.asn")
httpprobe_unique_region <- httpprobe$distinct("state")
httpprobe_AS_number_name_map <- httpprobe$aggregate('[{"$group":{"_id":"$ip_info.asn.asn", "AS_name": { "$first" : "$ip_info.asn.name" }}}]')

# For each AS number
for (asn in httpprobe_unique_AS) {
  # For each region
  for (region in httpprobe_unique_region) {
    # query distinct sites blocked for this asn in this region
    query_with_parameters <- paste('{ "result.test_result.censored": "True", "ip_info.asn.asn" :"', asn, '", "state":"', region, '"}', sep = "")
    results <- httpprobe$distinct("hostname", query_with_parameters)
    
    # if nothing is blocked, move on
    if (length(results) == 0) {
      next
    }
    
    # map AS number to AS name
    AS_name <- httpprobe_AS_number_name_map$AS_name[which(httpprobe_AS_number_name_map$"_id" == asn)]
    
    # print findings
    cat("AS number: ", asn, " AS name: ", AS_name, " blocks ", length(results), " websites in region: ", region, " using HTTP\n") 
  }
} 