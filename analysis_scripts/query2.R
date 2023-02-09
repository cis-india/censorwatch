dnsprobe_unique_AS <- dnsprobe$distinct("ip_info.asn.asn")
dnsprobe_AS_number_name_map <- dnsprobe$aggregate('[{"$group":{"_id":"$ip_info.asn.asn", "AS_name": { "$first" : "$ip_info.asn.name" }}}]')

# For each ASN 
for (asn in dnsprobe_unique_AS) {
  # Query how many blocked measurements were found for DNS as well as the total number of measurements
  query_with_parameters <- paste('{ "result.test_result.censored": "True", "ip_info.asn.asn" :"', asn, '"}', sep = "")
  results <- dnsprobe$find(query_with_parameters)
  number_of_dns_blocks <- nrow(results)
  
  query_with_parameters <- paste('{ "ip_info.asn.asn" :"', asn, '"}', sep = "")
  results <- dnsprobe$find(query_with_parameters)
  total_dns_measurements <- nrow(results)
  
  # Repeat, for SNI
  query_with_parameters <- paste('{ "result.test_result.censored": "True", "ip_info.asn.asn" :"', asn, '"}', sep = "")
  results <- tlsprobe$find(query_with_parameters)
  number_of_tls_blocks <- nrow(results)
  
  query_with_parameters <- paste('{ "ip_info.asn.asn" :"', asn, '"}', sep = "")
  results <- tlsprobe$find(query_with_parameters)
  total_tls_measurements <- nrow(results)
  
  # Repeat, for HTTP
  query_with_parameters <- paste('{ "result.test_result.censored": "True", "ip_info.asn.asn" :"', asn, '"}', sep = "")
  results <- httpprobe$find(query_with_parameters)
  number_of_http_blocks <- nrow(results)
  
  query_with_parameters <- paste('{ "ip_info.asn.asn" :"', asn, '"}', sep = "")
  results <- httpprobe$find(query_with_parameters)
  total_http_measurements <- nrow(results)
  
  # map AS number to AS name
  AS_name <- dnsprobe_AS_number_name_map$AS_name[which(dnsprobe_AS_number_name_map$"_id" == asn)]
  
  # print findings
  cat("AS number: ", asn, " AS name: ", AS_name, " blocks ", number_of_dns_blocks, " using DNS. Total readings for this ASN: ", total_dns_measurements, "\n") 
  cat("AS number: ", asn, " AS name: ", AS_name, " blocks ", number_of_tls_blocks, " using SNI. Total readings for this ASN: ", total_tls_measurements, "\n") 
  cat("AS number: ", asn, " AS name: ", AS_name, " blocks ", number_of_http_blocks, " using HTTP. Total readings for this ASN: ", total_http_measurements, "\n") 

}  