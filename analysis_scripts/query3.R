dnsprobe_unique_AS <- dnsprobe$distinct("ip_info.asn.asn")
dnsprobe_unique_company_name <- dnsprobe$distinct("ip_info.company.name")

dnsprobe_AS_name_company_name_map <- dnsprobe$aggregate('[{"$group":{"_id":"$ip_info.company.name", "asn_name": { "$first" : "$ip_info.asn.name" }, "region": { "$first" : "$ip_info.region" }}}]')


thing <- dnsprobe$aggregate('[{"$group":{"_id":"$userRecord", "company_name": { "$first" : "$ip_info.company.name" }, "asn_number": {"$first" : "$ip_info.asn.asn"}, "asn_name": { "$first" : "$ip_info.asn.name" }, "region": { "$first" : "$state" }, "measurements": { "$sum": 1 }, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')



thing2 <- dnsprobe$aggregate('[{"$group":{"_id": {"host":"$hostname", "asn_number": "$ip_info.asn.asn"}, "company_name": { "$first" : "$ip_info.company.name" }, "asn_number": {"$first" : "$ip_info.asn.asn"}, "asn_name": { "$first" : "$ip_info.asn.name" }, "region": { "$first" : "$ip_info.region" }, "measurements": { "$sum": 1 }, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')


thing3 <- dnsprobe$aggregate('[{"$group":{"_id": "$hostname", "company_name": { "$first" : "$ip_info.company.name" }, "asn_number": {"$first" : "$ip_info.asn.asn"}, "asn_name": { "$first" : "$ip_info.asn.name" }, "region": { "$first" : "$ip_info.region" }, "measurements": { "$sum": 1 }, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')


tlsHostsBlockedPerASNPerRegion <- tlsprobe$aggregate('[{"$group":{"_id": {"host":"$sniHostname", "asn_number": "$ip_info.asn.asn", "region": "$state" }, "company_name": { "$first" : "$ip_info.company.name" }, "asn_name": { "$first" : "$ip_info.asn.name" }, "measurements": { "$sum": 1 }, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')


httpHostsBlocked <- httpprobe$aggregate('[{"$group":{"_id": {"host":"$hostname"}, "company_name": { "$addToSet" : "$ip_info.company.name" }, "asn_name": { "$addToSet" : "$ip_info.asn.name" }, "asn_number": { "$addToSet" : "$ip_info.asn.asn"}, "region": { "$addToSet" : "$state" }, "measurements": { "$sum": 1 }, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')

httpHostsBlockedPerASN <- httpprobe$aggregate('[{"$group":{"_id": {"host":"$hostname", "asn_number": "$ip_info.asn.asn"}, "company_name": { "$first" : "$ip_info.company.name" }, "asn_name": { "$first" : "$ip_info.asn.name" }, "region": { "$first" : "$state" }, "measurements": { "$sum": 1 }, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')


httpHostsBlockedPerASNPerRegion <- httpprobe$aggregate('[{"$group":{"_id": {"host":"$hostname", "asn_number": "$ip_info.asn.asn", "region": "$state" }, "company_name": { "$addToSet" : "$ip_info.company.name" }, "asn_name": { "$addToSet" : "$ip_info.asn.name" }, "measurements": { "$sum": 1 }, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')


httpHostResponseCode <- httpprobe$aggregate('[{"$group":{"_id": {"host":"$hostname"}, "responseCode": { "$addToSet" : "$responseCode" }, "measurements": { "$sum": 1 }, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')



dnsHostsBlocked <- dnsprobe$aggregate('[{"$group":{"_id": {"host":"$hostname"}, "company_name": { "$addToSet" : "$ip_info.company.name" }, "asn_name": { "$addToSet" : "$ip_info.asn.name" }, "asn_number": { "$addToSet" : "$ip_info.asn.asn"}, "region": { "$addToSet" : "$state" }, "measurements": { "$sum": 1 }, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')

tlsHostsBlocked <- tlsprobe$aggregate('[{"$group":{"_id": {"host":"$sniHostname"}, "company_name": { "$addToSet" : "$ip_info.company.name" }, "asn_name": { "$addToSet" : "$ip_info.asn.name" }, "asn_number": { "$addToSet" : "$ip_info.asn.asn"}, "region": { "$addToSet" : "$state" }, "measurements": { "$sum": 1 }, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')


dnsHostsBlockedPerASNPerRegion <- dnsprobe$aggregate('[{"$group":{"_id": {"host":"$hostname", "asn_number": "$ip_info.asn.asn", "region": "$state" }, "company_name": { "$addToSet" : "$ip_info.company.name" }, "asn_name": { "$addToSet" : "$ip_info.asn.name" }, "measurements": { "$sum": 1 }, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')

dnsBlocksPerASNPerRegion <- dnsprobe$aggregate('[{"$group":{"_id": {"asn_number": "$ip_info.asn.asn", "region": "$state" }, "company_name": { "$first" : "$ip_info.company.name" }, "asn_name": { "$first" : "$ip_info.asn.name" }, "measurements": { "$sum": 1 }, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')

dnsBlocksPerASN <- dnsprobe$aggregate('[{"$group":{"_id": {"ASN Number": "$ip_info.asn.asn" }, "ASN Name": { "$first" : "$ip_info.asn.name" }, "Measurements": { "$sum": 1 }, "Number of Confirmed Blocks": { "$sum": { "$cond": [ { "$eq": [ "$confirmed_block", "True" ] }, 1, 0 ] }} }}]')
tlsBlocksPerASN <- dnsprobe$aggregate('[{"$group":{"_id": {"ASN Number": "$ip_info.asn.asn" }, "ASN Name": { "$first" : "$ip_info.asn.name" }, "Measurements": { "$sum": 1 }, "Number of Confirmed Blocks": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')


dnsAnomaliesPerASN <- dnsprobe$aggregate('[{"$group":{"_id": {"ASN Number": "$ip_info.asn.asn" }, "ASN Name": { "$first" : "$ip_info.asn.name" }, "Measurements": { "$sum": 1 }, "Num_error": { "$sum": { "$cond": [ {"$ifNull": ["$sourceIp", false]}, 1, 0 ] }} , "Number of Confirmed Blocks": { "$sum": { "$cond": [ { "$eq": [ "$confirmed_block", "True" ] }, 1, 0 ] }} }}]')


location_comparison <- httpprobe$aggregate('[{"$group":{"_id":"$userRecord", "ip_region": { "$first" : "$ip_info.region" }, "reported_region": { "$first" : "$state"}}}]')

dnsResponseIPs <- dnsprobe$aggregate('[{"$group":{"_id": "$result.test_result.resolved_ip", "websites": { "$addToSet" : "$hostname" }, "company_name": { "$addToSet" : "$ip_info.company.name" }, "asn_number": { "$addToSet" : "$ip_info.asn.asn"}, "region": { "$addToSet" : "$state"}, "asn_name": { "$addToSet" : "$ip_info.asn.name" }, "measurements": { "$sum": 1 }, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')

ASNsPerUserDNS <- dnsprobe$aggregate('[{"$group":{"_id": {"user":"$userRecord", "asn_number": "$ip_info.asn.asn"}, "company_name": { "$first" : "$ip_info.company.name" }, "asn_number": {"$first" : "$ip_info.asn.asn"}, "asn_name": { "$first" : "$ip_info.asn.name" }, "measurements": { "$sum": 1 }, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')
ASNsPerUserHTTP <- httpprobe$aggregate('[{"$group":{"_id": {"user":"$userRecord", "asn_number": "$ip_info.asn.asn"}, "company_name": { "$first" : "$ip_info.company.name" }, "asn_number": {"$first" : "$ip_info.asn.asn"}, "asn_name": { "$first" : "$ip_info.asn.name" }, "measurements": { "$sum": 1 }, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')

dnsprobe_hosts_unknown <- dnsprobe$distinct("hostname", '{"result.test_result.censored": "Unknown"}')


temp <- 0
for (i in 1:length(location_comparison[,2])) { 
  if (is.na(location_comparison[i, 2]) ) {
    next
  }
  if (location_comparison[i, 2] != location_comparison[i,3]) {
    temp <- temp + 1
  }
}  
cat(temp, "out of ", length(location_comparison[,2]), " mismatches")




#print block pages
httpprobe_unique_AS <- httpprobe$distinct("ip_info.asn.asn")

httpprobe_AS_number_name_map <- httpprobe$aggregate('[{"$group":{"_id":"$ip_info.asn.asn", "AS_name": { "$first" : "$ip_info.asn.name" }}}]')
blockpage_signatures <- c()
my_ASNs <- c("AS24309", "AS18209", "AS55577")

# For each AS number
for (asn in httpprobe_unique_AS) {

    # query distinct block pages for this asn
    query_with_parameters <- paste('{ "result.test_result.censored": "True", "ip_info.asn.asn" :"', asn, '"}', sep = "")
    results <- httpprobe$distinct("result.test_result.response", query_with_parameters)
    
    # if nothing is blocked, move on
    if (length(results) == 0) {
      next
    }
    
    # map AS number to AS name
    #AS_name <- httpprobe_AS_number_name_map$AS_name[which(httpprobe_AS_number_name_map$"_id" == asn)]
    
    # print findings
    #cat("AS number: ", asn, " AS name: ", AS_name, "uses the following block pages blockpages: \n \n \n", file="output.txt", sep="\n", append=TRUE) 
    
    for (result in results) {
      
      signature_exists <- FALSE
      for (signature in blockpage_signatures) {
        if (levenshteinSim(result, signature) >= 0.8) {
          signature_exists <- TRUE
          break
        }
      }
      
      if (signature_exists == FALSE) {
        blockpage_signatures <- c(blockpage_signatures, result)
      }
      #cat("response: ", result, "\n \n \n", file="output.txt", sep="\n", append=TRUE)
    }
  }


#print DNS results for blocked DNS hosts
dnsprobe_unique_AS <- dnsprobe$distinct("ip_info.asn.asn")
dnsprobe_AS_number_name_map <- dnsprobe$aggregate('[{"$group":{"_id":"$ip_info.asn.asn", "AS_name": { "$first" : "$ip_info.asn.name" }}}]')

# For each AS number
for (asn in dnsprobe_unique_AS) {
  
  # query distinct block pages for this asn
  query_with_parameters <- paste('{ "result.test_result.censored": "True", "ip_info.asn.asn" :"', asn, '"}', sep = "")
  results <- dnsprobe$distinct("result.test_result.resolved_ip", query_with_parameters)
  
  # if nothing is blocked, move on
  if (length(results) == 0) {
    next
  }
  
  # map AS number to AS name
  AS_name <- dnsprobe_AS_number_name_map$AS_name[which(dnsprobe_AS_number_name_map$"_id" == asn)]
  
  # print findings
  cat("AS number: ", asn, " AS name: ", AS_name, "gave the following dns servers in its own AS: \n \n \n") 
  
  temp <- 0
  for (result in results) {
    cat("response: ", result, "\n \n \n")
    temp <- temp + 1
    if (temp == 20) {
      break
    }
  }
}


results <- httpprobe$find('{"result.test_result.censored": "True"}', '{"result.test_result.response": 1}')
suspected_blocks <- unlist(results$result)
blockpage_snippets <- c("requested URL has been blocked", "webadmin/deny/", "The URL you're trying to reach has been blocked", "airtel.in/dot", "The URL you requested has been blocked", "This website/URL has been blocked")
confirmed_blocks <- 0
  
for (suspected_block in suspected_blocks) {
    match_found <- FALSE
    for (snippet in blockpage_snippets) {
      if (grepl(snippet, suspected_block, fixed=TRUE) == TRUE) {
        confirmed_blocks <- confirmed_blocks + 1
        match_found <- TRUE
        break
      }
    }
    
    if (match_found == FALSE) {
      cat("No match: ", suspected_block)
    }
}
cat("Number of suspected HTTP blocks: ", length(suspected_blocks), ". Number of confirmed blocks: ", confirmed_blocks)


dnsprobe_hosts <- dnsprobe$distinct("hostname")
dnsprobe_unique_AS <- dnsprobe$distinct("ip_info.asn.asn")
results <- data.frame(hosts = dnsprobe_hosts)
empty_list <- rep(NA, length(results$hosts))

for (x in 1:length(dnsprobe_hosts)) {
  for (asn in dnsprobe_unique_AS) {
    results[[asn]] = data.frame(dns_measurements = empty_list, dns_blocks = empty_list, tls_measurements = empty_list, tls_blocks = empty_list, http_measurements = empty_list, http_blocks = empty_list)

    # Find DNS blocks  
    query_with_parameters <- paste('[{"$match": {"hostname": "', dnsprobe_hosts[x], '", "ip_info.asn.asn" :"', asn, '"}}, {"$group":{"_id": {"asn_number": "$ip_info.asn.asn", "host":"$hostname"}, "measurements": { "$sum": 1 }, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]', sep = "")
    dnsBlocksForASNAndHost <- dnsprobe$aggregate(query_with_parameters)
  
    # Find TLS blocks  
    query_with_parameters <- paste('[{"$match": {"sniHostname": "', dnsprobe_hosts[x], '", "ip_info.asn.asn" :"', asn, '"}}, {"$group":{"_id": {"asn_number": "$ip_info.asn.asn", "host":"$hostname"}, "measurements": { "$sum": 1 }, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]', sep = "")
    tlsBlocksForASNAndHost <- tlsprobe$aggregate(query_with_parameters)
    
    # Find DNS blocks  
    query_with_parameters <- paste('[{"$match": {"hostname": "', dnsprobe_hosts[x], '", "ip_info.asn.asn" :"', asn, '"}}, {"$group":{"_id": {"asn_number": "$ip_info.asn.asn", "host":"$hostname"}, "measurements": { "$sum": 1 }, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]', sep = "")
    httpBlocksForASNAndHost <- httpprobe$aggregate(query_with_parameters)
    
    #Save results
    if (length(dnsBlocksForASNAndHost) != 0) {
      results[[asn]]$dns_measurements[x] = dnsBlocksForASNAndHost$measurements
      results[[asn]]$dns_blocks[x] = dnsBlocksForASNAndHost$Num_blocked
    }
    
    if (length(tlsBlocksForASNAndHost) != 0) {
      results[[asn]]$tls_measurements[x] = tlsBlocksForASNAndHost$measurements
      results[[asn]]$tls_blocks[x] = tlsBlocksForASNAndHost$Num_blocked
    }
    
    if (length(httpBlocksForASNAndHost) != 0) {
      results[[asn]]$http_measurements[x] = httpBlocksForASNAndHost$measurements
      results[[asn]]$http_blocks[x] = httpBlocksForASNAndHost$Num_blocked
    }
    View(results)
  }
}

httpHostsBlockedPerASN <- httpprobe$aggregate('[{"$group":{"_id": {"host":"$hostname", "asn_number": "$ip_info.asn.asn"}, "measurements": { "$sum": 1 }, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')
dnsHostsBlockedPerASN <- dnsprobe$aggregate('[{"$group":{"_id": {"host":"$hostname", "asn_number": "$ip_info.asn.asn"}, "measurements": { "$sum": 1 }, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')
tlsHostsBlockedPerASN <- tlsprobe$aggregate('[{"$group":{"_id": {"host":"$sniHostname", "asn_number": "$ip_info.asn.asn"}, "measurements": { "$sum": 1 }, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')

dnsprobe_hosts <- dnsprobe$distinct("hostname")
dnsprobe_unique_AS <- dnsprobe$distinct("ip_info.asn.asn")
results2 <- data.frame(hosts = dnsprobe_hosts)
empty_list <- rep(NA, length(results$hosts))

for (x in 9:10) {
  hostname <- dnsprobe_hosts[x]
  for (asn in dnsprobe_unique_AS) {
    if (is.null(results2[[asn]])) {
     results2[[asn]] = data.frame(dns_measurements = empty_list, dns_blocks = empty_list, tls_measurements = empty_list, tls_blocks = empty_list, http_measurements = empty_list, http_blocks = empty_list)
    }
    index <- which(dnsHostsBlockedPerASN$"_id"$host == hostname & dnsHostsBlockedPerASN$"_id"$asn_number == asn) 
    if(!identical(index, integer(0))){
      results2[[asn]]$dns_measurements[x] = dnsHostsBlockedPerASN$measurements[index]
      results2[[asn]]$dns_blocks[x] = dnsHostsBlockedPerASN$Num_blocked[index]
    }

    index <- which(tlsHostsBlockedPerASN$"_id"$host == hostname & tlsHostsBlockedPerASN$"_id"$asn_number == asn) 
    if(!identical(index, integer(0))){
      results2[[asn]]$tls_measurements[x] = tlsHostsBlockedPerASN$measurements[index]
      results2[[asn]]$tls_blocks[x] = tlsHostsBlockedPerASN$Num_blocked[index]
    }
    
    index <- which(httpHostsBlockedPerASN$"_id"$host == hostname & httpHostsBlockedPerASN$"_id"$asn_number == asn) 
    if(!identical(index, integer(0))){
      results2[[asn]]$http_measurements[x] = httpHostsBlockedPerASN$measurements[index]
      results2[[asn]]$http_blocks[x] = httpHostsBlockedPerASN$Num_blocked[index]
    }
    
  }
}  

for (asn in ASNs_to_consider) {
  httpcount <- 0
  for (measurement in results2[[asn]]$http_measurements) {
    if(is.na(measurement)) {
      httpcount <- httpcount + 1
    }
  }
  
  dnscount <- 0
  for (measurement in results2[[asn]]$dns_measurements) {
    if(is.na(measurement)) {
      dnscount <- dnscount + 1
    }
  }
  
  tlscount <- 0
  for (measurement in results2[[asn]]$tls_measurements) {
    if(is.na(measurement)) {
      tlscount <- tlscount + 1
    }
  }
  
  cat("ASN: ", asn, " has: ", httpcount, " HTTP blanks, ", dnscount, " DNS blanks, and ", tlscount, " TLS blanks  \n")
}    
