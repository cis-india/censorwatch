httpHostsBlockedPerASN <- httpprobe$aggregate('[{"$group":{"_id": {"host":"$hostname", "asn_number": "$ip_info.asn.asn"}, "measurements": { "$sum": 1 }, "Num_error": { "$sum": { "$cond": [ {"$ifNull": ["$error", false]}, 1, 0 ] }}, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')
dnsHostsBlockedPerASN <- dnsprobe$aggregate('[{"$group":{"_id": {"host":"$hostname", "asn_number": "$ip_info.asn.asn"}, "measurements": { "$sum": 1 }, "Num_error": { "$sum": { "$cond": [ {"$ifNull": ["$sourceIp", false]}, 1, 0 ] }}, "Num_unknown": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "Unknown" ] }, 1, 0 ] }} ,"Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$confirmed_block", "True" ] }, 1, 0 ] }} }}]')
tlsHostsBlockedPerASN <- tlsprobe$aggregate('[{"$group":{"_id": {"host":"$sniHostname", "asn_number": "$ip_info.asn.asn"}, "measurements": { "$sum": 1 }, "Num_error": { "$sum": { "$cond": [ {"$ifNull": ["$error1", false]}, 1, 0 ] }}, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')

dnsprobe_unique_AS <- dnsprobe$distinct("ip_info.asn.asn")
httpprobe_unique_AS <- httpprobe$distinct("ip_info.asn.asn")
tlsprobe_unique_AS <- tlsprobe$distinct("ip_info.asn.asn")

httpprobe_hosts <- httpprobe$distinct("hostname")

httpprobe_AS_number_name_map <- httpprobe$aggregate('[{"$group":{"_id":"$ip_info.asn.asn", "AS_name": { "$first" : "$ip_info.asn.name" }}}]')

unique_ASNs <- union( union(httpprobe_unique_AS, dnsprobe_unique_AS), tlsprobe_unique_AS)
ASNs_to_consider <- unique_ASNs[!unique_ASNs %in% bad_measurements]

Hosts_to_consider <- httpprobe_hosts[!httpprobe_hosts %in% bad_websites]
Hosts_to_consider <- Hosts_to_consider[!Hosts_to_consider %in% high_error_websites]

empty_list <- rep(0, length(ASNs_to_consider))
results3 <- data.frame(asn = ASNs_to_consider, asn_name = empty_list, measurements = empty_list, number_of_blocked_sites = empty_list, number_of_inconclusive = empty_list, number_of_unmeasured_sites = empty_list)

#for (host in Hosts_to_consider) {
#  if (is.null(results3[[host]])) {
#    results3[[host]] = data.frame(measurements = empty_list, errors = empty_list, blanks = empty_list, blocklist = empty_list)
#  }
#}
net_blocklist <- c()

for(x in 1:length(ASNs_to_consider)) {
  asn <- ASNs_to_consider[x]
  
  blocklist <- c()
  dns_hosts_measured <- c()
  tls_hosts_measured <- c()
  http_hosts_measured <- c()
  
  tls_hosts_error <- c()
  dns_hosts_error <- c()
  http_hosts_error <- c()
  
  dns_blocks <- 0
  tls_blocks <- 0
  http_blocks <- 0
  
  dns_measurements <- 0
  tls_measurements <- 0
  http_measurements <- 0
  
  dns_errors <- c()
  tls_errors <- c()
  http_errors <- c()
  
  dns_blanks <- 0
  tls_blanks <- 0
  http_blanks <- 0
  
  indexes <-  which(dnsHostsBlockedPerASN$"_id"$asn_number == asn)
  #cat("here ", length(indexes), "\n")
  for(index in indexes) {
    host <- dnsHostsBlockedPerASN$"_id"$host[index]
    #cat("here2 ", host, "\n")
  
    if(!(host %in% Hosts_to_consider)) {
      next
    }
    
    if(dnsHostsBlockedPerASN$measurements[index] != dnsHostsBlockedPerASN$Num_unknown[index]) {
      dns_hosts_measured <- append(dns_hosts_measured, host)
    }
    
    if(dnsHostsBlockedPerASN$measurements[index] == dnsHostsBlockedPerASN$Num_error[index]) {
      dns_hosts_error <- append(dns_hosts_error, host)
    }
    
    dns_measurements <- dns_measurements + dnsHostsBlockedPerASN$measurements[index]

    if (dnsHostsBlockedPerASN$Num_blocked[index] >= 1) {
        blocklist <- append(blocklist, host)
    }
    
    #cat("here2 measure: ", dnsHostsBlockedPerASN$measurements[index], " blocks ", dnsHostsBlockedPerASN$Num_blocked[index], "\n")
    
  }
  dns_blanks <- setdiff(Hosts_to_consider, dns_hosts_measured)
  #dns_errors <- setdiff(Hosts_to_consider, dns_hosts_error)
  #dns_hosts_error <- dns_hosts_error[!dns_hosts_error %in% dns_hosts_measured]
  
  
  indexes <-  which(tlsHostsBlockedPerASN$"_id"$asn_number == asn)
  for(index in indexes) {
    host <- tlsHostsBlockedPerASN$"_id"$host[index]

    if(!(host %in% Hosts_to_consider)) {
      next
    }  

    tls_hosts_measured <- append(tls_hosts_measured, host)
    
    if(tlsHostsBlockedPerASN$measurements[index] == tlsHostsBlockedPerASN$Num_error[index]) {
      tls_hosts_error <- append(tls_hosts_error, host)
    }
    
    tls_measurements <- tls_measurements + tlsHostsBlockedPerASN$measurements[index]

    if (tlsHostsBlockedPerASN$Num_blocked[index] >= 1) {
      blocklist <- append(blocklist, host)
    }
  }
  tls_blanks <- setdiff(Hosts_to_consider, tls_hosts_measured)

  indexes <-  which(httpHostsBlockedPerASN$"_id"$asn_number == asn)
  for(index in indexes) {
    host <- httpHostsBlockedPerASN$"_id"$host[index]
    
    if(!(host %in% Hosts_to_consider)) {
      next
    } 
    
    http_hosts_measured <- append(http_hosts_measured, host)

    if(httpHostsBlockedPerASN$measurements[index] == httpHostsBlockedPerASN$Num_error[index]) {
      http_hosts_error <- append(http_hosts_error, host)
    }
    
    http_measurements <- http_measurements + httpHostsBlockedPerASN$measurements[index]

    if (httpHostsBlockedPerASN$Num_blocked[index] >= 1) {
      blocklist <- append(blocklist, host)
    }
  }
  http_blanks <- setdiff(Hosts_to_consider, http_hosts_measured)
  #http_hosts_error <- http_hosts_error[!http_hosts_error %in% http_hosts_measured]
  #http_errors <- setdiff(Hosts_to_consider, http_hosts_error)

 # cat("asn:", asn, " measurements: ", (dns_measurements + tls_measurements + http_measurements), " dns_blocks ", dns_blocks, " tls_blocks ", tls_blocks, " http_blocks ", http_blocks, "for host ", host, "\n")
  blocklist <- unique(blocklist)
  results3$number_of_blocked_sites[x] <- length(blocklist)
  
  list_of_inconclusive <- union( union(dns_hosts_error, tls_hosts_error), http_hosts_error) 
  list_of_inconclusive <- list_of_inconclusive[!list_of_inconclusive %in% blocklist]
  results3$number_of_inconclusive[x] <- length(list_of_inconclusive)

  list_of_unmeasured <-  union( union(dns_blanks, tls_blanks), http_blanks)
  list_of_unmeasured <- list_of_unmeasured[!list_of_unmeasured %in% blocklist]
  results3$number_of_unmeasured_sites[x] <- length(list_of_unmeasured)

  results3$measurements[x] <- (dns_measurements + tls_measurements + http_measurements) / (length(Hosts_to_consider) * 3)
  results3$asn_name[x] <- httpprobe_AS_number_name_map$AS_name[which(httpprobe_AS_number_name_map$"_id" == asn)]
  
  net_blocklist <- union(net_blocklist, blocklist)
}  
