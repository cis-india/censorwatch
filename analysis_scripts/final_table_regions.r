httpHostsBlockedPerState <- httpprobe$aggregate('[{"$match": {"invalid": {"$ne": "True"}}} , {"$group":{"_id": {"host":"$hostname", "region": "$state"}, "measurements": { "$sum": 1 }, "Num_error": { "$sum": { "$cond": [ {"$ifNull": ["$error", false]}, 1, 0 ] }}, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')
dnsHostsBlockedPerState <- dnsprobe$aggregate('[{"$match": {"invalid": {"$ne": "True"}}} , {"$group":{"_id": {"host":"$hostname", "region": "$state"}, "measurements": { "$sum": 1 }, "Num_error": { "$sum": { "$cond": [ {"$ifNull": ["$error", false]}, 1, 0 ] }}, "Num_unknown": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "Unknown" ] }, 1, 0 ] }} , "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$confirmed_block", "True" ] }, 1, 0 ] }} }}]')
tlsHostsBlockedPerState <- tlsprobe$aggregate('[{"$match": {"invalid": {"$ne": "True"}}} , {"$group":{"_id": {"host":"$sniHostname", "region": "$state"}, "measurements": { "$sum": 1 }, "Num_error": { "$sum": { "$cond": [ {"$ifNull": ["$error1", false]}, 1, 0 ] }}, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')

dnsprobe_unique_state <- dnsprobe$distinct("state")
httpprobe_unique_state <- httpprobe$distinct("state")
httpprobe_hosts <- httpprobe$distinct("hostname")

unique_ASNs <- union(httpprobe_unique_AS, dnsprobe_unique_AS)
ASNs_to_consider <- unique_ASNs[!unique_ASNs %in% bad_measurements]

unique_states <- union(httpprobe_unique_state, dnsprobe_unique_state)

Hosts_to_consider <- httpprobe_hosts[!httpprobe_hosts %in% bad_websites]
Hosts_to_consider <- Hosts_to_consider[!Hosts_to_consider %in% high_error_websites]

empty_list <- rep(0, length(unique_states))
results4 <- data.frame(state = unique_states, measurements = empty_list, number_of_blocked_sites = empty_list, number_of_inconclusive = empty_list, number_of_unmeasured_sites = empty_list)

#for (host in Hosts_to_consider) {
#  if (is.null(results4[[host]])) {
#    results4[[host]] = data.frame(measurements = empty_list, errors = empty_list, blanks = empty_list, blocklist = empty_list)
#  }
#}

for(x in 1:length(unique_states)) {
  state <- unique_states[x]
  
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
  
  dns_blanks <- 0
  tls_blanks <- 0
  http_blanks <- 0
  
  indexes <-  which(dnsHostsBlockedPerState$"_id"$region == state)
  #cat("here ", length(indexes), "\n")
  for(index in indexes) {
    host <- dnsHostsBlockedPerState$"_id"$host[index]
    #cat("here2 ", host, "\n")
    
    if(!(host %in% Hosts_to_consider)) {
      next
    }
    
    if(dnsHostsBlockedPerState$measurements[index] != dnsHostsBlockedPerState$Num_unknown[index]) {
      dns_hosts_measured <- append(dns_hosts_measured, host)
    }
    
    if(dnsHostsBlockedPerState$measurements[index] == dnsHostsBlockedPerState$Num_error[index]) {
      dns_hosts_error <- append(dns_hosts_error, host)
    }
    
    dns_measurements <- dns_measurements + dnsHostsBlockedPerState$measurements[index]

    if (dnsHostsBlockedPerState$Num_blocked[index] >= 1) {
      blocklist <- append(blocklist, host)
    }
    
    #cat("here2 measure: ", dnsHostsBlockedPerASN$measurements[index], " blocks ", dnsHostsBlockedPerASN$Num_blocked[index], "\n")
    
  }
  dns_blanks <- setdiff(Hosts_to_consider, dns_hosts_measured)
  
  indexes <-  which(tlsHostsBlockedPerState$"_id"$region == state)
  for(index in indexes) {
    host <- tlsHostsBlockedPerState$"_id"$host[index]

    if(!(host %in% Hosts_to_consider)) {
      next
    }  
    
    tls_hosts_measured <- append(tls_hosts_measured, host)
    
    if(tlsHostsBlockedPerState$measurements[index] == tlsHostsBlockedPerState$Num_error[index]) {
      tls_hosts_error <- append(tls_hosts_error, host)
    }
    
    tls_measurements <- tls_measurements + tlsHostsBlockedPerState$measurements[index]

    if (tlsHostsBlockedPerState$Num_blocked[index] >= 1) {
      blocklist <- append(blocklist, host)
    }
  }
  tls_blanks <- setdiff(Hosts_to_consider, tls_hosts_measured)
  
  
  indexes <-  which(httpHostsBlockedPerState$"_id"$region == state)
  for(index in indexes) {
    host <- httpHostsBlockedPerState$"_id"$host[index]
    
    if(!(host %in% Hosts_to_consider)) {
      next
    } 
    
    http_hosts_measured <- append(http_hosts_measured, host)
    
    if(httpHostsBlockedPerState$measurements[index] == httpHostsBlockedPerState$Num_error[index]) {
      http_hosts_error <- append(http_hosts_error, host)
    }
    
    http_measurements <- http_measurements + httpHostsBlockedPerState$measurements[index]

    if (httpHostsBlockedPerState$Num_blocked[index] >= 1) {
      blocklist <- append(blocklist, host)
    }
  }
  http_blanks <- setdiff(Hosts_to_consider, http_hosts_measured)
  
  
  # cat("asn:", asn, " measurements: ", (dns_measurements + tls_measurements + http_measurements), " dns_blocks ", dns_blocks, " tls_blocks ", tls_blocks, " http_blocks ", http_blocks, "for host ", host, "\n")
  blocklist <- unique(blocklist)
  results4$number_of_blocked_sites[x] <- length(blocklist)
  
  list_of_inconclusive <- union( union(dns_hosts_error, tls_hosts_error), http_hosts_error) 
  list_of_inconclusive <- list_of_inconclusive[!list_of_inconclusive %in% blocklist]
  results4$number_of_inconclusive[x] <- length(list_of_inconclusive)
  
  list_of_unmeasured <-  union( union(dns_blanks, tls_blanks), http_blanks)
  list_of_unmeasured <- list_of_unmeasured[!list_of_unmeasured %in% blocklist]
  results4$number_of_unmeasured_sites[x] <- length(list_of_unmeasured)
  
  results4$measurements[x] <- (dns_measurements + tls_measurements + http_measurements) / (length(Hosts_to_consider) * 3)
}  

results4 <- results4[order(results4$number_of_unmeasured_sites),]
colnames(results4) <- c("Region", "Readings", "Number of Confirmed\nBlocked Sites", "Number of Sites With\nInconclusive Readings")
results4$Readings <- round(results4$Readings, digits = 1)
rownames(results4) <- 1:nrow(results4)
write.csv(results4, "BlocksByRegion.csv", row.names = F)
