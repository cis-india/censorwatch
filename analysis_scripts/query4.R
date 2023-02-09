httpHostsBlockedPerASN <- httpprobe$aggregate('[{"$group":{"_id": {"host":"$hostname", "asn_number": "$ip_info.asn.asn"}, "measurements": { "$sum": 1 }, "Num_error": { "$sum": { "$cond": [ {"$ifNull": ["$error", false]}, 1, 0 ] }}, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')
dnsHostsBlockedPerASN <- dnsprobe$aggregate('[{"$group":{"_id": {"host":"$hostname", "asn_number": "$ip_info.asn.asn"}, "measurements": { "$sum": 1 }, "Num_error": { "$sum": { "$cond": [ {"$ifNull": ["$error", false]}, 1, 0 ] }}, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$confirmed_block", "True" ] }, 1, 0 ] }} }}]')
tlsHostsBlockedPerASN <- tlsprobe$aggregate('[{"$group":{"_id": {"host":"$sniHostname", "asn_number": "$ip_info.asn.asn"}, "measurements": { "$sum": 1 }, "Num_error": { "$sum": { "$cond": [ {"$ifNull": ["$error", false]}, 1, 0 ] }}, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')

dnsprobe_unique_AS <- dnsprobe$distinct("ip_info.asn.asn")
httpprobe_unique_AS <- httpprobe$distinct("ip_info.asn.asn")
httpprobe_hosts <- httpprobe$distinct("hostname")

unique_ASNs <- union(httpprobe_unique_AS, dnsprobe_unique_AS)
ASNs_to_consider <- unique_ASNs[!unique_ASNs %in% bad_measurements]
Hosts_to_consider <- httpprobe_hosts[!httpprobe_hosts %in% bad_websites]
results2 <- data.frame(hosts = Hosts_to_consider)
empty_list <- rep(NA, length(results2$hosts))
for (asn in ASNs_to_consider) {
  if (is.null(results2[[asn]])) {
    results2[[asn]] = data.frame(dns_measurements = empty_list, dns_blocks = empty_list, tls_measurements = empty_list, tls_blocks = empty_list, http_measurements = empty_list, http_blocks = empty_list)
  }
}


for(x in 1:length(Hosts_to_consider)) {
  hostname <- Hosts_to_consider[x]
  
  indexes <-  which(dnsHostsBlockedPerASN$"_id"$host == hostname)
  for(index in indexes) {
    asn <- dnsHostsBlockedPerASN$"_id"$asn_number[index]
    if (is.na(asn) || is.null(results2[[asn]])) {
      next
    }
    
    results2[[asn]]$dns_measurements[x] = dnsHostsBlockedPerASN$measurements[index]
    results2[[asn]]$dns_blocks[x] = dnsHostsBlockedPerASN$Num_blocked[index]
  }
  
  indexes <-  which(tlsHostsBlockedPerASN$"_id"$host == hostname)
  for(index in indexes) {
    asn <- tlsHostsBlockedPerASN$"_id"$asn_number[index]
    if (is.na(asn) || is.null(results2[[asn]])) {
      next
    }
    
    results2[[asn]]$tls_measurements[x] = tlsHostsBlockedPerASN$measurements[index]
    results2[[asn]]$tls_blocks[x] = tlsHostsBlockedPerASN$Num_blocked[index]
  }
  
  indexes <-  which(httpHostsBlockedPerASN$"_id"$host == hostname)
  for(index in indexes) {
    asn <- httpHostsBlockedPerASN$"_id"$asn_number[index]
    if (is.na(asn) || is.null(results2[[asn]])) {
      next
    }
    
    results2[[asn]]$http_measurements[x] = httpHostsBlockedPerASN$measurements[index]
    results2[[asn]]$http_blocks[x] = httpHostsBlockedPerASN$Num_blocked[index]
  }
}


errorCounts <- httpprobe$aggregate('[{"$group":{"_id": {"host":"$hostname"}, "measurements": { "$sum": 1 },"Num_error": { "$sum": { "$cond": [ {"$ifNull": ["$error", false]}, 1, 0 ] }}, "Num_timeouts": { "$sum": { "$cond": [ {"$regexMatch": {"input": "$error", "regex": ".*Timeout*."} }, 1, 0 ] }}, "Num_NotFounds": { "$sum": { "$cond": [ {"$regexMatch": {"input": "$error", "regex": ".*NotFound*."} }, 1, 0 ] }}, "Num_socket_err": { "$sum": { "$cond": [ {"$regexMatch": {"input": "$error", "regex": ".*SocketException*."} }, 1, 0 ] }}, "Num_connect_err": { "$sum": { "$cond": [ {"$regexMatch": {"input": "$error", "regex": ".*ConnectException*."} }, 1, 0 ] }}, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')


errorCountsByUser <- httpprobe$aggregate('[{"$group":{"_id": {"user":"$userRecord"}, "measurements": { "$sum": 1 }, "Num_error": { "$sum": { "$cond": [ {"$ifNull": ["$error", false]}, 1, 0 ] }},"Num_timeouts": { "$sum": { "$cond": [ {"$regexMatch": {"input": "$error", "regex": ".*Timeout*."} }, 1, 0 ] }}, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')

errorCountsByASN <- httpprobe$aggregate('[{"$group":{"_id": {"user":"$ip_info.asn.asn"}, "measurements": { "$sum": 1 }, "Num_error": { "$sum": { "$cond": [ {"$ifNull": ["$error", false]}, 1, 0 ] }},"Num_timeouts": { "$sum": { "$cond": [ {"$regexMatch": {"input": "$error", "regex": ".*Timeout*."} }, 1, 0 ] }}, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')

errorCountsByIP <- httpprobe$aggregate('[{"$group":{"_id": {"source":"$sourceIp"}, "measurements": { "$sum": 1 }, "Num_error": { "$sum": { "$cond": [ {"$ifNull": ["$error", false]}, 1, 0 ] }},"Num_timeouts": { "$sum": { "$cond": [ {"$regexMatch": {"input": "$error", "regex": ".*Timeout*."} }, 1, 0 ] }}, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')

errorCountsByHost <- httpprobe$aggregate('[{"$group":{"_id": {"host":"$hostname"}, "measurements": { "$sum": 1 }, "Num_error": { "$sum": { "$cond": [ {"$ifNull": ["$error", false]}, 1, 0 ] }},"Num_timeouts": { "$sum": { "$cond": [ {"$regexMatch": {"input": "$error", "regex": ".*Timeout*."} }, 1, 0 ] }}, "Num_blocked": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "True" ] }, 1, 0 ] }} }}]')

unknownCountsByHost <- dnsprobe$aggregate('[{"$group":{"_id": {"host":"$hostname"}, "measurements": { "$sum": 1 }, "Num_error": { "$sum": { "$cond": [ {"$ifNull": ["$error", false]}, 1, 0 ] }}, "Num_unknown": { "$sum": { "$cond": [ { "$eq": [ "$result.test_result.censored", "Unknown" ] }, 1, 0 ] }} }}]')

unknownCountsByHost$present <- FALSE
for (x in 1:length(unknownCountsByHost$"_id"$host)) {
  host <- unknownCountsByHost$"_id"$host[x]
  if (host %in% Hosts_to_consider) {
    unknownCountsByHost$present[x] <- TRUE
  }
}

errorCountsByHost$errorRate <- 0
for (x in 1:length(errorCountsByHost$"_id"$host)) {
  host <- errorCountsByHost$"_id"$host[x]
  errorCountsByHost$errorRate[x] <- errorCountsByHost$Num_error[x]/errorCountsByHost$measurements[x]
}

high_error_websites <- c()
for (x in 1:length(errorCountsByHost$"_id"$host)) {
  host <- errorCountsByHost$"_id"$host[x]
  if (errorCountsByHost$errorRate[x] >= 0.85) {
    high_error_websites <- append(high_error_websites, host)
  }
}  

ASNs_to_consider <- unique_ASNs[!unique_ASNs %in% bad_measurements]
blanksByHost2 <- data.frame(hosts = results2$hosts)
blanksByHost2$Num_blanks <- 0
blanksByHost2$ASNs <- " "
for(x in 1:length(results2$hosts)) {
  hostname <- results2$hosts[x]
  for (asn in ASNs_to_consider) {
    if (is.na(results2[[asn]]$http_measurements[x])) {
      blanksByHost2$Num_blanks[x] <- blanksByHost2$Num_blanks[x] + 1
      blanksByHost2$ASNs[x] <- paste(blanksByHost2$ASNs[x], asn)
    }
  }
}

bad_websites <- c()
for(x in 1:length(blanksByHost$hosts)) {
  hostname <- blanksByHost$hosts[x]
  if (blanksByHost$Num_blanks[x] >= 10) {
    bad_websites <- append(bad_websites, hostname)
  }
}
  
pdf("mypdf.pdf", height=18, width=17)
grid.table(results3)
dev.off()